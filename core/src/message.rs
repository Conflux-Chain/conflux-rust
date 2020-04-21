// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type RequestId = u64;
pub type MsgId = u16;

pub use cfx_bytes::Bytes;
pub use priority_send_queue::SendQueuePriority;
use rlp::{Decodable, Encodable, Rlp};

pub use crate::network::{
    throttling::THROTTLING_SERVICE, Error as NetworkError,
    ErrorKind as NetworkErrorKind, NetworkContext, PeerId,
};
use crate::sync::msg_sender::metric_message;
use network::{node_table::NodeId, service::ProtocolVersion};

macro_rules! build_msgid {
    ($($name:ident = $value:expr)*) => {
        #[allow(dead_code)]
        pub mod msgid {
            use super::MsgId;
            $(pub const $name: MsgId = $value;)*
        }
    }
}

// TODO: GetMaybeRequestId is part of Message due to the implementation of
// TODO: Throttled. Conceptually this class isn't part of Message.
pub trait GetMaybeRequestId {
    fn get_request_id(&self) -> Option<RequestId> { None }
}

pub trait SetRequestId: GetMaybeRequestId {
    fn set_request_id(&mut self, _id: RequestId);
}

pub trait MessageProtocolVersionBound {
    fn version_introduced(&self) -> ProtocolVersion;
    /// The return type is NOT defined as Option intentionally,
    /// because I'd like to make it impossible to keep a Message
    /// forever by default.
    ///
    /// Whenever we bump a protocol version, always update the
    /// version_deprecated for each message.
    fn version_deprecated(&self) -> ProtocolVersion;
}

pub trait Message:
    Send + Sync + GetMaybeRequestId + MessageProtocolVersionBound + Encodable
{
    // If true, message may be throttled when sent to remote peer.
    fn is_size_sensitive(&self) -> bool { false }
    fn msg_id(&self) -> MsgId;
    fn push_msg_id_bytes(&self, buffer: &mut Vec<u8>) {
        let msg_id = self.msg_id();
        let msg_id_msb = (msg_id >> 8) as u8;
        let msg_id_lsb = msg_id as u8;
        buffer.push(msg_id_msb);
        buffer.push(msg_id_lsb);
    }
    fn msg_name(&self) -> &'static str;
    fn priority(&self) -> SendQueuePriority { SendQueuePriority::High }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = self.rlp_bytes();
        self.push_msg_id_bytes(&mut encoded);
        encoded
    }

    fn throttle_token_cost(&self) -> (u64, u64) { (1, 0) }

    fn send(
        &self, io: &dyn NetworkContext, node_id: &NodeId,
    ) -> Result<(), NetworkError> {
        self.send_with_throttling(io, node_id, false)
    }

    fn send_with_throttling(
        &self, io: &dyn NetworkContext, node_id: &NodeId,
        throttling_disabled: bool,
    ) -> Result<(), NetworkError>
    {
        if !throttling_disabled && self.is_size_sensitive() {
            if let Err(e) = THROTTLING_SERVICE.read().check_throttling() {
                debug!("Throttling failure: {:?}", e);
                return Err(e);
            }
        }

        let msg = self.encode();
        let size = msg.len();

        if let Err(e) =
            io.send(node_id, msg, self.version_introduced(), self.priority())
        {
            debug!("Error sending message: {:?}", e);
            return Err(e);
        };

        debug!(
            "Send message({}) to peer {:?}, protocol {:?}",
            self.msg_name(),
            node_id,
            io.get_protocol(),
        );

        if !io.is_peer_self(node_id) {
            metric_message(self.msg_id(), size);
        }

        Ok(())
    }
}

/// Check if we received deprecated message.
pub fn decode_rlp_and_check_deprecation<T: Message + Decodable>(
    rlp: &Rlp, our_protocol_version: ProtocolVersion,
) -> Result<T, NetworkError> {
    let msg: T = rlp.as_val()?;

    // FIXME: all usages filled in peer's protocol version. FIX them all
    if our_protocol_version >= msg.version_deprecated() {
        bail!(NetworkErrorKind::MessageDeprecated);
    }

    Ok(msg)
}

pub fn decode_msg(msg: &[u8]) -> Option<(MsgId, Rlp)> {
    let len = msg.len();
    if len < 2 {
        return None;
    }

    let msg_id = ((msg[len - 2] as MsgId) << 8) + (msg[len - 1] as MsgId);
    let rlp = Rlp::new(&msg[..len - 2]);

    Some((msg_id, rlp))
}

macro_rules! mark_msg_version_bound {
    ($name:ident, $msg_ver:expr, $msg_deprecation_ver:expr) => {
        impl MessageProtocolVersionBound for $name {
            fn version_introduced(&self) -> ProtocolVersion { $msg_ver }

            fn version_deprecated(&self) -> ProtocolVersion {
                $msg_deprecation_ver
            }
        }
    };
}

macro_rules! build_msg_basic {
    (
        $name:ident,
        $msg:expr,
        $name_str:literal,
        $msg_ver:expr,
        $msg_deprecation_ver:expr
    ) => {
        mark_msg_version_bound!($name, $msg_ver, $msg_deprecation_ver);

        impl Message for $name {
            fn msg_id(&self) -> MsgId { $msg }

            fn msg_name(&self) -> &'static str { $name_str }
        }
    };
}

macro_rules! build_msg_impl {
    (
        $name:ident,
        $msg:expr,
        $name_str:literal,
        $msg_ver:expr,
        $msg_deprecation_ver:expr
    ) => {
        impl GetMaybeRequestId for $name {}

        build_msg_basic!(
            $name,
            $msg,
            $name_str,
            $msg_ver,
            $msg_deprecation_ver
        );
    };
}

macro_rules! impl_request_id_methods {
    ($name:ty) => {
        impl GetMaybeRequestId for $name {
            fn get_request_id(&self) -> Option<RequestId> {
                Some(self.request_id)
            }
        }

        impl SetRequestId for $name {
            fn set_request_id(&mut self, id: RequestId) {
                self.request_id = id;
            }
        }
    };
}

macro_rules! build_msg_with_request_id_impl {
    (
        $name:ident,
        $msg:expr,
        $name_str:literal,
        $msg_ver:expr,
        $msg_deprecation_ver:expr
    ) => {
        build_msg_basic!(
            $name,
            $msg,
            $name_str,
            $msg_ver,
            $msg_deprecation_ver
        );
        impl_request_id_methods!($name);
    };
}
