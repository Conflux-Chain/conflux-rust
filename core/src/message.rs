// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type RequestId = u64;
pub type MsgId = u16;
const MSG_ID_MAX: u16 = 1 << 14;

pub use cfx_bytes::Bytes;
pub use priority_send_queue::SendQueuePriority;
use rlp::{Decodable, Encodable, Rlp};

pub use crate::network::{
    throttling::THROTTLING_SERVICE, Error as NetworkError,
    ErrorKind as NetworkErrorKind, NetworkContext, PeerId,
};
use crate::sync::msg_sender::metric_message;
use network::{
    node_table::NodeId, parse_msg_id_leb128_2_bytes_at_most,
    service::ProtocolVersion, ProtocolId,
};

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
    /// This message is introduced since this version.
    fn version_introduced(&self) -> ProtocolVersion;
    /// This message is valid until the specified version.
    ///
    /// The return type is NOT defined as Option intentionally,
    /// because I'd like to make it impossible to keep a Message
    /// forever by default.
    ///
    /// Whenever we bump a protocol version, always update the
    /// version_valid_till for each message.
    fn version_valid_till(&self) -> ProtocolVersion;
}

pub trait Message:
    Send + Sync + GetMaybeRequestId + MessageProtocolVersionBound + Encodable
{
    // If true, message may be throttled when sent to remote peer.
    fn is_size_sensitive(&self) -> bool { false }
    fn msg_id(&self) -> MsgId;
    fn push_msg_id_leb128_encoding(&self, buffer: &mut Vec<u8>) {
        let msg_id = self.msg_id();
        assert!(msg_id < MSG_ID_MAX);
        let msg_id_msb = (msg_id >> 7) as u8;
        let mut msg_id_lsb = (msg_id as u8) & 0x7f;
        if msg_id_msb != 0 {
            buffer.push(msg_id_msb);
            msg_id_lsb |= 0x80;
        }
        buffer.push(msg_id_lsb);
    }
    fn msg_name(&self) -> &'static str;
    fn priority(&self) -> SendQueuePriority { SendQueuePriority::High }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = self.rlp_bytes();
        self.push_msg_id_leb128_encoding(&mut encoded);
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

        if let Err(e) = io.send(
            node_id,
            msg,
            self.version_introduced(),
            self.version_valid_till(),
            self.priority(),
        ) {
            debug!("Error sending message: {:?}", e);
            return Err(e);
        };

        debug!(
            "Send message({}) to peer {}, protocol {:?}",
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
#[inline]
pub fn decode_rlp_and_check_deprecation<T: Message + Decodable>(
    rlp: &Rlp, min_supported_version: ProtocolVersion, protocol: ProtocolId,
) -> Result<T, NetworkError> {
    let msg: T = rlp.as_val()?;

    if min_supported_version > msg.version_valid_till() {
        bail!(NetworkErrorKind::MessageDeprecated {
            protocol,
            msg_id: msg.msg_id(),
            min_supported_version,
        });
    }

    Ok(msg)
}

pub fn decode_msg(mut msg: &[u8]) -> Option<(MsgId, Rlp)> {
    let len = msg.len();
    if len < 2 {
        return None;
    }

    let msg_id = parse_msg_id_leb128_2_bytes_at_most(&mut msg);
    if msg.is_empty() {
        return None;
    }
    let rlp = Rlp::new(&msg);

    Some((msg_id, rlp))
}

macro_rules! mark_msg_version_bound {
    ($name:ident, $msg_ver:expr, $msg_valid_till_ver:expr) => {
        impl MessageProtocolVersionBound for $name {
            fn version_introduced(&self) -> ProtocolVersion { $msg_ver }

            fn version_valid_till(&self) -> ProtocolVersion {
                $msg_valid_till_ver
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
        $msg_valid_till_ver:expr
    ) => {
        mark_msg_version_bound!($name, $msg_ver, $msg_valid_till_ver);

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
        $msg_valid_till_ver:expr
    ) => {
        impl GetMaybeRequestId for $name {}

        build_msg_basic!($name, $msg, $name_str, $msg_ver, $msg_valid_till_ver);
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
        $msg_valid_till_ver:expr
    ) => {
        build_msg_basic!($name, $msg, $name_str, $msg_ver, $msg_valid_till_ver);
        impl_request_id_methods!($name);
    };
}

#[cfg(test)]
mod test {
    use super::Message;
    use crate::message::{
        decode_msg, GetMaybeRequestId, MessageProtocolVersionBound, MSG_ID_MAX,
    };
    use network::service::ProtocolVersion;
    use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

    struct TestMessage {
        msg_id: u16,
    }

    impl Encodable for TestMessage {
        fn rlp_append(&self, s: &mut RlpStream) { s.append(&1u8); }
    }

    impl Decodable for TestMessage {
        fn decode(_rlp: &Rlp) -> Result<Self, DecoderError> {
            Ok(Self { msg_id: 0 })
        }
    }

    impl MessageProtocolVersionBound for TestMessage {
        fn version_introduced(&self) -> ProtocolVersion { unreachable!() }

        fn version_valid_till(&self) -> ProtocolVersion { unreachable!() }
    }

    impl GetMaybeRequestId for TestMessage {}

    impl Message for TestMessage {
        fn msg_id(&self) -> u16 { self.msg_id }

        fn msg_name(&self) -> &'static str { "TestMessageIdEncodeDecode" }
    }

    #[test]
    fn test_message_id_encode_decode() {
        for msg_id in 0..MSG_ID_MAX {
            let mut buf = vec![];
            let message = TestMessage { msg_id };
            buf.extend_from_slice(&message.rlp_bytes());
            message.push_msg_id_leb128_encoding(&mut buf);
            match decode_msg(&buf) {
                None => assert!(false, "Can not decode message"),
                Some((decoded_msg_id, rlp)) => {
                    assert_eq!(decoded_msg_id, msg_id);
                    assert_eq!(rlp.as_raw().len(), 1);
                }
            }
        }
    }
}
