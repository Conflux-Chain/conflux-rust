// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type RequestId = u64;
pub type MsgId = u8;

pub use cfx_bytes::Bytes;
pub use priority_send_queue::SendQueuePriority;
use rlp::{Encodable, Rlp};

pub use crate::network::{
    throttling::THROTTLING_SERVICE, Error as NetworkError, NetworkContext,
    PeerId,
};
use crate::sync::msg_sender::metric_message;

macro_rules! build_msgid {
    ($($name:ident = $value:expr)*) => {
        #[allow(dead_code)]
        pub mod msgid {
            use super::MsgId;
            $(pub const $name: MsgId = $value;)*
        }
    }
}

pub trait Message: Send + Sync + Encodable {
    // If true, message may be throttled when sent to remote peer.
    fn is_size_sensitive(&self) -> bool { false }
    fn msg_id(&self) -> MsgId;
    fn msg_name(&self) -> &'static str;
    fn priority(&self) -> SendQueuePriority { SendQueuePriority::High }

    fn get_request_id(&self) -> Option<RequestId> { None }
    fn set_request_id(&mut self, _id: RequestId) {}

    fn send(
        &self, io: &dyn NetworkContext, peer: PeerId,
    ) -> Result<(), NetworkError> {
        self.send_with_throttling(io, peer, false)
    }

    fn send_with_throttling(
        &self, io: &dyn NetworkContext, peer: PeerId, throttling_disabled: bool,
    ) -> Result<(), NetworkError> {
        if !throttling_disabled && self.is_size_sensitive() {
            if let Err(e) = THROTTLING_SERVICE.read().check_throttling() {
                debug!("Throttling failure: {:?}", e);
                return Err(e);
            }
        }

        let msg = self.encode();
        let size = msg.len();

        if let Err(e) = io.send(peer, msg, self.priority()) {
            debug!("Error sending message: {:?}", e);
            return Err(e);
        };

        debug!(
            "Send message({}) to {:?}",
            self.msg_name(),
            io.get_peer_node_id(peer)
        );

        metric_message(peer, self.msg_id(), size);

        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = self.rlp_bytes();
        encoded.push(self.msg_id());
        encoded
    }
}

pub fn decode_msg(msg: &[u8]) -> Option<(MsgId, Rlp)> {
    let len = msg.len();
    if len < 2 {
        return None;
    }

    let msg_id = msg[len - 1];
    let rlp = Rlp::new(&msg[..len - 1]);

    Some((msg_id, rlp))
}

macro_rules! build_msg_impl {
    ($name:ident, $msg:expr, $name_str:literal) => {
        impl Message for $name {
            fn msg_id(&self) -> MsgId { $msg }

            fn msg_name(&self) -> &'static str { $name_str }
        }
    };
}

macro_rules! build_msg_with_request_id_impl {
    ($name:ident, $msg:expr, $name_str:literal) => {
        impl Message for $name {
            fn msg_id(&self) -> MsgId { $msg }

            fn msg_name(&self) -> &'static str { $name_str }

            fn get_request_id(&self) -> Option<RequestId> {
                Some(self.request_id)
            }

            fn set_request_id(&mut self, id: RequestId) {
                self.request_id = id;
            }
        }
    };
}
