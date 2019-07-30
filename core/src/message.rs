// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type RequestId = u64;
pub type MsgId = u8;

pub use cfx_bytes::Bytes;
pub use priority_send_queue::SendQueuePriority;
use rlp::Encodable;
use std::any::Any;

pub use crate::network::{
    throttling::THROTTLING_SERVICE, Error as NetworkError, NetworkContext,
    PeerId,
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

pub trait Message: Send + Sync + Encodable {
    fn as_any(&self) -> &Any;
    // If true, message may be throttled when sent to remote peer.
    fn is_size_sensitive(&self) -> bool { false }
    fn msg_id(&self) -> MsgId;
    fn msg_name(&self) -> &'static str;
    fn priority(&self) -> SendQueuePriority { SendQueuePriority::High }

    fn send(
        &self, io: &NetworkContext, peer: PeerId,
    ) -> Result<usize, NetworkError> {
        self.send_with_throttling(io, peer, false)
    }

    fn send_with_throttling(
        &self, io: &NetworkContext, peer: PeerId, throttling_disabled: bool,
    ) -> Result<usize, NetworkError> {
        if !throttling_disabled && self.is_size_sensitive() {
            if let Err(e) = THROTTLING_SERVICE.read().check_throttling() {
                debug!("Throttling failure: {:?}", e);
                return Err(e);
            }
        }

        let mut raw = Bytes::new();
        raw.push(self.msg_id().into());
        raw.extend(self.rlp_bytes().iter());
        let size = raw.len();

        if let Err(e) = io.send(peer, raw, self.priority()) {
            debug!("Error sending message: {:?}", e);
            return Err(e);
        };

        debug!(
            "Send message({}) to {:?}",
            self.msg_name(),
            io.get_peer_node_id(peer)
        );

        Ok(size)
    }
}

macro_rules! build_msg_impl {
    ($name:ident, $msg:expr, $name_str:literal) => {
        impl Message for $name {
            fn as_any(&self) -> &Any { self }

            fn msg_id(&self) -> MsgId { $msg }

            fn msg_name(&self) -> &'static str { $name_str }
        }
    };
}

pub trait HasRequestId {
    fn request_id(&self) -> RequestId;
    fn set_request_id(&mut self, id: RequestId);
}

macro_rules! build_has_request_id_impl {
    ($name:ident) => {
        impl HasRequestId for $name {
            fn request_id(&self) -> RequestId { self.request_id }

            fn set_request_id(&mut self, id: RequestId) {
                self.request_id = id;
            }
        }
    };
}
