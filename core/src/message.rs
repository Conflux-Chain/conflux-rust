// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type RequestId = u64;

pub mod macro_deps {
    pub use super::RequestId;
    pub use ::rlp::Encodable;
    pub use priority_send_queue::SendQueuePriority;
    pub use std::{any::Any, fmt};
}

// `build_msgid { type=T A=1 B=2 ...}` generates an enum
// `MsgId` represented by the type `T` with the variants
// `A`, `B`, ..., along with conversion from/to type `T`
// and formatted output.
macro_rules! build_msgid {
    (type=$type:ident $($name:ident = $value:expr)*) => {
        #[derive(Debug, PartialEq)]
        #[repr($type)]
        #[allow(non_camel_case_types)]
        pub enum MsgId {
            $($name = $value,)*
            UNKNOWN = 0xff,
        }

        impl Into<$type> for MsgId {
            fn into(self) -> $type {
                self as $type
            }
        }

        impl From<$type> for MsgId {
            fn from(id: $type) -> MsgId {
                match id {
                    $($value => MsgId::$name,)*
                    _ => MsgId::UNKNOWN,
                }
            }
        }

        impl fmt::Display for MsgId {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let id = match self {
                    $(MsgId::$name => $value,)*
                    MsgId::UNKNOWN => 0xff,
                };
                write!(f, "{}", id)
            }
        }
    }
}

macro_rules! build_msg_trait {
    () => {
        pub trait Message: Send + Sync + Encodable {
            fn as_any(&self) -> &Any;
            // If true, message may be throttled when sent to remote peer.
            fn is_size_sensitive(&self) -> bool { false }
            fn msg_id(&self) -> MsgId;
            fn priority(&self) -> SendQueuePriority { SendQueuePriority::High }
        }
    };
}

macro_rules! build_msg_impl {
    ($name:ident, $msg:expr) => {
        impl Message for $name {
            fn as_any(&self) -> &Any { self }

            fn msg_id(&self) -> MsgId { $msg }
        }
    };
    ($name:ident, $msg:expr, $priority:expr) => {
        impl Message for $name {
            fn as_any(&self) -> &Any { self }

            fn msg_id(&self) -> MsgId { $msg }

            fn priority(&self) -> SendQueuePriority { $priority }
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
