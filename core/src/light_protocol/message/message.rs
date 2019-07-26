// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{GetStateEntry, GetStateRoot, RequestId, StateEntry, StateRoot};
use priority_send_queue::SendQueuePriority;
use rlp::Encodable;
use std::{any::Any, fmt};

pub type MsgIdInner = u8;
#[derive(Debug, PartialEq, Eq)]
pub struct MsgId(MsgIdInner);

macro_rules! build_msgid {
    ($($name:ident = $value:expr)*) => {
        impl MsgId {
            $(pub const $name: MsgId = MsgId($value);)*
        }
    }
}

build_msgid! {
    // STATUS = 0x00
    GET_STATE_ROOT = 0x01
    STATE_ROOT = 0x02
    GET_STATE_ENTRY = 0x03
    STATE_ENTRY = 0x04
}

impl From<u8> for MsgId {
    fn from(inner: u8) -> Self { MsgId(inner) }
}

impl Into<u8> for MsgId {
    fn into(self) -> u8 { self.0 }
}

impl fmt::Display for MsgId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

pub trait Message: Any + Send + Sync + Encodable + 'static {
    fn as_any(&self) -> &Any;

    // If true, message may be throttled when sent to remote peer.
    fn is_size_sensitive(&self) -> bool { false }

    fn msg_id(&self) -> MsgId;

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::High }

    fn set_request_id(&mut self, id: RequestId);
}

macro_rules! build_msg_impl {
    ($name:ident, $msg:ident) => {
        impl Message for $name {
            fn as_any(&self) -> &Any { self }

            fn msg_id(&self) -> MsgId { MsgId::$msg }

            fn set_request_id(&mut self, id: RequestId) {
                self.request_id = id;
            }
        }
    };
}

build_msg_impl! {GetStateRoot, GET_STATE_ROOT}
build_msg_impl! {StateRoot, STATE_ROOT}
build_msg_impl! {GetStateEntry, GET_STATE_ENTRY}
build_msg_impl! {StateEntry, STATE_ENTRY}
