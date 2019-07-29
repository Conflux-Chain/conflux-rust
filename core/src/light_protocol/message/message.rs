// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{GetStateEntry, GetStateRoot, StateEntry, StateRoot};
use crate::message::{HasRequestId, Message, MsgId, RequestId};
use std::any::Any;

// generate `pub mod msgid`
build_msgid! {
    // STATUS = 0x00
    GET_STATE_ROOT = 0x01
    STATE_ROOT = 0x02
    GET_STATE_ENTRY = 0x03
    STATE_ENTRY = 0x04
}

// generate `impl Message for _` for each message type
build_msg_impl! { GetStateRoot, msgid::GET_STATE_ROOT, "GetStateRoot" }
build_msg_impl! { StateRoot, msgid::STATE_ROOT, "StateRoot" }
build_msg_impl! { GetStateEntry, msgid::GET_STATE_ENTRY, "GetStateEntry" }
build_msg_impl! { StateEntry, msgid::STATE_ENTRY, "StateEntry" }

// generate `impl HasRequestId for _` for each request type
build_has_request_id_impl! { GetStateRoot }
build_has_request_id_impl! { GetStateEntry }
