// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    GetStateEntry, GetStateRoot, HasRequestId, RequestId, StateEntry, StateRoot,
};

// import all other modules needed for macro expansion
use crate::message::macro_deps::*;

// generate `pub enum MsgId`
build_msgid! {
    type=u8

    // STATUS = 0x00
    GET_STATE_ROOT = 0x01
    STATE_ROOT = 0x02
    GET_STATE_ENTRY = 0x03
    STATE_ENTRY = 0x04
}

// generate `pub trait Message`
build_msg_trait! {}

// generate `impl Message for _` for each message type
build_msg_impl! { GetStateRoot, MsgId::GET_STATE_ROOT }
build_msg_impl! { StateRoot, MsgId::STATE_ROOT }
build_msg_impl! { GetStateEntry, MsgId::GET_STATE_ENTRY }
build_msg_impl! { StateEntry, MsgId::STATE_ENTRY }

// generate `impl HasRequestId for _` for each request type
build_has_request_id_impl! { GetStateRoot }
build_has_request_id_impl! { GetStateEntry }
