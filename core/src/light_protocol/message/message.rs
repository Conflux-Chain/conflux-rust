// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::protocol::*;
use crate::message::{HasRequestId, Message, MsgId, RequestId};
use std::any::Any;

// generate `pub mod msgid`
// TODO(thegaram): reorder message ids
build_msgid! {
    STATUS_PING = 0x00
    GET_STATE_ROOT = 0x01
    STATE_ROOT = 0x02
    GET_STATE_ENTRY = 0x03
    STATE_ENTRY = 0x04
    GET_BLOCK_HASHES_BY_EPOCH = 0x05
    BLOCK_HASHES = 0x06
    GET_BLOCK_HEADERS = 0x07
    BLOCK_HEADERS = 0x08
    NEW_BLOCK_HASHES = 0x09
    STATUS_PONG = 0x0a
    SEND_RAW_TX = 0x0b

    INVALID = 0xff
}

// generate `impl Message for _` for each message type
build_msg_impl! { StatusPing, msgid::STATUS_PING, "StatusPing" }
build_msg_impl! { StatusPong, msgid::STATUS_PONG, "StatusPong" }
build_msg_impl! { GetStateRoot, msgid::GET_STATE_ROOT, "GetStateRoot" }
build_msg_impl! { StateRoot, msgid::STATE_ROOT, "StateRoot" }
build_msg_impl! { GetStateEntry, msgid::GET_STATE_ENTRY, "GetStateEntry" }
build_msg_impl! { StateEntry, msgid::STATE_ENTRY, "StateEntry" }
build_msg_impl! { GetBlockHashesByEpoch, msgid::GET_BLOCK_HASHES_BY_EPOCH, "GetBlockHashesByEpoch" }
build_msg_impl! { BlockHashes, msgid::BLOCK_HASHES, "BlockHashes" }
build_msg_impl! { GetBlockHeaders, msgid::GET_BLOCK_HEADERS, "GetBlockHeaders" }
build_msg_impl! { BlockHeaders, msgid::BLOCK_HEADERS, "BlockHeaders" }
build_msg_impl! { NewBlockHashes, msgid::NEW_BLOCK_HASHES, "NewBlockHashes" }
build_msg_impl! { SendRawTx, msgid::SEND_RAW_TX, "SendRawTx" }

// generate `impl HasRequestId for _` for each request type
build_has_request_id_impl! { GetStateRoot }
build_has_request_id_impl! { GetStateEntry }
