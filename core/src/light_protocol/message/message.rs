// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::protocol::*;
use crate::message::{Message, MsgId};
use std::any::Any;

// generate `pub mod msgid`
// TODO(thegaram): reorder message ids
build_msgid! {
    STATUS_PING = 0x00
    GET_STATE_ROOTS = 0x01
    STATE_ROOTS = 0x02
    GET_STATE_ENTRIES = 0x03
    STATE_ENTRIES = 0x04
    GET_BLOCK_HASHES_BY_EPOCH = 0x05
    BLOCK_HASHES = 0x06
    GET_BLOCK_HEADERS = 0x07
    BLOCK_HEADERS = 0x08
    NEW_BLOCK_HASHES = 0x09
    STATUS_PONG = 0x0a
    SEND_RAW_TX = 0x0b
    GET_RECEIPTS = 0x0c
    RECEIPTS = 0x0d
    GET_TXS = 0x0e
    TXS = 0x0f
    GET_WITNESS_INFO = 0x10
    WITNESS_INFO = 0x11
    GET_BLOOMS = 0x12
    BLOOMS = 0x13
    GET_BLOCK_TXS = 0x014
    BLOCK_TXS = 0x015

    INVALID = 0xff
}

// generate `impl Message for _` for each message type
build_msg_impl! { StatusPing, msgid::STATUS_PING, "StatusPing" }
build_msg_impl! { StatusPong, msgid::STATUS_PONG, "StatusPong" }
build_msg_impl! { GetStateRoots, msgid::GET_STATE_ROOTS, "GetStateRoots" }
build_msg_impl! { StateRoots, msgid::STATE_ROOTS, "StateRoots" }
build_msg_impl! { GetStateEntries, msgid::GET_STATE_ENTRIES, "GetStateEntries" }
build_msg_impl! { StateEntries, msgid::STATE_ENTRIES, "StateEntries" }
build_msg_impl! { GetBlockHashesByEpoch, msgid::GET_BLOCK_HASHES_BY_EPOCH, "GetBlockHashesByEpoch" }
build_msg_impl! { BlockHashes, msgid::BLOCK_HASHES, "BlockHashes" }
build_msg_impl! { GetBlockHeaders, msgid::GET_BLOCK_HEADERS, "GetBlockHeaders" }
build_msg_impl! { BlockHeaders, msgid::BLOCK_HEADERS, "BlockHeaders" }
build_msg_impl! { NewBlockHashes, msgid::NEW_BLOCK_HASHES, "NewBlockHashes" }
build_msg_impl! { SendRawTx, msgid::SEND_RAW_TX, "SendRawTx" }
build_msg_impl! { GetReceipts, msgid::GET_RECEIPTS, "GetReceipts" }
build_msg_impl! { Receipts, msgid::RECEIPTS, "Receipts" }
build_msg_impl! { GetTxs, msgid::GET_TXS, "GetTxs" }
build_msg_impl! { Txs, msgid::TXS, "Txs" }
build_msg_impl! { GetWitnessInfo, msgid::GET_WITNESS_INFO, "GetWitnessInfo" }
build_msg_impl! { WitnessInfo, msgid::WITNESS_INFO, "WitnessInfo" }
build_msg_impl! { GetBlooms, msgid::GET_BLOOMS, "GetBlooms" }
build_msg_impl! { Blooms, msgid::BLOOMS, "Blooms" }
build_msg_impl! { GetBlockTxs, msgid::GET_BLOCK_TXS, "GetBlockTxs" }
build_msg_impl! { BlockTxs, msgid::BLOCK_TXS, "BlockTxs" }
