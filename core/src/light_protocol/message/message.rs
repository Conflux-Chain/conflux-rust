// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::protocol::*;
use crate::{
    light_protocol::{LIGHT_PROTO_V1, LIGHT_PROTO_V2},
    message::{GetMaybeRequestId, Message, MessageProtocolVersionBound, MsgId},
};
use network::service::ProtocolVersion;

// generate `pub mod msgid`
build_msgid! {
    STATUS_PING_DEPRECATED = 0x00
    GET_STATE_ROOTS = 0x01
    STATE_ROOTS = 0x02
    GET_STATE_ENTRIES = 0x03
    STATE_ENTRIES = 0x04
    GET_BLOCK_HASHES_BY_EPOCH = 0x05
    BLOCK_HASHES = 0x06
    GET_BLOCK_HEADERS = 0x07
    BLOCK_HEADERS = 0x08
    NEW_BLOCK_HASHES = 0x09
    STATUS_PONG_DEPRECATED = 0x0a
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
    GET_TX_INFOS = 0x016
    TX_INFOS = 0x017
    STATUS_PING_V2 = 0x18
    STATUS_PONG_V2 = 0x19
    GET_STORAGE_ROOTS = 0x1a
    STORAGE_ROOTS = 0x1b

    THROTTLED = 0xfe
    INVALID = 0xff
}

// generate `impl Message for _` for each message type
build_msg_impl! { StatusPingDeprecatedV1, msgid::STATUS_PING_DEPRECATED, "StatusPing", LIGHT_PROTO_V1, LIGHT_PROTO_V1 }
build_msg_impl! { StatusPongDeprecatedV1, msgid::STATUS_PONG_DEPRECATED, "StatusPong", LIGHT_PROTO_V1, LIGHT_PROTO_V1 }
build_msg_impl! { StatusPingV2, msgid::STATUS_PING_V2, "StatusPingV2", LIGHT_PROTO_V2, LIGHT_PROTO_V2 }
build_msg_impl! { StatusPongV2, msgid::STATUS_PONG_V2, "StatusPongV2", LIGHT_PROTO_V2, LIGHT_PROTO_V2 }
build_msg_impl! { GetStateRoots, msgid::GET_STATE_ROOTS, "GetStateRoots", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { StateRoots, msgid::STATE_ROOTS, "StateRoots", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { GetStateEntries, msgid::GET_STATE_ENTRIES, "GetStateEntries", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { StateEntries, msgid::STATE_ENTRIES, "StateEntries", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { GetBlockHashesByEpoch, msgid::GET_BLOCK_HASHES_BY_EPOCH, "GetBlockHashesByEpoch", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { BlockHashes, msgid::BLOCK_HASHES, "BlockHashes", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { GetBlockHeaders, msgid::GET_BLOCK_HEADERS, "GetBlockHeaders", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { BlockHeaders, msgid::BLOCK_HEADERS, "BlockHeaders", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { NewBlockHashes, msgid::NEW_BLOCK_HASHES, "NewBlockHashes", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { SendRawTx, msgid::SEND_RAW_TX, "SendRawTx", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { GetReceipts, msgid::GET_RECEIPTS, "GetReceipts", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { Receipts, msgid::RECEIPTS, "Receipts", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { GetTxs, msgid::GET_TXS, "GetTxs", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { Txs, msgid::TXS, "Txs", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { GetWitnessInfo, msgid::GET_WITNESS_INFO, "GetWitnessInfo", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { WitnessInfo, msgid::WITNESS_INFO, "WitnessInfo", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { GetBlooms, msgid::GET_BLOOMS, "GetBlooms", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { Blooms, msgid::BLOOMS, "Blooms", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { GetBlockTxs, msgid::GET_BLOCK_TXS, "GetBlockTxs", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { BlockTxs, msgid::BLOCK_TXS, "BlockTxs", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { GetTxInfos, msgid::GET_TX_INFOS, "GetTxInfos", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { TxInfos, msgid::TX_INFOS, "TxInfos", LIGHT_PROTO_V1, LIGHT_PROTO_V2 }
build_msg_impl! { GetStorageRoots, msgid::GET_STORAGE_ROOTS, "GetStorageRoots", LIGHT_PROTO_V2, LIGHT_PROTO_V2 }
build_msg_impl! { StorageRoots, msgid::STORAGE_ROOTS, "StorageRoots", LIGHT_PROTO_V2, LIGHT_PROTO_V2 }
