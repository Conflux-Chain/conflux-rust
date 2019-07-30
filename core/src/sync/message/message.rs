// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use crate::{
    message::{HasRequestId, Message, MsgId, RequestId},
    sync::{
        state::{
            SnapshotChunkRequest, SnapshotChunkResponse,
            SnapshotManifestRequest, SnapshotManifestResponse,
        },
        Error,
    },
};
pub use priority_send_queue::SendQueuePriority;
use rlp::Rlp;
use std::any::Any;

// generate `pub mod msgid`
build_msgid! {
    STATUS = 0x00
    NEW_BLOCK_HASHES = 0x01
    TRANSACTIONS = 0x02
    GET_BLOCK_HASHES = 0x03
    GET_BLOCK_HASHES_RESPONSE = 0x04
    GET_BLOCK_HEADERS = 0x05
    GET_BLOCK_HEADERS_RESPONSE = 0x06
    GET_BLOCK_BODIES = 0x07
    GET_BLOCK_BODIES_RESPONSE = 0x08
    NEW_BLOCK = 0x09
    GET_TERMINAL_BLOCK_HASHES_RESPONSE = 0x0a
    GET_TERMINAL_BLOCK_HASHES = 0x0b
    GET_BLOCKS = 0x0c
    GET_BLOCKS_RESPONSE = 0x0d
    GET_BLOCKS_WITH_PUBLIC_RESPONSE = 0x0e
    GET_CMPCT_BLOCKS = 0x0f
    GET_CMPCT_BLOCKS_RESPONSE = 0x10
    GET_BLOCK_TXN = 0x11
    GET_BLOCK_TXN_RESPONSE = 0x12
    TRANSACTION_PROPAGATION_CONTROL = 0x13
    TRANSACTION_DIGESTS = 0x14
    GET_TRANSACTIONS = 0x15
    GET_TRANSACTIONS_RESPONSE = 0x16
    GET_BLOCK_HASHES_BY_EPOCH = 0x17
    GET_BLOCK_HEADER_CHAIN = 0x18
    GET_SNAPSHOT_MANIFEST = 0x19
    GET_SNAPSHOT_MANIFEST_RESPONSE = 0x1a
    GET_SNAPSHOT_CHUNK = 0x1b
    GET_SNAPSHOT_CHUNK_RESPONSE = 0x1c
}

// generate `impl Message for _` for each message type
// high priority message types
build_msg_impl! { Status, msgid::STATUS, "Status" }
build_msg_impl! { NewBlockHashes, msgid::NEW_BLOCK_HASHES, "NewBlockHashes" }
build_msg_impl! { GetBlockHashesResponse, msgid::GET_BLOCK_HASHES_RESPONSE, "GetBlockHashesResponse" }
build_msg_impl! { GetBlockHeaders, msgid::GET_BLOCK_HEADERS, "GetBlockHeaders" }
build_msg_impl! { GetBlockHeadersResponse, msgid::GET_BLOCK_HEADERS_RESPONSE, "GetBlockHeadersResponse" }
build_msg_impl! { NewBlock, msgid::NEW_BLOCK, "NewBlock" }
build_msg_impl! { GetTerminalBlockHashesResponse, msgid::GET_TERMINAL_BLOCK_HASHES_RESPONSE, "GetTerminalBlockHashesResponse" }
build_msg_impl! { GetTerminalBlockHashes, msgid::GET_TERMINAL_BLOCK_HASHES, "GetTerminalBlockHashes" }
build_msg_impl! { GetBlocks, msgid::GET_BLOCKS, "GetBlocks" }
build_msg_impl! { GetCompactBlocks, msgid::GET_CMPCT_BLOCKS, "GetCompactBlocks" }
build_msg_impl! { GetCompactBlocksResponse, msgid::GET_CMPCT_BLOCKS_RESPONSE, "GetCompactBlocksResponse" }
build_msg_impl! { GetBlockTxn, msgid::GET_BLOCK_TXN, "GetBlockTxn" }
build_msg_impl! { TransactionPropagationControl, msgid::TRANSACTION_PROPAGATION_CONTROL, "TransactionPropagationControl" }
build_msg_impl! { GetBlockHashesByEpoch, msgid::GET_BLOCK_HASHES_BY_EPOCH, "GetBlockHashesByEpoch" }

// normal priority and size-sensitive message types
impl Message for Transactions {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { msgid::TRANSACTIONS }

    fn msg_name(&self) -> &'static str { "Transactions" }

    fn is_size_sensitive(&self) -> bool { self.transactions.len() > 1 }
}

impl Message for GetBlocksResponse {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { msgid::GET_BLOCKS_RESPONSE }

    fn msg_name(&self) -> &'static str { "GetBlocksResponse" }

    fn is_size_sensitive(&self) -> bool { self.blocks.len() > 0 }
}

impl Message for GetBlocksWithPublicResponse {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { msgid::GET_BLOCKS_WITH_PUBLIC_RESPONSE }

    fn msg_name(&self) -> &'static str { "GetBlocksWithPublicResponse" }

    fn is_size_sensitive(&self) -> bool { self.blocks.len() > 0 }
}

impl Message for GetBlockTxnResponse {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { msgid::GET_BLOCK_TXN_RESPONSE }

    fn msg_name(&self) -> &'static str { "GetBlockTxnResponse" }

    fn is_size_sensitive(&self) -> bool { self.block_txn.len() > 1 }
}

impl Message for TransactionDigests {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { msgid::TRANSACTION_DIGESTS }

    fn msg_name(&self) -> &'static str { "TransactionDigests" }

    fn is_size_sensitive(&self) -> bool { self.trans_short_ids.len() > 1 }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }
}

impl Message for GetTransactions {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { msgid::GET_TRANSACTIONS }

    fn msg_name(&self) -> &'static str { "GetTransactions" }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }
}

impl Message for GetTransactionsResponse {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { msgid::GET_TRANSACTIONS_RESPONSE }

    fn msg_name(&self) -> &'static str { "GetTransactionsResponse" }

    fn is_size_sensitive(&self) -> bool { self.transactions.len() > 0 }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }
}

// generate `impl HasRequestId for _` for each request type
build_has_request_id_impl! { GetBlockHashesByEpoch }
build_has_request_id_impl! { GetBlockHeaders }
build_has_request_id_impl! { GetBlockHeadersResponse }
build_has_request_id_impl! { GetBlocks }
build_has_request_id_impl! { GetBlockTxn }
build_has_request_id_impl! { GetCompactBlocks }
build_has_request_id_impl! { GetTransactions }

/// handle the RLP encoded message with given context `ctx`.
/// If the message not handled, return `Ok(false)`.
/// Otherwise, return `Ok(true)` if handled successfully
/// or Err(e) on any error.
pub fn handle_rlp_message(
    id: MsgId, ctx: &Context, rlp: &Rlp,
) -> Result<bool, Error> {
    match id {
        msgid::STATUS => rlp.as_val::<Status>()?.handle(ctx)?,
        msgid::NEW_BLOCK => rlp.as_val::<NewBlock>()?.handle(&ctx)?,
        msgid::NEW_BLOCK_HASHES => {
            rlp.as_val::<NewBlockHashes>()?.handle(&ctx)?;
        }
        msgid::GET_BLOCK_HEADERS => {
            rlp.as_val::<GetBlockHeaders>()?.handle(ctx)?;
        }
        msgid::GET_BLOCK_HEADERS_RESPONSE => {
            rlp.as_val::<GetBlockHeadersResponse>()?.handle(&ctx)?;
        }
        msgid::GET_BLOCKS => rlp.as_val::<GetBlocks>()?.handle(&ctx)?,
        msgid::GET_BLOCKS_RESPONSE => {
            rlp.as_val::<GetBlocksResponse>()?.handle(&ctx)?;
        }
        msgid::GET_BLOCKS_WITH_PUBLIC_RESPONSE => {
            rlp.as_val::<GetBlocksWithPublicResponse>()?.handle(&ctx)?;
        }
        msgid::GET_TERMINAL_BLOCK_HASHES => {
            rlp.as_val::<GetTerminalBlockHashes>()?.handle(&ctx)?;
        }
        msgid::GET_TERMINAL_BLOCK_HASHES_RESPONSE => {
            rlp.as_val::<GetTerminalBlockHashesResponse>()?
                .handle(&ctx)?;
        }
        msgid::GET_CMPCT_BLOCKS => {
            rlp.as_val::<GetCompactBlocks>()?.handle(&ctx)?;
        }
        msgid::GET_CMPCT_BLOCKS_RESPONSE => {
            rlp.as_val::<GetCompactBlocksResponse>()?.handle(&ctx)?;
        }
        msgid::GET_BLOCK_TXN => {
            rlp.as_val::<GetBlockTxn>()?.handle(&ctx)?;
        }
        msgid::GET_BLOCK_TXN_RESPONSE => {
            rlp.as_val::<GetBlockTxnResponse>()?.handle(&ctx)?;
        }
        msgid::TRANSACTIONS => {
            rlp.as_val::<Transactions>()?.handle(&ctx)?;
        }
        msgid::TRANSACTION_PROPAGATION_CONTROL => {
            rlp.as_val::<TransactionPropagationControl>()?
                .handle(&ctx)?;
        }
        msgid::TRANSACTION_DIGESTS => {
            rlp.as_val::<TransactionDigests>()?.handle(&ctx)?;
        }
        msgid::GET_TRANSACTIONS => {
            rlp.as_val::<GetTransactions>()?.handle(&ctx)?;
        }
        msgid::GET_TRANSACTIONS_RESPONSE => {
            rlp.as_val::<GetTransactionsResponse>()?.handle(&ctx)?;
        }
        msgid::GET_BLOCK_HASHES_BY_EPOCH => {
            rlp.as_val::<GetBlockHashesByEpoch>()?.handle(&ctx)?;
        }
        msgid::GET_BLOCK_HASHES_RESPONSE => {
            rlp.as_val::<GetBlockHashesResponse>()?.handle(&ctx)?;
        }
        msgid::GET_SNAPSHOT_MANIFEST => {
            rlp.as_val::<SnapshotManifestRequest>()?.handle(&ctx)?;
        }
        msgid::GET_SNAPSHOT_MANIFEST_RESPONSE => {
            rlp.as_val::<SnapshotManifestResponse>()?.handle(&ctx)?;
        }
        msgid::GET_SNAPSHOT_CHUNK => {
            rlp.as_val::<SnapshotChunkRequest>()?.handle(&ctx)?;
        }
        msgid::GET_SNAPSHOT_CHUNK_RESPONSE => {
            rlp.as_val::<SnapshotChunkResponse>()?.handle(&ctx)?;
        }
        _ => return Ok(false),
    }

    Ok(true)
}
