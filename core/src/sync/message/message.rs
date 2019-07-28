// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use crate::sync::{
    state::{
        SnapshotChunkRequest, SnapshotChunkResponse, SnapshotManifestRequest,
        SnapshotManifestResponse,
    },
    Error,
};
use rlp::Rlp;

// import all other modules needed for macro expansion
use crate::message::macro_deps::*;

// generate `pub enum MsgId`
build_msgid! {
    type=u8

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

// generate `pub trait Message`
build_msg_trait! {}

// generate `impl Message for _` for each message type
// high priority message types
build_msg_impl! { Status, MsgId::STATUS }
build_msg_impl! { NewBlockHashes, MsgId::NEW_BLOCK_HASHES }
build_msg_impl! { GetBlockHashesResponse, MsgId::GET_BLOCK_HASHES_RESPONSE }
build_msg_impl! { GetBlockHeaders, MsgId::GET_BLOCK_HEADERS }
build_msg_impl! { GetBlockHeadersResponse, MsgId::GET_BLOCK_HEADERS_RESPONSE }
build_msg_impl! { NewBlock, MsgId::NEW_BLOCK }
build_msg_impl! { GetTerminalBlockHashesResponse, MsgId::GET_TERMINAL_BLOCK_HASHES_RESPONSE }
build_msg_impl! { GetTerminalBlockHashes, MsgId::GET_TERMINAL_BLOCK_HASHES }
build_msg_impl! { GetBlocks, MsgId::GET_BLOCKS }
build_msg_impl! { GetCompactBlocks, MsgId::GET_CMPCT_BLOCKS }
build_msg_impl! { GetCompactBlocksResponse, MsgId::GET_CMPCT_BLOCKS_RESPONSE }
build_msg_impl! { GetBlockTxn, MsgId::GET_BLOCK_TXN }
build_msg_impl! { TransactionPropagationControl, MsgId::TRANSACTION_PROPAGATION_CONTROL }
build_msg_impl! { GetBlockHashesByEpoch, MsgId::GET_BLOCK_HASHES_BY_EPOCH }
build_msg_impl! { GetBlockHeaderChain, MsgId::GET_BLOCK_HEADER_CHAIN }

// normal priority and size-sensitive message types
impl Message for Transactions {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { MsgId::TRANSACTIONS }

    fn is_size_sensitive(&self) -> bool { self.transactions.len() > 1 }
}

impl Message for GetBlocksResponse {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCKS_RESPONSE }

    fn is_size_sensitive(&self) -> bool { self.blocks.len() > 0 }
}

impl Message for GetBlocksWithPublicResponse {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCKS_WITH_PUBLIC_RESPONSE }

    fn is_size_sensitive(&self) -> bool { self.blocks.len() > 0 }
}

impl Message for GetBlockTxnResponse {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { MsgId::GET_BLOCK_TXN_RESPONSE }

    fn is_size_sensitive(&self) -> bool { self.block_txn.len() > 1 }
}

impl Message for TransactionDigests {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { MsgId::TRANSACTION_DIGESTS }

    fn is_size_sensitive(&self) -> bool { self.trans_short_ids.len() > 1 }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }
}

impl Message for GetTransactions {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { MsgId::GET_TRANSACTIONS }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }
}

impl Message for GetTransactionsResponse {
    fn as_any(&self) -> &Any { self }

    fn msg_id(&self) -> MsgId { MsgId::GET_TRANSACTIONS_RESPONSE }

    fn is_size_sensitive(&self) -> bool { self.transactions.len() > 0 }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }
}

// generate `impl HasRequestId for _` for each request type
build_has_request_id_impl! { GetBlockHashesByEpoch }
build_has_request_id_impl! { GetBlockHeaderChain }
build_has_request_id_impl! { GetBlockHeaders }
build_has_request_id_impl! { GetBlockHeadersResponse }
build_has_request_id_impl! { GetBlocks }
build_has_request_id_impl! { GetBlockTxn }
build_has_request_id_impl! { GetCompactBlocks }
build_has_request_id_impl! { GetTransactions }

impl MsgId {
    /// handle the RLP encoded message with given context `ctx`.
    /// If the message not handled, return `Ok(false)`.
    /// Otherwise, return `Ok(true)` if handled successfully
    /// or Err(e) on any error.
    pub fn handle(&self, ctx: &Context, rlp: &Rlp) -> Result<bool, Error> {
        match *self {
            MsgId::STATUS => rlp.as_val::<Status>()?.handle(ctx)?,
            MsgId::NEW_BLOCK => rlp.as_val::<NewBlock>()?.handle(&ctx)?,
            MsgId::NEW_BLOCK_HASHES => {
                rlp.as_val::<NewBlockHashes>()?.handle(&ctx)?;
            }
            MsgId::GET_BLOCK_HEADERS => {
                rlp.as_val::<GetBlockHeaders>()?.handle(ctx)?;
            }
            MsgId::GET_BLOCK_HEADERS_RESPONSE => {
                rlp.as_val::<GetBlockHeadersResponse>()?.handle(&ctx)?;
            }
            MsgId::GET_BLOCK_HEADER_CHAIN => {
                rlp.as_val::<GetBlockHeaderChain>()?.handle(&ctx)?;
            }
            MsgId::GET_BLOCKS => rlp.as_val::<GetBlocks>()?.handle(&ctx)?,
            MsgId::GET_BLOCKS_RESPONSE => {
                rlp.as_val::<GetBlocksResponse>()?.handle(&ctx)?;
            }
            MsgId::GET_BLOCKS_WITH_PUBLIC_RESPONSE => {
                rlp.as_val::<GetBlocksWithPublicResponse>()?.handle(&ctx)?;
            }
            MsgId::GET_TERMINAL_BLOCK_HASHES => {
                rlp.as_val::<GetTerminalBlockHashes>()?.handle(&ctx)?;
            }
            MsgId::GET_TERMINAL_BLOCK_HASHES_RESPONSE => {
                rlp.as_val::<GetTerminalBlockHashesResponse>()?
                    .handle(&ctx)?;
            }
            MsgId::GET_CMPCT_BLOCKS => {
                rlp.as_val::<GetCompactBlocks>()?.handle(&ctx)?;
            }
            MsgId::GET_CMPCT_BLOCKS_RESPONSE => {
                rlp.as_val::<GetCompactBlocksResponse>()?.handle(&ctx)?;
            }
            MsgId::GET_BLOCK_TXN => {
                rlp.as_val::<GetBlockTxn>()?.handle(&ctx)?;
            }
            MsgId::GET_BLOCK_TXN_RESPONSE => {
                rlp.as_val::<GetBlockTxnResponse>()?.handle(&ctx)?;
            }
            MsgId::TRANSACTIONS => {
                rlp.as_val::<Transactions>()?.handle(&ctx)?;
            }
            MsgId::TRANSACTION_PROPAGATION_CONTROL => {
                rlp.as_val::<TransactionPropagationControl>()?
                    .handle(&ctx)?;
            }
            MsgId::TRANSACTION_DIGESTS => {
                rlp.as_val::<TransactionDigests>()?.handle(&ctx)?;
            }
            MsgId::GET_TRANSACTIONS => {
                rlp.as_val::<GetTransactions>()?.handle(&ctx)?;
            }
            MsgId::GET_TRANSACTIONS_RESPONSE => {
                rlp.as_val::<GetTransactionsResponse>()?.handle(&ctx)?;
            }
            MsgId::GET_BLOCK_HASHES_BY_EPOCH => {
                rlp.as_val::<GetBlockHashesByEpoch>()?.handle(&ctx)?;
            }
            MsgId::GET_BLOCK_HASHES_RESPONSE => {
                rlp.as_val::<GetBlockHashesResponse>()?.handle(&ctx)?;
            }
            MsgId::GET_SNAPSHOT_MANIFEST => {
                rlp.as_val::<SnapshotManifestRequest>()?.handle(&ctx)?;
            }
            MsgId::GET_SNAPSHOT_MANIFEST_RESPONSE => {
                rlp.as_val::<SnapshotManifestResponse>()?.handle(&ctx)?;
            }
            MsgId::GET_SNAPSHOT_CHUNK => {
                rlp.as_val::<SnapshotChunkRequest>()?.handle(&ctx)?;
            }
            MsgId::GET_SNAPSHOT_CHUNK_RESPONSE => {
                rlp.as_val::<SnapshotChunkResponse>()?.handle(&ctx)?;
            }
            _ => return Ok(false),
        }

        Ok(true)
    }
}
