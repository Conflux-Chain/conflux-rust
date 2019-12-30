// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::*;
use crate::{
    message::{Message, MsgId, RequestId},
    sync::{
        message::throttling::Throttle,
        state::{
            SnapshotChunkRequest, SnapshotChunkResponse,
            SnapshotManifestRequest, SnapshotManifestResponse,
            StateSyncCandidateRequest, StateSyncCandidateResponse,
        },
        Error,
    },
};
pub use priority_send_queue::SendQueuePriority;
use rlp::{Decodable, Encodable, Rlp};
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
    DYNAMIC_CAPABILITY_CHANGE = 0x13
    TRANSACTION_DIGESTS = 0x14
    GET_TRANSACTIONS = 0x15
    GET_TRANSACTIONS_RESPONSE = 0x16
    GET_BLOCK_HASHES_BY_EPOCH = 0x17
    GET_BLOCK_HEADER_CHAIN = 0x18
    GET_SNAPSHOT_MANIFEST = 0x19
    GET_SNAPSHOT_MANIFEST_RESPONSE = 0x1a
    GET_SNAPSHOT_CHUNK = 0x1b
    GET_SNAPSHOT_CHUNK_RESPONSE = 0x1c
    GET_TRANSACTIONS_FROM_TX_HASHES = 0x1d
    GET_TRANSACTIONS_FROM_TX_HASHES_RESPONSE = 0x1e
    STATE_SYNC_CANDIDATE_REQUEST = 0x20
    STATE_SYNC_CANDIDATE_RESPONSE = 0x21

    THROTTLED = 0xfe

    INVALID = 0xff
}

// generate `impl Message for _` for each message type
// high priority message types
build_msg_impl! { Status, msgid::STATUS, "Status" }
build_msg_impl! { NewBlockHashes, msgid::NEW_BLOCK_HASHES, "NewBlockHashes" }
build_msg_with_request_id_impl! { GetBlockHashesResponse, msgid::GET_BLOCK_HASHES_RESPONSE, "GetBlockHashesResponse" }
build_msg_with_request_id_impl! { GetBlockHeaders, msgid::GET_BLOCK_HEADERS, "GetBlockHeaders" }
build_msg_with_request_id_impl! { GetBlockHeadersResponse, msgid::GET_BLOCK_HEADERS_RESPONSE, "GetBlockHeadersResponse" }
build_msg_impl! { NewBlock, msgid::NEW_BLOCK, "NewBlock" }
build_msg_with_request_id_impl! { GetTerminalBlockHashesResponse, msgid::GET_TERMINAL_BLOCK_HASHES_RESPONSE, "GetTerminalBlockHashesResponse" }
build_msg_with_request_id_impl! { GetTerminalBlockHashes, msgid::GET_TERMINAL_BLOCK_HASHES, "GetTerminalBlockHashes" }
build_msg_with_request_id_impl! { GetBlocks, msgid::GET_BLOCKS, "GetBlocks" }
build_msg_with_request_id_impl! { GetCompactBlocks, msgid::GET_CMPCT_BLOCKS, "GetCompactBlocks" }
build_msg_with_request_id_impl! { GetCompactBlocksResponse, msgid::GET_CMPCT_BLOCKS_RESPONSE, "GetCompactBlocksResponse" }
build_msg_with_request_id_impl! { GetBlockTxn, msgid::GET_BLOCK_TXN, "GetBlockTxn" }
build_msg_impl! { DynamicCapabilityChange, msgid::DYNAMIC_CAPABILITY_CHANGE, "DynamicCapabilityChange" }
build_msg_with_request_id_impl! { GetBlockHashesByEpoch, msgid::GET_BLOCK_HASHES_BY_EPOCH, "GetBlockHashesByEpoch" }
build_msg_with_request_id_impl! { SnapshotManifestRequest, msgid::GET_SNAPSHOT_MANIFEST, "SnapshotManifestRequest" }
build_msg_with_request_id_impl! { SnapshotManifestResponse, msgid::GET_SNAPSHOT_MANIFEST_RESPONSE, "SnapshotManifestResponse" }
build_msg_with_request_id_impl! { SnapshotChunkRequest, msgid::GET_SNAPSHOT_CHUNK, "SnapshotChunkRequest" }
build_msg_with_request_id_impl! { SnapshotChunkResponse, msgid::GET_SNAPSHOT_CHUNK_RESPONSE, "SnapshotChunkResponse" }
build_msg_with_request_id_impl! { StateSyncCandidateRequest, msgid::STATE_SYNC_CANDIDATE_REQUEST, "StateSyncCandidateRequest" }
build_msg_with_request_id_impl! { StateSyncCandidateResponse, msgid::STATE_SYNC_CANDIDATE_RESPONSE, "StateSyncCandidateResponse" }
build_msg_impl! { Throttled, msgid::THROTTLED, "Throttled" }

// normal priority and size-sensitive message types
impl Message for Transactions {
    fn msg_id(&self) -> MsgId { msgid::TRANSACTIONS }

    fn msg_name(&self) -> &'static str { "Transactions" }

    fn is_size_sensitive(&self) -> bool { self.transactions.len() > 1 }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = self.rlp_bytes();
        encoded.push(self.msg_id());
        encoded
    }
}

impl Message for GetBlocksResponse {
    fn msg_id(&self) -> MsgId { msgid::GET_BLOCKS_RESPONSE }

    fn msg_name(&self) -> &'static str { "GetBlocksResponse" }

    fn is_size_sensitive(&self) -> bool { self.blocks.len() > 0 }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = self.rlp_bytes();
        encoded.push(self.msg_id());
        encoded
    }
}

impl Message for GetBlocksWithPublicResponse {
    fn msg_id(&self) -> MsgId { msgid::GET_BLOCKS_WITH_PUBLIC_RESPONSE }

    fn msg_name(&self) -> &'static str { "GetBlocksWithPublicResponse" }

    fn is_size_sensitive(&self) -> bool { self.blocks.len() > 0 }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = self.rlp_bytes();
        encoded.push(self.msg_id());
        encoded
    }
}

impl Message for GetBlockTxnResponse {
    fn msg_id(&self) -> MsgId { msgid::GET_BLOCK_TXN_RESPONSE }

    fn msg_name(&self) -> &'static str { "GetBlockTxnResponse" }

    fn is_size_sensitive(&self) -> bool { self.block_txn.len() > 1 }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = self.rlp_bytes();
        encoded.push(self.msg_id());
        encoded
    }
}

impl Message for TransactionDigests {
    fn msg_id(&self) -> MsgId { msgid::TRANSACTION_DIGESTS }

    fn msg_name(&self) -> &'static str { "TransactionDigests" }

    fn is_size_sensitive(&self) -> bool { self.len() > 1 }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = self.rlp_bytes();
        encoded.push(self.msg_id());
        encoded
    }
}

impl Message for GetTransactions {
    fn msg_id(&self) -> MsgId { msgid::GET_TRANSACTIONS }

    fn msg_name(&self) -> &'static str { "GetTransactions" }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }

    fn get_request_id(&self) -> Option<RequestId> { Some(self.request_id) }

    fn set_request_id(&mut self, id: RequestId) { self.request_id = id; }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = self.rlp_bytes();
        encoded.push(self.msg_id());
        encoded
    }
}

impl Message for GetTransactionsFromTxHashes {
    fn msg_id(&self) -> MsgId { msgid::GET_TRANSACTIONS_FROM_TX_HASHES }

    fn msg_name(&self) -> &'static str { "GetTransactionsFromTxHashes" }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }

    fn get_request_id(&self) -> Option<RequestId> { Some(self.request_id) }

    fn set_request_id(&mut self, id: RequestId) { self.request_id = id; }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = self.rlp_bytes();
        encoded.push(self.msg_id());
        encoded
    }
}

impl Message for GetTransactionsResponse {
    fn msg_id(&self) -> MsgId { msgid::GET_TRANSACTIONS_RESPONSE }

    fn msg_name(&self) -> &'static str { "GetTransactionsResponse" }

    fn is_size_sensitive(&self) -> bool { self.transactions.len() > 0 }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = self.rlp_bytes();
        encoded.push(self.msg_id());
        encoded
    }
}

impl Message for GetTransactionsFromTxHashesResponse {
    fn msg_id(&self) -> MsgId {
        msgid::GET_TRANSACTIONS_FROM_TX_HASHES_RESPONSE
    }

    fn msg_name(&self) -> &'static str { "GetTransactionsFromTxHashesResponse" }

    fn is_size_sensitive(&self) -> bool { self.transactions.len() > 0 }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::Normal }

    fn encode(&self) -> Vec<u8> {
        let mut encoded = self.rlp_bytes();
        encoded.push(self.msg_id());
        encoded
    }
}
/// handle the RLP encoded message with given context `ctx`.
/// If the message not handled, return `Ok(false)`.
/// Otherwise, return `Ok(true)` if handled successfully
/// or Err(e) on any error.
pub fn handle_rlp_message(
    id: MsgId, ctx: &Context, rlp: &Rlp,
) -> Result<bool, Error> {
    match id {
        msgid::STATUS => handle_message::<Status>(ctx, rlp)?,
        msgid::NEW_BLOCK => handle_message::<NewBlock>(ctx, rlp)?,
        msgid::NEW_BLOCK_HASHES => {
            handle_message::<NewBlockHashes>(ctx, rlp)?;
        }
        msgid::GET_BLOCK_HEADERS => {
            handle_message::<GetBlockHeaders>(ctx, rlp)?;
        }
        msgid::GET_BLOCK_HEADERS_RESPONSE => {
            handle_message::<GetBlockHeadersResponse>(ctx, rlp)?;
        }
        msgid::GET_BLOCKS => handle_message::<GetBlocks>(ctx, rlp)?,
        msgid::GET_BLOCKS_RESPONSE => {
            handle_message::<GetBlocksResponse>(ctx, rlp)?;
        }
        msgid::GET_BLOCKS_WITH_PUBLIC_RESPONSE => {
            handle_message::<GetBlocksWithPublicResponse>(ctx, rlp)?;
        }
        msgid::GET_TERMINAL_BLOCK_HASHES => {
            handle_message::<GetTerminalBlockHashes>(ctx, rlp)?;
        }
        msgid::GET_TERMINAL_BLOCK_HASHES_RESPONSE => {
            handle_message::<GetTerminalBlockHashesResponse>(ctx, rlp)?;
        }
        msgid::GET_CMPCT_BLOCKS => {
            handle_message::<GetCompactBlocks>(ctx, rlp)?;
        }
        msgid::GET_CMPCT_BLOCKS_RESPONSE => {
            handle_message::<GetCompactBlocksResponse>(ctx, rlp)?;
        }
        msgid::GET_BLOCK_TXN => {
            handle_message::<GetBlockTxn>(ctx, rlp)?;
        }
        msgid::GET_BLOCK_TXN_RESPONSE => {
            handle_message::<GetBlockTxnResponse>(ctx, rlp)?;
        }
        msgid::TRANSACTIONS => {
            handle_message::<Transactions>(ctx, rlp)?;
        }
        msgid::DYNAMIC_CAPABILITY_CHANGE => {
            handle_message::<DynamicCapabilityChange>(ctx, rlp)?;
        }
        msgid::TRANSACTION_DIGESTS => {
            handle_message::<TransactionDigests>(ctx, rlp)?;
        }
        msgid::GET_TRANSACTIONS => {
            handle_message::<GetTransactions>(ctx, rlp)?;
        }
        msgid::GET_TRANSACTIONS_FROM_TX_HASHES => {
            handle_message::<GetTransactionsFromTxHashes>(ctx, rlp)?;
        }
        msgid::GET_TRANSACTIONS_RESPONSE => {
            handle_message::<GetTransactionsResponse>(ctx, rlp)?;
        }
        msgid::GET_TRANSACTIONS_FROM_TX_HASHES_RESPONSE => {
            handle_message::<GetTransactionsFromTxHashesResponse>(ctx, rlp)?;
        }
        msgid::GET_BLOCK_HASHES_BY_EPOCH => {
            handle_message::<GetBlockHashesByEpoch>(ctx, rlp)?;
        }
        msgid::GET_BLOCK_HASHES_RESPONSE => {
            handle_message::<GetBlockHashesResponse>(ctx, rlp)?;
        }
        msgid::GET_SNAPSHOT_MANIFEST => {
            handle_message::<SnapshotManifestRequest>(ctx, rlp)?;
        }
        msgid::GET_SNAPSHOT_MANIFEST_RESPONSE => {
            handle_message::<SnapshotManifestResponse>(ctx, rlp)?;
        }
        msgid::GET_SNAPSHOT_CHUNK => {
            handle_message::<SnapshotChunkRequest>(ctx, rlp)?;
        }
        msgid::GET_SNAPSHOT_CHUNK_RESPONSE => {
            handle_message::<SnapshotChunkResponse>(ctx, rlp)?;
        }
        msgid::STATE_SYNC_CANDIDATE_REQUEST => {
            handle_message::<StateSyncCandidateRequest>(ctx, rlp)?;
        }
        msgid::STATE_SYNC_CANDIDATE_RESPONSE => {
            handle_message::<StateSyncCandidateResponse>(ctx, rlp)?;
        }
        _ => return Ok(false),
    }

    Ok(true)
}

fn handle_message<T: Decodable + Handleable + Message>(
    ctx: &Context, rlp: &Rlp,
) -> Result<(), Error> {
    let msg: T = rlp.as_val()?;

    let msg_id = msg.msg_id();
    let msg_name = msg.msg_name();
    let req_id = msg.get_request_id();

    trace!(
        "handle sync protocol message, peer = {}, id = {}, name = {}, request_id = {:?}",
        ctx.peer, msg_id, msg_name, req_id,
    );

    msg.throttle(ctx)?;

    if let Err(e) = msg.handle(ctx) {
        info!(
            "failed to handle sync protocol message, peer = {}, id = {}, name = {}, request_id = {:?}, error_kind = {:?}",
            ctx.peer, msg_id, msg_name, req_id, e.0,
        );

        return Err(e);
    }

    Ok(())
}
