// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        transactions::Transactions, Context, GetBlockHashesByEpoch,
        GetBlockHashesResponse, GetBlockHeaderChain, GetBlockHeaders,
        GetBlockHeadersResponse, GetBlockTxn, GetBlockTxnResponse, GetBlocks,
        GetBlocksResponse, GetBlocksWithPublicResponse, GetCompactBlocks,
        GetCompactBlocksResponse, GetTerminalBlockHashes,
        GetTerminalBlockHashesResponse, GetTransactions,
        GetTransactionsResponse, Handleable, NewBlock, NewBlockHashes, Status,
        TransactionDigests, TransactionPropagationControl,
    },
    state::{
        SnapshotChunkRequest, SnapshotChunkResponse, SnapshotManifestRequest,
        SnapshotManifestResponse,
    },
    Error,
};
use priority_send_queue::SendQueuePriority;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::fmt;

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

pub trait Message: Send + Sync + Encodable + 'static {
    fn msg_id(&self) -> MsgId;

    // If true, message may be throttled when sent to remote peer.
    fn is_size_sensitive(&self) -> bool { false }

    fn priority(&self) -> SendQueuePriority { SendQueuePriority::High }
}

#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub struct RequestId {
    request_id: u64,
}

impl RequestId {
    pub fn request_id(&self) -> u64 { self.request_id }

    pub fn set_request_id(&mut self, request_id: u64) {
        self.request_id = request_id;
    }
}

impl From<u64> for RequestId {
    fn from(request_id: u64) -> Self { RequestId { request_id } }
}

impl Encodable for RequestId {
    fn rlp_append(&self, stream: &mut RlpStream) {
        self.request_id.rlp_append(stream);
    }
}

impl Decodable for RequestId {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            request_id: rlp.as_val()?,
        })
    }
}
