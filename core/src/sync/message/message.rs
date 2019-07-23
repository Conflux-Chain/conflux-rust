// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    message::{
        GetBlockHashesByEpoch, GetBlockHeaderChain, GetBlockHeaders,
        GetBlockTxn, GetBlocks, GetCompactBlocks, GetTerminalBlockHashes,
        GetTransactions, Request, RequestContext,
    },
    state::{SnapshotChunkRequest, SnapshotManifestRequest},
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
    pub fn handle_request(
        &self, context: &RequestContext, rlp: &Rlp,
    ) -> Result<bool, Error> {
        match *self {
            MsgId::GET_BLOCK_HEADERS => {
                rlp.as_val::<GetBlockHeaders>()?.handle(context)?
            }
            MsgId::GET_BLOCK_HEADER_CHAIN => {
                rlp.as_val::<GetBlockHeaderChain>()?.handle(&context)?
            }
            MsgId::GET_BLOCKS => rlp.as_val::<GetBlocks>()?.handle(&context)?,
            MsgId::GET_TERMINAL_BLOCK_HASHES => {
                rlp.as_val::<GetTerminalBlockHashes>()?.handle(&context)?
            }
            MsgId::GET_CMPCT_BLOCKS => {
                rlp.as_val::<GetCompactBlocks>()?.handle(&context)?
            }
            MsgId::GET_BLOCK_TXN => {
                rlp.as_val::<GetBlockTxn>()?.handle(&context)?
            }
            MsgId::GET_TRANSACTIONS => {
                rlp.as_val::<GetTransactions>()?.handle(&context)?
            }
            MsgId::GET_BLOCK_HASHES_BY_EPOCH => {
                rlp.as_val::<GetBlockHashesByEpoch>()?.handle(&context)?
            }
            MsgId::GET_SNAPSHOT_MANIFEST => {
                rlp.as_val::<SnapshotManifestRequest>()?.handle(&context)?
            }
            MsgId::GET_SNAPSHOT_CHUNK => {
                rlp.as_val::<SnapshotChunkRequest>()?.handle(&context)?
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
