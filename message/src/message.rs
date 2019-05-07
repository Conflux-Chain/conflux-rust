// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use std::fmt;

pub type MsgIdInner = u8;
#[derive(Debug, PartialEq, Eq)]
pub struct MsgId(MsgIdInner);

impl MsgId {
    pub const GET_BLOCKS: MsgId = MsgId(0x00);
    pub const GET_BLOCKS_RESPONSE: MsgId = MsgId(0x01);
    pub const GET_BLOCKS_WITH_PUBLIC_RESPONSE: MsgId = MsgId(0x02);
    pub const GET_BLOCK_BODIES: MsgId = MsgId(0x03);
    pub const GET_BLOCK_BODIES_RESPONSE: MsgId = MsgId(0x04);
    pub const GET_BLOCK_HASHES: MsgId = MsgId(0x05);
    pub const GET_BLOCK_HASHES_RESPONSE: MsgId = MsgId(0x06);
    pub const GET_BLOCK_HEADERS: MsgId = MsgId(0x07);
    pub const GET_BLOCK_HEADERS_RESPONSE: MsgId = MsgId(0x08);
    pub const GET_BLOCK_TXN: MsgId = MsgId(0x09);
    pub const GET_BLOCK_TXN_RESPONSE: MsgId = MsgId(0x0a);
    pub const GET_CMPCT_BLOCKS: MsgId = MsgId(0x0b);
    pub const GET_CMPCT_BLOCKS_RESPONSE: MsgId = MsgId(0x0c);
    pub const GET_TERMINAL_BLOCK_HASHES: MsgId = MsgId(0x0d);
    pub const GET_TERMINAL_BLOCK_HASHES_RESPONSE: MsgId = MsgId(0x0e);
    pub const NEW_BLOCK: MsgId = MsgId(0x0f);
    pub const NEW_BLOCK_HASHES: MsgId = MsgId(0x10);
    pub const STATUS: MsgId = MsgId(0x11);
    pub const TRANSACTIONS: MsgId = MsgId(0x12);
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
}

#[derive(Debug, PartialEq, Eq, Default)]
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
