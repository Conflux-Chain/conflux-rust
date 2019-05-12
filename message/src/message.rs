// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

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
