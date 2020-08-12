// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait DatabaseEncodable {
    fn db_encode(&self) -> Bytes;
}

pub trait DatabaseDecodable: Sized {
    fn db_decode(bytes: &[u8]) -> Result<Self, DecoderError>;
}

#[macro_export]
macro_rules! impl_db_encoding_as_rlp {
    ($type:ty) => {
        impl $crate::DatabaseEncodable for $type {
            fn db_encode(&self) -> Bytes { rlp::encode(self) }
        }

        impl $crate::DatabaseDecodable for $type {
            fn db_decode(bytes: &[u8]) -> Result<$type, DecoderError> {
                rlp::decode(bytes)
            }
        }
    };
}

impl_db_encoding_as_rlp!(H256);
impl_db_encoding_as_rlp!(u64);
impl_db_encoding_as_rlp!(TransactionIndex);

impl DatabaseDecodable for BlockHeader {
    fn db_decode(bytes: &[u8]) -> Result<Self, DecoderError> {
        BlockHeader::decode_with_pow_hash(bytes)
    }
}

impl DatabaseEncodable for BlockHeader {
    fn db_encode(&self) -> Bytes {
        let mut rlp_stream = RlpStream::new();
        self.stream_rlp_with_pow_hash(&mut rlp_stream);
        rlp_stream.drain()
    }
}

use cfx_bytes::Bytes;
use cfx_types::H256;
use primitives::{BlockHeader, TransactionIndex};
use rlp::*;
