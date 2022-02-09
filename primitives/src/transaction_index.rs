// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

/// Represents address of certain transaction within block
#[derive(Debug, PartialEq, Eq, Hash, Clone, Default)]
pub struct TransactionIndex {
    /// Block hash
    pub block_hash: H256,
    /// Transaction index within the block
    pub real_index: usize,
    /// true when this index belongs to a phantom transaction
    pub is_phantom: bool,
    /// Transaction index to be used in RPC responses
    pub rpc_index: Option<usize>,
}

impl MallocSizeOf for TransactionIndex {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

impl Encodable for TransactionIndex {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&self.block_hash);
        s.append(&self.real_index);
        s.append(&self.is_phantom);
        s.append(&self.rpc_index);
    }
}

impl Decodable for TransactionIndex {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match rlp.item_count()? {
            2 => Ok(TransactionIndex {
                block_hash: rlp.val_at(0)?,
                real_index: rlp.val_at(1)?,
                is_phantom: false,
                rpc_index: None,
            }),
            3 => Ok(TransactionIndex {
                block_hash: rlp.val_at(0)?,
                real_index: rlp.val_at(1)?,
                is_phantom: rlp.val_at(2)?,
                rpc_index: None,
            }),
            4 => Ok(TransactionIndex {
                block_hash: rlp.val_at(0)?,
                real_index: rlp.val_at(1)?,
                is_phantom: rlp.val_at(2)?,
                rpc_index: rlp.val_at(3)?,
            }),
            _ => Err(DecoderError::RlpInvalidLength),
        }
    }
}
