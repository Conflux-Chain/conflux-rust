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
    pub index: usize,
    /// true when this index belongs to a phantom transaction
    pub is_phantom: bool,
}

impl MallocSizeOf for TransactionIndex {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

impl Encodable for TransactionIndex {
    fn rlp_append(&self, s: &mut RlpStream) {
        if self.is_phantom {
            s.begin_list(3);
            s.append(&self.block_hash);
            s.append(&self.index);
            s.append(&self.is_phantom);
        } else {
            s.begin_list(2);
            s.append(&self.block_hash);
            s.append(&self.index);
        }
    }
}

impl Decodable for TransactionIndex {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        match rlp.item_count()? {
            2 => Ok(TransactionIndex {
                block_hash: rlp.val_at(0)?,
                index: rlp.val_at(1)?,
                is_phantom: false,
            }),
            3 => Ok(TransactionIndex {
                block_hash: rlp.val_at(0)?,
                index: rlp.val_at(1)?,
                is_phantom: rlp.val_at(2)?,
            }),
            _ => Err(DecoderError::RlpInvalidLength),
        }
    }
}
