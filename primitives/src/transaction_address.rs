// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use rlp_derive::{RlpDecodable, RlpEncodable};

/// Represents address of certain transaction within block
#[derive(
    Debug, PartialEq, Eq, Hash, Clone, RlpEncodable, RlpDecodable, Default,
)]
pub struct TransactionAddress {
    /// Block hash
    pub block_hash: H256,
    /// Transaction index within the block
    pub index: usize,
}

impl MallocSizeOf for TransactionAddress {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}
