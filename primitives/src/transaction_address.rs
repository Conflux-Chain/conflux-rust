// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use heapsize::HeapSizeOf;
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

impl HeapSizeOf for TransactionAddress {
    fn heap_size_of_children(&self) -> usize { 0 }
}
