// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// receipts_root and logs_bloom got after an epoch is executed.
/// It is NOT deferred.
#[derive(Clone, Debug, RlpEncodable, RlpDecodable)]
pub struct EpochExecutionCommitment {
    pub state_root_with_aux_info: StateRootWithAuxInfo,
    pub receipts_root: MerkleHash,
    pub logs_bloom_hash: MerkleHash,
}

impl MallocSizeOf for EpochExecutionCommitment {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

impl_db_encoding_as_rlp!(EpochExecutionCommitment);

use crate::StateRootWithAuxInfo;
use cfx_bytes::Bytes;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use primitives::MerkleHash;
use rlp::*;
use rlp_derive::*;
