// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use keccak_hash::KECCAK_EMPTY;

pub type EpochId = H256;
pub const NULL_EPOCH: EpochId = KECCAK_EMPTY;

/// Uniquely identifies epoch.
#[derive(Debug, Clone, PartialEq)]
pub enum EpochNumber {
    /// Epoch number within canon blockchain.
    Number(u64),
    /// Earliest block (checkpoint).
    Earliest,
    /// The latest checkpoint (cur_era_genesis)
    LatestCheckpoint,
    /// Latest block with state.
    LatestState,
    /// Latest mined block.
    LatestMined,
}

impl Into<EpochNumber> for u64 {
    fn into(self) -> EpochNumber { EpochNumber::Number(self) }
}

#[derive(Debug, PartialEq, Clone)]
pub enum BlockHashOrEpochNumber {
    BlockHash(H256),
    EpochNumber(EpochNumber),
}
