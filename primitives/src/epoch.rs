// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;

pub type EpochId = H256;

/// Uniquely identifies epoch.
#[derive(Debug, Clone, PartialEq)]
pub enum EpochNumber {
    /// Epoch number within canon blockchain.
    Number(u64),
    /// Earliest block (checkpoint).
    Earliest,
    /// Latest mined block.
    LatestMined,
    /// Latest block with state.
    LatestState,
}

impl Into<EpochNumber> for u64 {
    fn into(self) -> EpochNumber { EpochNumber::Number(self) }
}

#[derive(Debug, PartialEq, Clone)]
pub enum BlockHashOrEpochNumber {
    BlockHash(H256),
    EpochNumber(EpochNumber),
}
