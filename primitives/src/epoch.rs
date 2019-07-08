// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;

pub type EpochId = H256;

/// Uniquely identifies epoch.
#[derive(Debug, Clone)]
pub enum EpochNumber {
    /// Epoch number within canon blockchain.
    Number(u64),
    /// Earliest block (genesis).
    Earliest,
    /// Latest mined block.
    LatestMined,
    /// Latest block with state.
    LatestState,
}
