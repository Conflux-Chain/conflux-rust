// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::block_info::PivotBlockDecision;
use diem_crypto::HashValue;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedBlock {
    pub hash: HashValue,
    pub epoch: u64,
    pub round: u64,
    pub pivot_decision: PivotBlockDecision,
    pub version: u64,
}
