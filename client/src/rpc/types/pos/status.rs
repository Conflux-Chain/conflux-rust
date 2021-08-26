// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{U64};
use serde_derive::Serialize;
use diem_types::block_info::PivotBlockDecision;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    ///
    pub chain_id: u32,
    ///
    pub epoch: U64,
    ///
    pub round: U64,
    ///
    pub catch_up_mode: bool,
    ///
    pub pivot_decision: PivotBlockDecision,
}

impl Default for Status {
    fn default() -> Status {
        Status {
            chain_id: 0,
            epoch: Default::default(),
            round: Default::default(),
            catch_up_mode: false,
            pivot_decision: PivotBlockDecision { height: 0, block_hash: Default::default() }
        }
    }
}

