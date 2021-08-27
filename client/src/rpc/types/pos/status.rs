// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use serde_derive::Serialize;
use diem_types::block_info::PivotBlockDecision;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    ///
    pub chain_id: u8,
    ///
    pub block_number: u64,
    ///
    pub epoch: u64,
    ///
    pub catch_up_mode: bool,
    ///
    pub pivot_decision: PivotBlockDecision,
}

impl Default for Status {
    fn default() -> Status {
        let default_decision = PivotBlockDecision {
            height: 0,
            block_hash:
            Default::default()
        };
        Status {
            chain_id: 0,
            epoch: 0,
            block_number: 0,
            catch_up_mode: false,
            pivot_decision: default_decision,
        }
    }
}

