// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use serde_derive::Serialize;
use cfx_types::{U64};
use super::Decision;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    ///
    pub block_number: U64,
    ///
    pub epoch: U64,
    ///
    pub catch_up_mode: bool,
    ///
    pub pivot_decision: Decision,
}

impl Default for Status {
    fn default() -> Status {
        let default_decision = Decision {
            height: U64::from(0),
            block_hash: Default::default()
        };
        Status {
            epoch: U64::default(),
            block_number: U64::default(),
            catch_up_mode: false,
            pivot_decision: default_decision,
        }
    }
}
