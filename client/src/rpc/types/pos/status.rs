// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::U64;
use serde_derive::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    ///
    pub latest_committed: U64,
    ///
    pub epoch: U64,
    ///
    pub pivot_decision: U64,
    ///
    pub latest_voted: Option<U64>,
    ///
    pub latest_tx_number: U64,
}

impl Default for Status {
    fn default() -> Status {
        Status {
            epoch: U64::default(),
            latest_committed: U64::default(),
            pivot_decision: U64::default(),
            latest_voted: None,
            latest_tx_number: U64::default(),
        }
    }
}
