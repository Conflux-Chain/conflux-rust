// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::U64;
use serde_derive::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    ///
    pub block_number: U64,
    ///
    pub epoch: U64,
    ///
    pub pivot_decision: U64,
}

impl Default for Status {
    fn default() -> Status {
        Status {
            epoch: U64::default(),
            block_number: U64::default(),
            pivot_decision: U64::default(),
        }
    }
}
