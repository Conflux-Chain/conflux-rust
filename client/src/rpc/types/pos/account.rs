// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U64};
use diem_types::term_state::NodeStatus;
use serde_derive::Serialize;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    ///
    pub address: H256,
    ///
    pub status: NodeStatus,
    ///
    pub status_start_view: U64,
    ///
    pub voting_power: U64,
}

impl Default for Account {
    fn default() -> Account {
        Account {
            address: Default::default(),
            status: NodeStatus::Accepted,
            status_start_view: Default::default(),
            voting_power: Default::default(),
        }
    }
}
