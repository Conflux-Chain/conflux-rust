// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::pos::NodeLockStatus;
use cfx_types::{H256, U64};
use serde_derive::Serialize;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    ///
    pub address: H256,
    ///
    pub block_number: U64,
    ///
    pub status: NodeLockStatus,
}

impl Default for Account {
    fn default() -> Account {
        Account {
            address: Default::default(),
            block_number: Default::default(),
            status: NodeLockStatus {
                in_queue: Default::default(),
                locked: Default::default(),
                out_queue: Default::default(),
                unlocked: Default::default(),
                available_votes: Default::default(),
                force_retired: false,
                exempt_from_forfeit: None,
            },
        }
    }
}
