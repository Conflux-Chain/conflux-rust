// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U256, U64};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncGraphBlockState {
    pub block_hash: H256,
    pub parent: H256,
    pub referees: Vec<H256>,
    pub nonce: U256,
    pub timestamp: U64,
    pub adaptive: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// This struct maintains some inner state of synchronization graph.
pub struct SyncGraphStates {
    pub ready_block_vec: Vec<SyncGraphBlockState>,
}
