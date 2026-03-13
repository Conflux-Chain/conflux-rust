// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U64};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusGraphBlockState {
    pub block_hash: H256,
    pub best_block_hash: H256,
    pub block_status: U64,
    pub era_block_hash: H256,
    pub adaptive: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusGraphBlockExecutionState {
    pub block_hash: H256,
    pub deferred_state_root: H256,
    pub deferred_receipt_root: H256,
    pub deferred_logs_bloom_hash: H256,
    pub state_valid: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// This struct maintains some inner state of consensus graph.
pub struct ConsensusGraphStates {
    pub block_state_vec: Vec<ConsensusGraphBlockState>,
    pub block_execution_state_vec: Vec<ConsensusGraphBlockExecutionState>,
}
