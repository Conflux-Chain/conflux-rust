// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U64};
use cfxcore_types::state_exposer::ConsensusGraphStates as PrimitiveConsensusGraphStates;
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

impl ConsensusGraphStates {
    pub fn new(consensus_graph_states: PrimitiveConsensusGraphStates) -> Self {
        let mut block_state_vec = Vec::new();
        let mut block_execution_state_vec = Vec::new();

        for block_state in &consensus_graph_states.block_state_vec {
            block_state_vec.push(ConsensusGraphBlockState {
                block_hash: block_state.block_hash.into(),
                best_block_hash: block_state.best_block_hash.into(),
                block_status: (block_state.block_status as u8).into(),
                era_block_hash: block_state.era_block_hash.into(),
                adaptive: block_state.adaptive,
            })
        }
        for exec_state in &consensus_graph_states.block_execution_state_vec {
            block_execution_state_vec.push(ConsensusGraphBlockExecutionState {
                block_hash: exec_state.block_hash.into(),
                deferred_state_root: exec_state.deferred_state_root.into(),
                deferred_receipt_root: exec_state.deferred_receipt_root.into(),
                deferred_logs_bloom_hash: exec_state
                    .deferred_logs_bloom_hash
                    .into(),
                state_valid: exec_state.state_valid,
            })
        }

        Self {
            block_state_vec,
            block_execution_state_vec,
        }
    }
}
