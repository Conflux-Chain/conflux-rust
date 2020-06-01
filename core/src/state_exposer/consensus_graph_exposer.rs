// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::block_data_manager::block_data_types::BlockStatus;
use cfx_types::H256;
use std::mem;

pub struct ConsensusGraphBlockState {
    pub block_hash: H256,
    pub best_block_hash: H256,
    pub block_status: BlockStatus,
    pub era_block_hash: H256,
    pub adaptive: bool,
}

pub struct ConsensusGraphBlockExecutionState {
    pub block_hash: H256,
    pub deferred_state_root: H256,
    pub deferred_receipt_root: H256,
    pub deferred_logs_bloom_hash: H256,
    pub state_valid: bool,
}

#[derive(Default)]
/// This struct maintains some inner state of consensus graph.
pub struct ConsensusGraphStates {
    pub block_state_vec: Vec<ConsensusGraphBlockState>,
    pub block_execution_state_vec: Vec<ConsensusGraphBlockExecutionState>,
}

impl ConsensusGraphStates {
    pub fn retrieve(&mut self) -> Self {
        let mut block_state_vec = Vec::new();
        let mut block_execution_state_vec = Vec::new();
        mem::swap(&mut block_state_vec, &mut self.block_state_vec);
        mem::swap(
            &mut block_execution_state_vec,
            &mut self.block_execution_state_vec,
        );
        Self {
            block_state_vec,
            block_execution_state_vec,
        }
    }
}
