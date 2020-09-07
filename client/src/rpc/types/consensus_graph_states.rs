// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U64};
use cfxcore::state_exposer::ConsensusGraphStates as PrimitiveConsensusGraphStates;

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusGraphBlockState {
    pub block_hash: H256,
    pub best_block_hash: H256,
    pub block_status: U64,
    pub era_block_hash: H256,
    pub adaptive: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusGraphBlockExecutionState {
    pub block_hash: H256,
    pub deferred_state_root: H256,
    pub deferred_receipt_root: H256,
    pub deferred_logs_bloom_hash: H256,
    pub state_valid: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
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

#[cfg(test)]
mod tests{
    use super::*;
    use cfxcore::block_data_manager::BlockStatus;
    use cfxcore::state_exposer::{ConsensusGraphStates as PrimitiveConsensusGraphStates,
                                 ConsensusGraphBlockState as PrimitiveConsensusGraphBlockState,
                                 ConsensusGraphBlockExecutionState as PrimitiveConsensusGraphBlockExecutionState};
    #[test]
    fn test_consensus_graph_states_serialize() {
        let block_state = ConsensusGraphBlockState{
            block_hash: H256([0xff;32]),
            best_block_hash: H256([0xff;32]),
            block_status: U64::one(),
            era_block_hash: H256([0xff;32]),
            adaptive: false
        };
        let execution = ConsensusGraphBlockExecutionState{
            block_hash: H256([0xff;32]),
            deferred_state_root: H256([0xff;32]),
            deferred_receipt_root: H256([0xff;32]),
            deferred_logs_bloom_hash: H256([0xff;32]),
            state_valid: false
        };
        let mut block_state_vec = Vec::new();
        block_state_vec.push(block_state);
        let mut execution_vec = Vec::new();
        execution_vec.push(execution);
        let graph_state = ConsensusGraphStates{
            block_state_vec,
            block_execution_state_vec: execution_vec
        };
        let serialize = serde_json::to_string(&graph_state).unwrap();
        assert_eq!(serialize,"{\"blockStateVec\":[{\"blockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"bestBlockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"blockStatus\":\"0x1\",\"eraBlockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"adaptive\":false}],\"blockExecutionStateVec\":[{\"blockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"deferredStateRoot\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"deferredReceiptRoot\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"deferredLogsBloomHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"stateValid\":false}]}");
        let graph_state_empty = ConsensusGraphStates{
            block_state_vec: vec![],
            block_execution_state_vec: vec![]
        };
        let serialize2 = serde_json::to_string(&graph_state_empty).unwrap();
        assert_eq!(serialize2,"{\"blockStateVec\":[],\"blockExecutionStateVec\":[]}");
    }
    #[test]
    fn test_consensus_graph_states_deserialize() {
        let serialize = "{\"blockStateVec\":[{\"blockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"bestBlockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"blockStatus\":\"0x1\",\"eraBlockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"adaptive\":false}],\"blockExecutionStateVec\":[{\"blockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"deferredStateRoot\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"deferredReceiptRoot\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"deferredLogsBloomHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"stateValid\":false}]}";
        let deserialize:ConsensusGraphStates = serde_json::from_str(serialize).unwrap();
        let block_state = ConsensusGraphBlockState{
            block_hash: H256([0xff;32]),
            best_block_hash: H256([0xff;32]),
            block_status: U64::one(),
            era_block_hash: H256([0xff;32]),
            adaptive: false
        };
        let execution = ConsensusGraphBlockExecutionState{
            block_hash: H256([0xff;32]),
            deferred_state_root: H256([0xff;32]),
            deferred_receipt_root: H256([0xff;32]),
            deferred_logs_bloom_hash: H256([0xff;32]),
            state_valid: false
        };
        let mut block_state_vec = Vec::new();
        block_state_vec.push(block_state);
        let mut execution_vec = Vec::new();
        execution_vec.push(execution);
        let graph_state = ConsensusGraphStates{
            block_state_vec,
            block_execution_state_vec: execution_vec
        };
        assert_eq!(deserialize, graph_state);
    }
    #[test]
    fn test_consensus_graph_states_new() {
        let pri_block_state = PrimitiveConsensusGraphBlockState {
            block_hash: H256([0xff;32]),
            best_block_hash: H256([0xff;32]),
            block_status: BlockStatus::Valid,
            era_block_hash: H256([0xff;32]),
            adaptive: false
        };
        let pri_execution = PrimitiveConsensusGraphBlockExecutionState {
            block_hash: H256([0xff;32]),
            deferred_state_root: H256([0xff;32]),
            deferred_receipt_root: H256([0xff;32]),
            deferred_logs_bloom_hash: H256([0xff;32]),
            state_valid: false
        };
        let mut pri_block_state_vec = Vec::new();
        let mut pri_pri_execution_vec = Vec::new();
        pri_block_state_vec.push(pri_block_state);
        pri_pri_execution_vec.push(pri_execution);
        let pri_consensus_graph_states = PrimitiveConsensusGraphStates{
            block_state_vec: pri_block_state_vec,
            block_execution_state_vec: pri_pri_execution_vec
        };
        let consensus_graph_states = ConsensusGraphStates::new(pri_consensus_graph_states);
        let consensus_graph_states_info = serde_json::to_string(&consensus_graph_states).unwrap();
        assert_eq!(consensus_graph_states_info,
        r#"{"blockStateVec":[{"blockHash":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","bestBlockHash":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","blockStatus":"0x0","eraBlockHash":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","adaptive":false}],"blockExecutionStateVec":[{"blockHash":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","deferredStateRoot":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","deferredReceiptRoot":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","deferredLogsBloomHash":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","stateValid":false}]}"#);
    }
}