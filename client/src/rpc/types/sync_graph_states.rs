// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{H256, U256, U64};
use cfxcore::state_exposer::SyncGraphStates as PrimitiveSyncGraphStates;

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SyncGraphBlockState {
    pub block_hash: H256,
    pub parent: H256,
    pub referees: Vec<H256>,
    pub nonce: U256,
    pub timestamp: U64,
    pub adaptive: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
/// This struct maintains some inner state of synchronization graph.
pub struct SyncGraphStates {
    pub ready_block_vec: Vec<SyncGraphBlockState>,
}

impl SyncGraphStates {
    pub fn new(sync_graph_states: PrimitiveSyncGraphStates) -> Self {
        let mut ready_block_vec = Vec::new();
        for block_state in sync_graph_states.ready_block_vec {
            ready_block_vec.push(SyncGraphBlockState {
                block_hash: block_state.block_hash.into(),
                parent: block_state.parent.into(),
                referees: block_state
                    .referees
                    .iter()
                    .map(|x| H256::from(*x))
                    .collect(),
                nonce: block_state.nonce.into(),
                timestamp: U64::from(block_state.timestamp),
                adaptive: block_state.adaptive,
            })
        }

        Self { ready_block_vec }
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::types::{
        sync_graph_states::SyncGraphBlockState, SyncGraphStates,
    };
    use cfx_types::{H256, U256, U64};
    use cfxcore::state_exposer::{
        SyncGraphBlockState as PrimitiveSyncGraphBlockState,
        SyncGraphStates as PrimitiveSyncGraphStates,
    };

    #[test]
    fn test_sync_graph_states_new() {
        let block_state = PrimitiveSyncGraphBlockState {
            block_hash: H256([0xff; 32]),
            parent: H256([0xff; 32]),
            referees: vec![],
            nonce: U256::one(),
            timestamp: U256::one().as_u64(),
            adaptive: false,
        };
        let mut vec = Vec::new();
        vec.push(block_state);
        let pri_graph_state = PrimitiveSyncGraphStates {
            ready_block_vec: vec,
        };
        let graph_state = SyncGraphStates::new(pri_graph_state);
        let graph_state_info = graph_state.ready_block_vec;
        let graph_block_info =
            serde_json::to_string(&graph_state_info[0]).unwrap();
        assert_eq!(graph_block_info,
        r#"{"blockHash":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","parent":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","referees":[],"nonce":"0x1","timestamp":"0x1","adaptive":false}"#);
    }
    #[test]
    fn test_sync_graph_state_serialize() {
        let block_state = SyncGraphBlockState {
            block_hash: H256([0xff; 32]),
            parent: H256([0xff; 32]),
            referees: vec![],
            nonce: U256::one(),
            timestamp: U64::one(),
            adaptive: false,
        };
        let mut vec = Vec::new();
        vec.push(block_state);
        let graph_state = SyncGraphStates {
            ready_block_vec: vec,
        };
        let serialize = serde_json::to_string(&graph_state).unwrap();
        assert_eq!(serialize,"{\"readyBlockVec\":[{\"blockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"parent\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"referees\":[],\"nonce\":\"0x1\",\"timestamp\":\"0x1\",\"adaptive\":false}]}");
        let empty_graph_state = SyncGraphStates {
            ready_block_vec: vec![],
        };
        let serialize_empty =
            serde_json::to_string(&empty_graph_state).unwrap();
        assert_eq!(serialize_empty, "{\"readyBlockVec\":[]}");
    }
    #[test]
    fn test_sync_graph_states_deserialize() {
        let serialize = r#"{"blockHash":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","parent":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","referees":[],"nonce":"0x1","timestamp":"0x1","adaptive":false}"#;
        let deserialize: SyncGraphBlockState =
            serde_json::from_str(serialize).unwrap();
        let block_state = SyncGraphBlockState {
            block_hash: H256([0xff; 32]),
            parent: H256([0xff; 32]),
            referees: vec![],
            nonce: U256::one(),
            timestamp: U64::one(),
            adaptive: false,
        };
        assert_eq!(deserialize, block_state);
        let mut vec = Vec::new();
        vec.push(block_state);
        let graph_state = SyncGraphStates {
            ready_block_vec: vec,
        };
        let s = "{\"readyBlockVec\":[{\"blockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"parent\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"referees\":[],\"nonce\":\"0x1\",\"timestamp\":\"0x1\",\"adaptive\":false}]}";
        let de: SyncGraphStates = serde_json::from_str(s).unwrap();
        assert_eq!(de, graph_state);
        let empty_s = "{\"readyBlockVec\":[]}";
        let empty_de: SyncGraphStates = serde_json::from_str(empty_s).unwrap();
        let empty_graph_state = SyncGraphStates {
            ready_block_vec: vec![],
        };
        assert_eq!(empty_de, empty_graph_state);
    }
}
