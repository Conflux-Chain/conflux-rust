// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::types::H256;
use cfxcore::state_exposer::SyncGraphStates as PrimitiveSyncGraphStates;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncGraphBlockState {
    pub block_hash: H256,
    pub parent: H256,
    pub referees: Vec<H256>,
    pub nonce: u64,
    pub timestamp: u64,
    pub adaptive: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
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
                nonce: block_state.nonce,
                timestamp: block_state.timestamp,
                adaptive: block_state.adaptive,
            })
        }

        Self { ready_block_vec }
    }
}
