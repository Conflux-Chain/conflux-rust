// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod bft_exposer;
mod consensus_graph_exposer;
mod network_exposer;
mod sync_graph_exposer;

pub use self::{
    bft_exposer::{BFTCommitEvent, BFTStates},
    consensus_graph_exposer::{
        ConsensusGraphBlockExecutionState, ConsensusGraphBlockState,
        ConsensusGraphStates,
    },
    network_exposer::NetworkExposer,
    sync_graph_exposer::{SyncGraphBlockState, SyncGraphStates},
};

use parking_lot::Mutex;
use std::sync::Arc;

pub type SharedStateExposer = Arc<StateExposer>;

pub struct StateExposer {
    pub consensus_graph: Mutex<ConsensusGraphStates>,
    pub sync_graph: Mutex<SyncGraphStates>,
    pub network: Mutex<NetworkExposer>,
    pub bft: Mutex<BFTStates>,
}

impl StateExposer {
    pub fn new() -> Self {
        Self {
            consensus_graph: Mutex::new(Default::default()),
            sync_graph: Mutex::new(Default::default()),
            network: Mutex::new(Default::default()),
            bft: Mutex::new(Default::default()),
        }
    }
}

lazy_static! {
    pub static ref STATE_EXPOSER: SharedStateExposer =
        SharedStateExposer::new(StateExposer::new());
}
