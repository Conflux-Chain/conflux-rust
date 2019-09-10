// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod consensus_graph_exposer;
mod network_exposer;
mod sync_graph_exposer;

use self::{
    consensus_graph_exposer::ConsensusGraphExposer,
    network_exposer::NetworkExposer, sync_graph_exposer::SyncGraphExposer,
};

use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::sync::Arc;

pub struct StateExposerInner {
    pub consensus_graph: ConsensusGraphExposer,
    pub sync_graph: SyncGraphExposer,
    pub network: NetworkExposer,
}

impl StateExposerInner {
    pub fn new() -> Self {
        Self {
            consensus_graph: Default::default(),
            sync_graph: SyncGraphExposer {},
            network: NetworkExposer {},
        }
    }
}

pub type SharedStateExposer = Arc<StateExposer>;

pub struct StateExposer {
    /// TODO: maybe we can use three RwLocks
    inner: RwLock<StateExposerInner>,
}

impl StateExposer {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(StateExposerInner::new()),
        }
    }

    pub fn read(&self) -> RwLockReadGuard<StateExposerInner> {
        self.inner.read()
    }

    pub fn write(&self) -> RwLockWriteGuard<StateExposerInner> {
        self.inner.write()
    }
}
