// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    impls::{defaults, errors::*},
    state::State,
};
use crate::snapshot::snapshot::Snapshot;
use primitives::EpochId;
use std::sync::Arc;

// StateManager is the single entry-point to access State for any epoch.
// StateManager has Internal mutability and is thread-safe.
pub use super::impls::state_manager::StateManager;

pub type SharedStateManager = Arc<StateManager>;

// The trait is created to separate the implementation to another file, and the
// concrete struct is put into inner mod, because the implementation is
// anticipated to be too complex to present in the same file of the API.
// TODO(yz): check if this is the best way to organize code for this library.
pub trait StateManagerTrait {
    fn from_snapshot(snapshot: &Snapshot) -> Self;
    fn make_snapshot(&self, epoch_id: EpochId) -> Snapshot;
    /// Even for non-existing the method returns a State because we need a way
    /// to create the genesis State. However there should be a special
    /// epoch_id to create the genesis State.
    //  TODO(yz): special epoch_id for empty state.
    fn get_state_at(&self, epoch_id: EpochId) -> Result<State>;
    fn contains_state(&self, epoch_id: EpochId) -> bool;
    fn drop_state_outside(&self, epoch_id: EpochId);
}

#[derive(Debug)]
pub struct StorageConfiguration {
    pub cache_start_size: u32,
    pub cache_size: u32,
    pub idle_size: u32,
    pub node_map_size: u32,
    pub recent_lfu_factor: f64,
}

impl Default for StorageConfiguration {
    fn default() -> Self {
        StorageConfiguration {
            cache_start_size: defaults::DEFAULT_CACHE_START_SIZE,
            cache_size: defaults::DEFAULT_CACHE_SIZE,
            idle_size: defaults::DEFAULT_IDLE_SIZE,
            node_map_size: defaults::MAX_CACHED_TRIE_NODES_R_LFU_COUNTER,
            recent_lfu_factor: defaults::DEFAULT_RECENT_LFU_FACTOR,
        }
    }
}
