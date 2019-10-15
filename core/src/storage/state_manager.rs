// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// StateManager is the single entry-point to access State for any epoch.
// StateManager manages internal mutability and is thread-safe.
pub use super::impls::state_manager::StateManager;

pub type SharedStateManager = Arc<StateManager>;

// TODO: Set the parameter to a normal value after we have tested all snapshot
// related implementations.
// FIXME: u32.
// The current delta switching rule is simply split by height at
// multiple of SNAPSHOT_EPOCHS_CAPACITY.
//
// Only if we see problem dealing with attacks, consider rules like the
// size of delta trie.
pub const SNAPSHOT_EPOCHS_CAPACITY: u64 = 1_000_000_000_000_000;
pub fn height_to_delta_height(height: u64) -> u32 {
    (height % SNAPSHOT_EPOCHS_CAPACITY) as u32
}

pub struct SnapshotAndEpochId {
    pub snapshot_epoch_id: EpochId,
    pub epoch_id: EpochId,
    pub delta_trie_height: Option<u32>,
    pub height: Option<u64>,
    pub intermediate_epoch_id: EpochId,
}

impl SnapshotAndEpochId {
    pub fn from_ref(r: SnapshotAndEpochIdRef) -> Self {
        Self {
            snapshot_epoch_id: r.snapshot_epoch_id.clone(),
            epoch_id: r.epoch_id.clone(),
            delta_trie_height: r.delta_trie_height,
            height: r.height,
            intermediate_epoch_id: r.intermediate_epoch_id.clone(),
        }
    }

    pub fn as_ref(&self) -> SnapshotAndEpochIdRef {
        SnapshotAndEpochIdRef {
            snapshot_epoch_id: &self.snapshot_epoch_id,
            epoch_id: &self.epoch_id,
            delta_trie_height: self.delta_trie_height,
            height: self.height,
            intermediate_epoch_id: &self.intermediate_epoch_id,
        }
    }
}

#[derive(Debug)]
pub struct SnapshotAndEpochIdRef<'a> {
    pub snapshot_epoch_id: &'a EpochId,
    pub intermediate_epoch_id: &'a EpochId,
    pub epoch_id: &'a EpochId,
    pub delta_trie_height: Option<u32>,
    pub height: Option<u64>,
}

// The trait is created to separate the implementation to another file, and the
// concrete struct is put into inner mod, because the implementation is
// anticipated to be too complex to present in the same file of the API.
pub trait StateManagerTrait {
    /// At the boundary of snapshot, getting a state for new epoch will switch
    /// to new Delta MPT, but it's unnecessary getting a no-commit state.
    fn get_state_no_commit(
        &self, epoch_id: SnapshotAndEpochIdRef,
    ) -> Result<Option<State>>;
    fn get_state_for_next_epoch(
        &self, parent_epoch_id: SnapshotAndEpochIdRef,
    ) -> Result<Option<State>>;
    fn get_state_for_genesis_write(&self) -> State;

    /// False in case of db failure.
    fn contains_state(&self, epoch_id: SnapshotAndEpochIdRef) -> Result<bool>;
}

impl<'a> SnapshotAndEpochIdRef<'a> {
    pub fn new_for_test_only_delta_mpt(epoch_id: &'a EpochId) -> Self {
        Self {
            snapshot_epoch_id: &MERKLE_NULL_NODE,
            intermediate_epoch_id: &MERKLE_NULL_NODE,
            epoch_id,
            delta_trie_height: Some(0),
            height: Some(0),
        }
    }

    /// Height is used to check for shifting snapshot.
    /// The state root and height information should be provided from consensus.
    pub fn new_for_next_epoch(
        base_epoch_id: &'a EpochId, state_root: &'a StateRootWithAuxInfo,
        height: u64,
    ) -> Self
    {
        Self {
            snapshot_epoch_id: &state_root.aux_info.snapshot_epoch_id,
            intermediate_epoch_id: &state_root.aux_info.intermediate_epoch_id,
            epoch_id: base_epoch_id,
            delta_trie_height: Some(height_to_delta_height(height)),
            height: Some(height),
        }
    }

    pub fn new_for_readonly(
        epoch_id: &'a EpochId, state_root: &'a StateRootWithAuxInfo,
    ) -> Self {
        Self {
            snapshot_epoch_id: &state_root.aux_info.snapshot_epoch_id,
            intermediate_epoch_id: &state_root.aux_info.intermediate_epoch_id,
            epoch_id,
            delta_trie_height: None,
            height: None,
        }
    }
}

#[derive(Debug, Clone)]
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

use super::{
    impls::{defaults, errors::*},
    state::State,
};
use primitives::{EpochId, StateRootWithAuxInfo, MERKLE_NULL_NODE};
use std::sync::Arc;
