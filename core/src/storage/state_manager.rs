// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// StateManager is the single entry-point to access State for any epoch.
// StateManager manages internal mutability and is thread-safe.
pub use super::impls::state_manager::StateManager;

pub type SharedStateManager = Arc<StateManager>;

pub struct SnapshotAndEpochId {
    pub snapshot_root: MerkleHash,
    pub previous_snapshot_root: MerkleHash,
    pub epoch_id: EpochId,
    pub delta_trie_height: Option<u32>,
    pub height: Option<u64>,
    pub intermediate_epoch_id: EpochId,
}

impl SnapshotAndEpochId {
    pub fn from_ref(r: SnapshotAndEpochIdRef) -> Self {
        Self {
            snapshot_root: r.snapshot_root.clone(),
            previous_snapshot_root: r.previous_snapshot_root.clone(),
            epoch_id: r.epoch_id.clone(),
            delta_trie_height: r.delta_trie_height,
            height: r.height,
            intermediate_epoch_id: r.intermediate_epoch_id.clone(),
        }
    }

    pub fn as_ref(&self) -> SnapshotAndEpochIdRef {
        SnapshotAndEpochIdRef {
            snapshot_root: &self.snapshot_root,
            previous_snapshot_root: &self.previous_snapshot_root,
            epoch_id: &self.epoch_id,
            delta_trie_height: self.delta_trie_height,
            height: self.height,
            intermediate_epoch_id: &self.intermediate_epoch_id,
        }
    }
}

#[derive(Debug)]
pub struct SnapshotAndEpochIdRef<'a> {
    pub snapshot_root: &'a MerkleHash,
    pub previous_snapshot_root: &'a MerkleHash,
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

    fn get_snapshot_wire_format(
        &self, snapshot_root: MerkleHash,
    ) -> Result<Option<Snapshot>>;

    // FIXME: this method is reserved for checkpoint, but we have to change its
    // FIXME: parameters, because storage knows nothing about consensus
    // FIXME: graph, therefore it can't know which snapshot to drop.
    fn drop_state_outside(&self, epoch_id: EpochId);
}

impl<'a> SnapshotAndEpochIdRef<'a> {
    // FIXME: this should be replaced by a real one.
    /// Delta height is used to check for shifting snapshot.
    /// The information should be provided from consensus.
    pub fn new(epoch_id: &'a EpochId, maybe_height: Option<u64>) -> Self {
        let delta_height = maybe_height
            .map(|height| (height % SNAPSHOT_EPOCHS_CAPACITY) as u32);
        Self {
            snapshot_root: &MERKLE_NULL_NODE,
            previous_snapshot_root: &MERKLE_NULL_NODE,
            intermediate_epoch_id: &MERKLE_NULL_NODE,
            epoch_id,
            delta_trie_height: delta_height,
            height: maybe_height,
        }
    }

    #[allow(unused)]
    pub fn new_for_next_epoch(
        epoch_id: &'a EpochId, state_root: &'a StateRootWithAuxInfo,
        height: u64, delta_height: u32,
    ) -> Self
    {
        Self {
            snapshot_root: &state_root.state_root.snapshot_root,
            previous_snapshot_root: &state_root.aux_info.previous_snapshot_root,
            intermediate_epoch_id: &state_root
                .aux_info
                .intermediate_delta_epoch_id,
            epoch_id,
            delta_trie_height: Some(delta_height),
            height: Some(height),
        }
    }

    pub fn new_for_readonly(
        epoch_id: &'a EpochId, state_root: &'a StateRootWithAuxInfo,
    ) -> Self {
        Self {
            snapshot_root: &state_root.state_root.snapshot_root,
            previous_snapshot_root: &state_root.aux_info.previous_snapshot_root,
            intermediate_epoch_id: &state_root
                .aux_info
                .intermediate_delta_epoch_id,
            epoch_id,
            delta_trie_height: None,
            height: None,
        }
    }

    #[allow(unused)]
    pub fn new_for_test(
        epoch_id: &'a EpochId, state_root: &'a StateRootWithAuxInfo,
    ) -> Self {
        Self::new_for_readonly(epoch_id, state_root)
    }
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

use super::{
    impls::{defaults, errors::*},
    state::State,
};
// FIXME: snapshot... wire format?
use super::impls::state_manager::SNAPSHOT_EPOCHS_CAPACITY;
use crate::snapshot::snapshot::Snapshot;
use primitives::{EpochId, MerkleHash, StateRootWithAuxInfo, MERKLE_NULL_NODE};
use std::sync::Arc;
