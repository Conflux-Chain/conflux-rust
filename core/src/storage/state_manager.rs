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
    if height == 0 {
        0
    } else {
        ((height - 1) % SNAPSHOT_EPOCHS_CAPACITY) as u32 + 1
    }
}

pub struct StateReadonlyIndex {
    pub snapshot_epoch_id: EpochId,
    pub intermediate_epoch_id: EpochId,
    pub maybe_intermediate_key_padding: Option<DeltaMptKeyPadding>,
    pub epoch_id: EpochId,
    pub delta_mpt_key_padding: DeltaMptKeyPadding,
}

impl StateReadonlyIndex {
    pub fn from_ref(r: StateIndex) -> Self {
        Self {
            snapshot_epoch_id: r.snapshot_epoch_id.clone(),
            intermediate_epoch_id: r.intermediate_epoch_id.clone(),
            maybe_intermediate_key_padding: r
                .maybe_intermediate_mpt_key_padding
                .cloned(),
            epoch_id: r.epoch_id.clone(),
            delta_mpt_key_padding: r.delta_mpt_key_padding.clone(),
        }
    }

    pub fn as_ref(&self) -> StateIndex {
        StateIndex {
            snapshot_epoch_id: &self.snapshot_epoch_id,
            intermediate_epoch_id: &self.intermediate_epoch_id,
            maybe_intermediate_mpt_key_padding: self
                .maybe_intermediate_key_padding
                .as_ref(),
            epoch_id: &self.epoch_id,
            delta_mpt_key_padding: &self.delta_mpt_key_padding,
            maybe_delta_trie_height: None,
            maybe_height: None,
        }
    }
}

#[derive(Debug)]
pub struct StateIndex<'a> {
    pub snapshot_epoch_id: &'a EpochId,
    pub intermediate_epoch_id: &'a EpochId,
    pub maybe_intermediate_mpt_key_padding: Option<&'a DeltaMptKeyPadding>,
    pub epoch_id: &'a EpochId,
    pub delta_mpt_key_padding: &'a DeltaMptKeyPadding,
    pub maybe_delta_trie_height: Option<u32>,
    pub maybe_height: Option<u64>,
}

// The trait is created to separate the implementation to another file, and the
// concrete struct is put into inner mod, because the implementation is
// anticipated to be too complex to present in the same file of the API.
pub trait StateManagerTrait {
    /// At the boundary of snapshot, getting a state for new epoch will switch
    /// to new Delta MPT, but it's unnecessary getting a no-commit state.
    fn get_state_no_commit(
        &self, epoch_id: StateIndex,
    ) -> Result<Option<State>>;
    fn get_state_for_next_epoch(
        &self, parent_epoch_id: StateIndex,
    ) -> Result<Option<State>>;
    fn get_state_for_genesis_write(&self) -> State;
}

impl<'a> StateIndex<'a> {
    pub fn new_for_test_only_delta_mpt(epoch_id: &'a EpochId) -> Self {
        Self {
            snapshot_epoch_id: &MERKLE_NULL_NODE,
            intermediate_epoch_id: &MERKLE_NULL_NODE,
            maybe_intermediate_mpt_key_padding: None,
            epoch_id,
            delta_mpt_key_padding: &*GENESIS_DELTA_MPT_KEY_PADDING,
            maybe_delta_trie_height: Some(0),
            maybe_height: Some(0),
        }
    }

    /// Height is used to check for shifting snapshot.
    /// The state root and height information should be provided from consensus.
    pub fn new_for_next_epoch(
        base_epoch_id: &'a EpochId, aux_info: &'a StateRootAuxInfo, height: u64,
    ) -> Self {
        Self {
            snapshot_epoch_id: &aux_info.snapshot_epoch_id,
            intermediate_epoch_id: &aux_info.intermediate_epoch_id,
            maybe_intermediate_mpt_key_padding: aux_info
                .maybe_intermediate_mpt_key_padding
                .as_ref(),
            epoch_id: base_epoch_id,
            delta_mpt_key_padding: &aux_info.delta_mpt_key_padding,
            maybe_delta_trie_height: Some(height_to_delta_height(height)),
            maybe_height: Some(height),
        }
    }

    pub fn new_for_readonly(
        epoch_id: &'a EpochId, aux_info: &'a StateRootAuxInfo,
    ) -> Self {
        Self {
            snapshot_epoch_id: &aux_info.snapshot_epoch_id,
            intermediate_epoch_id: &aux_info.intermediate_epoch_id,
            maybe_intermediate_mpt_key_padding: aux_info
                .maybe_intermediate_mpt_key_padding
                .as_ref(),
            epoch_id,
            delta_mpt_key_padding: &aux_info.delta_mpt_key_padding,
            maybe_delta_trie_height: None,
            maybe_height: None,
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

use crate::storage::{
    impls::{defaults, errors::*},
    state::State,
    StateRootAuxInfo,
};
use primitives::{
    DeltaMptKeyPadding, EpochId, GENESIS_DELTA_MPT_KEY_PADDING,
    MERKLE_NULL_NODE,
};
use std::sync::Arc;
