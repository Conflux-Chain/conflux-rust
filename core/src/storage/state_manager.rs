// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// StateManager is the single entry-point to access State for any epoch.
// StateManager manages internal mutability and is thread-safe.
pub use super::impls::state_manager::StateManager;

pub type SharedStateManager = Arc<StateManager>;

pub struct StateReadonlyIndex {
    pub snapshot_epoch_id: EpochId,
    pub snapshot_merkle_root: MerkleHash,
    pub intermediate_epoch_id: EpochId,
    pub intermediate_trie_root_merkle: MerkleHash,
    pub maybe_intermediate_key_padding: Option<DeltaMptKeyPadding>,
    pub epoch_id: EpochId,
    pub delta_mpt_key_padding: DeltaMptKeyPadding,
}

impl StateReadonlyIndex {
    pub fn from_ref(r: StateIndex) -> Self {
        Self {
            snapshot_epoch_id: r.snapshot_epoch_id.clone(),
            snapshot_merkle_root: r.snapshot_merkle_root.clone(),
            intermediate_epoch_id: r.intermediate_epoch_id.clone(),
            intermediate_trie_root_merkle: r
                .intermediate_trie_root_merkle
                .clone(),
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
            snapshot_merkle_root: &self.snapshot_merkle_root,
            intermediate_epoch_id: &self.intermediate_epoch_id,
            intermediate_trie_root_merkle: &self.intermediate_trie_root_merkle,
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
    pub snapshot_merkle_root: &'a MerkleHash,
    pub intermediate_epoch_id: &'a EpochId,
    pub intermediate_trie_root_merkle: &'a MerkleHash,
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
    ///
    /// With try_open == true, the call fails immediately when the max number of
    /// snapshot open is reached.
    fn get_state_no_commit(
        &self, epoch_id: StateIndex, try_open: bool,
    ) -> Result<Option<State>>;
    fn get_state_for_next_epoch(
        &self, parent_epoch_id: StateIndex,
    ) -> Result<Option<State>>;
    fn get_state_for_genesis_write(&self) -> State;
}

impl<'a> StateIndex<'a> {
    pub fn height_to_delta_height(
        height: u64, snapshot_epoch_count: u32,
    ) -> u32 {
        if height == 0 {
            0
        } else {
            ((height - 1) % (snapshot_epoch_count as u64)) as u32 + 1
        }
    }

    pub fn new_for_test_only_delta_mpt(epoch_id: &'a EpochId) -> Self {
        Self {
            snapshot_epoch_id: &NULL_EPOCH,
            snapshot_merkle_root: &MERKLE_NULL_NODE,
            intermediate_epoch_id: &NULL_EPOCH,
            intermediate_trie_root_merkle: &MERKLE_NULL_NODE,
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
        base_epoch_id: &'a EpochId, state_root: &'a StateRootWithAuxInfo,
        height: u64, snapshot_epoch_count: u32,
    ) -> Self
    {
        Self {
            snapshot_epoch_id: &state_root.aux_info.snapshot_epoch_id,
            snapshot_merkle_root: &state_root.state_root.snapshot_root,
            intermediate_epoch_id: &state_root.aux_info.intermediate_epoch_id,
            intermediate_trie_root_merkle: &state_root
                .state_root
                .intermediate_delta_root,
            maybe_intermediate_mpt_key_padding: state_root
                .aux_info
                .maybe_intermediate_mpt_key_padding
                .as_ref(),
            epoch_id: base_epoch_id,
            delta_mpt_key_padding: &state_root.aux_info.delta_mpt_key_padding,
            maybe_delta_trie_height: Some(Self::height_to_delta_height(
                height,
                snapshot_epoch_count,
            )),
            maybe_height: Some(height),
        }
    }

    pub fn new_for_readonly(
        epoch_id: &'a EpochId, state_root: &'a StateRootWithAuxInfo,
    ) -> Self {
        Self {
            snapshot_epoch_id: &state_root.aux_info.snapshot_epoch_id,
            snapshot_merkle_root: &state_root.state_root.snapshot_root,
            intermediate_epoch_id: &state_root.aux_info.intermediate_epoch_id,
            intermediate_trie_root_merkle: &state_root
                .state_root
                .intermediate_delta_root,
            maybe_intermediate_mpt_key_padding: state_root
                .aux_info
                .maybe_intermediate_mpt_key_padding
                .as_ref(),
            epoch_id,
            delta_mpt_key_padding: &state_root.aux_info.delta_mpt_key_padding,
            maybe_delta_trie_height: None,
            maybe_height: None,
        }
    }
}

use crate::storage::{impls::errors::*, state::State, StateRootWithAuxInfo};
use primitives::{
    DeltaMptKeyPadding, EpochId, MerkleHash, GENESIS_DELTA_MPT_KEY_PADDING,
    MERKLE_NULL_NODE, NULL_EPOCH,
};
use std::sync::Arc;
