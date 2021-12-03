use crate::StateRootWithAuxInfo;
use primitives::{
    DeltaMptKeyPadding, EpochId, MerkleHash, GENESIS_DELTA_MPT_KEY_PADDING,
    MERKLE_NULL_NODE, NULL_EPOCH,
};

#[derive(Debug)]
pub struct StateIndex {
    pub snapshot_epoch_id: EpochId,
    pub snapshot_merkle_root: MerkleHash,
    pub intermediate_epoch_id: EpochId,
    pub intermediate_trie_root_merkle: MerkleHash,
    pub maybe_intermediate_mpt_key_padding: Option<DeltaMptKeyPadding>,
    pub epoch_id: EpochId,
    pub delta_mpt_key_padding: DeltaMptKeyPadding,
    pub maybe_delta_trie_height: Option<u32>,
    pub maybe_height: Option<u64>,
}

impl StateIndex {
    pub fn height_to_delta_height(
        height: u64, snapshot_epoch_count: u32,
    ) -> u32 {
        if height == 0 {
            0
        } else {
            ((height - 1) % (snapshot_epoch_count as u64)) as u32 + 1
        }
    }

    pub fn new_for_test_only_delta_mpt(epoch_id: &EpochId) -> Self {
        Self {
            snapshot_epoch_id: NULL_EPOCH,
            snapshot_merkle_root: MERKLE_NULL_NODE,
            intermediate_epoch_id: NULL_EPOCH,
            intermediate_trie_root_merkle: MERKLE_NULL_NODE,
            maybe_intermediate_mpt_key_padding: None,
            epoch_id: *epoch_id,
            delta_mpt_key_padding: GENESIS_DELTA_MPT_KEY_PADDING.clone(),
            maybe_delta_trie_height: Some(0),
            maybe_height: Some(0),
        }
    }

    /// Height is used to check for shifting snapshot.
    /// The state root and height information should be provided from consensus.
    pub fn new_for_next_epoch(
        base_epoch_id: &EpochId, state_root: &StateRootWithAuxInfo,
        height: u64, snapshot_epoch_count: u32,
    ) -> Self
    {
        Self {
            snapshot_epoch_id: state_root.aux_info.snapshot_epoch_id,
            snapshot_merkle_root: state_root.state_root.snapshot_root,
            intermediate_epoch_id: state_root.aux_info.intermediate_epoch_id,
            intermediate_trie_root_merkle: state_root
                .state_root
                .intermediate_delta_root,
            maybe_intermediate_mpt_key_padding: state_root
                .aux_info
                .maybe_intermediate_mpt_key_padding
                .clone(),
            epoch_id: *base_epoch_id,
            delta_mpt_key_padding: state_root
                .aux_info
                .delta_mpt_key_padding
                .clone(),
            maybe_delta_trie_height: Some(Self::height_to_delta_height(
                height,
                snapshot_epoch_count,
            )),
            maybe_height: Some(height),
        }
    }

    pub fn new_for_readonly(
        epoch_id: &EpochId, state_root: &StateRootWithAuxInfo,
    ) -> Self {
        Self {
            snapshot_epoch_id: state_root.aux_info.snapshot_epoch_id,
            snapshot_merkle_root: state_root.state_root.snapshot_root,
            intermediate_epoch_id: state_root.aux_info.intermediate_epoch_id,
            intermediate_trie_root_merkle: state_root
                .state_root
                .intermediate_delta_root,
            maybe_intermediate_mpt_key_padding: state_root
                .aux_info
                .maybe_intermediate_mpt_key_padding
                .clone(),
            epoch_id: *epoch_id,
            delta_mpt_key_padding: state_root
                .aux_info
                .delta_mpt_key_padding
                .clone(),
            maybe_delta_trie_height: None,
            maybe_height: None,
        }
    }
}
