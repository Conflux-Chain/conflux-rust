// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Auxiliary information for deferred state root, which is necessary for state
/// trees look-up. The StateRootAuxInfo should be provided by consensus layer
/// for state storage access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateRootAuxInfo {
    // We need the snapshot epoch_id to associate the intermediate mpt and
    // delta mpt, because snapshot merkle root are not guaranteed to be
    // unique.
    pub snapshot_epoch_id: EpochId,
    // When we need to shift the snapshot, this is the only "known" information
    // from consensus to retrieve the new snapshot.
    pub intermediate_epoch_id: EpochId,
    // We need key_padding in order to retrieve key-values from (Intermediate-)
    // Delta MPT.
    pub maybe_intermediate_mpt_key_padding: Option<DeltaMptKeyPadding>,

    // FIXME: how is it possible to fill this field for recovered state from
    // FIXME: blame? what's the expectation of saving as many
    // FIXME: EpochExecutionCommitments from blame?
    pub delta_mpt_key_padding: DeltaMptKeyPadding,

    // The merged hash of the original three fields
    pub state_root_hash: MerkleHash,
}

impl StateRootAuxInfo {
    pub fn genesis_state_root_aux_info(
        genesis_state_root: &MerkleHash,
    ) -> Self {
        Self {
            snapshot_epoch_id: NULL_EPOCH,
            intermediate_epoch_id: NULL_EPOCH,
            maybe_intermediate_mpt_key_padding: None,
            delta_mpt_key_padding: GENESIS_DELTA_MPT_KEY_PADDING.clone(),
            state_root_hash: genesis_state_root.clone(),
        }
    }
}

/// This struct is stored as state execution result and is used to compute state
/// of children blocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateRootWithAuxInfo {
    pub state_root: StateRoot,
    pub aux_info: StateRootAuxInfo,
}

impl StateRootWithAuxInfo {
    pub fn genesis(genesis_root: &MerkleHash) -> Self {
        let state_root = StateRoot::genesis(genesis_root);
        let genesis_state_root = state_root.compute_state_root_hash();
        Self {
            state_root,
            aux_info: StateRootAuxInfo::genesis_state_root_aux_info(
                &genesis_state_root,
            ),
        }
    }
}

impl From<(&StateRoot, &StateRootAuxInfo)> for StateRootWithAuxInfo {
    fn from(x: (&StateRoot, &StateRootAuxInfo)) -> Self {
        Self {
            state_root: x.0.clone(),
            aux_info: x.1.clone(),
        }
    }
}

impl Encodable for StateRootAuxInfo {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(5)
            .append(&self.snapshot_epoch_id)
            .append(&self.intermediate_epoch_id)
            .append(&self.maybe_intermediate_mpt_key_padding)
            .append(&&self.delta_mpt_key_padding[..])
            .append(&self.state_root_hash);
    }
}

impl Decodable for StateRootAuxInfo {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            snapshot_epoch_id: rlp.val_at(0)?,
            intermediate_epoch_id: rlp.val_at(1)?,
            maybe_intermediate_mpt_key_padding: rlp.val_at(2)?,
            delta_mpt_key_padding: rlp.val_at(3)?,
            state_root_hash: rlp.val_at(4)?,
        })
    }
}

impl Encodable for StateRootWithAuxInfo {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append(&self.state_root)
            .append(&self.aux_info);
    }
}

impl Decodable for StateRootWithAuxInfo {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            state_root: rlp.val_at(0)?,
            aux_info: rlp.val_at(1)?,
        })
    }
}

use primitives::{
    DeltaMptKeyPadding, EpochId, MerkleHash, StateRoot,
    GENESIS_DELTA_MPT_KEY_PADDING, NULL_EPOCH,
};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde_derive::{Deserialize, Serialize};
