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
    pub maybe_intermediate_mpt_key_padding: Option<KeyPadding>,

    // FIXME: how is it possible to fill this field for recovered state from
    // FIXME: blame? what's the expectation of saving as many
    // FIXME: EpochExecutionCommitments from blame?
    pub delta_mpt_key_padding: KeyPadding,
}

impl StateRootAuxInfo {
    pub fn genesis_state_root_aux_info() -> Self {
        Self {
            snapshot_epoch_id: NULL_EPOCH,
            intermediate_epoch_id: NULL_EPOCH,
            maybe_intermediate_mpt_key_padding: None,
            delta_mpt_key_padding: GENESIS_DELTA_MPT_KEY_PADDING.clone(),
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
        Self {
            state_root: StateRoot::genesis(genesis_root),
            aux_info: StateRootAuxInfo::genesis_state_root_aux_info(),
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
        s.begin_list(4)
            .append(&self.snapshot_epoch_id)
            .append(&self.intermediate_epoch_id)
            .append(
                &self
                    .maybe_intermediate_mpt_key_padding
                    .as_ref()
                    .map(|padding| &padding[..]),
            )
            .append(&&self.delta_mpt_key_padding[..]);
    }
}

impl Decodable for StateRootAuxInfo {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let mut maybe_intermediate_mpt_key_padding: Option<KeyPadding> =
            Default::default();
        {
            let rlp_parsed = rlp.val_at::<Option<Vec<u8>>>(2)?;
            if rlp_parsed.is_some() {
                if rlp_parsed.as_ref().unwrap().len() != KEY_PADDING_BYTES {
                    return Err(DecoderError::Custom(
                        "incorrect length for KeyPadding.",
                    ));
                }
                maybe_intermediate_mpt_key_padding.as_mut().unwrap()[..]
                    .copy_from_slice(&rlp_parsed.as_ref().unwrap());
            }
        }
        let mut delta_mpt_key_padding: KeyPadding = Default::default();
        {
            let rlp_parsed = rlp.val_at::<Vec<u8>>(3)?;
            if rlp_parsed.len() != KEY_PADDING_BYTES {
                return Err(DecoderError::Custom(
                    "incorrect length for KeyPadding.",
                ));
            }
            delta_mpt_key_padding[..].copy_from_slice(&rlp_parsed);
        }

        Ok(Self {
            snapshot_epoch_id: rlp.val_at(0)?,
            intermediate_epoch_id: rlp.val_at(1)?,
            maybe_intermediate_mpt_key_padding,
            delta_mpt_key_padding,
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

use super::storage_key::*;
use primitives::{EpochId, MerkleHash, StateRoot, NULL_EPOCH};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde_derive::{Deserialize, Serialize};
