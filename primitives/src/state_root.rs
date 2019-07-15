// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::hash::keccak;

pub type MerkleHash = H256;

/// The deferred state root consists of 3 parts: snapshot, delta_0, delta.
/// when delta grows over threshold, snapshot and delta_0 is merged into new
/// snapshot, and the delta becomes new delta_0.
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateRoot {
    pub snapshot_root: MerkleHash,
    pub intermediate_delta_root: MerkleHash,
    pub delta_root: MerkleHash,
}

impl StateRoot {
    pub fn compute_state_root_hash(&self) -> H256 {
        let mut rlp_stream = RlpStream::new_list(3);
        rlp_stream.append_list(&self.snapshot_root);
        rlp_stream.append_list(&self.intermediate_delta_root);
        rlp_stream.append_list(&self.delta_root);
        keccak(rlp_stream.out())
    }
}

/// The Merkle Hash for an empty MPT (either as a subtree or as a whole tree).
pub const MERKLE_NULL_NODE: MerkleHash = KECCAK_EMPTY;

/// Auxiliary information for deferred state root: previous snapshot root
/// and intermediate_delta_epoch_id to help looking up for the intermediate
/// delta tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateRootAuxInfo {
    pub previous_snapshot_root: MerkleHash,
    pub intermediate_delta_epoch_id: EpochId,
}

impl Default for StateRootAuxInfo {
    /// The default value is for non-existence intermediate MPT.
    fn default() -> Self {
        Self {
            previous_snapshot_root: MERKLE_NULL_NODE,
            intermediate_delta_epoch_id: KECCAK_EMPTY,
        }
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateRootWithAuxInfo {
    pub state_root: StateRoot,
    pub aux_info: StateRootAuxInfo,
}

impl From<(&StateRoot, &StateRootAuxInfo)> for StateRootWithAuxInfo {
    fn from(x: (&StateRoot, &StateRootAuxInfo)) -> Self {
        Self {
            state_root: x.0.clone(),
            aux_info: x.1.clone(),
        }
    }
}

impl Encodable for StateRoot {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3)
            .append(&self.snapshot_root)
            .append(&self.intermediate_delta_root)
            .append(&self.delta_root);
    }
}

impl Decodable for StateRoot {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            snapshot_root: rlp.val_at(0)?,
            intermediate_delta_root: rlp.val_at(1)?,
            delta_root: rlp.val_at(2)?,
        })
    }
}

impl Encodable for StateRootAuxInfo {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append(&self.previous_snapshot_root)
            .append(&self.intermediate_delta_epoch_id);
    }
}

impl Decodable for StateRootAuxInfo {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            previous_snapshot_root: rlp.val_at(0)?,
            intermediate_delta_epoch_id: rlp.val_at(1)?,
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

use super::EpochId;
use crate::hash::KECCAK_EMPTY;
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde_derive::{Deserialize, Serialize};
