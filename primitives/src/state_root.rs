// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{EpochId, NULL_EPOCH};
use crate::hash::{keccak, KECCAK_EMPTY};
use cfx_types::H256;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde_derive::{Deserialize, Serialize};

pub type MerkleHash = H256;

/// The Merkle Hash for an empty MPT (either as a subtree or as a whole tree).
pub const MERKLE_NULL_NODE: MerkleHash = KECCAK_EMPTY;

/// The deferred state root consists of 3 parts: snapshot, delta_0, delta.
/// when delta grows over threshold, snapshot and delta_0 is merged into new
/// snapshot, and the delta becomes new delta_0.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateRoot {
    pub snapshot_root: MerkleHash,
    pub intermediate_delta_root: MerkleHash,
    pub delta_root: MerkleHash,
}

impl Default for StateRoot {
    fn default() -> Self {
        Self {
            snapshot_root: MERKLE_NULL_NODE,
            intermediate_delta_root: MERKLE_NULL_NODE,
            delta_root: MERKLE_NULL_NODE,
        }
    }
}

impl StateRoot {
    pub fn compute_state_root_hash(&self) -> H256 {
        let mut rlp_stream = RlpStream::new_list(3);
        rlp_stream.append_list(self.snapshot_root.as_bytes());
        rlp_stream.append_list(self.intermediate_delta_root.as_bytes());
        rlp_stream.append_list(self.delta_root.as_bytes());
        keccak(rlp_stream.out())
    }

    pub fn genesis(genesis_root: &MerkleHash) -> StateRoot {
        Self {
            snapshot_root: MERKLE_NULL_NODE,
            intermediate_delta_root: MERKLE_NULL_NODE,
            delta_root: genesis_root.clone(),
        }
    }
}

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
}

impl Default for StateRootAuxInfo {
    /// The default value is for non-existence intermediate MPT.
    fn default() -> Self {
        Self {
            snapshot_epoch_id: NULL_EPOCH,
            intermediate_epoch_id: NULL_EPOCH,
        }
    }
}

// TODO: Consider remove this hack.
/// This struct is returned upon State commitments as a hack,
/// because we don't look up and construct StateRootAuxInfo from consensus,
/// instead, we store it for the block's children.
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateRootWithAuxInfo {
    pub state_root: StateRoot,
    pub aux_info: StateRootAuxInfo,
}

impl StateRootWithAuxInfo {
    pub fn genesis(genesis_root: &MerkleHash) -> Self {
        Self {
            state_root: StateRoot::genesis(genesis_root),
            aux_info: Default::default(),
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
            .append(&self.snapshot_epoch_id)
            .append(&self.intermediate_epoch_id);
    }
}

impl Decodable for StateRootAuxInfo {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Self {
            snapshot_epoch_id: rlp.val_at(0)?,
            intermediate_epoch_id: rlp.val_at(1)?,
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
