// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

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
    // FIXME: Add a field here for intermediate MPT KeyPadding or validate it
    // FIXME: from snapshot_root? The intermediate MPT KeyPadding is necessary
    // FIXME: for light proof.
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
