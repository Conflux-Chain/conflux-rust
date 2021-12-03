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
        let mut buffer: [u8; 96] = [0; 96];
        buffer[0..32].copy_from_slice(self.snapshot_root.as_bytes());
        buffer[32..64].copy_from_slice(self.intermediate_delta_root.as_bytes());
        buffer[64..96].copy_from_slice(self.delta_root.as_bytes());
        keccak(&buffer[..])
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

use crate::key_value::MERKLE_NULL_NODE;
use cfx_primitives::MerkleHash;
use cfx_types::H256;
use keccak_hash::keccak;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde_derive::{Deserialize, Serialize};
