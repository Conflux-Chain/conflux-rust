// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub use super::multi_version_merkle_patricia_trie::TrieProof;
use crate::hash::KECCAK_EMPTY;
use primitives::MerkleHash;

#[derive(Clone, Debug)]
pub struct StateProof {
    pub delta_proof: Option<TrieProof>,
    pub intermediate_proof: Option<TrieProof>,
    pub snapshot_proof: Option<TrieProof>,
}

impl StateProof {
    pub fn for_delta(delta_proof: TrieProof) -> Self {
        StateProof {
            delta_proof: Some(delta_proof),
            intermediate_proof: None,
            snapshot_proof: None,
        }
    }

    pub fn for_intermediate(
        delta_proof: TrieProof, intermediate_proof: TrieProof,
    ) -> Self {
        StateProof {
            delta_proof: Some(delta_proof),
            intermediate_proof: Some(intermediate_proof),
            snapshot_proof: None,
        }
    }

    pub fn is_valid(
        &self, key: &[u8], value: Option<&[u8]>, delta_root: MerkleHash,
        intermediate_root: MerkleHash, snapshot_root: MerkleHash,
    ) -> bool
    {
        match (
            value,
            &self.delta_proof,
            &self.intermediate_proof,
            &self.snapshot_proof,
        ) {
            // proof of existence for key in delta trie
            (Some(_), Some(p1), None, None) => {
                p1.is_valid(key, value, delta_root)
            }
            // proof of existence for key in intermediate trie
            (Some(_), Some(p1), Some(p2), None) => {
                p1.is_valid(key, None, delta_root)
                    && p2.is_valid(key, value, intermediate_root)
            }
            // proof of existence for key in snapshot
            (Some(_), Some(p1), Some(p2), Some(p3)) => {
                p1.is_valid(key, None, delta_root)
                    && p2.is_valid(key, None, intermediate_root)
                    && p3.is_valid(key, value, snapshot_root)
            }
            // proof of non-existence with a single trie
            (None, Some(p1), None, None) => {
                p1.is_valid(key, None, delta_root)
                    && intermediate_root == KECCAK_EMPTY
                    && snapshot_root == KECCAK_EMPTY
            }
            // proof of non-existence with two tries
            (None, Some(p1), Some(p2), None) => {
                p1.is_valid(key, None, delta_root)
                    && p2.is_valid(key, None, intermediate_root)
                    && snapshot_root == KECCAK_EMPTY
            }
            // proof of non-existence with all tries
            (None, Some(p1), Some(p2), Some(p3)) => {
                p1.is_valid(key, None, delta_root)
                    && p2.is_valid(key, None, intermediate_root)
                    && p3.is_valid(key, None, snapshot_root)
            }
            // no proofs available
            (_, None, None, None) => {
                value.is_none()
                    && delta_root == KECCAK_EMPTY
                    && intermediate_root == KECCAK_EMPTY
                    && snapshot_root == KECCAK_EMPTY
            }
            _ => false,
        }
    }
}
