// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub use super::multi_version_merkle_patricia_trie::{
    merkle_patricia_trie::merkle::MaybeMerkleTableRef, TrieProof,
};
use primitives::{StateRoot, MERKLE_NULL_NODE};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug, Default, PartialEq, RlpEncodable, RlpDecodable)]
pub struct StateProof {
    pub delta_proof: Option<TrieProof>,
    pub intermediate_proof: Option<TrieProof>,
    pub snapshot_proof: Option<TrieProof>,
}

impl StateProof {
    pub fn with_delta(mut self, maybe_delta_proof: Option<TrieProof>) -> Self {
        self.delta_proof = maybe_delta_proof;
        self
    }

    pub fn with_intermediate(
        mut self, maybe_intermediate_proof: Option<TrieProof>,
    ) -> Self {
        self.intermediate_proof = maybe_intermediate_proof;
        self
    }

    pub fn is_valid_kv(
        &self, key: &Vec<u8>, value: Option<&[u8]>, root: StateRoot,
    ) -> bool {
        let delta_root = root.delta_root;
        let intermediate_root = root.intermediate_delta_root;
        let snapshot_root = root.snapshot_root;

        match (
            value,
            &self.delta_proof,
            &self.intermediate_proof,
            &self.snapshot_proof,
        ) {
            // proof of existence for key in delta trie
            (Some(_), Some(p1), None, None) => {
                p1.is_valid_kv(key, value, delta_root)
            }
            // proof of existence for key in intermediate trie
            (Some(_), Some(p1), Some(p2), None) => {
                p1.is_valid_kv(key, None, delta_root)
                    && p2.is_valid_kv(key, value, intermediate_root)
            }
            // proof of existence for key in snapshot
            (Some(_), Some(p1), Some(p2), Some(p3)) => {
                p1.is_valid_kv(key, None, delta_root)
                    && p2.is_valid_kv(key, None, intermediate_root)
                    && p3.is_valid_kv(key, value, snapshot_root)
            }
            // proof of non-existence with a single trie
            (None, Some(p1), None, None) => {
                p1.is_valid_kv(key, None, delta_root)
                    && intermediate_root == MERKLE_NULL_NODE
                    && snapshot_root == MERKLE_NULL_NODE
            }
            // proof of non-existence with two tries
            (None, Some(p1), Some(p2), None) => {
                p1.is_valid_kv(key, None, delta_root)
                    && p2.is_valid_kv(key, None, intermediate_root)
                    && snapshot_root == MERKLE_NULL_NODE
            }
            // proof of non-existence with all tries
            (None, Some(p1), Some(p2), Some(p3)) => {
                p1.is_valid_kv(key, None, delta_root)
                    && p2.is_valid_kv(key, None, intermediate_root)
                    && p3.is_valid_kv(key, None, snapshot_root)
            }
            // no proofs available
            (_, None, None, None) => {
                value.is_none()
                    && delta_root == MERKLE_NULL_NODE
                    && intermediate_root == MERKLE_NULL_NODE
                    && snapshot_root == MERKLE_NULL_NODE
            }
            _ => false,
        }
    }
}
