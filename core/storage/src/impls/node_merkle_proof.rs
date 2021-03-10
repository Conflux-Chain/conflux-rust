// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Clone, Debug, Default, PartialEq, RlpEncodable, RlpDecodable)]
pub struct NodeMerkleProof {
    pub delta_proof: Option<TrieProof>,
    pub intermediate_proof: Option<TrieProof>,
    pub snapshot_proof: Option<TrieProof>,
}

pub type StorageRootProof = NodeMerkleProof;

impl NodeMerkleProof {
    pub fn with_delta(
        &mut self, maybe_delta_proof: Option<TrieProof>,
    ) -> &mut Self {
        self.delta_proof = maybe_delta_proof;
        self
    }

    pub fn with_intermediate(
        &mut self, maybe_intermediate_proof: Option<TrieProof>,
    ) -> &mut Self {
        self.intermediate_proof = maybe_intermediate_proof;
        self
    }

    pub fn with_snapshot(
        &mut self, maybe_snapshot_proof: Option<TrieProof>,
    ) -> &mut Self {
        self.snapshot_proof = maybe_snapshot_proof;
        self
    }

    pub fn is_valid(
        &self, key: &Vec<u8>, storage_root: &StorageRoot,
        state_root: StateRoot,
        maybe_intermediate_padding: Option<DeltaMptKeyPadding>,
    ) -> bool {
        let delta_root = &state_root.delta_root;
        let intermediate_root = &state_root.intermediate_delta_root;
        let snapshot_root = &state_root.snapshot_root;

        let storage_key = match StorageKey::from_key_bytes::<CheckInput>(&key) {
            Ok(k) => k,
            Err(e) => {
                warn!("Checking proof with invalid key: {:?}", e);
                return false;
            }
        };

        match self.delta_proof {
            None => {
                // empty proof for non-empty trie is invalid
                if delta_root.ne(&MERKLE_NULL_NODE) {
                    return false;
                }

                // empty proof for non-empty storage root is invalid
                if storage_root.delta != MptValue::None {
                    return false;
                }
            }

            Some(ref proof) => {
                // convert storage key into delta mpt key
                let padding = StorageKey::delta_mpt_padding(
                    &snapshot_root,
                    &intermediate_root,
                );

                let key = storage_key.to_delta_mpt_key_bytes(&padding);

                // check if delta proof is valid
                if !proof.is_valid_node_merkle(
                    &key,
                    &storage_root.delta,
                    delta_root,
                ) {
                    return false;
                }
            }
        }

        match self.intermediate_proof {
            None => {
                // empty proof for non-empty trie is invalid
                if intermediate_root.ne(&MERKLE_NULL_NODE) {
                    return false;
                }

                // empty proof for non-empty storage root is invalid
                if storage_root.intermediate != MptValue::None {
                    return false;
                }
            }

            Some(ref proof) => {
                // convert storage key into delta mpt key
                let key = match maybe_intermediate_padding {
                    None => return false,
                    Some(p) => storage_key.to_delta_mpt_key_bytes(&p),
                };

                // check if intermediate proof is valid
                if !proof.is_valid_node_merkle(
                    &key,
                    &storage_root.intermediate,
                    intermediate_root,
                ) {
                    return false;
                }
            }
        }

        match self.snapshot_proof {
            None => {
                // empty proof for non-empty trie is invalid
                if snapshot_root.ne(&MERKLE_NULL_NODE) {
                    return false;
                }

                // empty proof for non-empty storage root is invalid
                if storage_root.snapshot != None {
                    return false;
                }
            }

            Some(ref proof) => {
                // check if snapshot proof is valid
                if !proof.is_valid_node_merkle(
                    &key,
                    &storage_root.snapshot.into(),
                    snapshot_root,
                ) {
                    return false;
                }
            }
        }

        true
    }
}

use super::merkle_patricia_trie::TrieProof;
use primitives::{
    CheckInput, DeltaMptKeyPadding, MptValue, StateRoot, StorageKey,
    StorageRoot, MERKLE_NULL_NODE,
};
use rlp_derive::{RlpDecodable, RlpEncodable};
