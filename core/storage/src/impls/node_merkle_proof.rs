// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Clone, Debug, Default, PartialEq, RlpEncodable, RlpDecodable)]
pub struct NodeMerkleProof {
    pub delta_proof: Option<TrieProof>,
    pub intermediate_proof: Option<TrieProof>,
    pub snapshot_proof: Option<TrieProof>,
}

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

    #[cfg(test)]
    pub fn is_valid_triplet(
        &self, key: &Vec<u8>, triplet: NodeMerkleTriplet,
        state_root: StateRoot,
        maybe_intermediate_padding: Option<DeltaMptKeyPadding>,
    ) -> bool
    {
        self.is_valid(
            key,
            &StorageRoot::from_node_merkle_triplet(triplet),
            state_root,
            maybe_intermediate_padding,
        )
    }

    pub fn is_valid(
        &self, key: &Vec<u8>, storage_root: &Option<StorageRoot>,
        state_root: StateRoot,
        maybe_intermediate_padding: Option<DeltaMptKeyPadding>,
    ) -> bool
    {
        let delta_root = &state_root.delta_root;
        let intermediate_root = &state_root.intermediate_delta_root;
        let snapshot_root = &state_root.snapshot_root;

        // convert key as necessary
        let delta_mpt_padding =
            StorageKey::delta_mpt_padding(&snapshot_root, &intermediate_root);
        let storage_key = StorageKey::from_key_bytes(&key);
        let delta_mpt_key =
            storage_key.to_delta_mpt_key_bytes(&delta_mpt_padding);
        let maybe_intermediate_mpt_key = maybe_intermediate_padding
            .as_ref()
            .map(|p| storage_key.to_delta_mpt_key_bytes(p));

        match self.delta_proof {
            None => {
                // empty proof for non-empty trie is invalid
                if delta_root.ne(&MERKLE_NULL_NODE) {
                    return false;
                }

                // empty proof for non-empty storage root is invalid
                match storage_root {
                    Some(StorageRoot { delta, .. })
                        if delta.ne(&MERKLE_NULL_NODE) =>
                    {
                        return false
                    }
                    _ => {}
                }
            }

            Some(ref proof) => {
                let key = delta_mpt_key;
                let delta = storage_root
                    .as_ref()
                    .map(|r| r.delta)
                    .unwrap_or(MERKLE_NULL_NODE);

                if !proof.is_valid_node_merkle(&key, &delta, delta_root) {
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
                match storage_root {
                    Some(StorageRoot { intermediate, .. })
                        if intermediate.ne(&MERKLE_NULL_NODE) =>
                    {
                        return false
                    }
                    _ => {}
                }
            }

            Some(ref proof) => {
                let key = match maybe_intermediate_mpt_key {
                    None => return false,
                    Some(k) => k,
                };

                let intermediate = storage_root
                    .as_ref()
                    .map(|r| r.intermediate)
                    .unwrap_or(MERKLE_NULL_NODE);

                if !proof.is_valid_node_merkle(
                    &key,
                    &intermediate,
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
                match storage_root {
                    Some(StorageRoot { snapshot, .. })
                        if snapshot.ne(&MERKLE_NULL_NODE) =>
                    {
                        return false
                    }
                    _ => {}
                }
            }

            Some(ref proof) => {
                let snapshot = storage_root
                    .as_ref()
                    .map(|r| r.snapshot)
                    .unwrap_or(MERKLE_NULL_NODE);

                if !proof.is_valid_node_merkle(&key, &snapshot, snapshot_root) {
                    return false;
                }
            }
        }

        true
    }
}

use super::merkle_patricia_trie::TrieProof;
use primitives::{
    DeltaMptKeyPadding, StateRoot, StorageKey, StorageRoot, MERKLE_NULL_NODE,
};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[cfg(test)]
use primitives::NodeMerkleTriplet;
