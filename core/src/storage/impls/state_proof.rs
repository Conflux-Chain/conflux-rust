// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// FIXME: What's the proper way to express: 1) Proof not available;
// FIXME: 2) What if Intermediate Delta Root is MERKLE_NULL_NODE.
// TODO: Maybe create a new class for special situation when
// TODO: a full node does not have full state proof, but it
// TODO: could provide a shortcut proof with snapshot_proof
// TODO: at intermediate_epoch_id with delta_proof.
#[derive(Clone, Debug, Default, PartialEq, RlpEncodable, RlpDecodable)]
pub struct StateProof {
    // TODO(thegaram): get rid of maybe_intermediate_padding
    pub maybe_intermediate_padding: Option<DeltaMptKeyPadding>,
    pub delta_proof: Option<TrieProof>,
    pub intermediate_proof: Option<TrieProof>,
    pub snapshot_proof: Option<TrieProof>,
}

impl StateProof {
    pub fn with_delta(
        &mut self, maybe_delta_proof: Option<TrieProof>,
    ) -> &mut Self {
        self.delta_proof = maybe_delta_proof;
        self
    }

    pub fn with_intermediate(
        &mut self, maybe_intermediate_proof: Option<TrieProof>,
        maybe_intermediate_padding: Option<DeltaMptKeyPadding>,
    ) -> &mut Self
    {
        self.intermediate_proof = maybe_intermediate_proof;
        self.maybe_intermediate_padding = maybe_intermediate_padding;
        self
    }

    pub fn with_snapshot(
        &mut self, maybe_snapshot_proof: Option<TrieProof>,
    ) -> &mut Self {
        self.snapshot_proof = maybe_snapshot_proof;
        self
    }

    pub fn is_valid_kv(
        &self, key: &Vec<u8>, value: Option<&[u8]>, root: StateRoot,
    ) -> bool {
        let delta_root = &root.delta_root;
        let intermediate_root = &root.intermediate_delta_root;
        let snapshot_root = &root.snapshot_root;

        let delta_mpt_padding =
            StorageKey::delta_mpt_padding(&snapshot_root, &intermediate_root);
        let storage_key = StorageKey::from_key_bytes(&key);
        let delta_mpt_key =
            storage_key.to_delta_mpt_key_bytes(&delta_mpt_padding);
        let maybe_intermediate_mpt_key = self
            .maybe_intermediate_padding
            .as_ref()
            .map(|p| storage_key.to_delta_mpt_key_bytes(p));

        let tombstone_value = MptValue::<Box<[u8]>>::TombStone.unwrap();
        let delta_value = if value.is_some() {
            // Actual value.
            value.clone()
        } else {
            // Tombstone value.
            Some(&*tombstone_value)
        };

        // The delta proof must prove the key-value or key non-existence.
        match &self.delta_proof {
            Some(proof) => {
                // Existence proof.
                if proof.is_valid_kv(&delta_mpt_key, delta_value, delta_root) {
                    return true;
                }
                // Non-existence proof.
                if !proof.is_valid_kv(&delta_mpt_key, None, delta_root) {
                    return false;
                }
            }
            None => {
                // When delta trie exists, the proof can't be empty.
                if delta_root.ne(&MERKLE_NULL_NODE) {
                    return false;
                }
            }
        }

        // Now check intermediate_proof since it's required. Same logic applies.
        match &self.intermediate_proof {
            Some(proof) => {
                if maybe_intermediate_mpt_key.is_none() {
                    return false;
                }
                if proof.is_valid_kv(
                    maybe_intermediate_mpt_key.as_ref().unwrap(),
                    delta_value,
                    intermediate_root,
                ) {
                    return true;
                }
                if !proof.is_valid_kv(
                    maybe_intermediate_mpt_key.as_ref().unwrap(),
                    None,
                    intermediate_root,
                ) {
                    return false;
                }
            }
            None => {
                // When intermediate trie exists, the proof can't be empty.
                if intermediate_root.ne(&MERKLE_NULL_NODE) {
                    return false;
                }
            }
        }

        // At last, check snapshot
        match &self.snapshot_proof {
            None => false,
            Some(proof) => proof.is_valid_kv(key, value, snapshot_root),
        }
    }
}

use super::merkle_patricia_trie::TrieProof;
use crate::storage::impls::merkle_patricia_trie::MptValue;
use primitives::{DeltaMptKeyPadding, StateRoot, StorageKey, MERKLE_NULL_NODE};
use rlp_derive::{RlpDecodable, RlpEncodable};
