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

    pub fn is_valid_kv(
        &self, key: &Vec<u8>, value: Option<&[u8]>, root: StateRoot,
        maybe_intermediate_padding: Option<DeltaMptKeyPadding>,
    ) -> bool
    {
        let delta_root = &root.delta_root;
        let intermediate_root = &root.intermediate_delta_root;
        let snapshot_root = &root.snapshot_root;

        let delta_mpt_padding =
            StorageKey::delta_mpt_padding(&snapshot_root, &intermediate_root);

        let storage_key = match StorageKey::from_key_bytes::<CheckInput>(&key) {
            Ok(k) => k,
            Err(e) => {
                warn!("Checking proof with invalid key: {:?}", e);
                return false;
            }
        };

        let delta_mpt_key =
            storage_key.to_delta_mpt_key_bytes(&delta_mpt_padding);
        let maybe_intermediate_mpt_key = maybe_intermediate_padding
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

    pub fn get_value(
        &self, storage_key: StorageKey, state_root: &StateRoot,
        maybe_intermediate_padding: &Option<DeltaMptKeyPadding>,
    ) -> (bool, Option<&[u8]>)
    {
        let delta_root = &state_root.delta_root;
        let intermediate_root = &state_root.intermediate_delta_root;
        let snapshot_root = &state_root.snapshot_root;

        match self.delta_proof {
            None => {
                // empty proof for non-empty trie is invalid
                if delta_root.ne(&MERKLE_NULL_NODE) {
                    return (false, None);
                }
            }

            Some(ref proof) => {
                let padding = StorageKey::delta_mpt_padding(
                    &snapshot_root,
                    &intermediate_root,
                );

                let key = storage_key.to_delta_mpt_key_bytes(&padding);

                // check if delta proof is valid
                match proof.get_value(&key[..], delta_root) {
                    (false, _) => return (false, None),
                    (true, Some(x)) => return (true, Some(x)),
                    _ => {}
                }
            }
        }

        match self.intermediate_proof {
            None => {
                // empty proof for non-empty trie is invalid
                if intermediate_root.ne(&MERKLE_NULL_NODE) {
                    return (false, None);
                }
            }

            Some(ref proof) => {
                // convert storage key into delta mpt key
                let key = match maybe_intermediate_padding {
                    None => return (false, None),
                    Some(p) => storage_key.to_delta_mpt_key_bytes(&p),
                };

                // check if intermediate proof is valid
                match proof.get_value(&key[..], intermediate_root) {
                    (false, _) => return (false, None),
                    (true, Some(x)) => return (true, Some(x)),
                    _ => {}
                }
            }
        }

        match self.snapshot_proof {
            None => {
                // empty proof for non-empty trie is invalid
                if snapshot_root.ne(&MERKLE_NULL_NODE) {
                    return (false, None);
                }

                (true, None)
            }

            Some(ref proof) => {
                let key = storage_key.to_key_bytes();

                match proof.get_value(&key[..], snapshot_root) {
                    (false, _) => return (false, None),
                    (true, Some(x)) => return (true, Some(x)),
                    _ => return (true, None),
                }
            }
        }
    }

    pub fn get_all_kv_in_subtree(
        &self, storage_key_prefix: StorageKey, root: &StateRoot,
        maybe_intermediate_padding: &Option<DeltaMptKeyPadding>,
    ) -> (bool, Vec<MptKeyValue>)
    {
        let delta_root = &root.delta_root;
        let intermediate_root = &root.intermediate_delta_root;
        let snapshot_root = &root.snapshot_root;

        let delta_trie_kvs = match self.delta_proof {
            None => {
                // empty proof for non-empty trie is invalid
                if delta_root.ne(&MERKLE_NULL_NODE) {
                    return (false, vec![]);
                }

                None
            }

            Some(ref proof) => {
                let padding = StorageKey::delta_mpt_padding(
                    &snapshot_root,
                    &intermediate_root,
                );

                let key = storage_key_prefix.to_delta_mpt_key_bytes(&padding);

                match proof.get_all_kv_in_subtree(&key[..], &delta_root) {
                    (false, _) => return (false, vec![]),
                    (true, kvs) => Some(kvs),
                }
            }
        };

        let intermediate_trie_kvs = match self.intermediate_proof {
            None => {
                // empty proof for non-empty trie is invalid
                if intermediate_root.ne(&MERKLE_NULL_NODE) {
                    return (false, vec![]);
                }

                None
            }

            Some(ref proof) => {
                // convert storage key into delta mpt key
                let key = match maybe_intermediate_padding {
                    None => return (false, vec![]),
                    Some(p) => storage_key_prefix.to_delta_mpt_key_bytes(&p),
                };

                match proof.get_all_kv_in_subtree(&key[..], &intermediate_root)
                {
                    (false, _) => return (false, vec![]),
                    (true, kvs) => Some(kvs),
                }
            }
        };

        let snapshot_kvs = match self.snapshot_proof {
            None => {
                // empty proof for non-empty trie is invalid
                if snapshot_root.ne(&MERKLE_NULL_NODE) {
                    return (false, vec![]);
                }

                None
            }

            Some(ref proof) => {
                let key = storage_key_prefix.to_key_bytes();

                match proof.get_all_kv_in_subtree(&key[..], &snapshot_root) {
                    (false, _) => return (false, vec![]),
                    (true, kvs) => Some(kvs),
                }
            }
        };

        // collect visited keys
        let mut visited = std::collections::HashSet::new();
        let mut result = vec![];

        if let Some(kvs) = delta_trie_kvs {
            for (k, v) in kvs {
                if !visited.contains(&k) && v.len() > 0 {
                    let storage_key = StorageKey::from_delta_mpt_key(&k);
                    let k = storage_key.to_key_bytes();
                    visited.insert(k.clone());
                    result.push((k, v));
                }
            }
        }

        if let Some(kvs) = intermediate_trie_kvs {
            for (k, v) in kvs {
                if !visited.contains(&k) && v.len() > 0 {
                    let storage_key = StorageKey::from_delta_mpt_key(&k);
                    let k = storage_key.to_key_bytes();
                    visited.insert(k.clone());
                    result.push((k, v));
                }
            }
        }

        if let Some(kvs) = snapshot_kvs {
            for (k, v) in kvs {
                if !visited.contains(&k) && v.len() > 0 {
                    // visited.insert(k.clone());
                    result.push((k, v));
                }
            }
        }

        (true, result)
    }
}

use crate::impls::merkle_patricia_trie::{MptKeyValue, TrieProof};
use primitives::{
    CheckInput, DeltaMptKeyPadding, MptValue, StateRoot, StorageKey,
    MERKLE_NULL_NODE,
};
use rlp_derive::{RlpDecodable, RlpEncodable};
