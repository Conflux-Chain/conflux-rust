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

        // FIXME: if peer send proof with v1, v2, v3, where v2 and v3 are
        // FIXME: non-mandatory the code below falsely assume that v1
        // FIXME: and v2 must be non-existence proof.
        match (
            value,
            &self.delta_proof,
            &self.intermediate_proof,
            &self.snapshot_proof,
        ) {
            // proof of existence for key in delta trie
            (Some(_), Some(p1), None, None) => {
                p1.is_valid_kv(&delta_mpt_key, value, delta_root)
            }
            // proof of existence for key in intermediate trie
            (Some(_), Some(p1), Some(p2), None) => {
                p1.is_valid_kv(&delta_mpt_key, None, delta_root)
                    && p2.is_valid_kv(
                        maybe_intermediate_mpt_key.as_ref().unwrap(),
                        value,
                        intermediate_root,
                    )
            }
            // proof of existence for key in snapshot
            (Some(_), Some(p1), maybe_p2, Some(p3)) => {
                p1.is_valid_kv(&delta_mpt_key, None, delta_root)
                    && maybe_p2.as_ref().map_or(
                        intermediate_root.eq(&MERKLE_NULL_NODE),
                        |p2| {
                            p2.is_valid_kv(
                                maybe_intermediate_mpt_key.as_ref().unwrap(),
                                None,
                                intermediate_root,
                            )
                        },
                    )
                    && p3.is_valid_kv(key, value, snapshot_root)
            }
            // proof of non-existence with a single trie
            (None, Some(p1), None, None) => {
                p1.is_valid_kv(key, MptValue::TombStone.unwrap(), delta_root)
                    && intermediate_root.eq(&MERKLE_NULL_NODE)
                    && snapshot_root.eq(&MERKLE_NULL_NODE)
            }
            // proof of non-existence with two tries
            (None, Some(p1), Some(p2), None) => {
                p1.is_valid_kv(&delta_mpt_key, None, delta_root)
                    && p2.is_valid_kv(
                        maybe_intermediate_mpt_key.as_ref().unwrap(),
                        MptValue::TombStone.unwrap(),
                        intermediate_root,
                    )
                    && snapshot_root.eq(&MERKLE_NULL_NODE)
            }
            // proof of non-existence with all tries
            (None, Some(p1), maybe_p2, Some(p3)) => {
                p1.is_valid_kv(&delta_mpt_key, None, delta_root)
                    && maybe_p2.as_ref().map_or(
                        intermediate_root.eq(&MERKLE_NULL_NODE),
                        |p2| {
                            p2.is_valid_kv(
                                maybe_intermediate_mpt_key.as_ref().unwrap(),
                                None,
                                intermediate_root,
                            )
                        },
                    )
                    && p3.is_valid_kv(key, None, snapshot_root)
            }
            // no proofs available
            (_, None, None, None) => {
                value.is_none()
                    && delta_root.eq(&MERKLE_NULL_NODE)
                    && intermediate_root.eq(&MERKLE_NULL_NODE)
                    && snapshot_root.eq(&MERKLE_NULL_NODE)
            }
            _ => false,
        }
    }
}

use super::merkle_patricia_trie::TrieProof;
use crate::storage::impls::merkle_patricia_trie::MptValue;
use primitives::{DeltaMptKeyPadding, StateRoot, StorageKey, MERKLE_NULL_NODE};
use rlp_derive::{RlpDecodable, RlpEncodable};
