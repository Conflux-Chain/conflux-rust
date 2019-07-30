// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use rlp_derive::{RlpDecodable, RlpEncodable};
use std::{collections::HashMap, convert::TryInto};

use crate::hash::KECCAK_EMPTY;
use primitives::MerkleHash;

use super::{
    children_table::CHILDREN_COUNT,
    compressed_path::CompressedPathRef,
    merkle::compute_merkle,
    walk::{access_mode::Read, walk, KeyPart, WalkStop},
};

#[derive(Clone, Debug, Default, PartialEq, RlpEncodable, RlpDecodable)]
pub struct TrieProofNode {
    // fields necessary for traversal & hashing
    pub path_end_mask: u8,
    pub path: Vec<u8>,
    pub value: Vec<u8>,
    pub children_table: Vec<MerkleHash>,
    pub merkle_hash: MerkleHash,
}

impl TrieProofNode {
    pub fn is_valid(&self) -> bool { self.merkle_hash == self.merkle() }

    fn compressed_path_ref(&self) -> CompressedPathRef {
        CompressedPathRef {
            path_slice: &self.path,
            end_mask: self.path_end_mask,
        }
    }

    // \w  path: keccak([mask, [path...], keccak(rlp([[children...]?, value]))])
    // \wo path: keccak(rlp([[children...]?, value]))
    pub fn merkle(&self) -> MerkleHash {
        // convert `children_table` to `Option<&[MerkleHash; CHILDREN_COUNT]>`
        let children_table = match &self.children_table {
            v if v == &vec![] => None,
            v => v[..].try_into().ok(),
        };

        // convert `value` to `Option<&[u8]>`
        let value = match &self.value {
            v if v == &Vec::<u8>::new() => None,
            v => v[..].try_into().ok(),
        };

        // NOTE: conversion to option is necessary for
        // computing the correct merkle hash

        compute_merkle(self.compressed_path_ref(), children_table, value)
    }
}

impl TrieProofNode {
    fn get_child(&self, index: u8) -> Option<MerkleHash> {
        match self.children_table.len() {
            0 => None,
            CHILDREN_COUNT => match self.children_table[index as usize] {
                h if h == KECCAK_EMPTY => None,
                h => Some(h),
            },
            len @ _ => {
                error!("Invalid TrieProofNode child count: {}", len);
                None
            }
        }
    }

    pub fn walk<'key>(&self, key: KeyPart<'key>) -> WalkStop<'key, MerkleHash> {
        walk::<Read, MerkleHash>(
            key,
            self.compressed_path_ref(),
            self.path_end_mask,
            &|index| self.get_child(index),
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, RlpEncodable, RlpDecodable)]
pub struct TrieProof {
    pub nodes: Vec<TrieProofNode>,
}

impl TrieProof {
    pub fn new(nodes: Vec<TrieProofNode>) -> Self { TrieProof { nodes } }

    pub fn is_valid(
        &self, key: &Vec<u8>, value: &Option<Vec<u8>>, root: MerkleHash,
    ) -> bool {
        // empty proof
        if self.nodes.is_empty() {
            return value == &None && root == KECCAK_EMPTY;
        }

        // store (hash -> node) mapping
        let mut nodes = HashMap::new();
        for node in &self.nodes {
            nodes.insert(node.merkle_hash, node);
        }

        let value = value.clone().unwrap_or_default();
        let mut key = &key[..];
        let mut hash = root;

        loop {
            match nodes.get(&hash) {
                // proof has missing node
                None => {
                    debug_assert!(hash != KECCAK_EMPTY); // this should lead to `ChildNotFound`
                    return false;
                }
                Some(node) => {
                    // node hash does not match its contents
                    if !node.is_valid() {
                        return false;
                    }

                    match node.walk(key) {
                        WalkStop::Arrived => {
                            return value == node.value;
                        }
                        WalkStop::PathDiverted { .. } => {
                            return value == Vec::<u8>::new();
                        }
                        WalkStop::ChildNotFound { .. } => {
                            return value == Vec::<u8>::new();
                        }
                        WalkStop::Descent {
                            key_remaining,
                            child_node,
                            ..
                        } => {
                            hash = child_node;
                            key = key_remaining;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TrieProof, TrieProofNode};
    use crate::hash::KECCAK_EMPTY;

    #[test]
    fn test_rlp() {
        let node1 = TrieProofNode::default();
        assert_eq!(node1, rlp::decode(&rlp::encode(&node1)).unwrap());

        let node2 = {
            let mut node = TrieProofNode::default();
            node.path_end_mask = 0x0f;
            node.path = vec![0x00, 0x01, 0x02];
            node.value = vec![0x03, 0x04, 0x05];
            node.children_table = [KECCAK_EMPTY; 16].to_vec();
            node.merkle_hash = node.merkle();
            node
        };

        assert_eq!(node2, rlp::decode(&rlp::encode(&node2)).unwrap());

        let proof = TrieProof::default();
        assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());

        let nodes = [node1, node2].iter().cloned().cycle().take(20).collect();
        let proof = TrieProof::new(nodes);
        assert_eq!(proof, rlp::decode(&rlp::encode(&proof)).unwrap());
    }

    #[test]
    fn test_proofs() {
        //       ------|path: []|-----
        //      |                     |
        //      |              |path: [0x00, 0x00]|
        //      |                     |
        // |path: [0x02]|   |path: [0x03]            |
        // |val : [0x02]|   |val : [0x00, 0x00, 0x03]|

        let (key1, value1) = (vec![0x02], vec![0x02]);
        let (key2, value2) = (vec![0x00, 0x00, 0x03], vec![0x00, 0x00, 0x03]);

        let leaf1 = {
            let mut node = TrieProofNode::default();
            node.path = vec![0x02];
            node.value = value1.clone();
            node.merkle_hash = node.merkle();
            node
        };

        let leaf2 = {
            let mut node = TrieProofNode::default();
            node.path = vec![0x03];
            node.value = value2.clone();
            node.merkle_hash = node.merkle();
            node
        };

        let ext = {
            let mut children = [KECCAK_EMPTY; 16].to_vec();
            children[0x03] = leaf2.merkle();

            let mut node = TrieProofNode::default();
            node.path = vec![0x00, 0x00];
            node.children_table = children;
            node.merkle_hash = node.merkle();
            node
        };

        let branch = {
            let mut children = [KECCAK_EMPTY; 16].to_vec();
            children[0x00] = ext.merkle();
            children[0x02] = leaf1.merkle();

            let mut node = TrieProofNode::default();
            node.path = vec![];
            node.children_table = children;
            node.merkle_hash = node.merkle();
            node
        };

        // empty proof
        let proof = TrieProof::new(vec![]);
        assert!(proof.is_valid(&vec![0x00], &None, KECCAK_EMPTY));
        assert!(!proof.is_valid(&vec![0x00], &None, leaf1.merkle()));
        assert!(!proof.is_valid(&key1, &Some(vec![0x00]), KECCAK_EMPTY));

        // valid proof
        let proof = TrieProof::new(vec![
            leaf1.clone(),
            leaf2.clone(),
            ext.clone(),
            branch.clone(),
        ]);

        let root = branch.merkle();
        assert!(proof.is_valid(&key1, &Some(value1.clone()), root));
        assert!(proof.is_valid(&key2, &Some(value2.clone()), root));
        assert!(proof.is_valid(&vec![0x01], &None, root));

        // wrong root
        assert!(!proof.is_valid(&key2, &Some(value2.clone()), leaf1.merkle()));

        // missing node
        let proof = TrieProof::new(vec![ext.clone(), branch.clone()]);
        assert!(!proof.is_valid(&key2, &Some(value2.clone()), root));

        // wrong hash
        let mut leaf2_wrong = leaf2;
        leaf2_wrong.merkle_hash[0] = 0x00;

        let proof = TrieProof::new(vec![leaf1, leaf2_wrong, ext, branch]);
        assert!(!proof.is_valid(&key2, &Some(value2), root));

        // wrong value
        assert!(!proof.is_valid(&key2, &Some(vec![0x00, 0x00, 0x04]), root));
    }
}
