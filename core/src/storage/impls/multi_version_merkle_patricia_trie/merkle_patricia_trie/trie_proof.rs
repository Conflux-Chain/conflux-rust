// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::hash::KECCAK_EMPTY;
use primitives::MerkleHash;
use std::collections::HashMap;

use super::{
    children_table::CHILDREN_COUNT,
    compressed_path::CompressedPathRef,
    merkle::compute_merkle,
    walk::{access_mode::Read, walk, KeyPart, WalkStop},
};

#[derive(Clone, Debug, Default)]
pub struct TrieProofNode {
    // fields necessary for traversal & hashing
    pub path_end_mask: u8,
    pub path: Box<[u8]>,
    pub value: Option<Box<[u8]>>,
    pub children_table: Option<[MerkleHash; CHILDREN_COUNT]>,
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
        compute_merkle(
            self.compressed_path_ref(),
            self.children_table.as_ref().map(|x| &*x),
            self.value.as_ref().map(|x| &**x),
        )
    }
}

impl TrieProofNode {
    pub fn walk<'key>(&self, key: KeyPart<'key>) -> WalkStop<'key, MerkleHash> {
        walk::<Read, MerkleHash>(
            key,
            self.compressed_path_ref(),
            self.path_end_mask,
            &|index| {
                self.children_table
                    .map(|table| table[index as usize])
                    .and_then(|child| {
                        if child == KECCAK_EMPTY {
                            return None;
                        }
                        return Some(child);
                    })
            },
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct TrieProof {
    pub nodes: Vec<TrieProofNode>,
}

impl TrieProof {
    pub fn new(nodes: Vec<TrieProofNode>) -> Self { TrieProof { nodes } }

    pub fn is_valid(
        &self, key: &[u8], value: Option<&[u8]>, root: MerkleHash,
    ) -> bool {
        // empty proof
        if self.nodes.is_empty() {
            return value == None && root == KECCAK_EMPTY;
        }

        // store (hash -> node) mapping
        let mut nodes = HashMap::new();
        for node in &self.nodes {
            nodes.insert(node.merkle_hash, node);
        }

        let mut key = key;
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
                            return value == node.value.as_ref().map(|x| &**x);
                        }
                        WalkStop::PathDiverted { .. } => {
                            return value == None;
                        }
                        WalkStop::ChildNotFound { .. } => {
                            return value == None;
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
    fn test_proofs() {
        //       ------|path: []|-----
        //      |                     |
        //      |              |path: [0x00, 0x00]|
        //      |                     |
        // |path: [0x02]|   |path: [0x03]            |
        // |val : [0x02]|   |val : [0x00, 0x00, 0x03]|

        let (key1, value1) = ([0x02], [0x02]);
        let (key2, value2) = ([0x00, 0x00, 0x03], [0x00, 0x00, 0x03]);

        let leaf1 = {
            let mut node = TrieProofNode::default();
            node.path = Box::new([0x02]);
            node.value = Some(Box::new(value1.clone()));
            node.merkle_hash = node.merkle();
            node
        };

        let leaf2 = {
            let mut node = TrieProofNode::default();
            node.path = Box::new([0x03]);
            node.value = Some(Box::new(value2.clone()));
            node.merkle_hash = node.merkle();
            node
        };

        let ext = {
            let mut children = [KECCAK_EMPTY; 16];
            children[0x03] = leaf2.merkle();

            let mut node = TrieProofNode::default();
            node.path = Box::new([0x00, 0x00]);
            node.children_table = Some(children);
            node.merkle_hash = node.merkle();
            node
        };

        let branch = {
            let mut children = [KECCAK_EMPTY; 16];
            children[0x00] = ext.merkle();
            children[0x02] = leaf1.merkle();

            let mut node = TrieProofNode::default();
            node.path = Box::new([]);
            node.children_table = Some(children);
            node.merkle_hash = node.merkle();
            node
        };

        // empty proof
        let proof = TrieProof::new(vec![]);
        assert!(proof.is_valid(&[0x00], None, KECCAK_EMPTY));
        assert!(!proof.is_valid(&[0x00], None, leaf1.merkle()));
        assert!(!proof.is_valid(&key1, Some(&[0x00]), KECCAK_EMPTY));

        // valid proof
        let proof = TrieProof::new(vec![
            leaf1.clone(),
            leaf2.clone(),
            ext.clone(),
            branch.clone(),
        ]);

        let root = branch.merkle();
        assert!(proof.is_valid(&key1, Some(&value1), root));
        assert!(proof.is_valid(&key2, Some(&value2), root));
        assert!(proof.is_valid(&[0x01], None, root));

        // wrong root
        assert!(!proof.is_valid(&key2, Some(&value2), leaf1.merkle()));

        // missing node
        let proof = TrieProof::new(vec![ext.clone(), branch.clone()]);
        assert!(!proof.is_valid(&key2, Some(&value2), root));

        // wrong hash
        let mut leaf2_wrong = leaf2;
        leaf2_wrong.merkle_hash[0] = 0x00;

        let proof = TrieProof::new(vec![leaf1, leaf2_wrong, ext, branch]);
        assert!(!proof.is_valid(&key2, Some(&value2), root));

        // wrong value
        assert!(!proof.is_valid(&key2, Some(&[0x00, 0x00, 0x04]), root));
    }
}
