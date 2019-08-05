// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use primitives::{MerkleHash, MERKLE_NULL_NODE};
use std::collections::HashMap;

use super::{
    merkle::compute_merkle,
    walk::{access_mode::Read, walk, GetChildTrait, KeyPart, WalkStop},
    TrieNodeTrait, VanillaTrieNode,
};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug, Default, PartialEq, RlpDecodable, RlpEncodable)]
// FIXME: in rlp encode / decode, children_count should be omitted.
pub struct TrieProofNode(pub VanillaTrieNode<MerkleHash>);

impl TrieProofNode {
    pub fn is_valid(&self) -> bool { self.merkle().eq(self.0.get_merkle()) }

    // \w  path: keccak([mask, [path...], keccak(rlp([[children...]?, value]))])
    // \wo path: keccak(rlp([[children...]?, value]))
    pub fn merkle(&self) -> MerkleHash {
        compute_merkle(
            self.0.compressed_path_ref(),
            self.0.get_children_merkle(),
            self.0.value_as_slice().into_option(),
        )
    }
}

impl TrieProofNode {
    pub fn walk<'key, 'node>(
        &'node self, key: KeyPart<'key>,
    ) -> WalkStop<'key, &'node MerkleHash> {
        walk::<Read, _>(key, &self.0.compressed_path_ref(), self)
    }
}

impl<'node> GetChildTrait<'node> for TrieProofNode {
    type ChildIdType = &'node MerkleHash;

    fn get_child(&'node self, child_index: u8) -> Option<&'node MerkleHash> {
        self.0.get_child(child_index)
    }
}

#[derive(Clone, Debug, Default, PartialEq, RlpEncodable, RlpDecodable)]
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
            return value == None && root == MERKLE_NULL_NODE;
        }

        // store (hash -> node) mapping
        let mut nodes = HashMap::new();
        for node in &self.nodes {
            nodes.insert(node.0.get_merkle(), node);
        }

        let mut key = key;
        let mut hash = &root;

        loop {
            match nodes.get(hash) {
                // proof has missing node
                None => {
                    debug_assert!(!hash.eq(&MERKLE_NULL_NODE)); // this should lead to `ChildNotFound`
                    return false;
                }
                Some(node) => {
                    // node hash does not match its contents
                    if !node.is_valid() {
                        return false;
                    }

                    match node.walk(key) {
                        WalkStop::Arrived => {
                            return value
                                == node.0.value_as_slice().into_option();
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

    #[test]
    fn test_rlp() {
        let node1 = TrieProofNode::default();
        assert_eq!(node1, rlp::decode(&rlp::encode(&node1)).unwrap());

        let node2 = {
            let mut node = TrieProofNode::default();
            node.path_end_mask = 0x0f;
            node.path = vec![0x00, 0x01, 0x02];
            node.value = Some(vec![0x03, 0x04, 0x05]);
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
            let mut children = [MERKLE_NULL_NODE; 16];
            children[0x03] = leaf2.merkle();

            let mut node = TrieProofNode::default();
            node.path = Box::new([0x00, 0x00]);
            node.children_table = Some(children);
            node.merkle_hash = node.merkle();
            node
        };

        let branch = {
            let mut children = [MERKLE_NULL_NODE; 16];
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
        assert!(proof.is_valid(&[0x00], None, MERKLE_NULL_NODE));
        assert!(!proof.is_valid(&[0x00], None, leaf1.merkle()));
        assert!(!proof.is_valid(&key1, Some(&[0x00]), MERKLE_NULL_NODE));

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
