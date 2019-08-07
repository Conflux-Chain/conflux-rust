// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use primitives::{MerkleHash, MERKLE_NULL_NODE};
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

use super::{
    merkle::compute_merkle,
    walk::{access_mode::Read, TrieNodeWalkTrait, WalkStop},
    TrieNodeTrait, VanillaTrieNode,
};
use rlp_derive::{RlpDecodable, RlpEncodable};

#[derive(Clone, Debug, Default, PartialEq, RlpDecodable, RlpEncodable)]
// FIXME: in rlp encode / decode, children_count should be omitted.
pub struct TrieProofNode(pub VanillaTrieNode<MerkleHash>);

impl TrieProofNode {
    pub fn is_valid(&self) -> bool {
        self.compute_merkle().eq(self.get_merkle())
    }

    // \w  path: keccak([mask, [path...], keccak(rlp([[children...]?, value]))])
    // \wo path: keccak(rlp([[children...]?, value]))
    pub fn compute_merkle(&self) -> MerkleHash {
        compute_merkle(
            self.compressed_path_ref(),
            self.get_children_merkle(),
            self.value_as_slice().into_option(),
        )
    }
}

impl Deref for TrieProofNode {
    type Target = VanillaTrieNode<MerkleHash>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for TrieProofNode {
    fn deref_mut(&mut self) -> &mut <Self as Deref>::Target { &mut self.0 }
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
            nodes.insert(node.get_merkle(), node);
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

                    match node.walk::<Read>(key) {
                        WalkStop::Arrived => {
                            return value
                                == node.value_as_slice().into_option();
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
    use super::{
        super::{CompressedPathRaw, VanillaTrieNode},
        TrieProof, TrieProofNode,
    };
    use primitives::MERKLE_NULL_NODE;

    #[test]
    fn test_rlp() {
        let node1 = TrieProofNode::default();
        assert_eq!(node1, rlp::decode(&rlp::encode(&node1)).unwrap());

        let node2 = {
            let mut node = TrieProofNode(VanillaTrieNode::new(
                MERKLE_NULL_NODE,
                Default::default(),
                Some(Box::new([0x03, 0x04, 0x05])),
                CompressedPathRaw::new(&[0x00, 0x01, 0x02], 0x0f),
            ));
            // Use .0 to avoid annoying rust compiler error: "cannot borrow
            // `node` as immutable because it is also borrowed as mutable"
            node.0.set_merkle(&node.compute_merkle());
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
            let mut node = TrieProofNode(VanillaTrieNode::new(
                MERKLE_NULL_NODE,
                Default::default(),
                Some(Box::new(value1)),
                (&[0x02u8][..]).into(),
            ));
            node.0.set_merkle(&node.compute_merkle());
            node
        };

        let leaf2 = {
            let mut node = TrieProofNode(VanillaTrieNode::new(
                MERKLE_NULL_NODE,
                Default::default(),
                Some(Box::new(value2)),
                (&[0x03u8][..]).into(),
            ));
            node.0.set_merkle(&node.compute_merkle());
            node
        };

        let ext = {
            let mut children = [MERKLE_NULL_NODE; 16];
            children[0x03] = leaf2.get_merkle().clone();

            let mut node = TrieProofNode(VanillaTrieNode::new(
                MERKLE_NULL_NODE,
                children.into(),
                None,
                (&[0x00u8, 0x00u8][..]).into(),
            ));
            node.0.set_merkle(&node.compute_merkle());

            node
        };

        let branch = {
            let mut children = [MERKLE_NULL_NODE; 16];
            children[0x00] = ext.compute_merkle();
            children[0x02] = leaf1.compute_merkle();

            let mut node = TrieProofNode(VanillaTrieNode::new(
                MERKLE_NULL_NODE,
                children.into(),
                None,
                Default::default(),
            ));
            node.0.set_merkle(&node.compute_merkle());

            node
        };

        // empty proof
        let proof = TrieProof::new(vec![]);
        assert!(proof.is_valid(&[0x00], None, MERKLE_NULL_NODE));
        assert!(!proof.is_valid(&[0x00], None, leaf1.compute_merkle()));
        assert!(!proof.is_valid(&key1, Some(&[0x00]), MERKLE_NULL_NODE));

        // valid proof
        let proof = TrieProof::new(vec![
            leaf1.clone(),
            leaf2.clone(),
            ext.clone(),
            branch.clone(),
        ]);

        let root = branch.compute_merkle();
        assert!(proof.is_valid(&key1, Some(&value1), root));
        assert!(proof.is_valid(&key2, Some(&value2), root));
        assert!(proof.is_valid(&[0x01], None, root));

        // wrong root
        assert!(!proof.is_valid(&key2, Some(&value2), leaf1.compute_merkle()));

        // missing node
        let proof = TrieProof::new(vec![ext.clone(), branch.clone()]);
        assert!(!proof.is_valid(&key2, Some(&value2), root));

        // wrong hash
        let mut leaf2_wrong = leaf2;
        let mut wrong_merkle = leaf2_wrong.get_merkle().clone();
        wrong_merkle[0] = 0x00;
        leaf2_wrong.set_merkle(&wrong_merkle);

        let proof = TrieProof::new(vec![leaf1, leaf2_wrong, ext, branch]);
        assert!(!proof.is_valid(&key2, Some(&value2), root));

        // wrong value
        assert!(!proof.is_valid(&key2, Some(&[0x00, 0x00, 0x04]), root));
    }
}
