// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
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

    /// Verify that the trie `root` has `value` under `key`.
    /// Use `None` for exclusion proofs (i.e. there is no value under `key`).
    // NOTE: This API cannot be used to prove that there is a value under `key`
    // but it does not equal a given value. We add this later on if it's needed.
    pub fn is_valid_kv(
        &self, key: &[u8], value: Option<&[u8]>, root: MerkleHash,
    ) -> bool {
        self.is_valid(key, &root, |node| match node {
            None => value == None,
            Some(node) => value == node.value_as_slice().into_option(),
        })
    }

    /// Verify that the trie `root` has a node with `hash` under `path`.
    /// Use `MERKLE_NULL_NODE` for exclusion proofs (i.e. `path` does not exist
    /// or leads to another hash).
    pub fn is_valid_path_to(
        &self, path: &[u8], hash: MerkleHash, root: MerkleHash,
    ) -> bool {
        self.is_valid(path, &root, |node| match node {
            None => hash == MERKLE_NULL_NODE,
            Some(node) => hash == *node.get_merkle(),
        })
    }

    /// Verify that the trie `root` has a node under `key`.
    pub fn is_valid_key(&self, key: &[u8], root: &MerkleHash) -> bool {
        self.is_valid(key, root, |node| node.is_some())
    }

    fn is_valid(
        &self, path: &[u8], root: &MerkleHash,
        pred: impl FnOnce(Option<&TrieProofNode>) -> bool,
    ) -> bool
    {
        // empty trie
        if root == &MERKLE_NULL_NODE {
            return pred(None);
        }

        // NOTE: an empty proof is only valid if it is an
        // exclusion proof for an empty trie, covered above

        // store (hash -> node) mapping
        let nodes = self
            .nodes
            .iter()
            .map(|node| (node.get_merkle(), node))
            .collect::<HashMap<&H256, &TrieProofNode>>();

        // traverse the trie along `path`
        let mut key = path;
        let mut hash = root;

        loop {
            let node = match nodes.get(hash) {
                Some(node) => node,
                None => {
                    // missing node
                    debug_assert!(!hash.eq(&MERKLE_NULL_NODE)); // this should lead to `ChildNotFound`
                    return false;
                }
            };

            // node hash does not match its contents
            if !node.is_valid() {
                return false;
            }

            match node.walk::<Read>(key) {
                WalkStop::Arrived => {
                    return pred(Some(node));
                }
                WalkStop::PathDiverted { .. } => {
                    return pred(None);
                }
                WalkStop::ChildNotFound { .. } => {
                    return pred(None);
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

#[cfg(test)]
mod tests {
    use super::{
        super::{CompressedPathRaw, TrieNodeTrait, VanillaTrieNode},
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
                CompressedPathRaw::new(
                    &[0x00, 0x01, 0x02],
                    CompressedPathRaw::first_nibble_mask(),
                ),
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
        // |path: [0x20]|   |path: [0x30]            |
        // |val : [0x02]|   |val : [0x00, 0x00, 0x03]|

        let (key1, value1) = ([0x20], [0x02]);
        let (key2, value2) = ([0x00, 0x00, 0x30], [0x00, 0x00, 0x03]);

        let leaf1 = {
            let mut node = TrieProofNode(VanillaTrieNode::new(
                MERKLE_NULL_NODE,
                Default::default(),
                Some(Box::new(value1)),
                (&[0x20u8][..]).into(),
            ));
            node.0.set_merkle(&node.compute_merkle());
            node
        };

        let leaf2 = {
            let mut node = TrieProofNode(VanillaTrieNode::new(
                MERKLE_NULL_NODE,
                Default::default(),
                Some(Box::new(value2)),
                (&[0x30u8][..]).into(),
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

        let leaf1_hash = leaf1.compute_merkle();
        let leaf2_hash = leaf2.compute_merkle();
        let ext_hash = ext.compute_merkle();
        let branch_hash = branch.compute_merkle();
        let root = branch_hash.clone();
        let null = MERKLE_NULL_NODE;

        // empty proof
        let proof = TrieProof::new(vec![]);
        assert!(proof.is_valid_kv(&[0x00], None, null));
        assert!(!proof.is_valid_kv(&[0x00], None, leaf1_hash));
        assert!(!proof.is_valid_kv(&key1, Some(&[0x00]), null));

        // missing node
        let proof = TrieProof::new(vec![ext.clone(), branch.clone()]);
        assert!(!proof.is_valid_kv(&key2, Some(&value2), root));

        // wrong hash
        let mut leaf2_wrong = leaf2.clone();
        let mut wrong_merkle = leaf2_wrong.get_merkle().clone();
        wrong_merkle.as_bytes_mut()[0] = 0x00;
        leaf2_wrong.set_merkle(&wrong_merkle);

        let proof = TrieProof::new(vec![
            leaf1.clone(),
            leaf2_wrong,
            ext.clone(),
            branch.clone(),
        ]);
        assert!(!proof.is_valid_kv(&key2, Some(&value2), root));

        // wrong value
        assert!(!proof.is_valid_kv(&key2, Some(&[0x00, 0x00, 0x04]), root));

        // valid proof
        let proof = TrieProof::new(vec![
            leaf1.clone(),
            leaf2.clone(),
            ext.clone(),
            branch.clone(),
        ]);

        assert!(proof.is_valid_kv(&key1, Some(&value1), root));
        assert!(proof.is_valid_kv(&key2, Some(&value2), root));
        assert!(proof.is_valid_kv(&[0x01], None, root));

        // wrong root
        assert!(!proof.is_valid_kv(&key2, Some(&value2), leaf1_hash));

        // path to `branch` (root)
        let key = &[];
        assert!(proof.is_valid_path_to(key, branch_hash, root));
        assert!(!proof.is_valid_path_to(key, leaf1_hash, root));
        assert!(!proof.is_valid_path_to(key, ext_hash, root));
        assert!(!proof.is_valid_path_to(key, leaf2_hash, root));

        // path to `leaf1`
        let path = leaf1.compressed_path_ref().path_slice;
        assert!(proof.is_valid_path_to(path, leaf1_hash, root));
        assert!(!proof.is_valid_path_to(path, branch_hash, root));
        assert!(!proof.is_valid_path_to(path, ext_hash, root));
        assert!(!proof.is_valid_path_to(path, leaf2_hash, root));

        // path to `ext`
        let path = ext.compressed_path_ref().path_slice;
        assert!(proof.is_valid_path_to(path, ext_hash, root));
        assert!(!proof.is_valid_path_to(path, branch_hash, root));
        assert!(!proof.is_valid_path_to(path, leaf1_hash, root));
        assert!(!proof.is_valid_path_to(path, leaf2_hash, root));

        // path to `leaf2`
        let path = &key2[..];
        assert!(proof.is_valid_path_to(path, leaf2_hash, root));
        assert!(!proof.is_valid_path_to(path, branch_hash, root));
        assert!(!proof.is_valid_path_to(path, leaf1_hash, root));
        assert!(!proof.is_valid_path_to(path, ext_hash, root));

        // non-existent prefix
        let path = &[0x00];
        assert!(proof.is_valid_path_to(path, null, root));
        assert!(!proof.is_valid_path_to(path, branch_hash, root));
        assert!(!proof.is_valid_path_to(path, leaf1_hash, root));
        assert!(!proof.is_valid_path_to(path, ext_hash, root));
        assert!(!proof.is_valid_path_to(path, leaf2_hash, root));

        // non-existent path
        let path = &[0x10];
        assert!(proof.is_valid_path_to(path, null, root));
        assert!(!proof.is_valid_path_to(path, branch_hash, root));
        assert!(!proof.is_valid_path_to(path, leaf1_hash, root));
        assert!(!proof.is_valid_path_to(path, ext_hash, root));
        assert!(!proof.is_valid_path_to(path, leaf2_hash, root));

        // non-existent path with existing prefix
        let path = &[0x00, 0x00, 0x30, 0x04];
        assert!(proof.is_valid_path_to(path, null, root));
        assert!(!proof.is_valid_path_to(path, branch_hash, root));
        assert!(!proof.is_valid_path_to(path, ext_hash, root));
        assert!(!proof.is_valid_path_to(path, leaf1_hash, root));
        assert!(!proof.is_valid_path_to(path, leaf2_hash, root));

        // empty trie
        assert!(proof.is_valid_path_to(&[], null, null));
        assert!(proof.is_valid_path_to(&[0x00], null, null));

        assert!(!proof.is_valid_path_to(&[], branch_hash, null));
        assert!(!proof.is_valid_path_to(&[0x00], branch_hash, null));
    }
}
