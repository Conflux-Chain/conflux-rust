// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrieProof {
    /// The first node must be the root node. Child node must come later than
    /// parent node.
    pub nodes: Vec<TrieProofNode>,
    pub merkle_to_node_index: HashMap<MerkleHash, usize>,
    /// Root node doesn't have parent, so we set an invalid parent_index:
    /// number_nodes.
    pub parent_node_index: Vec<usize>,
    // Root node doesn't have parent, so we leave child_index[0]
    // default-initialized to 0.
    pub child_index: Vec<u8>,
    pub number_leaf_nodes: u32,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrieProofNode(VanillaTrieNode<MerkleHash>);

impl TrieProofNode {
    pub fn new(
        children_table: VanillaChildrenTable<MerkleHash>,
        maybe_value: Option<Box<[u8]>>, compressed_path: CompressedPathRaw,
    ) -> Self
    {
        let merkle = Self::compute_merkle(
            compressed_path.as_ref(),
            if children_table.get_children_count() == 0 {
                None
            } else {
                Some(children_table.get_children_table())
            },
            maybe_value.as_ref().map(|v| v.as_ref()),
        );
        Self(VanillaTrieNode::new(
            merkle,
            children_table,
            maybe_value,
            compressed_path,
        ))
    }

    // \w  path: keccak([mask, [path...], keccak(rlp([[children...]?, value]))])
    // \wo path: keccak(rlp([[children...]?, value]))
    pub fn compute_merkle(
        compressed_path_ref: CompressedPathRef,
        children_merkles: MaybeMerkleTableRef, maybe_value: Option<&[u8]>,
    ) -> MerkleHash
    {
        compute_merkle(compressed_path_ref, children_merkles, maybe_value)
    }
}

impl TrieProof {
    /// Makes sure that the proof nodes are valid and connected at the time of
    /// creation.
    pub fn new(nodes: Vec<TrieProofNode>) -> Result<Self> {
        let merkle_to_node_index = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.get_merkle().clone(), index))
            .collect::<HashMap<H256, usize>>();
        let number_nodes = nodes.len();
        let mut parent_node_index = Vec::with_capacity(number_nodes);
        let mut child_index = Vec::with_capacity(number_nodes);
        let mut is_non_leaf = vec![false; number_nodes];

        // Connectivity check.
        let mut connected_child_parent_map =
            HashMap::<MerkleHash, (usize, u8), RandomState>::default();
        match nodes.get(0) {
            None => {}
            Some(node) => {
                connected_child_parent_map
                    .insert(node.get_merkle().clone(), (number_nodes, 0));
            }
        }
        for (parent_index, node) in nodes.iter().enumerate() {
            match connected_child_parent_map.get(node.get_merkle()) {
                // Not connected.
                None => bail!(ErrorKind::InvalidTrieProof),
                Some((parent_index, child_index_of_parent)) => {
                    parent_node_index.push(*parent_index);
                    child_index.push(*child_index_of_parent);
                    if *parent_index < number_nodes {
                        is_non_leaf[*parent_index] = true;
                    }
                }
            }
            for (child_index, child_merkle) in
                node.get_children_table_ref().iter()
            {
                connected_child_parent_map
                    .insert(child_merkle.clone(), (parent_index, child_index));
            }
        }

        let mut number_leaf_nodes = 0;
        for non_leaf in is_non_leaf {
            if !non_leaf {
                number_leaf_nodes += 1;
            }
        }

        Ok(TrieProof {
            nodes,
            merkle_to_node_index,
            parent_node_index,
            child_index,
            number_leaf_nodes,
        })
    }

    /// Verify that the trie `root` has `value` under `key`.
    /// Use `None` for exclusion proofs (i.e. there is no value under `key`).
    // NOTE: This API cannot be used to prove that there is a value under `key`
    // but it does not equal a given value. We add this later on if it's needed.
    pub fn is_valid_kv(
        &self, key: &[u8], value: Option<&[u8]>, root: &MerkleHash,
    ) -> bool {
        self.is_valid(key, root, |node| match node {
            None => value == None,
            Some(node) => value == node.value_as_slice().into_option(),
        })
    }

    #[cfg(test)]
    /// Verify that the trie `root` has a node with `hash` under `path`.
    /// Use `MERKLE_NULL_NODE` for exclusion proofs (i.e. `path` does not exist
    /// or leads to another hash).
    pub fn is_valid_path_to(
        &self, path: &[u8], hash: &MerkleHash, root: &MerkleHash,
    ) -> bool {
        self.is_valid(path, root, |node| match node {
            None => hash.eq(&MERKLE_NULL_NODE),
            Some(node) => hash == node.get_merkle(),
        })
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

        // traverse the trie along `path`
        let mut key = path;
        let mut hash = root;

        loop {
            let node = match self.merkle_to_node_index.get(hash) {
                Some(node_index) =>
                // The node_index is guaranteed to exist so it's actually safe.
                unsafe { self.nodes.get_unchecked(*node_index) }
                None => {
                    // Missing node. The proof can be invalid or incomplete for
                    // the key.
                    return false;
                }
            };

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

    #[inline]
    pub fn number_nodes(&self) -> usize { self.nodes.len() }

    pub fn compute_paths_for_all_nodes(&self) -> Vec<CompressedPathRaw> {
        let mut paths = Vec::with_capacity(self.nodes.len());
        for i in 0..self.nodes.len() {
            paths.push(CompressedPathRaw::concat(
                &paths[self.parent_node_index[i]],
                self.child_index[i],
                &self.nodes[i].compressed_path_ref(),
            ))
        }

        paths
    }
}

impl Encodable for TrieProof {
    fn rlp_append(&self, s: &mut RlpStream) { s.append_list(&self.nodes); }
}

impl Decodable for TrieProof {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        match Self::new(rlp.as_list()?) {
            Err(_) => Err(DecoderError::Custom("Invalid TrieProof")),
            Ok(proof) => Ok(proof),
        }
    }
}

// FIXME: in rlp encode / decode, children_count and merkle_hash should be
// omitted.
impl Encodable for TrieProofNode {
    fn rlp_append(&self, s: &mut RlpStream) { s.append_internal(&self.0); }
}

impl From<TrieProofNode> for VanillaTrieNode<MerkleHash> {
    fn from(x: TrieProofNode) -> Self { x.0 }
}

impl Decodable for TrieProofNode {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        Ok(Self(rlp.as_val()?))
    }
}

impl Deref for TrieProofNode {
    type Target = VanillaTrieNode<MerkleHash>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for TrieProofNode {
    fn deref_mut(&mut self) -> &mut <Self as Deref>::Target { &mut self.0 }
}

use super::{
    super::errors::*,
    merkle::{compute_merkle, MaybeMerkleTableRef},
    walk::{access_mode::Read, TrieNodeWalkTrait, WalkStop},
    CompressedPathRaw, CompressedPathRef, CompressedPathTrait, TrieNodeTrait,
    VanillaChildrenTable, VanillaTrieNode,
};
use cfx_types::H256;
use primitives::{MerkleHash, MERKLE_NULL_NODE};
use rlp::*;
use std::{
    collections::{hash_map::RandomState, HashMap},
    ops::{Deref, DerefMut},
};
