// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrieProof {
    /// The first node must be the root node. Child node must come later than
    /// parent node.
    nodes: Vec<TrieProofNode>,
    merkle_to_node_index: HashMap<MerkleHash, usize>,
    /// Root node doesn't have parent, so we set an invalid parent_index:
    /// number_nodes.
    parent_node_index: Vec<usize>,
    // Root node doesn't have parent, so we leave child_index[0]
    // default-initialized to 0.
    pub child_index: Vec<u8>,
    number_leaf_nodes: u32,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TrieProofNode(VanillaTrieNode<MerkleHash>);

impl TrieProofNode {
    pub fn new(
        children_table: VanillaChildrenTable<MerkleHash>,
        maybe_value: Option<Box<[u8]>>, compressed_path: CompressedPathRaw,
    ) -> Self
    {
        let merkle = compute_merkle(
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
}

impl TrieProof {
    pub const MAX_NODES: usize = 1000;

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

    pub fn get_merkle_root(&self) -> &MerkleHash {
        match self.nodes.get(0) {
            None => &MERKLE_NULL_NODE,
            Some(node) => node.get_merkle(),
        }
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

    /// Check if the key can be proved. The only reason of inability to prove a
    /// key is missing nodes.
    pub fn if_proves_key(&self, key: &[u8]) -> (bool, Option<&TrieProofNode>) {
        let mut proof_node = None;
        let proof_node_mut = &mut proof_node;
        let proves = self.is_valid(key, self.get_merkle_root(), |maybe_node| {
            *proof_node_mut = maybe_node.clone();
            true
        });
        drop(proof_node_mut);
        (proves, proof_node)
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

    fn is_valid<'this: 'pred_param, 'pred_param>(
        &'this self, path: &[u8], root: &MerkleHash,
        pred: impl FnOnce(Option<&'pred_param TrieProofNode>) -> bool,
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

    #[inline]
    pub fn number_leaf_nodes(&self) -> u32 { self.number_leaf_nodes }

    pub fn get_proof_nodes(&self) -> &Vec<TrieProofNode> { &self.nodes }

    pub fn compute_snapshot_mpt_key_for_all_nodes(
        &self,
    ) -> Vec<CompressedPathRaw> {
        let mut full_paths = Vec::with_capacity(self.nodes.len());
        let mut keys = Vec::with_capacity(self.nodes.len());
        // At the time of coding, The root node is guaranteed to have empty
        // compressed_path. But to be on the safe side, we use the root
        // node's compressed path as its full path.
        if let Some(node) = self.nodes.get(0) {
            full_paths.push(node.compressed_path_ref().into());
            keys.push(CompressedPathRaw::default());
        }
        for i in 1..self.nodes.len() {
            full_paths.push(CompressedPathRaw::join_connected_paths(
                &full_paths[self.parent_node_index[i]],
                self.child_index[i],
                &self.nodes[i].compressed_path_ref(),
            ));

            keys.push(CompressedPathRaw::extend_path(
                &full_paths[self.parent_node_index[i]],
                self.child_index[i],
            ));
        }

        keys
    }
}

impl Encodable for TrieProof {
    fn rlp_append(&self, s: &mut RlpStream) { s.append_list(&self.nodes); }
}

impl Decodable for TrieProof {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        if rlp.item_count()? > Self::MAX_NODES {
            return Err(DecoderError::Custom("TrieProof too long."));
        }
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
    merkle::compute_merkle,
    walk::{access_mode::Read, TrieNodeWalkTrait, WalkStop},
    CompressedPathRaw, CompressedPathTrait, TrieNodeTrait,
    VanillaChildrenTable, VanillaTrieNode,
};
use cfx_types::H256;
use primitives::{MerkleHash, MERKLE_NULL_NODE};
use rlp::*;
use std::{
    collections::{hash_map::RandomState, HashMap},
    ops::{Deref, DerefMut},
};
