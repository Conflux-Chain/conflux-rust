// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait SnapshotMptTraitReadOnly {
    fn get_merkle_root(&self) -> &MerkleHash;
    fn load_node(
        &self, path: &dyn CompressedPathTrait,
    ) -> Result<Option<VanillaTrieNode<MerkleHash>>>;
    fn iterate_subtree_trie_nodes_without_root(
        &self, path: &dyn CompressedPathTrait,
    ) -> Box<dyn SnapshotMptIteraterTrait>;
}

pub trait SnapshotMptTraitSingleWriter: SnapshotMptTraitReadOnly {
    fn delete_node(&mut self, path: &dyn CompressedPathTrait) -> Result<()>;
    fn write_node(
        &mut self, path: &dyn CompressedPathTrait,
        trie_node: &VanillaTrieNode<MerkleHash>,
    ) -> Result<()>;
}

pub trait SnapshotMptIteraterTrait {
    fn next(
        &mut self,
    ) -> Result<Option<(CompressedPathRaw, VanillaTrieNode<MerkleHash>)>>;
}

// TODO: A snapshot mpt iterator is suitable to work as base_mpt in MptMerger's
// TODO: save-as mode, because MptMerger always access nodes in snapshot mpt in
// TODO: increasing order. we need to make special generalization for MptMerger
// TODO: to take SnapshotMptIteraterTrait as input.

use super::super::impls::{
    errors::*,
    multi_version_merkle_patricia_trie::merkle_patricia_trie::{
        trie_node::VanillaTrieNode, CompressedPathRaw, CompressedPathTrait,
    },
};
use primitives::MerkleHash;
