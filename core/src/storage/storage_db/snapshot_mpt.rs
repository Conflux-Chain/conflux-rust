// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type SnapshotMptValue = (Box<[u8]>, Box<[u8]>, i64);

make_tuple_with_index_ext!(SnapshotMptDbValue(Box<[u8]>: pub, i64: pub));
make_tuple_with_index_ext!(SnapshotMptNode(VanillaTrieNode<MerkleHash>: pub, i64: pub));

pub trait SnapshotMptTraitReadOnly {
    fn get_merkle_root(&self) -> &MerkleHash;
    fn load_node(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Option<SnapshotMptNode>>;
    fn iterate_subtree_trie_nodes_without_root(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Box<dyn SnapshotMptIteraterTrait + '_>>;

    fn get_manifest(
        &self, start_chunk: &ChunkKey,
    ) -> Result<Option<RangedManifest>>;
    fn get_chunk(&self, key: &ChunkKey) -> Result<Option<Chunk>>;
}

pub trait SnapshotMptTraitSingleWriter: SnapshotMptTraitReadOnly {
    fn delete_node(&mut self, path: &dyn CompressedPathTrait) -> Result<()>;
    fn write_node(
        &mut self, path: &dyn CompressedPathTrait, trie_node: &SnapshotMptNode,
    ) -> Result<()>;
}

pub trait SnapshotMptIteraterTrait:
    FallibleIterator<
    Item = (CompressedPathRaw, VanillaTrieNode<MerkleHash>, i64),
    Error = Error,
>
{
}

impl<
        T: FallibleIterator<
            Item = (CompressedPathRaw, VanillaTrieNode<MerkleHash>, i64),
            Error = Error,
        >,
    > SnapshotMptIteraterTrait for T
{
}

// TODO: A snapshot mpt iterator is suitable to work as base_mpt in MptMerger's
// TODO: save-as mode, because MptMerger always access nodes in snapshot mpt in
// TODO: increasing order. we need to make special generalization for MptMerger
// TODO: to take SnapshotMptIteraterTrait as input.

impl Deref for SnapshotMptNode {
    type Target = VanillaTrieNode<MerkleHash>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for SnapshotMptNode {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

use super::super::{
    impls::{
        errors::*,
        multi_version_merkle_patricia_trie::merkle_patricia_trie::{
            trie_node::VanillaTrieNode, CompressedPathRaw, CompressedPathTrait,
        },
        storage_db::snapshot_sync::{Chunk, ChunkKey, RangedManifest},
    },
    utils::tuple::*,
};
use fallible_iterator::FallibleIterator;
use primitives::MerkleHash;
use std::ops::{Deref, DerefMut};
