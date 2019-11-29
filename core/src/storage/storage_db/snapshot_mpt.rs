// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type SnapshotMptValue = (Box<[u8]>, Box<[u8]>);

pub type SnapshotMptDbValue = Box<[u8]>;
/// We use VanillaTrieNode<(MerkleHash, i64)> instead of
/// (VanillaTrieNode<MerkleHash>, i64) to make seeking by rlp size position
/// faster.
#[derive(Clone, Default)]
pub struct SnapshotMptNode(pub VanillaTrieNode<SubtreeMerkleWithSize>);

#[derive(Copy, Clone, PartialEq, Debug)]
pub struct SubtreeMerkleWithSize {
    pub merkle: MerkleHash,
    pub subtree_size: u64,
    pub delta_subtree_size: u64,
}

pub trait SnapshotMptTraitReadOnly {
    fn get_merkle_root(&self) -> &MerkleHash;
    fn load_node(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Option<SnapshotMptNode>>;
    fn iterate_subtree_trie_nodes_without_root(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Box<dyn SnapshotMptIteraterTrait + '_>>;
}

pub trait SnapshotMptTraitSingleWriter: SnapshotMptTraitReadOnly {
    fn as_readonly(&mut self) -> &mut dyn SnapshotMptTraitReadOnly;
    fn delete_node(&mut self, path: &dyn CompressedPathTrait) -> Result<()>;
    // FIXME: It seems better to pass by value, however in one place we can't
    // move away structure field in drop().
    fn write_node(
        &mut self, path: &dyn CompressedPathTrait, trie_node: &SnapshotMptNode,
    ) -> Result<()>;
}

// TODO: A snapshot mpt iterator is suitable to work as base_mpt in MptMerger's
// TODO: save-as mode, because MptMerger always access nodes in snapshot mpt in
// TODO: increasing order. we need to make special generalization for MptMerger
// TODO: to take SnapshotMptIteraterTrait as input.
pub trait SnapshotMptIteraterTrait:
    FallibleIterator<Item = (CompressedPathRaw, SnapshotMptNode), Error = Error>
{
}

impl<
        T: FallibleIterator<
            Item = (CompressedPathRaw, SnapshotMptNode),
            Error = Error,
        >,
    > SnapshotMptIteraterTrait for T
{
}

impl SnapshotMptNode {
    pub const EMPTY_CHILD: SubtreeMerkleWithSize = SubtreeMerkleWithSize {
        merkle: MERKLE_NULL_NODE,
        subtree_size: 0,
        delta_subtree_size: 0,
    };

    pub fn new(node: VanillaTrieNode<SubtreeMerkleWithSize>) -> Self {
        Self(node)
    }

    pub fn subtree_size(&self) -> u64 { Self::initial_subtree_size(&self.0) }

    fn initial_subtree_size(
        node: &VanillaTrieNode<SubtreeMerkleWithSize>,
    ) -> u64 {
        let mut size = 0;
        for (
            _child_index,
            &SubtreeMerkleWithSize {
                merkle: _,
                ref subtree_size,
                delta_subtree_size: _,
            },
        ) in node.get_children_table_ref().iter()
        {
            size += subtree_size;
        }

        size
    }

    pub fn get_children_merkle(&self) -> MaybeMerkleTable {
        if self.get_children_count() > 0 {
            let mut merkle_table = Some(
                [ChildrenTableItem::<MerkleHash>::no_child().clone();
                    CHILDREN_COUNT],
            );
            for (
                child_index,
                &SubtreeMerkleWithSize {
                    ref merkle,
                    subtree_size: _,
                    delta_subtree_size: _,
                },
            ) in self.get_children_table_ref().iter()
            {
                merkle_table.as_mut().unwrap()[child_index as usize] = *merkle;
            }
            merkle_table
        } else {
            None
        }
    }
}

impl Decodable for SnapshotMptNode {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        Ok(Self::new(rlp.as_val()?))
    }
}

impl Deref for SnapshotMptNode {
    type Target = VanillaTrieNode<SubtreeMerkleWithSize>;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for SnapshotMptNode {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl Decodable for SubtreeMerkleWithSize {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        Ok(Self {
            merkle: rlp.val_at(0)?,
            subtree_size: rlp.val_at::<u64>(1)?,
            delta_subtree_size: rlp.val_at::<u64>(2)?,
        })
    }
}

impl Encodable for SubtreeMerkleWithSize {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2)
            .append(&self.merkle)
            .append(&self.subtree_size)
            .append(&self.delta_subtree_size);
    }
}

impl NodeRefTrait for SubtreeMerkleWithSize {}

impl DefaultChildrenItem<SubtreeMerkleWithSize>
    for ChildrenTableItem<SubtreeMerkleWithSize>
{
    fn no_child() -> &'static SubtreeMerkleWithSize {
        &SnapshotMptNode::EMPTY_CHILD
    }
}

use super::super::impls::{
    errors::*,
    merkle_patricia_trie::{
        merkle::MaybeMerkleTable, ChildrenTableItem, CompressedPathRaw,
        CompressedPathTrait, DefaultChildrenItem, NodeRefTrait, TrieNodeTrait,
        VanillaTrieNode, CHILDREN_COUNT,
    },
};
use fallible_iterator::FallibleIterator;
use primitives::{MerkleHash, MERKLE_NULL_NODE};
use rlp::*;
use std::ops::{Deref, DerefMut};
