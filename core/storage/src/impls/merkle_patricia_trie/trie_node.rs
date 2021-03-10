// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Methods that a trie node type should implement in general.
/// Note that merkle hash isn't necessarily stored together with
/// a trie node because the merkle hash is mainly used when
/// obtaining a proof or computed when committing a block.
/// Merkle hash maybe stored in different way for IO optimizations.
pub trait TrieNodeTrait: Default {
    type NodeRefType: NodeRefTrait;
    type ChildrenTableType;

    fn compressed_path_ref(&self) -> CompressedPathRef;

    fn has_value(&self) -> bool;

    fn get_children_count(&self) -> u8;

    fn value_as_slice(&self) -> MptValue<&[u8]>;

    fn set_compressed_path(&mut self, compressed_path: CompressedPathRaw);

    /// Unsafe because it's assumed that the child_index is valid but the child
    /// doesn't exist.
    unsafe fn add_new_child_unchecked<T>(&mut self, child_index: u8, child: T)
    where
        ChildrenTableItem<Self::NodeRefType>:
            WrappedCreateFrom<T, Self::NodeRefType>;

    /// Unsafe because it's assumed that the child_index already exists.
    unsafe fn get_child_mut_unchecked(
        &mut self, child_index: u8,
    ) -> &mut Self::NodeRefType;

    /// Unsafe because it's assumed that the child_index already exists.
    unsafe fn replace_child_unchecked<T>(&mut self, child_index: u8, child: T)
    where
        ChildrenTableItem<Self::NodeRefType>:
            WrappedCreateFrom<T, Self::NodeRefType>;

    /// Unsafe because it's assumed that the child_index already exists.
    unsafe fn delete_child_unchecked(&mut self, child_index: u8);

    /// Delete value when we know that it already exists.
    unsafe fn delete_value_unchecked(&mut self) -> Box<[u8]>;

    fn replace_value_valid(
        &mut self, valid_value: Box<[u8]>,
    ) -> MptValue<Box<[u8]>>;

    fn get_children_table_ref(&self) -> &Self::ChildrenTableType;

    fn compute_merkle(
        &self, children_merkles: MaybeMerkleTableRef,
        path_without_first_nibble: bool,
    ) -> MerkleHash {
        compute_merkle(
            self.compressed_path_ref(),
            path_without_first_nibble,
            children_merkles,
            self.value_as_slice().into_option(),
        )
    }
}

// This trie node isn't memory efficient.
#[derive(Clone, Debug, PartialEq)]
pub struct VanillaTrieNode<NodeRefT: NodeRefTrait> {
    compressed_path: CompressedPathRaw,
    mpt_value: MptValue<Box<[u8]>>,
    children_table: VanillaChildrenTable<NodeRefT>,
    merkle_hash: MerkleHash,
}

impl<NodeRefT: 'static + NodeRefTrait> Default for VanillaTrieNode<NodeRefT>
where
    ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>,
{
    fn default() -> Self {
        Self {
            compressed_path: Default::default(),
            mpt_value: MptValue::None,
            children_table: Default::default(),
            merkle_hash: MERKLE_NULL_NODE,
        }
    }
}

impl<'node, NodeRefT: 'static + NodeRefTrait> GetChildTrait<'node>
    for VanillaTrieNode<NodeRefT>
where
    ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>,
{
    type ChildIdType = &'node NodeRefT;

    fn get_child(&'node self, child_index: u8) -> Option<&'node NodeRefT> {
        self.children_table.get_child(child_index)
    }
}

impl<'node, NodeRefT: 'static + NodeRefTrait> TrieNodeWalkTrait<'node>
    for VanillaTrieNode<NodeRefT>
where
    ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>,
{
}

impl<NodeRefT: 'static + NodeRefTrait> TrieNodeTrait
    for VanillaTrieNode<NodeRefT>
where
    ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>,
{
    type ChildrenTableType = VanillaChildrenTable<NodeRefT>;
    type NodeRefType = NodeRefT;

    fn compressed_path_ref(&self) -> CompressedPathRef {
        self.compressed_path.as_ref()
    }

    fn has_value(&self) -> bool {
        self.mpt_value.is_some()
    }

    fn get_children_count(&self) -> u8 {
        self.children_table.get_children_count()
    }

    fn value_as_slice(&self) -> MptValue<&[u8]> {
        match &self.mpt_value {
            MptValue::None => MptValue::None,
            MptValue::TombStone => MptValue::TombStone,
            MptValue::Some(v) => MptValue::Some(v.as_ref()),
        }
    }

    fn set_compressed_path(&mut self, compressed_path: CompressedPathRaw) {
        self.compressed_path = compressed_path;
    }

    unsafe fn add_new_child_unchecked<T>(&mut self, child_index: u8, child: T)
    where
        ChildrenTableItem<NodeRefT>: WrappedCreateFrom<T, NodeRefT>,
    {
        ChildrenTableItem::<NodeRefT>::take_from(
            self.children_table.get_child_mut_unchecked(child_index),
            child,
        );
        *self.children_table.get_children_count_mut() += 1;
    }

    unsafe fn get_child_mut_unchecked(
        &mut self, child_index: u8,
    ) -> &mut NodeRefT {
        self.children_table.get_child_mut_unchecked(child_index)
    }

    unsafe fn replace_child_unchecked<T>(&mut self, child_index: u8, child: T)
    where
        ChildrenTableItem<NodeRefT>: WrappedCreateFrom<T, NodeRefT>,
    {
        ChildrenTableItem::<NodeRefT>::take_from(
            self.children_table.get_child_mut_unchecked(child_index),
            child,
        );
    }

    unsafe fn delete_child_unchecked(&mut self, child_index: u8) {
        ChildrenTableItem::<NodeRefT>::take_from(
            self.children_table.get_child_mut_unchecked(child_index),
            ChildrenTableItem::<NodeRefT>::no_child(),
        );
        *self.children_table.get_children_count_mut() -= 1;
    }

    unsafe fn delete_value_unchecked(&mut self) -> Box<[u8]> {
        self.mpt_value.take().unwrap()
    }

    fn replace_value_valid(
        &mut self, valid_value: Box<[u8]>,
    ) -> MptValue<Box<[u8]>> {
        let new_mpt_value = if valid_value.len() == 0 {
            MptValue::TombStone
        } else {
            MptValue::Some(valid_value)
        };

        std::mem::replace(&mut self.mpt_value, new_mpt_value)
    }

    fn get_children_table_ref(&self) -> &VanillaChildrenTable<NodeRefT> {
        &self.children_table
    }
}

impl<NodeRefT: NodeRefTrait> VanillaTrieNode<NodeRefT> {
    pub fn new(
        merkle: MerkleHash, children_table: VanillaChildrenTable<NodeRefT>,
        maybe_value: Option<Box<[u8]>>, compressed_path: CompressedPathRaw,
    ) -> Self {
        let mpt_value = match maybe_value {
            None => MptValue::None,
            Some(v) => {
                if v.len() == 0 {
                    MptValue::TombStone
                } else {
                    MptValue::Some(v)
                }
            }
        };

        Self {
            compressed_path,
            mpt_value,
            children_table,
            merkle_hash: merkle.clone(),
        }
    }

    pub fn get_merkle(&self) -> &MerkleHash {
        &self.merkle_hash
    }

    pub fn set_merkle(&mut self, merkle: &MerkleHash) {
        self.merkle_hash = merkle.clone();
    }
}

impl VanillaTrieNode<MerkleHash> {
    pub fn get_children_merkles(&self) -> MaybeMerkleTableRef {
        if self.get_children_count() > 0 {
            Some(&self.children_table.get_children_table())
        } else {
            None
        }
    }

    pub fn get_merkle_hash_wo_compressed_path(&self) -> MerkleHash {
        compute_node_merkle(
            self.get_children_merkles(),
            self.value_as_slice().into_option(),
        )
    }
}

impl<NodeRefT: 'static + NodeRefTrait> Encodable for VanillaTrieNode<NodeRefT>
where
    ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>,
{
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list()
            .append(self.get_merkle())
            .append(self.get_children_table_ref())
            .append(&self.value_as_slice().into_option());

        let compressed_path_ref = self.compressed_path_ref();
        if compressed_path_ref.path_size() > 0 {
            s.append(&compressed_path_ref);
        }

        s.finalize_unbounded_list();
    }
}

impl<NodeRefT: 'static + NodeRefTrait> Decodable for VanillaTrieNode<NodeRefT>
where
    ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>,
{
    fn decode(rlp: &Rlp) -> ::std::result::Result<Self, DecoderError> {
        let compressed_path;
        if rlp.item_count()? != 4 {
            compressed_path = CompressedPathRaw::new(&[], 0);
        } else {
            compressed_path = rlp.val_at(3)?;
        }

        Ok(VanillaTrieNode::new(
            MerkleHash::from_slice(rlp.val_at::<Vec<u8>>(0)?.as_slice()),
            rlp.val_at::<VanillaChildrenTable<NodeRefT>>(1)?,
            rlp.val_at::<Option<Vec<u8>>>(2)?
                .map(|v| v.into_boxed_slice()),
            compressed_path,
        ))
    }
}

use super::{
    super::super::utils::WrappedCreateFrom,
    children_table::*,
    compressed_path::*,
    merkle::{compute_merkle, compute_node_merkle, MaybeMerkleTableRef},
    walk::*,
};
use primitives::{MerkleHash, MptValue, MERKLE_NULL_NODE};
use rlp::*;
use std::vec::Vec;
