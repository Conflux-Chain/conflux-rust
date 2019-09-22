// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    super::{
        super::errors::*, cache::algorithm::CacheAlgoDataTrait, node_ref::*,
        slab::*,
    },
    children_table::*,
    compressed_path::*,
    maybe_in_place_byte_array::*,
    merkle::{compute_merkle, MaybeMerkleTableRef},
    mpt_value::MptValue,
    walk::*,
    WrappedCreateFrom,
};
use primitives::{MerkleHash, MERKLE_NULL_NODE};
use rlp::*;
use std::{
    fmt::{Debug, Formatter},
    hint::unreachable_unchecked,
    marker::{Send, Sync},
    vec::Vec,
};

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
    where ChildrenTableItem<Self::NodeRefType>:
            WrappedCreateFrom<T, Self::NodeRefType>;

    /// Unsafe because it's assumed that the child_index already exists.
    unsafe fn replace_child_unchecked<T>(&mut self, child_index: u8, child: T)
    where ChildrenTableItem<Self::NodeRefType>:
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
    ) -> MerkleHash {
        compute_merkle(
            self.compressed_path_ref(),
            children_merkles,
            self.value_as_slice().into_option(),
        )
    }
}

// This trie node isn't memory efficient.
#[derive(Clone, Debug, PartialEq)]
pub struct VanillaTrieNode<NodeRefT: NodeRefTrait> {
    compressed_path: CompressedPathRaw,
    maybe_value: Option<Box<[u8]>>,
    children_table: VanillaChildrenTable<NodeRefT>,
    merkle_hash: MerkleHash,
}

impl<NodeRefT: 'static + NodeRefTrait> Default for VanillaTrieNode<NodeRefT>
where ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>
{
    fn default() -> Self {
        Self {
            compressed_path: Default::default(),
            maybe_value: None,
            children_table: Default::default(),
            merkle_hash: MERKLE_NULL_NODE,
        }
    }
}

impl<'node, NodeRefT: 'static + NodeRefTrait> GetChildTrait<'node>
    for VanillaTrieNode<NodeRefT>
where ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>
{
    type ChildIdType = &'node NodeRefT;

    fn get_child(&'node self, child_index: u8) -> Option<&'node NodeRefT> {
        self.children_table.get_child(child_index)
    }
}

impl<'node, NodeRefT: 'static + NodeRefTrait> TrieNodeWalkTrait<'node>
    for VanillaTrieNode<NodeRefT>
where ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>
{
}

impl<NodeRefT: 'static + NodeRefTrait> TrieNodeTrait
    for VanillaTrieNode<NodeRefT>
where ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>
{
    type ChildrenTableType = VanillaChildrenTable<NodeRefT>;
    type NodeRefType = NodeRefT;

    fn compressed_path_ref(&self) -> CompressedPathRef {
        self.compressed_path.as_ref()
    }

    fn has_value(&self) -> bool { self.maybe_value.is_some() }

    fn get_children_count(&self) -> u8 {
        self.children_table.get_children_count()
    }

    fn value_as_slice(&self) -> MptValue<&[u8]> {
        match &self.maybe_value {
            None => MptValue::None,
            Some(v) => {
                if v.len() == 0 {
                    MptValue::TombStone
                } else {
                    MptValue::Some(v.as_ref())
                }
            }
        }
    }

    fn set_compressed_path(&mut self, compressed_path: CompressedPathRaw) {
        self.compressed_path = compressed_path;
    }

    unsafe fn add_new_child_unchecked<T>(&mut self, child_index: u8, child: T)
    where ChildrenTableItem<NodeRefT>: WrappedCreateFrom<T, NodeRefT> {
        ChildrenTableItem::<NodeRefT>::take_from(
            self.children_table.get_child_mut_unchecked(child_index),
            child,
        );
        *self.children_table.get_children_count_mut() += 1;
    }

    unsafe fn replace_child_unchecked<T>(&mut self, child_index: u8, child: T)
    where ChildrenTableItem<NodeRefT>: WrappedCreateFrom<T, NodeRefT> {
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
        self.maybe_value.take().unwrap()
    }

    fn replace_value_valid(
        &mut self, valid_value: Box<[u8]>,
    ) -> MptValue<Box<[u8]>> {
        let old_value = self.maybe_value.replace(valid_value);

        match old_value {
            None => MptValue::None,
            Some(v) => {
                if v.len() == 0 {
                    MptValue::TombStone
                } else {
                    MptValue::Some(v)
                }
            }
        }
    }

    fn get_children_table_ref(&self) -> &VanillaChildrenTable<NodeRefT> {
        &self.children_table
    }
}

impl<NodeRefT: NodeRefTrait> VanillaTrieNode<NodeRefT> {
    pub fn new(
        merkle: MerkleHash, children_table: VanillaChildrenTable<NodeRefT>,
        maybe_value: Option<Box<[u8]>>, compressed_path: CompressedPathRaw,
    ) -> Self
    {
        Self {
            compressed_path,
            maybe_value,
            children_table,
            merkle_hash: merkle.clone(),
        }
    }

    pub fn get_merkle(&self) -> &MerkleHash { &self.merkle_hash }

    pub fn set_merkle(&mut self, merkle: &MerkleHash) {
        self.merkle_hash = merkle.clone();
    }
}

impl VanillaTrieNode<MerkleHash> {
    pub fn get_children_merkle(&self) -> MaybeMerkleTableRef {
        if self.get_children_count() > 0 {
            Some(&self.children_table.get_children_table())
        } else {
            None
        }
    }
}

/// A node consists of an optional compressed path (concept of Patricia
/// Trie), an optional ChildrenTable (if the node is intermediate), an
/// optional value attached, and the Merkle hash for subtree.
#[derive(Default)]
pub struct MemOptimizedTrieNode<CacheAlgoDataT: CacheAlgoDataTrait> {
    /// Slab entry section. We keep a next vacant index of slab in case if the
    /// slot is vacant. By keeping the next vacant index, we save extra 8B
    /// space per trie node.
    ///
    /// The next vacant index is xor()ed by
    /// NodeRefDeltaMptCompact::PERSISTENT_KEY_BIT so that 0 can be
    /// reserved for "occupied" label.
    slab_next_vacant_index: u32,

    ///
    ///
    /// CompactPath section. The CompactPath if defined as separate struct
    /// would consume 16B, while the current expanded layout plus other u8
    /// and u16 fields consumes 24B instead of 32B.

    /// Conceptually, path_begin_mask can be: "no mask" (0x00), "second half"
    /// (second_nibble), "first half" (first_nibble).
    /// path_end_mask can be: "no mask" (0x00), "first half" (first_nibble).
    ///
    /// When there is only one half-byte in path and it's the "first half",
    /// path_end_mask is set. When there is only one half-byte in path and
    /// it's the "second half", compressed_path is set to one full byte
    /// with the missing "first half", and path_end_mask is set to "no
    /// mask". In comparison it still matches the corresponding byte of the
    /// key. We don't store path_begin_mask because it isn't used at all in
    /// comparison.
    path_end_mask: u8,
    /// 4 bits per step.
    /// We limit the maximum key steps by u16.
    path_size: u16,
    path: MaybeInPlaceByteArray,
    path_memory_manager: FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
        u16,
        TrivialSizeFieldConverterU16,
        MemOptimizedTrieNodePathMemoryManager<CacheAlgoDataT>,
        MemOptimizedTrieNodePathMemoryManager<CacheAlgoDataT>,
    >,

    // End of CompactPath section
    // TODO(yz): Unpack the fields from ChildrenTableDeltaMpt to save
    // memory. In this case create temporary ChildrenTableDeltaMpt for
    // update / iteration.
    pub(super) children_table: ChildrenTableDeltaMpt,
    // Rust automatically moves the value_size field in order to minimize the
    // total size of the struct.
    /// We limit the maximum value length by u16. If it proves insufficient,
    /// manage the length and content separately.
    value_size: u32,
    value: MaybeInPlaceByteArray,
    value_memory_manager: FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
        u32,
        TrieNodeValueSizeFieldConverter,
        MemOptimizedTrieNodeValueMemoryManager<CacheAlgoDataT>,
        MemOptimizedTrieNodeValueMemoryManager<CacheAlgoDataT>,
    >,

    // TODO(yz): we don't have to store MerkleHash directly in TrieNode,
    // because it's only used in proof and committing.
    /// The merkle hash without the compressed path.
    merkle_hash: MerkleHash,

    pub(in super::super) cache_algo_data: CacheAlgoDataT,
}

#[cfg(test)]
use super::super::node_memory_manager::TrieNodeDeltaMpt;
#[test]
fn test_mem_optimized_trie_node_size() {
    assert_eq!(std::mem::size_of::<TrieNodeDeltaMpt>(), 80);
    // TrieNodeDeltaMpt itself as Slab entry saves space.
    assert_ne!(std::mem::size_of::<Entry<TrieNodeDeltaMpt>>(), 80)
}

make_parallel_field_maybe_in_place_byte_array_memory_manager!(
    MemOptimizedTrieNodePathMemoryManager<CacheAlgoDataT> where <CacheAlgoDataT: CacheAlgoDataTrait>,
    MemOptimizedTrieNode<CacheAlgoDataT>,
    path_memory_manager,
    path,
    path_size: u16,
    TrivialSizeFieldConverterU16,
);

make_parallel_field_maybe_in_place_byte_array_memory_manager!(
    MemOptimizedTrieNodeValueMemoryManager<CacheAlgoDataT> where <CacheAlgoDataT: CacheAlgoDataTrait>,
    MemOptimizedTrieNode<CacheAlgoDataT>,
    value_memory_manager,
    value,
    value_size: u32,
    TrieNodeValueSizeFieldConverter,
);

impl<CacheAlgoDataT: CacheAlgoDataTrait> Clone
    for MemOptimizedTrieNode<CacheAlgoDataT>
{
    fn clone(&self) -> Self {
        Self::new(
            self.merkle_hash.clone(),
            self.children_table.clone(),
            self.value_clone().into_option(),
            self.compressed_path_ref().into(),
        )
    }
}

/// Compiler is not sure about the pointer in MaybeInPlaceByteArray fields.
/// It's Send because TrieNode is move only and it's impossible to change any
/// part of it without &mut.
unsafe impl<CacheAlgoDataT: CacheAlgoDataTrait> Send
    for MemOptimizedTrieNode<CacheAlgoDataT>
{
}
/// Compiler is not sure about the pointer in MaybeInPlaceByteArray fields.
/// We do not allow a &TrieNode to be able to change anything the pointer
/// is pointing to, therefore TrieNode is Sync.
unsafe impl<CacheAlgoDataT: CacheAlgoDataTrait> Sync
    for MemOptimizedTrieNode<CacheAlgoDataT>
{
}

#[derive(Default, Debug)]
struct TrieNodeValueSizeFieldConverter {}

impl TrieNodeValueSizeFieldConverter {
    const MAX_VALUE_SIZE: usize = 0xfffffffe;
    /// A special value to use in Delta Mpt to indicate that the value is
    /// deleted.
    ///
    /// In current implementation the TOMBSTONE is represented by empty string
    /// in serialized trie node and in methods manipulating value for trie
    /// node / MPT.
    const VALUE_TOMBSTONE: u32 = 0xffffffff;
}

impl SizeFieldConverterTrait<u32> for TrieNodeValueSizeFieldConverter {
    fn is_size_over_limit(size: usize) -> bool { size > Self::MAX_VALUE_SIZE }

    fn get(size_field: &u32) -> usize {
        if *size_field == Self::VALUE_TOMBSTONE {
            0
        } else {
            (*size_field) as usize
        }
    }

    fn set(size_field: &mut u32, size: usize) { *size_field = size as u32; }
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> MemOptimizedTrieNode<CacheAlgoDataT> {
    pub fn get_compressed_path_size(&self) -> u16 { self.path_size }

    pub fn copy_compressed_path(&mut self, new_path: CompressedPathRef) {
        // Remove old path. Not unsafe because the path size is set right later.
        unsafe {
            self.path_memory_manager.drop_value();
        }
        self.path_size = new_path.path_size();
        self.path_end_mask = new_path.end_mask;
        let path_slice = new_path.path_slice;
        self.path =
            MaybeInPlaceByteArray::copy_from(path_slice, path_slice.len());
    }

    pub fn value_clone(&self) -> MptValue<Box<[u8]>> {
        let size = self.value_size;
        if size == 0 {
            MptValue::None
        } else if size == TrieNodeValueSizeFieldConverter::VALUE_TOMBSTONE {
            MptValue::TombStone
        } else {
            MptValue::Some(self.value.get_slice(size as usize).into())
        }
    }

    /// Take value out of self.
    /// This method can only be called by replace_value / delete_value because
    /// empty node must be removed and path compression must be maintained.
    fn value_into_boxed_slice(&mut self) -> MptValue<Box<[u8]>> {
        let size = self.value_size;
        let maybe_value;
        if size == 0 {
            maybe_value = MptValue::None;
        } else {
            if size == TrieNodeValueSizeFieldConverter::VALUE_TOMBSTONE {
                maybe_value = MptValue::TombStone
            } else {
                maybe_value =
                    MptValue::Some(self.value.into_boxed_slice(size as usize));
            }
            self.value_size = 0;
        }
        maybe_value
    }

    pub fn check_value_size(value: &[u8]) -> Result<()> {
        let value_size = value.len();
        if TrieNodeValueSizeFieldConverter::is_size_over_limit(value_size) {
            // TODO(yz): value too long.
            return Err(Error::from_kind(ErrorKind::MPTInvalidValue));
        }
        // We may use empty value to represent special state, such as tombstone.
        // Therefore We don't check for emptiness.

        Ok(())
    }

    pub fn check_key_size(access_key: &[u8]) -> Result<()> {
        let key_size = access_key.len();
        if TrivialSizeFieldConverterU16::is_size_over_limit(key_size) {
            // TODO(yz): key too long.
            return Err(Error::from_kind(ErrorKind::MPTInvalidKey));
        }
        if key_size == 0 {
            // TODO(yz): key is empty.
            return Err(Error::from_kind(ErrorKind::MPTInvalidKey));
        }

        Ok(())
    }
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> TrieNodeTrait
    for MemOptimizedTrieNode<CacheAlgoDataT>
{
    type ChildrenTableType = ChildrenTableDeltaMpt;
    type NodeRefType = NodeRefDeltaMptCompact;

    fn compressed_path_ref(&self) -> CompressedPathRef {
        let size = self.path_size;
        CompressedPathRef {
            path_slice: self.path.get_slice(size as usize),
            end_mask: self.path_end_mask,
        }
    }

    fn has_value(&self) -> bool { self.value_size > 0 }

    fn get_children_count(&self) -> u8 {
        self.children_table.get_children_count()
    }

    fn value_as_slice(&self) -> MptValue<&[u8]> {
        let size = self.value_size;
        if size == 0 {
            MptValue::None
        } else if size == TrieNodeValueSizeFieldConverter::VALUE_TOMBSTONE {
            MptValue::TombStone
        } else {
            MptValue::Some(self.value.get_slice(size as usize))
        }
    }

    fn set_compressed_path(&mut self, mut path: CompressedPathRaw) {
        self.path_end_mask = path.end_mask();

        path.byte_array_memory_manager
            .move_to(&mut self.path_memory_manager);
    }

    unsafe fn add_new_child_unchecked<T>(&mut self, child_index: u8, child: T)
    where ChildrenTableItem<NodeRefDeltaMptCompact>:
            WrappedCreateFrom<T, NodeRefDeltaMptCompact> {
        self.children_table = CompactedChildrenTable::insert_child_unchecked(
            self.children_table.to_ref(),
            child_index,
            ChildrenTableItem::<NodeRefDeltaMptCompact>::take(child),
        );
    }

    unsafe fn replace_child_unchecked<T>(&mut self, child_index: u8, child: T)
    where ChildrenTableItem<NodeRefDeltaMptCompact>:
            WrappedCreateFrom<T, NodeRefDeltaMptCompact> {
        self.children_table.set_child_unchecked(
            child_index,
            ChildrenTableItem::<NodeRefDeltaMptCompact>::take(child),
        );
    }

    unsafe fn delete_child_unchecked(&mut self, child_index: u8) {
        self.children_table = CompactedChildrenTable::delete_child_unchecked(
            self.children_table.to_ref(),
            child_index,
        );
    }

    unsafe fn delete_value_unchecked(&mut self) -> Box<[u8]> {
        self.value_into_boxed_slice().unwrap()
    }

    fn replace_value_valid(
        &mut self, valid_value: Box<[u8]>,
    ) -> MptValue<Box<[u8]>> {
        let old_value = self.value_into_boxed_slice();
        let value_size = valid_value.len();
        if value_size == 0 {
            self.value_size = TrieNodeValueSizeFieldConverter::VALUE_TOMBSTONE;
        } else {
            self.value = MaybeInPlaceByteArray::new(valid_value, value_size);
            self.value_size = value_size as u32;
        }

        old_value
    }

    fn get_children_table_ref(&self) -> &Self::ChildrenTableType {
        &self.children_table
    }
}

impl<'node, CacheAlgoDataT: CacheAlgoDataTrait> GetChildTrait<'node>
    for MemOptimizedTrieNode<CacheAlgoDataT>
{
    type ChildIdType = NodeRefDeltaMptCompact;

    fn get_child(
        &'node self, child_index: u8,
    ) -> Option<NodeRefDeltaMptCompact> {
        self.children_table.get_child(child_index)
    }
}

impl<'node, CacheAlgoDataT: CacheAlgoDataTrait> TrieNodeWalkTrait<'node>
    for MemOptimizedTrieNode<CacheAlgoDataT>
{
}

/// The action variants after a value deletion.
pub enum TrieNodeAction {
    Modify,
    Delete,
    MergePath {
        child_index: u8,
        child_node_ref: NodeRefDeltaMpt,
    },
}

/// The actual TrieNode type used in DeltaMpt.
/// We'd like to keep as many of them as possible in memory.
impl<CacheAlgoDataT: CacheAlgoDataTrait> MemOptimizedTrieNode<CacheAlgoDataT> {
    pub fn new(
        merkle: MerkleHash, children_table: ChildrenTableDeltaMpt,
        maybe_value: Option<Box<[u8]>>, compressed_path: CompressedPathRaw,
    ) -> MemOptimizedTrieNode<CacheAlgoDataT>
    {
        let mut ret = MemOptimizedTrieNode::default();

        ret.merkle_hash = merkle;
        ret.children_table = children_table;
        match maybe_value {
            None => {}
            Some(value) => {
                ret.replace_value_valid(value);
            }
        }
        ret.set_compressed_path(compressed_path);

        ret
    }

    /// new_value can only be set according to the situation.
    /// children_table can only be replaced when there is no children in both
    /// old and new table.
    ///
    /// unsafe because:
    /// 1. precondition on children_table;
    /// 2. delete value assumes that self contains some value.
    pub unsafe fn copy_and_replace_fields(
        &self, new_value: Option<Option<Box<[u8]>>>,
        new_path: Option<CompressedPathRaw>,
        children_table: Option<ChildrenTableDeltaMpt>,
    ) -> MemOptimizedTrieNode<CacheAlgoDataT>
    {
        let mut ret = MemOptimizedTrieNode::default();

        match new_value {
            Some(maybe_value) => match maybe_value {
                Some(value) => {
                    ret.replace_value_valid(value);
                }
                None => {}
            },
            None => {
                let value_size = self.value_size as usize;
                ret.value_size = self.value_size;
                ret.value = MaybeInPlaceByteArray::copy_from(
                    self.value.get_slice(value_size),
                    value_size,
                );
            }
        }

        match new_path {
            Some(path) => ret.set_compressed_path(path),
            None => ret.copy_compressed_path(self.compressed_path_ref()),
        }

        match children_table {
            Some(table) => ret.children_table = table,
            None => ret.children_table = self.children_table.clone(),
        }

        ret
    }

    /// Returns: old_value, is_self_about_to_delete, replacement_node_for_self
    pub fn check_delete_value(&self) -> Result<TrieNodeAction> {
        if self.has_value() {
            Ok(match self.get_children_count() {
                0 => TrieNodeAction::Delete,
                1 => self.merge_path_action(),
                _ => TrieNodeAction::Modify,
            })
        } else {
            Err(ErrorKind::MPTKeyNotFound.into())
        }
    }

    fn merge_path_action(&self) -> TrieNodeAction {
        for (i, node_ref) in self.children_table.iter() {
            return TrieNodeAction::MergePath {
                child_index: i,
                child_node_ref: (*node_ref).into(),
            };
        }
        unsafe { unreachable_unchecked() }
    }

    fn merge_path_action_after_child_deletion(
        &self, child_index: u8,
    ) -> TrieNodeAction {
        for (i, node_ref) in self.children_table.iter() {
            if i != child_index {
                return TrieNodeAction::MergePath {
                    child_index: i,
                    child_node_ref: (*node_ref).into(),
                };
            }
        }
        unsafe { unreachable_unchecked() }
    }

    pub unsafe fn set_first_child_unchecked(
        &mut self, child_index: u8, child: NodeRefDeltaMptCompact,
    ) {
        self.children_table =
            ChildrenTableDeltaMpt::new_from_one_child(child_index, child);
    }

    /// Returns old_child, is_self_about_to_delete, replacement_node_for_self
    pub fn check_replace_or_delete_child_action(
        &self, child_index: u8, new_child_node: Option<NodeRefDeltaMptCompact>,
    ) -> TrieNodeAction {
        if new_child_node.is_none() {
            match self.get_children_count() {
                2 => {
                    return self
                        .merge_path_action_after_child_deletion(child_index);
                }
                _ => {}
            }
        }
        return TrieNodeAction::Modify;
    }

    pub fn get_merkle(&self) -> &MerkleHash { &self.merkle_hash }

    pub fn set_merkle(&mut self, merkle: &MerkleHash) {
        self.merkle_hash = merkle.clone();
    }
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> EntryTrait
    for MemOptimizedTrieNode<CacheAlgoDataT>
{
    type EntryType = MemOptimizedTrieNode<CacheAlgoDataT>;

    fn from_value(value: Self) -> Self { value }

    fn from_vacant_index(next: usize) -> Self {
        Self {
            slab_next_vacant_index: (next as u32)
                ^ NodeRefDeltaMptCompact::DIRTY_SLOT_LIMIT,
            children_table: Default::default(),
            merkle_hash: Default::default(),
            path_end_mask: 0,
            path_size: 0,
            path: Default::default(),
            path_memory_manager: Default::default(),
            value_size: 0,
            value: Default::default(),
            value_memory_manager: Default::default(),
            cache_algo_data: Default::default(),
        }
    }

    fn is_vacant(&self) -> bool {
        // A valid next vacant index can't be 0.
        self.slab_next_vacant_index != MaybeNodeRefDeltaMptCompact::NULL
    }

    fn take_occupied_and_replace_with_vacant_index(
        &mut self, next: usize,
    ) -> MemOptimizedTrieNode<CacheAlgoDataT> {
        std::mem::replace(self, Self::from_vacant_index(next))
    }

    fn get_next_vacant_index(&self) -> usize {
        (self.slab_next_vacant_index ^ NodeRefDeltaMptCompact::DIRTY_SLOT_LIMIT)
            as usize
    }

    fn get_occupied_ref(&self) -> &MemOptimizedTrieNode<CacheAlgoDataT> { self }

    fn get_occupied_mut(
        &mut self,
    ) -> &mut MemOptimizedTrieNode<CacheAlgoDataT> {
        self
    }
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> Encodable
    for MemOptimizedTrieNode<CacheAlgoDataT>
{
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_unbounded_list()
            .append(self.get_merkle())
            .append(&self.get_children_table_ref().to_ref())
            .append(&self.value_as_slice().into_option());

        let compressed_path_ref = self.compressed_path_ref();
        if compressed_path_ref.path_size() > 0 {
            s.append(&compressed_path_ref);
        }

        s.complete_unbounded_list();
    }
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> Decodable
    for MemOptimizedTrieNode<CacheAlgoDataT>
{
    fn decode(rlp: &Rlp) -> ::std::result::Result<Self, DecoderError> {
        let compressed_path = if rlp.item_count()? != 4 {
            CompressedPathRaw::new(&[], 0)
        } else {
            rlp.val_at(3)?
        };

        Ok(MemOptimizedTrieNode::new(
            MerkleHash::from_slice(rlp.val_at::<Vec<u8>>(0)?.as_slice()),
            rlp.val_at::<ChildrenTableManagedDeltaMpt>(1)?.into(),
            rlp.val_at::<Option<Vec<u8>>>(2)?
                .map(|v| v.into_boxed_slice()),
            compressed_path,
        ))
    }
}

impl<NodeRefT: 'static + NodeRefTrait> Encodable for VanillaTrieNode<NodeRefT>
where ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>
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

        s.complete_unbounded_list();
    }
}

impl<NodeRefT: 'static + NodeRefTrait> Decodable for VanillaTrieNode<NodeRefT>
where ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>
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

impl<CacheAlgoDataT: CacheAlgoDataTrait> PartialEq
    for MemOptimizedTrieNode<CacheAlgoDataT>
{
    fn eq(&self, other: &Self) -> bool {
        self.value_as_slice() == other.value_as_slice()
            && self.children_table == other.children_table
            && self.merkle_hash == other.merkle_hash
            && self.compressed_path_ref() == other.compressed_path_ref()
    }
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> Debug
    for MemOptimizedTrieNode<CacheAlgoDataT>
{
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f,
               "TrieNode{{ merkle: {:?}, value: {:?}, children_table: {:?}, compressed_path: {:?} }}",
               self.merkle_hash, self.value_as_slice(),
               &self.children_table, self.compressed_path_ref())
    }
}
