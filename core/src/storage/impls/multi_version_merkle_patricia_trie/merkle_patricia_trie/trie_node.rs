// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// TODO(yz): statically check the size to be "around" 64B + 64B (merkle_hash)
// TODO(yz): TrieNode should leave one byte so that it can be used to indicate a
// free slot in memory region, in order to implement EntryTrait.
/// A node consists of an optional compressed path (concept of Patricia
/// Trie), an optional ChildrenTable (if the node is intermediate), an
/// optional value attached, and the Merkle hash for subtree.
#[derive(Default)]
pub struct TrieNode<CacheAlgoDataT: CacheAlgoDataTrait> {
    /// CompactPath section. The CompactPath if defined as separate struct
    /// would consume 16B, while the current layout plus the
    /// previous u8 field consumes 16B in total and keep integers
    /// aligned.

    /// Can be: "no mask" (0x00), "second half" (second_nibble), "first half"
    /// (first_nibble). When there is only one half-byte in path and it's
    /// the "first half", both path_begin_mask and path_end_mask are set.
    /// This field is not used in comparison because matching one more
    /// half-byte at the beginning doesn't matter.
    // TODO(yz): remove since it's unused, now it's always 0.
    _path_begin_mask: u8,
    /// Can be: "no mask" (0x00), "first half" (first_nibble).
    /// When there is only one half-byte in path and it's the "second half",
    /// only path_begin_mask is set, path_end_mask is set to "no mask",
    /// because the first byte of path actually keeps the missing
    /// "first half" so that it still matches to the corresponding byte of the
    /// key.
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
    // TODO(yz): maybe unpack the fields from ChildrenTableDeltaMpt to save
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

    /// The merkle hash without the compressed path.
    pub(in super::super) merkle_hash: MerkleHash,

    pub(in super::super) cache_algo_data: CacheAlgoDataT,
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> Clone for TrieNode<CacheAlgoDataT> {
    fn clone(&self) -> Self {
        Self::new(
            &self.merkle_hash,
            self.children_table.clone(),
            self.value_clone().into_option(),
            self.compressed_path_ref().into(),
        )
    }
}

make_parallel_field_maybe_in_place_byte_array_memory_manager!(
    MemOptimizedTrieNodePathMemoryManager<CacheAlgoDataT> where <CacheAlgoDataT: CacheAlgoDataTrait>,
    TrieNode<CacheAlgoDataT>,
    path_memory_manager,
    path,
    path_size: u16,
    TrivialSizeFieldConverterU16,
);

make_parallel_field_maybe_in_place_byte_array_memory_manager!(
    MemOptimizedTrieNodeValueMemoryManager<CacheAlgoDataT> where <CacheAlgoDataT: CacheAlgoDataTrait>,
    TrieNode<CacheAlgoDataT>,
    value_memory_manager,
    value,
    value_size: u32,
    TrieNodeValueSizeFieldConverter,
);

/// Compiler is not sure about the pointer in MaybeInPlaceByteArray fields.
/// It's Send because TrieNode is move only and it's impossible to change any
/// part of it without &mut.
unsafe impl<CacheAlgoDataT: CacheAlgoDataTrait> Send
    for TrieNode<CacheAlgoDataT>
{
}
/// Compiler is not sure about the pointer in MaybeInPlaceByteArray fields.
/// We do not allow a &TrieNode to be able to change anything the pointer
/// is pointing to, therefore TrieNode is Sync.
unsafe impl<CacheAlgoDataT: CacheAlgoDataTrait> Sync
    for TrieNode<CacheAlgoDataT>
{
}

#[derive(Default)]
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

impl<CacheAlgoDataT: CacheAlgoDataTrait> TrieNode<CacheAlgoDataT> {
    pub fn get_compressed_path_size(&self) -> u16 { self.path_size }

    pub fn compressed_path_ref(&self) -> CompressedPathRef {
        let size = self.path_size;
        CompressedPathRef {
            path_slice: self.path.get_slice(size as usize),
            end_mask: self.path_end_mask,
        }
    }

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

    pub fn set_compressed_path(&mut self, mut path: CompressedPathRaw) {
        self.path_end_mask = path.end_mask();

        path.byte_array_memory_manager
            .move_to(&mut self.path_memory_manager);
    }

    pub fn has_value(&self) -> bool { self.value_size > 0 }

    fn get_children_count(&self) -> u8 {
        self.children_table.get_children_count()
    }

    pub fn value_as_slice(&self) -> MptValue<&[u8]> {
        let size = self.value_size;
        if size == 0 {
            MptValue::None
        } else if size == TrieNodeValueSizeFieldConverter::VALUE_TOMBSTONE {
            MptValue::TombStone
        } else {
            MptValue::Some(self.value.get_slice(size as usize))
        }
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

    pub fn replace_value_valid(
        &mut self, valid_value: &[u8],
    ) -> MptValue<Box<[u8]>> {
        let old_value = self.value_into_boxed_slice();
        let value_size = valid_value.len();
        if value_size == 0 {
            self.value_size = TrieNodeValueSizeFieldConverter::VALUE_TOMBSTONE;
        } else {
            self.value =
                MaybeInPlaceByteArray::copy_from(valid_value, value_size);
            self.value_size = value_size as u32;
        }

        old_value
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

    pub fn create_proof_node(&self) -> TrieProofNode {
        TrieProofNode {
            path_end_mask: self.path_end_mask,
            path: self
                .path
                .get_slice(self.get_compressed_path_size() as usize)
                .into(),
            value: self
                .value_clone()
                .into_option()
                .map(Into::into)
                .unwrap_or_default(),
            children_table: vec![],
            merkle_hash: self.merkle_hash,
        }
    }
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> TrieNode<CacheAlgoDataT> {
    pub fn walk<'key, AM: AccessMode>(
        &self, key: KeyPart<'key>,
    ) -> WalkStop<'key, NodeRefDeltaMpt> {
        walk::<AM, NodeRefDeltaMpt>(
            key,
            self.compressed_path_ref(),
            self.path_end_mask,
            &|index| self.get_child(index).map(Into::into),
        )
    }
}

/// The actions for the logical trie. Since we maintain a multiple version trie
/// the action must be translated into trie node operations, which may vary
/// depends on whether the node is owned by current version, etc.
pub enum TrieNodeAction {
    Modify,
    Delete,
    MergePath {
        child_index: u8,
        child_node_ref: NodeRefDeltaMpt,
    },
}

/// Update
impl<CacheAlgoDataT: CacheAlgoDataTrait> TrieNode<CacheAlgoDataT> {
    pub fn new(
        merkle: &MerkleHash, children_table: ChildrenTableDeltaMpt,
        maybe_value: Option<Box<[u8]>>, compressed_path: CompressedPathRaw,
    ) -> TrieNode<CacheAlgoDataT>
    {
        let mut ret = TrieNode::default();

        ret.merkle_hash = *merkle;
        ret.children_table = children_table;
        match maybe_value {
            None => {}
            Some(value) => {
                ret.replace_value_valid(value.as_ref());
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
        &self, new_value: Option<Option<&[u8]>>,
        new_path: Option<CompressedPathRaw>,
        children_table: Option<ChildrenTableDeltaMpt>,
    ) -> TrieNode<CacheAlgoDataT>
    {
        let mut ret = TrieNode::default();

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

    /// Delete value when we know that it already exists.
    pub unsafe fn delete_value_unchecked(&mut self) -> Box<[u8]> {
        self.value_into_boxed_slice().unwrap()
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

    fn get_child(&self, child_index: u8) -> Option<NodeRefDeltaMptCompact> {
        self.children_table.get_child(child_index)
    }

    pub unsafe fn set_first_child_unchecked(
        &mut self, child_index: u8, child: NodeRefDeltaMptCompact,
    ) {
        self.children_table =
            ChildrenTableDeltaMpt::new_from_one_child(child_index, child);
    }

    pub unsafe fn add_new_child_unchecked(
        &mut self, child_index: u8, child: NodeRefDeltaMptCompact,
    ) {
        self.children_table = CompactedChildrenTable::insert_child_unchecked(
            self.children_table.to_ref(),
            child_index,
            child,
        );
    }

    /// Unsafe because it's assumed that the child_index already exists.
    pub unsafe fn delete_child_unchecked(&mut self, child_index: u8) {
        self.children_table = CompactedChildrenTable::delete_child_unchecked(
            self.children_table.to_ref(),
            child_index,
        );
    }

    /// Unsafe because it's assumed that the child_index already exists.
    pub unsafe fn replace_child_unchecked(
        &mut self, child_index: u8, new_child_node: NodeRefDeltaMptCompact,
    ) {
        self.children_table
            .set_child_unchecked(child_index, new_child_node);
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
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> Encodable
    for TrieNode<CacheAlgoDataT>
{
    fn rlp_append(&self, s: &mut RlpStream) {
        // Format: [ merkle, children_table ([] or [*16], value (maybe empty) ]
        // ( + [compressed_path] )
        s.begin_unbounded_list()
            .append(&self.merkle_hash)
            .append(&self.children_table.to_ref())
            .append(&self.value_as_slice().into_option());

        let compressed_path_ref = self.compressed_path_ref();
        if compressed_path_ref.path_slice.len() > 0 {
            s.append(&compressed_path_ref);
        }

        s.complete_unbounded_list();
    }
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> Decodable
    for TrieNode<CacheAlgoDataT>
{
    fn decode(rlp: &Rlp) -> ::std::result::Result<Self, DecoderError> {
        let compressed_path;
        if rlp.item_count()? != 4 {
            compressed_path = CompressedPathRaw::new(&[], 0);
        } else {
            compressed_path = rlp.val_at(3)?;
        }

        Ok(TrieNode::new(
            &rlp.val_at::<Vec<u8>>(0)?.as_slice().into(),
            rlp.val_at::<ChildrenTableManagedDeltaMpt>(1)?.into(),
            rlp.val_at::<Option<Vec<u8>>>(2)?
                .map(|v| v.into_boxed_slice()),
            compressed_path,
        ))
    }
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> PartialEq
    for TrieNode<CacheAlgoDataT>
{
    fn eq(&self, other: &Self) -> bool {
        self.value_as_slice() == other.value_as_slice()
            && self.children_table == other.children_table
            && self.merkle_hash == other.merkle_hash
            && self.compressed_path_ref() == other.compressed_path_ref()
    }
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> Debug for TrieNode<CacheAlgoDataT> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "TrieNode{{ merkle: {:?}, value: {:?}, children_table: {:?}, compressed_path: {:?} }}",
               self.merkle_hash, self.value_as_slice(),
               &self.children_table, self.compressed_path_ref())
    }
}

use super::{
    super::{
        super::errors::*, cache::algorithm::CacheAlgoDataTrait, node_ref::*,
    },
    children_table::*,
    compressed_path::*,
    maybe_in_place_byte_array::*,
    mpt_value::MptValue,
    trie_proof::TrieProofNode,
    walk::{access_mode::AccessMode, walk, KeyPart, WalkStop},
};
use primitives::MerkleHash;
use rlp::*;
use std::{
    fmt::{Debug, Formatter},
    hint::unreachable_unchecked,
    marker::{Send, Sync},
    vec::Vec,
};
