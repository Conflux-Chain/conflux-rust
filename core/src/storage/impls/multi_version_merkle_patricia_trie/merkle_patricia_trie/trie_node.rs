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
    /// The number of children plus one if there is value attached.
    /// After a delete operation, when there is no value attached to this
    /// path, and if there is only one child left, path compression
    /// should apply. Path compression can only happen when
    /// number_of_children_plus_value drop from 2 to 1.
    // TODO(yz): refactor out this value. Move the number_of_children counter
    // to children_table.
    number_of_children_plus_value: u8,

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
    path_begin_mask: u8,
    /// Can be: "no mask" (0x00), "first half" (first_nibble).
    /// When there is only one half-byte in path and it's the "second half",
    /// only path_begin_mask is set, path_end_mask is set to "no mask",
    /// because the first byte of path actually keeps the missing
    /// "first half" so that it still matches to the corresponding byte of the
    /// key.
    path_end_mask: u8,
    /// 4 bits per step.
    /// We limit the maximum key steps by u16.
    path_steps: u16,
    path: MaybeInPlaceByteArray,
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

    /// The merkle hash without the compressed path.
    pub(in super::super) merkle_hash: MerkleHash,

    pub(in super::super) cache_algo_data: CacheAlgoDataT,
}

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

/// Key length should be multiple of 8.
// TODO(yz): align key @8B with mask.
pub type KeyPart<'a> = &'a [u8];
const EMPTY_KEY_PART: KeyPart = &[];

impl<CacheAlgoDataT: CacheAlgoDataTrait> Drop for TrieNode<CacheAlgoDataT> {
    fn drop(&mut self) {
        unsafe {
            let size = self.value_size as usize;
            if size > MaybeInPlaceByteArray::MAX_INPLACE_SIZE {
                self.value.ptr_into_vec(size);
            }

            self.clear_path();
        }
    }
}

impl<CacheAlgoDataT: CacheAlgoDataTrait> TrieNode<CacheAlgoDataT> {
    const MAX_VALUE_SIZE: usize = 0xfffffffe;
    /// A special value to use in Delta Mpt to indicate that the value is
    /// deleted.
    ///
    /// In current implementation the TOMBSTONE is represented by empty string
    /// in serialized trie node and in methods manipulating value for trie
    /// node / MPT.
    const VALUE_TOMBSTONE: u32 = 0xffffffff;

    pub fn get_compressed_path_size(&self) -> u16 {
        (self.path_steps / 2)
            + (((self.path_begin_mask | self.path_end_mask) != 0) as u16)
    }

    pub fn compressed_path_ref(&self) -> CompressedPathRef {
        let size = self.get_compressed_path_size();
        CompressedPathRef {
            path_slice: self.path.get_slice(size as usize),
            end_mask: self.path_end_mask,
        }
    }

    unsafe fn clear_path(&mut self) {
        let size = self.get_compressed_path_size() as usize;
        if size > MaybeInPlaceByteArray::MAX_INPLACE_SIZE {
            self.path.ptr_into_vec(size);
        }
    }

    fn compute_path_steps(path_size: u16, end_mask: u8) -> u16 {
        path_size * 2 - (end_mask != 0) as u16
    }

    pub fn copy_compressed_path(&mut self, new_path: CompressedPathRef) {
        let path_slice = new_path.path_slice;

        // Remove old path.
        unsafe {
            self.clear_path();
        }

        self.path_steps = Self::compute_path_steps(
            path_slice.len() as u16,
            new_path.end_mask,
        );
        self.path_end_mask = new_path.end_mask;
        self.path =
            MaybeInPlaceByteArray::copy_from(path_slice, path_slice.len());
    }

    pub fn set_compressed_path(&mut self, path: CompressedPathRaw) {
        // Remove old path.
        unsafe {
            self.clear_path();
        }

        self.path_steps =
            Self::compute_path_steps(path.path_size, path.end_mask());
        self.path_end_mask = path.end_mask();
        self.path = path.path;
    }

    pub fn has_value(&self) -> bool { self.value_size > 0 }

    fn get_children_count(&self) -> u8 {
        self.children_table.get_children_count()
    }

    pub fn value_as_slice(&self) -> MptValue<&[u8]> {
        let size = self.value_size;
        if size == 0 {
            MptValue::None
        } else if size == Self::VALUE_TOMBSTONE {
            MptValue::TombStone
        } else {
            MptValue::Some(self.value.get_slice(size as usize))
        }
    }

    pub fn value_clone(&self) -> MptValue<Box<[u8]>> {
        let size = self.value_size;
        if size == 0 {
            MptValue::None
        } else if size == Self::VALUE_TOMBSTONE {
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
            if size == Self::VALUE_TOMBSTONE {
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
            self.value_size = Self::VALUE_TOMBSTONE;
        } else {
            self.value =
                MaybeInPlaceByteArray::copy_from(valid_value, value_size);
            self.value_size = value_size as u32;
        }

        old_value
    }

    pub fn check_value_size(value: &[u8]) -> Result<()> {
        let value_size = value.len();
        if value_size > Self::MAX_VALUE_SIZE {
            // TODO(yz): value too long.
            return Err(Error::from_kind(ErrorKind::MPTInvalidValue));
        }
        // We may use empty value to represent special state, such as tombstone.
        // Therefore We don't check for emptiness.

        Ok(())
    }

    pub fn check_key_size(access_key: &[u8]) -> Result<()> {
        let key_size = access_key.len();
        if key_size > MaybeInPlaceByteArray::MAX_SIZE_U16 {
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

pub enum WalkStop<'key> {
    // path matching fails at some point. Want the new path_steps,
    // path_end_mask, ..., etc Basically, a new node should be created to
    // replace the current node from parent children table;
    // modify this node or create a new node to insert as children of new
    // node, (update path) then
    // the child that should be followed is nil at the new node.
    // if put single version, this node changes, this node replaced, parent
    // update child and merkle. Before merkle update, this node must be saved
    // in mem or into disk db (not that expensive). if get / delete (not
    // found)
    PathDiverted {
        /// Key may terminate on the path.
        key_child_index: Option<u8>,
        key_remaining: KeyPart<'key>,
        matched_path: CompressedPathRaw,
        unmatched_child_index: u8,
        unmatched_path_remaining: CompressedPathRaw,
    },

    // If exactly at this node.
    // if put, update this node
    // if delete, may cause deletion / path compression (delete this node,
    // parent update child, update path of original child node)
    Arrived,

    Descent {
        key_remaining: KeyPart<'key>,
        child_index: u8,
        child_node: NodeRefDeltaMpt,
    },

    // To descent, however child doesn't exists:
    // to modify this node or create a new node to replace this node (update
    // child) Then create a new node for remaining key_part (we don't care
    // about begin_mask). if put single version, this node changes, parent
    // update merkle. if get / delete (not found)
    ChildNotFound {
        key_remaining: KeyPart<'key>,
        child_index: u8,
    },
}

impl<'key> WalkStop<'key> {
    fn child_not_found_uninitialized() -> Self {
        WalkStop::ChildNotFound {
            key_remaining: Default::default(),
            child_index: 0,
        }
    }

    fn path_diverted_uninitialized() -> Self {
        WalkStop::PathDiverted {
            key_child_index: None,
            key_remaining: Default::default(),
            matched_path: Default::default(),
            unmatched_child_index: 0,
            unmatched_path_remaining: Default::default(),
        }
    }
}

pub mod access_mode {
    pub trait AccessMode {
        fn is_read_only() -> bool;
    }

    pub struct Read {}
    pub struct Write {}

    impl AccessMode for Read {
        fn is_read_only() -> bool { return true; }
    }

    impl AccessMode for Write {
        fn is_read_only() -> bool { return false; }
    }
}

/// Traverse.
impl<CacheAlgoDataT: CacheAlgoDataTrait> TrieNode<CacheAlgoDataT> {
    // TODO(yz): write test.
    /// The start of key is always aligned with compressed path of
    /// current node, e.g. if compressed path starts at the second-half, so
    /// should be key.
    pub fn walk<'key, AM: AccessMode>(
        &self, key: KeyPart<'key>,
    ) -> WalkStop<'key> {
        let path = self.compressed_path_ref();
        let path_slice = path.path_slice;

        // Compare bytes till the last full byte. The first byte is always
        // included because even if it's the second-half, it must be
        // already matched before entering this TrieNode.
        let memcmp_len = min(
            path_slice.len() - ((path.end_mask != 0) as usize),
            key.len(),
        );

        for i in 0..memcmp_len {
            if path_slice[i] != key[i] {
                if AM::is_read_only() {
                    return WalkStop::path_diverted_uninitialized();
                } else {
                    let matched_path: CompressedPathRaw;
                    let key_child_index: u8;
                    let key_remaining: &[u8];
                    let unmatched_child_index: u8;
                    let unmatched_path_remaining: &[u8];

                    if CompressedPathRaw::first_nibble(path_slice[i] ^ key[i])
                        == 0
                    {
                        // "First half" matched
                        matched_path = CompressedPathRaw::new_and_apply_mask(
                            &path_slice[0..i + 1],
                            CompressedPathRaw::first_nibble(!0),
                        );

                        key_child_index =
                            CompressedPathRaw::second_nibble(key[i]);
                        key_remaining = &key[i + 1..];
                        unmatched_child_index =
                            CompressedPathRaw::second_nibble(path_slice[i]);
                        unmatched_path_remaining = &path_slice[i + 1..];
                    } else {
                        matched_path =
                            CompressedPathRaw::new(&path_slice[0..i], 0);
                        key_child_index =
                            CompressedPathRaw::first_nibble(key[i]);
                        key_remaining = &key[i..];
                        unmatched_child_index =
                            CompressedPathRaw::first_nibble(path_slice[i]);
                        unmatched_path_remaining = &path_slice[i..];
                    }
                    return WalkStop::PathDiverted {
                        key_child_index: Some(key_child_index),
                        key_remaining: key_remaining.into(),
                        matched_path: matched_path,
                        unmatched_child_index: unmatched_child_index,
                        unmatched_path_remaining: CompressedPathRaw::new(
                            unmatched_path_remaining,
                            self.path_end_mask,
                        ),
                    };
                }
            }
        }
        // Key is fully consumed, get value attached.
        if key.len() == memcmp_len {
            // Compressed path isn't fully consumed.
            if path_slice.len() > memcmp_len {
                if AM::is_read_only() {
                    return WalkStop::path_diverted_uninitialized();
                } else {
                    return WalkStop::PathDiverted {
                        // key_remaining is empty, and key_child_index doesn't
                        // make sense, but we need to
                        // mark it.
                        key_remaining: Default::default(),
                        key_child_index: None,
                        matched_path: CompressedPathRaw::new(
                            &path_slice[0..memcmp_len],
                            0,
                        ),
                        unmatched_child_index: CompressedPathRaw::first_nibble(
                            path_slice[memcmp_len],
                        ),
                        unmatched_path_remaining: CompressedPathRaw::new(
                            &path_slice[memcmp_len..],
                            self.path_end_mask,
                        ),
                    };
                }
            } else {
                return WalkStop::Arrived;
            }
        } else {
            // Key is not fully consumed.

            // When path is fully consumed, check if child exists under
            // child_index.
            let child_index;
            let key_remaining;

            if path_slice.len() == memcmp_len {
                // Compressed path is fully consumed. Descend into one child.
                child_index = CompressedPathRaw::first_nibble(key[memcmp_len]);
                key_remaining = &key[memcmp_len..];
            } else {
                // One half byte remaining to match with path. Consume it in the
                // key.
                if CompressedPathRaw::first_nibble(
                    path_slice[memcmp_len] ^ key[memcmp_len],
                ) != 0
                {
                    // Mismatch.
                    if AM::is_read_only() {
                        return WalkStop::path_diverted_uninitialized();
                    } else {
                        return WalkStop::PathDiverted {
                            key_child_index: Some(
                                CompressedPathRaw::first_nibble(
                                    key[memcmp_len],
                                ),
                            ),
                            key_remaining: &key[memcmp_len..],
                            matched_path: CompressedPathRaw::new(
                                &path_slice[0..memcmp_len],
                                0,
                            ),
                            unmatched_child_index:
                                CompressedPathRaw::first_nibble(
                                    path_slice[memcmp_len],
                                ),
                            unmatched_path_remaining: CompressedPathRaw::new(
                                &path_slice[memcmp_len..],
                                self.path_end_mask,
                            ),
                        };
                    }
                } else {
                    child_index =
                        CompressedPathRaw::second_nibble(key[memcmp_len]);
                    key_remaining = &key[memcmp_len + 1..];
                }
            }

            match self.get_child(child_index) {
                Option::None => {
                    if AM::is_read_only() {
                        return WalkStop::child_not_found_uninitialized();
                    }
                    return WalkStop::ChildNotFound {
                        key_remaining: key_remaining,
                        child_index: child_index,
                    };
                }
                Option::Some(child_node) => {
                    return WalkStop::Descent {
                        key_remaining: key_remaining,
                        child_node: child_node.into(),
                        child_index: child_index,
                    };
                }
            }
        }
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
        maybe_value: Option<Vec<u8>>, compressed_path: CompressedPathRaw,
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
                None => {
                    ret.delete_value_unchecked();
                }
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

    pub fn path_prepended(
        &self, prefix: CompressedPathRaw, child_index: u8,
    ) -> CompressedPathRaw {
        let prefix_size = prefix.path_slice().len();
        let path_size = self.get_compressed_path_size();
        // TODO(yz): it happens to be the same no matter what end_mask is,
        // because u8 = 2 nibbles. When we switch to u32 as path unit
        // the concated size may vary.
        let concated_size = prefix_size as u16 + path_size;

        let path = self.compressed_path_ref();

        let mut new_path =
            CompressedPathRaw::new_zeroed(concated_size, path.end_mask);

        {
            let slice = new_path.path.get_slice_mut(concated_size as usize);
            if prefix.end_mask() == 0 {
                slice[0..prefix_size].copy_from_slice(prefix.path_slice());
                slice[prefix_size..].copy_from_slice(path.path_slice);
            } else {
                slice[0..prefix_size - 1]
                    .copy_from_slice(&prefix.path_slice()[0..prefix_size - 1]);
                slice[prefix_size - 1] = CompressedPathRaw::set_second_nibble(
                    prefix.path_slice()[prefix_size - 1],
                    child_index,
                );
                slice[prefix_size..].copy_from_slice(path.path_slice);
            }
        }

        new_path
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
            rlp.val_at::<Option<Vec<u8>>>(2)?,
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

use self::access_mode::*;
use super::{
    super::{
        super::errors::*, cache::algorithm::CacheAlgoDataTrait, merkle::*,
        node_ref::*,
    },
    children_table::*,
    compressed_path::*,
    maybe_in_place_byte_array::MaybeInPlaceByteArray,
    mpt_value::MptValue,
};
use rlp::*;
use std::{
    cmp::min,
    fmt::{Debug, Formatter},
    hint::unreachable_unchecked,
    marker::{Send, Sync},
    vec::Vec,
};
