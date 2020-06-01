// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait NodeRefTrait:
    Copy + Clone + Encodable + Decodable + PartialEq + Debug
{
}

impl NodeRefTrait for MerkleHash {}

#[derive(Clone, Debug, PartialEq)]
pub struct VanillaChildrenTable<NodeRefT: NodeRefTrait> {
    table: [NodeRefT; CHILDREN_COUNT],
    // TODO(yz): Use bitmap to save space for rlp format.
    // TODO(yz): the proof format may differ.
    children_count: u8,
}

impl From<ChildrenMerkleTable> for VanillaChildrenTable<MerkleHash> {
    fn from(x: ChildrenMerkleTable) -> Self {
        let mut children_count = 0;
        for merkle in &x {
            if !merkle.eq(ChildrenTableItem::<MerkleHash>::no_child()) {
                children_count += 1;
            }
        }
        Self {
            table: x,
            children_count,
        }
    }
}

impl From<MaybeMerkleTable> for VanillaChildrenTable<MerkleHash> {
    fn from(x: MaybeMerkleTable) -> Self {
        match x {
            None => Self::default(),
            Some(t) => t.into(),
        }
    }
}

pub trait DefaultChildrenItem<NodeRefT: NodeRefTrait> {
    fn no_child() -> &'static NodeRefT;
}

pub struct ChildrenTableItem<NodeRefT: NodeRefTrait> {
    _marker: PhantomData<NodeRefT>,
}

impl DefaultChildrenItem<MerkleHash> for ChildrenTableItem<MerkleHash> {
    fn no_child() -> &'static MerkleHash { &MERKLE_NULL_NODE }
}

impl<NodeRefT: NodeRefTrait> WrappedCreateFrom<NodeRefT, NodeRefT>
    for ChildrenTableItem<NodeRefT>
{
    fn take(x: NodeRefT) -> NodeRefT { x }
}

impl<'x, NodeRefT: NodeRefTrait> WrappedCreateFrom<&'x NodeRefT, NodeRefT>
    for ChildrenTableItem<NodeRefT>
{
    fn take(x: &'x NodeRefT) -> NodeRefT { x.clone() }

    fn take_from(dest: &mut NodeRefT, x: &'x NodeRefT) { dest.clone_from(x); }
}

impl<NodeRefT: 'static + NodeRefTrait> Default
    for VanillaChildrenTable<NodeRefT>
where ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>
{
    fn default() -> Self {
        Self {
            children_count: 0,
            table: [ChildrenTableItem::<NodeRefT>::no_child().clone();
                CHILDREN_COUNT],
        }
    }
}

impl<NodeRefT: 'static + NodeRefTrait> VanillaChildrenTable<NodeRefT> {
    // FIXME: put most method in a trait.

    pub fn new_from_one_child(child_index: u8, child: &NodeRefT) -> Self
    where ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT> {
        let mut table = VanillaChildrenTable::default();
        table.children_count = 1;
        table.table[child_index as usize] = child.clone();
        table
    }

    pub fn get_children_table(&self) -> &[NodeRefT; CHILDREN_COUNT] {
        &self.table
    }

    pub fn get_children_count(&self) -> u8 { self.children_count }

    pub unsafe fn get_children_count_mut(&mut self) -> &mut u8 {
        &mut self.children_count
    }

    pub fn get_child(&self, child_index: u8) -> Option<&NodeRefT>
    where ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT> {
        let child_ref =
            unsafe { self.table.get_unchecked(child_index as usize) };
        if child_ref.eq(ChildrenTableItem::<NodeRefT>::no_child()) {
            None
        } else {
            Some(child_ref)
        }
    }

    pub unsafe fn get_child_mut_unchecked(
        &mut self, child_index: u8,
    ) -> &mut NodeRefT {
        self.table.get_unchecked_mut(child_index as usize)
    }

    pub fn iter(&self) -> VanillaChildrenTableIterator<NodeRefT> {
        VanillaChildrenTableIterator {
            next_child_index: 0,
            table: &self.table,
        }
    }
}

// TODO(yz): Use bitmap to save space for rlp format.
// TODO(yz): the proof format may differ.
impl<NodeRefT: 'static + NodeRefTrait> Encodable
    for VanillaChildrenTable<NodeRefT>
where ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>
{
    fn rlp_append(&self, s: &mut RlpStream) {
        if self.children_count == 0 {
            s.begin_list(0);
        } else {
            s.append_list(&self.table[..]);
        };
    }
}

impl<NodeRefT: 'static + NodeRefTrait> Decodable
    for VanillaChildrenTable<NodeRefT>
where ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>
{
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        if rlp.is_empty() {
            Ok(Default::default())
        } else {
            let mut table: [NodeRefT; CHILDREN_COUNT] =
                unsafe { std::mem::uninitialized() };
            let mut children_count = 0;
            for i in 0..16 {
                table[i] = rlp.val_at::<NodeRefT>(i)?;
                if !table[i].eq(ChildrenTableItem::<NodeRefT>::no_child()) {
                    children_count += 1;
                }
            }

            Ok(VanillaChildrenTable {
                table,
                children_count,
            })
        }
    }
}

pub struct VanillaChildrenTableIterator<'a, NodeRefT: NodeRefTrait> {
    next_child_index: u8,
    table: &'a [NodeRefT; CHILDREN_COUNT],
}

impl<'a, NodeRefT: 'static + NodeRefTrait> Iterator
    for VanillaChildrenTableIterator<'a, NodeRefT>
where ChildrenTableItem<NodeRefT>: DefaultChildrenItem<NodeRefT>
{
    type Item = (u8, &'a NodeRefT);

    fn next(&mut self) -> Option<Self::Item> {
        while (self.next_child_index as usize) < CHILDREN_COUNT {
            let child_index = self.next_child_index;
            let child_ref = unsafe {
                self.table.get_unchecked(self.next_child_index as usize)
            };
            self.next_child_index = child_index + 1;
            if !child_ref.eq(ChildrenTableItem::<NodeRefT>::no_child()) {
                return Some((child_index, child_ref));
            }
        }
        None
    }
}

impl<'a, NodeRefT: NodeRefTrait> ChildrenTableIteratorStartIndex
    for VanillaChildrenTableIterator<'a, NodeRefT>
{
    fn set_start_index(mut self, index: u8) -> Self {
        self.next_child_index = index;
        self
    }
}

/// NodeRefT for delta MPT and persistent MPT can be different.
pub struct CompactedChildrenTable<NodeRefT: NodeRefTrait> {
    /// Stores whether each child exists.
    bitmap: u16,
    /// Stores the number of children in children table.
    children_count: u8,
    /// Stores the existing children ordered.
    table_ptr: *mut NodeRefT,
}

pub const CHILDREN_COUNT: usize = 16;

impl<NodeRefT: NodeRefTrait> Default for CompactedChildrenTable<NodeRefT> {
    fn default() -> Self {
        Self {
            bitmap: 0,
            children_count: 0,
            table_ptr: null_mut(),
        }
    }
}

impl<NodeRefT: NodeRefTrait> Clone for CompactedChildrenTable<NodeRefT> {
    fn clone(&self) -> Self { self.to_ref().into() }
}

impl<NodeRefT: NodeRefTrait> Debug for CompactedChildrenTable<NodeRefT> {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "ChildrenTable{{ {:?} }}", self.to_ref())
    }
}

impl<NodeRefT: NodeRefTrait> CompactedChildrenTable<NodeRefT> {
    pub fn get_children_count(&self) -> u8 { self.children_count }

    pub fn get_child(&self, index: u8) -> Option<NodeRefT> {
        if Self::has_index(self.bitmap, index) {
            Some(unsafe {
                (*self.table_ptr.add(Self::lower_bound(self.bitmap, index)))
                    .clone()
            })
        } else {
            None
        }
    }

    pub unsafe fn get_child_mut_unchecked(
        &mut self, index: u8,
    ) -> &mut NodeRefT {
        &mut *self.table_ptr.add(Self::lower_bound(self.bitmap, index))
    }

    /// Unsafe because child must already exist at the index.
    pub unsafe fn set_child_unchecked(&mut self, index: u8, value: NodeRefT) {
        *self.table_ptr.add(Self::lower_bound(self.bitmap, index)) =
            value.clone();
    }

    pub fn new_from_one_child(index: u8, value: NodeRefT) -> Self {
        Self {
            bitmap: Self::bit(index.into()),
            children_count: 1,
            table_ptr: unsafe {
                Self::managed_slice_into_raw(vec![value].into_boxed_slice())
            },
        }
    }

    pub unsafe fn insert_child_unchecked(
        old_table: ChildrenTableRef<NodeRefT>, index: u8, value: NodeRefT,
    ) -> Self {
        let insertion_pos = Self::lower_bound(old_table.bitmap, index);
        Self {
            bitmap: old_table.bitmap | Self::bit(index.into()),
            children_count: old_table.table.len() as u8 + 1,
            table_ptr: Self::managed_slice_into_raw(
                [
                    &old_table.table[0..insertion_pos],
                    &[value],
                    &old_table.table[insertion_pos..],
                ]
                .concat()
                .into_boxed_slice(),
            ),
        }
    }

    pub unsafe fn delete_child_unchecked(
        old_table: ChildrenTableRef<NodeRefT>, index: u8,
    ) -> Self {
        let deletion_pos = Self::lower_bound(old_table.bitmap, index);
        Self {
            bitmap: old_table.bitmap & (!Self::bit(index.into())),
            children_count: old_table.table.len() as u8 - 1,
            table_ptr: Self::managed_slice_into_raw(
                [
                    &old_table.table[0..deletion_pos],
                    &old_table.table[deletion_pos + 1..],
                ]
                .concat()
                .into_boxed_slice(),
            ),
        }
    }
}

#[cfg(test)]
impl<NodeRefT: NodeRefTrait> CompactedChildrenTable<NodeRefT> {
    pub fn assert_no_alloc_in_empty_children_table(&self) {
        assert_eq!(
            true,
            self.children_count != 0
                || self.table_ptr == null_mut()
                || self.table_ptr as usize == mem::align_of::<NodeRefT>()
        )
    }
}

impl<NodeRefT: NodeRefTrait> Drop for CompactedChildrenTable<NodeRefT> {
    fn drop(&mut self) {
        if self.children_count != 0 {
            drop(unsafe { self.into_managed_slice() });
        } else {
            // When children_count is 0, the table_ptr must be null.
            // If the table_ptr is an "empty array" there could be memory leak.
            //
            // The assertion is commented out here because it's checked in unit
            // test.
            /*
            assert_eq!(
                true,
                self.table_ptr == null_mut()
                    || self.table_ptr as usize == mem::align_of::<NodeRefT>()
            );
            */
        }
    }
}

impl<NodeRefT: NodeRefTrait> CompactedChildrenTable<NodeRefT> {
    unsafe fn into_managed_slice(&self) -> Option<Vec<NodeRefT>> {
        if self.children_count != 0 {
            Some(Vec::from_raw_parts(
                self.table_ptr,
                self.children_count.into(),
                self.children_count.into(),
            ))
        } else {
            None
        }
    }

    unsafe fn managed_slice_into_raw(
        mut managed: Box<[NodeRefT]>,
    ) -> *mut NodeRefT {
        // If the slice has length 0, the pointer returned from as_mut_ptr
        // isn't NULL, but alignment of the type in rust's stdlib
        // implementation. This is OK because we always check (unless
        // otherwise specified) before using the pointer.
        let ret = managed.as_mut_ptr();

        mem::forget(managed);
        ret
    }

    pub fn from_managed(managed: ChildrenTable<NodeRefT>) -> Self {
        let children_count = managed.table.len() as u8;
        Self {
            bitmap: managed.bitmap,
            table_ptr: unsafe { Self::managed_slice_into_raw(managed.table) },
            children_count,
        }
    }

    pub fn to_ref(&self) -> ChildrenTableRef<NodeRefT> {
        ChildrenTableRef {
            table: unsafe {
                slice::from_raw_parts(
                    self.table_ptr,
                    self.children_count.into(),
                )
            },
            bitmap: self.bitmap,
        }
    }

    pub fn from_ref<'a>(r: ChildrenTableRef<'a, NodeRefT>) -> Self {
        Self {
            bitmap: r.bitmap,
            table_ptr: unsafe {
                Self::managed_slice_into_raw(r.table.to_vec().into())
            },
            children_count: r.table.len() as u8,
        }
    }
}

impl<NodeRefT: NodeRefTrait> CompactedChildrenTable<NodeRefT> {
    fn bit(index: u16) -> u16 { 1 << index }

    fn has_index(bitmap: u16, index: u8) -> bool {
        Self::bit(index.into()) & bitmap != 0
    }

    fn lower_bits(index: u16) -> u16 { (1 << index) - 1 }

    fn all_bits() -> u16 { !0 }

    fn count_bits(bitmap: u16) -> u16 {
        let mut count = (bitmap & 0b0101010101010101)
            + ((bitmap >> 1) & 0b0101010101010101);
        count =
            (count & 0b0011001100110011) + ((count >> 2) & 0b0011001100110011);
        count =
            (count & 0b0000111100001111) + ((count >> 4) & 0b0000111100001111);
        (count & 0b0000000011111111) + (count >> 8)
    }

    fn lowest_bit_at(bitmap: u16) -> u8 {
        Self::count_bits(1 ^ bitmap ^ (bitmap - 1)) as u8
    }

    fn remove_lowest_bit(bitmap: u16) -> u16 { bitmap & (bitmap - 1) }

    fn lower_bound(bitmap: u16, index: u8) -> usize {
        Self::count_bits(bitmap & Self::lower_bits(index.into())).into()
    }
}

impl<NodeRefT: NodeRefTrait> CompactedChildrenTable<NodeRefT> {
    pub fn iter(&self) -> CompactedChildrenTableIterator<NodeRefT> {
        CompactedChildrenTableIterator {
            elements: self.table_ptr,
            bitmap: self.bitmap,
            __marker: PhantomData,
        }
    }

    pub fn iter_mut(&mut self) -> CompactedChildrenTableIteratorMut<NodeRefT> {
        CompactedChildrenTableIteratorMut {
            elements: self.table_ptr,
            bitmap: self.bitmap,
            __marker: PhantomData,
        }
    }

    pub fn iter_non_skip(
        &self,
    ) -> CompactedChildrenTableIteratorNonSkip<NodeRefT> {
        CompactedChildrenTableIteratorNonSkip {
            next_child_index: 0,
            elements: self.table_ptr,
            bitmap: self.bitmap,
            __marker: PhantomData,
        }
    }

    pub fn iter_non_skip_mut(
        &mut self,
    ) -> CompactedChildrenTableIteratorNonSkipMut<NodeRefT> {
        CompactedChildrenTableIteratorNonSkipMut {
            next_child_index: 0,
            elements: self.table_ptr,
            bitmap: self.bitmap,
            __marker: PhantomData,
        }
    }
}

impl<NodeRefT: NodeRefTrait> PartialEq for CompactedChildrenTable<NodeRefT> {
    fn eq(&self, other: &Self) -> bool { self.to_ref() == other.to_ref() }
}

pub trait ChildrenTableIteratorStartIndex {
    fn set_start_index(self, index: u8) -> Self;
}

trait CompactedChildrenTableIteratorTrait: ChildrenTableIteratorStartIndex {
    type NodeRefT: NodeRefTrait;
    type RefType;

    fn get_bitmap(&self) -> u16;

    /// Only for CompactedChildrenTableIteratorNextTrait
    fn set_bitmap(&mut self, bitmap: u16);

    /// Only for CompactedChildrenTableIteratorNonSkipNextTrait
    fn set_next_child_index(&mut self, child_index: u8);

    fn get_current_element(&self) -> Self::RefType;

    fn advance_elements(&mut self);
}

trait CompactedChildrenTableIteratorNonSkipImplTrait:
    CompactedChildrenTableIteratorTrait
{
    fn set_start_index_impl(&mut self, index: u8) {
        self.set_next_child_index(index);
    }

    fn next_impl(
        &mut self, child_index: u8,
    ) -> Option<(u8, Option<Self::RefType>)> {
        if child_index as usize == CHILDREN_COUNT {
            return None;
        }

        let ret;
        if CompactedChildrenTable::<Self::NodeRefT>::has_index(
            self.get_bitmap(),
            child_index,
        ) {
            ret = Some((child_index, Some(self.get_current_element())));
            self.advance_elements();
        } else {
            ret = Some((child_index, None));
        }
        self.set_next_child_index(child_index + 1);

        ret
    }
}

trait CompactedChildrenTableIteratorImplTrait:
    CompactedChildrenTableIteratorTrait
{
    fn set_start_index_impl(&mut self, index: u8) {
        self.set_bitmap(
            self.get_bitmap()
                & !CompactedChildrenTable::<Self::NodeRefT>::lower_bits(
                    index.into(),
                ),
        );
    }

    fn next_impl(&mut self) -> Option<(u8, Self::RefType)> {
        let ret;
        if self.get_bitmap() != 0 {
            ret = Some((
                CompactedChildrenTable::<Self::NodeRefT>::lowest_bit_at(
                    self.get_bitmap(),
                ),
                self.get_current_element(),
            ));
        } else {
            return None;
        }

        self.advance_elements();
        self.set_bitmap(
            CompactedChildrenTable::<Self::NodeRefT>::remove_lowest_bit(
                self.get_bitmap(),
            ),
        );

        ret
    }
}

pub struct CompactedChildrenTableIteratorNonSkip<'a, NodeRefT> {
    next_child_index: u8,
    elements: *const NodeRefT,
    bitmap: u16,
    __marker: PhantomData<&'a NodeRefT>,
}

impl<'a, NodeRefT: NodeRefTrait> CompactedChildrenTableIteratorTrait
    for CompactedChildrenTableIteratorNonSkip<'a, NodeRefT>
{
    type NodeRefT = NodeRefT;
    type RefType = &'a NodeRefT;

    fn get_bitmap(&self) -> u16 { self.bitmap }

    /// This method is unnecessary.
    fn set_bitmap(&mut self, _bitmap: u16) { unreachable!() }

    fn set_next_child_index(&mut self, child_index: u8) {
        self.next_child_index = child_index;
    }

    fn get_current_element(&self) -> &'a NodeRefT { unsafe { &*self.elements } }

    fn advance_elements(&mut self) {
        unsafe {
            self.elements = self.elements.offset(1);
        }
    }
}

impl<'a, NodeRefT: NodeRefTrait> CompactedChildrenTableIteratorNonSkipImplTrait
    for CompactedChildrenTableIteratorNonSkip<'a, NodeRefT>
{
}

impl<'a, NodeRefT: NodeRefTrait> Iterator
    for CompactedChildrenTableIteratorNonSkip<'a, NodeRefT>
{
    type Item = (u8, Option<&'a NodeRefT>);

    fn next(&mut self) -> Option<Self::Item> {
        self.next_impl(self.next_child_index)
    }
}

impl<'a, NodeRefT: NodeRefTrait> ChildrenTableIteratorStartIndex
    for CompactedChildrenTableIteratorNonSkip<'a, NodeRefT>
{
    fn set_start_index(mut self, index: u8) -> Self {
        self.set_start_index_impl(index);
        self
    }
}

pub struct CompactedChildrenTableIteratorNonSkipMut<'a, NodeRefT> {
    next_child_index: u8,
    elements: *mut NodeRefT,
    bitmap: u16,
    __marker: PhantomData<&'a mut NodeRefT>,
}

impl<'a, NodeRefT: NodeRefTrait> CompactedChildrenTableIteratorTrait
    for CompactedChildrenTableIteratorNonSkipMut<'a, NodeRefT>
{
    type NodeRefT = NodeRefT;
    type RefType = &'a mut NodeRefT;

    fn get_bitmap(&self) -> u16 { self.bitmap }

    /// This method is unnecessary.
    fn set_bitmap(&mut self, _bitmap: u16) { unreachable!() }

    fn set_next_child_index(&mut self, child_index: u8) {
        self.next_child_index = child_index;
    }

    fn get_current_element(&self) -> &'a mut NodeRefT {
        unsafe { &mut *self.elements }
    }

    fn advance_elements(&mut self) {
        unsafe {
            self.elements = self.elements.offset(1);
        }
    }
}

impl<'a, NodeRefT: NodeRefTrait> CompactedChildrenTableIteratorNonSkipImplTrait
    for CompactedChildrenTableIteratorNonSkipMut<'a, NodeRefT>
{
}

impl<'a, NodeRefT: NodeRefTrait> Iterator
    for CompactedChildrenTableIteratorNonSkipMut<'a, NodeRefT>
{
    type Item = (u8, Option<&'a mut NodeRefT>);

    fn next(&mut self) -> Option<Self::Item> {
        self.next_impl(self.next_child_index)
    }
}

impl<'a, NodeRefT: NodeRefTrait> ChildrenTableIteratorStartIndex
    for CompactedChildrenTableIteratorNonSkipMut<'a, NodeRefT>
{
    fn set_start_index(mut self, index: u8) -> Self {
        self.set_start_index_impl(index);
        self
    }
}

pub struct CompactedChildrenTableIterator<'a, NodeRefT> {
    elements: *const NodeRefT,
    bitmap: u16,
    __marker: PhantomData<&'a NodeRefT>,
}

impl<'a, NodeRefT: NodeRefTrait> CompactedChildrenTableIteratorTrait
    for CompactedChildrenTableIterator<'a, NodeRefT>
{
    type NodeRefT = NodeRefT;
    type RefType = &'a NodeRefT;

    fn get_bitmap(&self) -> u16 { self.bitmap }

    fn set_bitmap(&mut self, bitmap: u16) { self.bitmap = bitmap }

    /// This method is unnecessary.
    fn set_next_child_index(&mut self, _child_index: u8) { unreachable!() }

    fn get_current_element(&self) -> &'a NodeRefT { unsafe { &*self.elements } }

    fn advance_elements(&mut self) {
        unsafe {
            self.elements = self.elements.offset(1);
        }
    }
}

impl<'a, NodeRefT: NodeRefTrait> CompactedChildrenTableIteratorImplTrait
    for CompactedChildrenTableIterator<'a, NodeRefT>
{
}

impl<'a, NodeRefT: NodeRefTrait> Iterator
    for CompactedChildrenTableIterator<'a, NodeRefT>
{
    type Item = (u8, &'a NodeRefT);

    fn next(&mut self) -> Option<Self::Item> { self.next_impl() }
}

impl<'a, NodeRefT: NodeRefTrait> ChildrenTableIteratorStartIndex
    for CompactedChildrenTableIterator<'a, NodeRefT>
{
    fn set_start_index(mut self, index: u8) -> Self {
        self.set_start_index_impl(index);
        self
    }
}

pub struct CompactedChildrenTableIteratorMut<'a, NodeRefT> {
    elements: *mut NodeRefT,
    bitmap: u16,
    __marker: PhantomData<&'a mut NodeRefT>,
}

impl<'a, NodeRefT: NodeRefTrait> CompactedChildrenTableIteratorTrait
    for CompactedChildrenTableIteratorMut<'a, NodeRefT>
{
    type NodeRefT = NodeRefT;
    type RefType = &'a mut NodeRefT;

    fn get_bitmap(&self) -> u16 { self.bitmap }

    fn set_bitmap(&mut self, bitmap: u16) { self.bitmap = bitmap }

    /// This method is unnecessary.
    fn set_next_child_index(&mut self, _child_index: u8) { unreachable!() }

    fn get_current_element(&self) -> &'a mut NodeRefT {
        unsafe { &mut *self.elements }
    }

    fn advance_elements(&mut self) {
        unsafe {
            self.elements = self.elements.offset(1);
        }
    }
}

impl<'a, NodeRefT: NodeRefTrait> CompactedChildrenTableIteratorImplTrait
    for CompactedChildrenTableIteratorMut<'a, NodeRefT>
{
}

impl<'a, NodeRefT: NodeRefTrait> Iterator
    for CompactedChildrenTableIteratorMut<'a, NodeRefT>
{
    type Item = (u8, &'a mut NodeRefT);

    fn next(&mut self) -> Option<Self::Item> { self.next_impl() }
}

impl<'a, NodeRefT: NodeRefTrait> ChildrenTableIteratorStartIndex
    for CompactedChildrenTableIteratorMut<'a, NodeRefT>
{
    fn set_start_index(mut self, index: u8) -> Self {
        self.set_start_index_impl(index);
        self
    }
}

pub struct ChildrenTable<NodeRefT: NodeRefTrait> {
    /// Stores the existing children ordered.
    table: Box<[NodeRefT]>,
    /// Stores whether each child exists.
    bitmap: u16,
}

impl<NodeRefT: NodeRefTrait> Default for ChildrenTable<NodeRefT> {
    fn default() -> Self {
        Self {
            table: vec![].into_boxed_slice(),
            bitmap: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChildrenTableRef<'a, NodeRefT: NodeRefTrait> {
    table: &'a [NodeRefT],
    bitmap: u16,
}

impl<'a, NodeRefT: NodeRefTrait> From<ChildrenTableRef<'a, NodeRefT>>
    for CompactedChildrenTable<NodeRefT>
{
    fn from(x: ChildrenTableRef<'a, NodeRefT>) -> Self { Self::from_ref(x) }
}

impl<NodeRefT: NodeRefTrait> From<ChildrenTable<NodeRefT>>
    for CompactedChildrenTable<NodeRefT>
{
    fn from(x: ChildrenTable<NodeRefT>) -> Self { Self::from_managed(x) }
}

impl<'a, NodeRefT: NodeRefTrait> Encodable for ChildrenTableRef<'a, NodeRefT> {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self.table.len() {
            0 => s.begin_list(0),
            // Skip bitmap if list has length of 16.
            16 => s.append_list(self.table),
            // TODO(yz): Instead, use [bitmap, child_0, ... , child_n] for N @
            // 1..14; when N == 15: [bitmap, 0, child_0, ... ,
            // child_15] to save 2 bytes.
            _ => s.begin_list(2).append(&self.bitmap).append_list(self.table),
        };
    }
}

impl<NodeRefT: NodeRefTrait> Decodable for ChildrenTable<NodeRefT> {
    fn decode(rlp: &Rlp) -> ::std::result::Result<Self, DecoderError> {
        let item_count = rlp.item_count()?;
        Ok(match item_count {
            0..=1 => Self::default(),
            16 => Self {
                bitmap: CompactedChildrenTable::<NodeRefT>::all_bits(),
                table: rlp.as_list::<NodeRefT>()?.into_boxed_slice(),
            },
            _ => Self {
                bitmap: rlp.val_at::<u16>(0)?,
                table: rlp.list_at::<NodeRefT>(1)?.into_boxed_slice(),
            },
        })
    }
}

use super::{
    super::super::utils::WrappedCreateFrom,
    merkle::{ChildrenMerkleTable, MaybeMerkleTable},
};
use primitives::{MerkleHash, MERKLE_NULL_NODE};
use rlp::*;
use std::{fmt::*, marker::PhantomData, mem, ptr::null_mut, slice};
