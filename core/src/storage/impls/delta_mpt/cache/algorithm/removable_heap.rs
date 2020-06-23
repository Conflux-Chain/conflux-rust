// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{super::super::super::errors::*, MyInto, PrimitiveNum};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use std::{cmp::Ordering, marker::PhantomData, mem, ptr, vec::Vec};

// To make it easy for any value type to implement HeapValueUtil.
pub struct HeapHandle<PosT> {
    pos: PosT,
}

impl<PosT: PrimitiveNum> HeapHandle<PosT> {
    pub const NULL_POS: i32 = -1;

    // Used in tests and by a currently unused class.
    #[allow(dead_code)]
    pub fn get_pos(&self) -> PosT { self.pos }

    // Update heap handle for value being moved in heap.
    pub fn set_handle(&mut self, pos: PosT) { self.pos = pos; }

    pub fn set_removed(&mut self) { self.pos = PosT::from(Self::NULL_POS); }
}

impl<PosT: PrimitiveNum> Default for HeapHandle<PosT> {
    fn default() -> Self {
        Self {
            pos: PosT::from(Self::NULL_POS),
        }
    }
}

pub struct TrivialValueWithHeapHandle<ValueType, PosT: PrimitiveNum> {
    pub value: ValueType,
    handle: HeapHandle<PosT>,
}

impl<ValueType, PosT: PrimitiveNum>
    TrivialValueWithHeapHandle<ValueType, PosT>
{
    // Used in tests.
    #[allow(dead_code)]
    pub fn new(value: ValueType) -> Self {
        Self {
            value,
            handle: unsafe { mem::uninitialized() },
        }
    }

    pub fn get_handle_mut(&mut self) -> &mut HeapHandle<PosT> {
        &mut self.handle
    }

    // Update heap handle for value being moved in heap.
    pub fn set_handle(&mut self, pos: PosT) {
        self.get_handle_mut().set_handle(pos);
    }

    pub fn set_removed(&mut self) { self.get_handle_mut().set_removed(); }
}

impl<ValueType, PosT: PrimitiveNum> AsRef<ValueType>
    for TrivialValueWithHeapHandle<ValueType, PosT>
{
    fn as_ref(&self) -> &ValueType { &self.value }
}

/// The value util should only be passed for each action. The problem of holding
/// it for the lifetime of the heap is that the "reference" to some data may
/// prevent modification in other part of the system.
pub trait HeapValueUtil<ValueType, PosT: PrimitiveNum> {
    type KeyType: Ord + Clone;

    /// Update handle for value being moved in heap(or the latter non-heap
    /// part).
    fn set_handle(&mut self, value: &mut ValueType, pos: PosT);

    /// A special one to set the handle for the value being changed by Hole.
    /// This method should only be implemented differently for special
    /// access, e.g. operating the element to insert into cache which hasn't
    /// yet been inserted. For the special cases any hole used in
    /// heap operations must be exactly for the special element.
    ///
    /// Please pay extra attention because this method is called on finalize
    /// method for all Hole object, i.e. all heap operations.

    // FIXME: test case.
    fn set_handle_final(&mut self, value: &mut ValueType, pos: PosT);
    /// In the current implementation set_removed is always called when the
    /// value still lives in heap. However it works perfectly fine when the
    /// value is already removed from heap, so please do not access the heap
    /// at the old position for the removed value.
    fn set_removed(&mut self, value: &mut ValueType);

    fn get_key_for_comparison<'a>(
        &'a self, value: &'a ValueType,
    ) -> &Self::KeyType;
}

/// A demo of heap value util for heap which directly maintains value where the
/// handle is stored together.
///
/// Do not use this heap value util in real application.
// Used in tests.
#[allow(dead_code)]
pub struct TrivialHeapValueUtil<ValueType: Ord + Clone, PosT: PrimitiveNum> {
    __marker_pos_t: PhantomData<PosT>,
    __marker_value_type: PhantomData<ValueType>,
}

// Derive doesn't work because it unreasonably requires that ValueType is
// default.
impl<PosT: PrimitiveNum, ValueType: Ord + Clone> Default
    for TrivialHeapValueUtil<ValueType, PosT>
{
    fn default() -> Self {
        Self {
            __marker_pos_t: PhantomData,
            __marker_value_type: PhantomData,
        }
    }
}

impl<PosT: PrimitiveNum, ValueType: Ord + Clone>
    HeapValueUtil<TrivialValueWithHeapHandle<ValueType, PosT>, PosT>
    for TrivialHeapValueUtil<ValueType, PosT>
{
    type KeyType = ValueType;

    fn set_handle(
        &mut self, value: &mut TrivialValueWithHeapHandle<ValueType, PosT>,
        pos: PosT,
    )
    {
        value.set_handle(pos);
    }

    fn set_handle_final(
        &mut self, value: &mut TrivialValueWithHeapHandle<ValueType, PosT>,
        pos: PosT,
    )
    {
        value.set_handle(pos);
    }

    fn set_removed(
        &mut self, value: &mut TrivialValueWithHeapHandle<ValueType, PosT>,
    ) {
        value.set_removed();
    }

    fn get_key_for_comparison<'a>(
        &'a self, value: &'a TrivialValueWithHeapHandle<ValueType, PosT>,
    ) -> &ValueType {
        value.as_ref()
    }
}

pub struct RemovableHeap<PosT: PrimitiveNum, ValueType> {
    /// The array holds the heap. The array may keep more elements after the
    /// heap.
    ///
    /// Typical use of the non-heap part is to hold elements which are removed
    /// from heap but may be maintained and push to heap again.
    array: Vec<ValueType>,
    heap_size: PosT,
}

impl<PosT: PrimitiveNum, ValueType: MallocSizeOf> MallocSizeOf
    for RemovableHeap<PosT, ValueType>
{
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.array.size_of(ops) + self.heap_size.size_of(ops)
    }
}

impl<PosT: PrimitiveNum, ValueType> RemovableHeap<PosT, ValueType> {
    // Used in tests and by a currently unused class.
    #[allow(dead_code)]
    pub fn new(capacity: PosT) -> Self {
        if capacity == PosT::from(HeapHandle::<PosT>::NULL_POS) {
            panic!("LRU: capacity {:?} is too large!", capacity)
        }

        Self {
            array: Vec::with_capacity(capacity.into()),
            heap_size: PosT::from(0),
        }
    }

    pub fn get_heap_size(&self) -> PosT { self.heap_size }

    pub unsafe fn set_heap_size_unchecked(&mut self, size: PosT) {
        self.heap_size = size;
    }

    pub fn get_array_mut(&mut self) -> &mut Vec<ValueType> { &mut self.array }

    pub unsafe fn get_unchecked(&self, pos: PosT) -> &ValueType {
        self.array.get_unchecked(MyInto::<usize>::into(pos))
    }

    pub unsafe fn get_unchecked_mut(&mut self, pos: PosT) -> &mut ValueType {
        self.array.get_unchecked_mut(MyInto::<usize>::into(pos))
    }

    /// Replace an element with hole, and place the removed element at the end
    /// of array (non-heap part).
    ///
    /// Unsafe because pos and capacity are unchecked.
    pub unsafe fn hole_push_back_and_swap_unchecked<
        ValueUtilT: HeapValueUtil<ValueType, PosT>,
    >(
        &mut self, pos: PosT, hole: &mut Hole<ValueType>,
        value_util: &mut ValueUtilT,
    ) -> PosT
    {
        let array_pos = self.array.len();

        self.array.set_len(array_pos + 1);
        let array_pos = PosT::from(array_pos);
        if pos != array_pos {
            ptr::copy_nonoverlapping(
                self.get_unchecked(pos),
                self.get_unchecked_mut(array_pos),
                1,
            );
            value_util.set_handle(self.get_unchecked_mut(array_pos), array_pos);
        }
        hole.pointer_pos = self.get_unchecked_mut(pos);

        array_pos
    }
}

trait OrderChecker<
    ValueType,
    KeyType: Ord + Clone,
    PosT: PrimitiveNum,
    ValueUtilT: HeapValueUtil<ValueType, PosT, KeyType = KeyType>,
>
{
    // Settle the heap pos for the value and return None if the order is
    // correct, otherwise return an order checker object for further order
    // corrections.
    fn new_checked(
        heap_base: *mut ValueType, pos: PosT, heap_size: PosT,
        key_comparison: KeyType, value_util: &mut ValueUtilT,
    ) -> Option<(Self, *mut ValueType)>
    where
        Self: Sized,
    {
        let mut order_checker =
            Self::new(heap_base, pos, heap_size, key_comparison, value_util);

        if let Some(pointer_parent) = order_checker.calculate_next(value_util) {
            Some((order_checker, pointer_parent))
        } else {
            value_util.set_handle_final(
                unsafe { &mut *order_checker.pointer_pos() },
                pos,
            );
            None
        }
    }

    fn new(
        heap_base: *mut ValueType, pos: PosT, heap_size: PosT,
        key_comparison: KeyType, value_util: &mut ValueUtilT,
    ) -> Self;

    fn calculate_next(
        &mut self, value_util: &ValueUtilT,
    ) -> Option<*mut ValueType>;

    fn current_pos(&self) -> PosT;

    fn pointer_pos(&self) -> *mut ValueType;
}

struct UpOrderChecker<
    ValueType,
    KeyType: Ord + Clone,
    PosT: PrimitiveNum,
    ValueUtilT: HeapValueUtil<ValueType, PosT, KeyType = KeyType>,
> {
    key_comparison: KeyType,
    heap_base: *mut ValueType,
    pointer_pos: *mut ValueType,
    pos: PosT,
    _util_marker: PhantomData<ValueUtilT>,
}

impl<
        ValueType,
        KeyType: Ord + Clone,
        PosT: PrimitiveNum,
        ValueUtilT: HeapValueUtil<ValueType, PosT, KeyType = KeyType>,
    > OrderChecker<ValueType, KeyType, PosT, ValueUtilT>
    for UpOrderChecker<ValueType, KeyType, PosT, ValueUtilT>
{
    fn new(
        heap_base: *mut ValueType, pos: PosT, _heap_size: PosT,
        key_comparison: KeyType, _value_util: &mut ValueUtilT,
    ) -> Self
    {
        let pointer_pos = unsafe { heap_base.offset(pos.into()) };

        Self {
            key_comparison,
            heap_base,
            pointer_pos,
            pos,
            _util_marker: PhantomData,
        }
    }

    fn calculate_next(
        &mut self, value_util: &ValueUtilT,
    ) -> Option<*mut ValueType> {
        if self.pos == PosT::from(0) {
            None
        } else {
            let parent = (self.pos - PosT::from(1)) / PosT::from(2);
            let pointer_parent =
                unsafe { self.heap_base.offset(parent.into()) };

            if self
                .key_comparison
                .lt(value_util
                    .get_key_for_comparison(unsafe { &*pointer_parent }))
            {
                self.pos = parent;
                self.pointer_pos = pointer_parent;

                Some(pointer_parent)
            } else {
                None
            }
        }
    }

    fn current_pos(&self) -> PosT { self.pos }

    fn pointer_pos(&self) -> *mut ValueType { self.pointer_pos }
}

struct DownOrderChecker<
    ValueType,
    KeyType: Ord + Clone,
    PosT: PrimitiveNum,
    ValueUtilT: HeapValueUtil<ValueType, PosT, KeyType = KeyType>,
> {
    key_comparison: KeyType,
    heap_base: *mut ValueType,
    pointer_pos: *mut ValueType,
    pos: PosT,
    pos_limit: PosT,
    max_right_child: PosT,
    _util_marker: PhantomData<ValueUtilT>,
}

impl<
        ValueType,
        KeyType: Ord + Clone,
        PosT: PrimitiveNum,
        ValueUtilT: HeapValueUtil<ValueType, PosT, KeyType = KeyType>,
    > OrderChecker<ValueType, KeyType, PosT, ValueUtilT>
    for DownOrderChecker<ValueType, KeyType, PosT, ValueUtilT>
{
    fn new(
        heap_base: *mut ValueType, pos: PosT, heap_size: PosT,
        key_comparison: KeyType, _value_util: &mut ValueUtilT,
    ) -> Self
    {
        let pointer_pos = unsafe { heap_base.offset(pos.into()) };

        Self {
            key_comparison,
            heap_base,
            pointer_pos,
            pos,
            pos_limit: heap_size / PosT::from(2),
            max_right_child: heap_size - PosT::from(1),
            _util_marker: PhantomData,
        }
    }

    fn calculate_next(
        &mut self, value_util: &ValueUtilT,
    ) -> Option<*mut ValueType> {
        if self.pos >= self.pos_limit {
            return None;
        }
        let left_child = self.pos * PosT::from(2) + PosT::from(1);

        let pointer_left_child =
            unsafe { self.heap_base.offset(left_child.into()) };
        let left_child_key_comparison =
            value_util.get_key_for_comparison(unsafe { &*pointer_left_child });

        let mut best_child = left_child;
        let mut pointer_best_child = pointer_left_child;
        let mut best_child_key = left_child_key_comparison;

        if left_child < self.max_right_child {
            let right_child = left_child + PosT::from(1);

            let pointer_right_child =
                unsafe { self.heap_base.offset(right_child.into()) };
            let right_child_key_comparison = value_util
                .get_key_for_comparison(unsafe { &*pointer_right_child });

            if right_child_key_comparison < best_child_key {
                best_child = right_child;
                pointer_best_child = pointer_right_child;
                best_child_key = right_child_key_comparison;
            }
        }

        if best_child_key.lt(&self.key_comparison) {
            self.pos = best_child;
            self.pointer_pos = pointer_best_child;

            Some(pointer_best_child)
        } else {
            None
        }
    }

    fn current_pos(&self) -> PosT { self.pos }

    fn pointer_pos(&self) -> *mut ValueType { self.pointer_pos }
}

pub struct Hole<ValueType> {
    pub pointer_pos: *mut ValueType,
    pub value: ValueType,
}

impl<ValueType> Hole<ValueType> {
    pub fn new(pointer_pos: *mut ValueType) -> Self {
        Self {
            pointer_pos,
            value: unsafe { ptr::read(pointer_pos) },
        }
    }

    pub fn new_from_value_ptr_read(
        pointer_pos: *mut ValueType, value: &ValueType,
    ) -> Self {
        Self {
            pointer_pos,
            value: unsafe { ptr::read(value) },
        }
    }

    pub fn finalize<
        PosT: PrimitiveNum,
        ValueUtilT: HeapValueUtil<ValueType, PosT>,
    >(
        mut self, pos: PosT, value_updater: &mut ValueUtilT,
    ) {
        unsafe {
            value_updater.set_handle_final(&mut self.value, pos);
            ptr::write(self.pointer_pos, self.value);
        };
    }

    pub fn move_to<
        PosT: PrimitiveNum,
        ValueUtilT: HeapValueUtil<ValueType, PosT>,
    >(
        &mut self, pointer_new_pos: *mut ValueType, pos: PosT,
        value_updater: &mut ValueUtilT,
    )
    {
        unsafe {
            value_updater.set_handle(&mut *pointer_new_pos, pos);
            ptr::copy_nonoverlapping(pointer_new_pos, self.pointer_pos, 1);
            self.pointer_pos = pointer_new_pos;
        }
    }
}

impl<PosT: PrimitiveNum, ValueType> RemovableHeap<PosT, ValueType> {
    /// Insert an element carried in a hole into heap.
    ///
    /// Unsafe because the capacity isn't checked.
    pub unsafe fn insert_with_hole_unchecked<
        ValueUtilT: HeapValueUtil<ValueType, PosT>,
    >(
        &mut self, mut hole: Hole<ValueType>, value_util: &mut ValueUtilT,
    ) -> PosT {
        let heap_size = self.heap_size;
        self.hole_push_back_and_swap_unchecked(
            heap_size, &mut hole, value_util,
        );

        self.sift_up_with_hole(heap_size, hole, value_util);
        self.heap_size += PosT::from(1);

        heap_size
    }

    // Used in tests and by a currently unused class.
    #[allow(dead_code)]
    pub fn insert<ValueUtilT: HeapValueUtil<ValueType, PosT>>(
        &mut self, value: ValueType, value_util: &mut ValueUtilT,
    ) -> Result<PosT> {
        if self.array.capacity() == self.array.len() {
            return Err(ErrorKind::OutOfCapacity.into());
        }

        let mut hole: Hole<ValueType> = unsafe { mem::uninitialized() };
        hole.value = value;

        let pos = unsafe { self.insert_with_hole_unchecked(hole, value_util) };

        Ok(pos)
    }

    /// Unsafe because the emptiness is unchecked.
    /// Please note that the value_util.set_removed isn't called from this
    /// method. Please call outside this method when necessary.
    pub unsafe fn replace_head_unchecked_with_hole<
        ValueUtilT: HeapValueUtil<ValueType, PosT>,
    >(
        &mut self, hole: Hole<ValueType>, replaced: &mut ValueType,
        value_util: &mut ValueUtilT,
    )
    {
        ptr::copy_nonoverlapping(
            self.get_unchecked_mut(PosT::from(0)),
            replaced,
            1,
        );

        self.sift_down_with_hole(PosT::from(0), hole, value_util);
    }

    /// The value is set to removed from heap. However if user provides a value
    /// from the non-heap part of self.array, user may want the heap handle
    /// to point to the non-heap location.
    ///
    /// Unsafe because the emptiness is unchecked.
    #[allow(dead_code)]
    pub unsafe fn replace_head_unchecked<
        ValueUtilT: HeapValueUtil<ValueType, PosT>,
    >(
        &mut self, value: &mut ValueType, value_util: &mut ValueUtilT,
    ) {
        let hole =
            Hole::new_from_value_ptr_read(self.array.as_mut_ptr(), value);

        // The value may be in-place updated so set_removed must be called
        // before set_handle is called from Hole.
        value_util.set_removed(value);
        self.replace_head_unchecked_with_hole(hole, value, value_util);
    }

    // Used in tests and by a currently unused class.
    #[allow(dead_code)]
    pub fn pop_head<ValueUtilT: HeapValueUtil<ValueType, PosT>>(
        &mut self, value_util: &mut ValueUtilT,
    ) -> Option<ValueType> {
        if self.heap_size == PosT::from(0) {
            None
        } else {
            unsafe {
                value_util.set_removed(self.get_unchecked_mut(PosT::from(0)));

                self.heap_size -= PosT::from(1);
                let mut ret = Some(mem::uninitialized());
                let last_element_pos = self.heap_size;
                if self.heap_size == PosT::from(0) {
                    ptr::copy_nonoverlapping(
                        self.get_unchecked_mut(PosT::from(0)),
                        ret.as_mut().unwrap(),
                        1,
                    );
                } else {
                    let hole = Hole::new_from_value_ptr_read(
                        self.get_unchecked_mut(PosT::from(0)),
                        self.get_unchecked_mut(last_element_pos),
                    );
                    self.replace_head_unchecked_with_hole(
                        hole,
                        ret.as_mut().unwrap(),
                        value_util,
                    );
                }

                let new_len = self.array.len() - 1;
                if PosT::from(new_len) != last_element_pos {
                    ptr::copy_nonoverlapping(
                        self.get_unchecked(PosT::from(new_len)),
                        self.get_unchecked_mut(last_element_pos),
                        1,
                    );
                    value_util.set_handle(
                        self.get_unchecked_mut(last_element_pos),
                        last_element_pos,
                    );
                }
                self.array.set_len(new_len);

                ret
            }
        }
    }

    /// Unsafe because pos is unchecked, and because of using of hole.
    /// Please note that the value_util.set_removed isn't called from this
    /// method. Please call outside this method when necessary.
    pub unsafe fn replace_at_unchecked_with_hole<
        ValueUtilT: HeapValueUtil<ValueType, PosT>,
    >(
        &mut self, pos: PosT, hole: Hole<ValueType>, replaced: *mut ValueType,
        value_util: &mut ValueUtilT,
    )
    {
        ptr::copy_nonoverlapping(self.get_unchecked_mut(pos), replaced, 1);

        if value_util.get_key_for_comparison(self.get_unchecked_mut(pos))
            < value_util.get_key_for_comparison(&hole.value)
        {
            self.sift_down_with_hole(pos, hole, value_util);
        } else {
            self.sift_up_with_hole(pos, hole, value_util);
        }
    }

    /// Unsafe because the pos is unchecked.
    // Used in tests and by a currently unused class.
    #[allow(dead_code)]
    pub unsafe fn replace_at_unchecked<
        ValueUtilT: HeapValueUtil<ValueType, PosT>,
    >(
        &mut self, pos: PosT, value: &mut ValueType,
        value_util: &mut ValueUtilT,
    )
    {
        let hole = {
            let replaced = self.get_unchecked_mut(pos);
            let hole = Hole::new_from_value_ptr_read(replaced, value);

            // The value may be in-place updated so set_removed must be
            // called before set_handle is called from Hole.
            value_util.set_removed(replaced);

            hole
        };
        self.replace_at_unchecked_with_hole(pos, hole, value, value_util);
    }

    /// Unsafe because the pos is unchecked.
    // Used in tests and by a currently unused class.
    #[allow(dead_code)]
    pub unsafe fn move_out_from_heap_at_unchecked<
        ValueUtilT: HeapValueUtil<ValueType, PosT>,
    >(
        &mut self, pos: PosT, value_util: &mut ValueUtilT,
    ) {
        self.heap_size -= PosT::from(1);
        let heap_last_pos = self.heap_size;
        if pos < heap_last_pos {
            let hole = Hole::new_from_value_ptr_read(
                self.get_unchecked_mut(pos),
                self.get_unchecked_mut(heap_last_pos),
            );
            let ptr_heap_last_element =
                self.get_unchecked_mut(heap_last_pos) as *mut ValueType;
            self.replace_at_unchecked_with_hole(
                pos,
                hole,
                ptr_heap_last_element,
                value_util,
            );
            value_util.set_handle(
                self.get_unchecked_mut(heap_last_pos),
                heap_last_pos,
            );
        }
    }

    /// Unsafe because the pos is unchecked.
    pub unsafe fn remove_at_unchecked<
        ValueUtilT: HeapValueUtil<ValueType, PosT>,
    >(
        &mut self, pos: PosT, value_util: &mut ValueUtilT,
    ) -> ValueType {
        let mut removed = mem::uninitialized();
        value_util.set_removed(self.get_unchecked_mut(pos));
        let hole_pos = if self.heap_size > pos {
            self.heap_size -= PosT::from(1);
            let last_element_pos = self.heap_size;
            if last_element_pos != pos {
                let hole = Hole::new_from_value_ptr_read(
                    self.get_unchecked_mut(pos),
                    self.get_unchecked_mut(last_element_pos),
                );

                self.replace_at_unchecked_with_hole(
                    pos,
                    hole,
                    &mut removed,
                    value_util,
                );
            }
            last_element_pos
        } else {
            let value_to_remove = self.get_unchecked_mut(pos);
            ptr::copy_nonoverlapping(value_to_remove, &mut removed, 1);
            pos
        };
        let new_len = self.array.len() - 1;
        if PosT::from(new_len) != hole_pos {
            ptr::copy_nonoverlapping(
                self.get_unchecked(PosT::from(new_len)),
                self.get_unchecked_mut(hole_pos),
                1,
            );
            value_util.set_handle(self.get_unchecked_mut(hole_pos), hole_pos);
        }
        self.array.set_len(new_len);

        removed
    }

    pub fn sift_up_with_hole<ValueUtilT: HeapValueUtil<ValueType, PosT>>(
        &mut self, pos: PosT, hole: Hole<ValueType>,
        value_util: &mut ValueUtilT,
    )
    {
        let up_order_checker = UpOrderChecker::new(
            self.array.as_mut_ptr(),
            pos,
            self.heap_size,
            value_util.get_key_for_comparison(&hole.value).clone(),
            value_util,
        );
        self.sift_with_hole(pos, hole, up_order_checker, value_util)
    }

    pub fn sift_down_with_hole<ValueUtilT: HeapValueUtil<ValueType, PosT>>(
        &mut self, pos: PosT, hole: Hole<ValueType>,
        value_util: &mut ValueUtilT,
    )
    {
        let down_order_checker = DownOrderChecker::new(
            self.array.as_mut_ptr(),
            pos,
            self.heap_size,
            value_util.get_key_for_comparison(&hole.value).clone(),
            value_util,
        );
        self.sift_with_hole(pos, hole, down_order_checker, value_util)
    }

    fn sift_with_hole<
        KeyType: Ord + Clone,
        OrderCheckerT: OrderChecker<ValueType, KeyType, PosT, ValueUtilT>,
        ValueUtilT: HeapValueUtil<ValueType, PosT, KeyType = KeyType>,
    >(
        &mut self, mut pos: PosT, mut hole: Hole<ValueType>,
        mut order_checker: OrderCheckerT, value_util: &mut ValueUtilT,
    )
    {
        while let Some(pointer_new_pos) =
            order_checker.calculate_next(value_util)
        {
            hole.move_to(pointer_new_pos, pos, value_util);
            pos = order_checker.current_pos();
        }
        hole.finalize(pos, value_util);
    }

    /// User may call this function when user increased value at pos.
    pub fn sift_down<ValueUtilT: HeapValueUtil<ValueType, PosT>>(
        &mut self, pos: PosT, value_util: &mut ValueUtilT,
    ) -> bool {
        let maybe_order_checker = DownOrderChecker::new_checked(
            self.array.as_mut_ptr(),
            pos,
            self.heap_size,
            unsafe {
                value_util
                    .get_key_for_comparison(self.get_unchecked(pos))
                    .clone()
            },
            value_util,
        );
        self.sift(pos, maybe_order_checker, value_util)
    }

    /// User may call this function when user decreased value at pos.
    #[allow(dead_code)]
    pub fn sift_up<ValueUtilT: HeapValueUtil<ValueType, PosT>>(
        &mut self, pos: PosT, value_util: &mut ValueUtilT,
    ) -> bool {
        let maybe_order_checker = UpOrderChecker::new_checked(
            self.array.as_mut_ptr(),
            pos,
            self.heap_size,
            unsafe {
                value_util
                    .get_key_for_comparison(self.get_unchecked(pos))
                    .clone()
            },
            value_util,
        );
        self.sift(pos, maybe_order_checker, value_util)
    }

    fn sift<
        KeyType: Ord + Clone,
        OrderCheckerT: OrderChecker<ValueType, KeyType, PosT, ValueUtilT>,
        ValueUtilT: HeapValueUtil<ValueType, PosT, KeyType = KeyType>,
    >(
        &mut self, pos: PosT,
        maybe_order_checker: Option<(OrderCheckerT, *mut ValueType)>,
        value_util: &mut ValueUtilT,
    ) -> bool
    {
        match maybe_order_checker {
            None => false,
            Some((order_checker, pointer_new_pos)) => {
                // The order checker holds the next position to check.
                let mut hole =
                    Hole::new(unsafe { self.get_unchecked_mut(pos) });
                hole.move_to(pointer_new_pos, pos, value_util);
                self.sift_with_hole(
                    order_checker.current_pos(),
                    hole,
                    order_checker,
                    value_util,
                );
                true
            }
        }
    }
}

impl<ValueType: PartialEq, PosT: PrimitiveNum> PartialEq
    for TrivialValueWithHeapHandle<ValueType, PosT>
{
    fn eq(&self, other: &Self) -> bool { self.value.eq(&other.value) }
}

impl<ValueType: Eq, PosT: PrimitiveNum> Eq
    for TrivialValueWithHeapHandle<ValueType, PosT>
{
}

impl<ValueType: PartialOrd, PosT: PrimitiveNum> PartialOrd
    for TrivialValueWithHeapHandle<ValueType, PosT>
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl<ValueType: Ord, PosT: PrimitiveNum> Ord
    for TrivialValueWithHeapHandle<ValueType, PosT>
{
    fn cmp(&self, other: &Self) -> Ordering { self.value.cmp(&other.value) }
}
