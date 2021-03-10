// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{marker::PhantomData, ptr::null_mut, slice};

/// Use FieldsOffsetMaybeInPlaceByteArrayMemoryManager and macro
/// make_parallel_field_maybe_in_place_byte_array_memory_manager to manage
/// construction / destruction of MaybeInPlaceByteArray.
///
/// The memory manager should be placed as a parallel field in the same struct
/// as the MaybeInPlaceByteArray. See CompressedPathRaw for example.
pub union MaybeInPlaceByteArray {
    pub in_place: [u8; Self::MAX_INPLACE_SIZE],
    /// Only raw pointer is 8B.
    pub ptr: *mut u8,
}

impl MaybeInPlaceByteArray {
    pub const MAX_INPLACE_SIZE: usize = 8;
}

#[test]
fn test_maybe_inplace_byte_array_size_is_8_bytes() {
    assert_eq!(
        std::mem::size_of::<MaybeInPlaceByteArray>(),
        MaybeInPlaceByteArray::MAX_INPLACE_SIZE
    );
}
impl Default for MaybeInPlaceByteArray {
    fn default() -> Self {
        Self {
            in_place: Default::default(),
        }
    }
}

/// Trait for managing construction / destruction of MaybeInPlaceByteArray.
/// FieldsOffsetMaybeInPlaceByteArrayMemoryManager implements this trait.
#[allow(drop_bounds)]
pub trait MaybeInPlaceByteArrayMemoryManagerTrait: Drop {
    /// Unsafe because the size isn't set to 0.
    unsafe fn drop_value(&mut self) {
        let size = self.get_size();
        if size > MaybeInPlaceByteArray::MAX_INPLACE_SIZE {
            self.get_in_place_byte_array_mut().ptr_into_vec(size);
        }
    }

    fn get_size(&self) -> usize;
    fn set_size(&mut self, size: usize);
    fn get_in_place_byte_array(&self) -> &MaybeInPlaceByteArray;
    fn get_in_place_byte_array_mut(&mut self) -> &mut MaybeInPlaceByteArray;

    /// Unsafe because the destination may not be empty.
    unsafe fn move_byte_array_dest_unchecked(
        &mut self, free_dest: &mut MaybeInPlaceByteArray,
    ) {
        self.set_size(0);

        std::ptr::copy_nonoverlapping(
            self.get_in_place_byte_array(),
            free_dest,
            1,
        );
    }

    fn move_to<T: MaybeInPlaceByteArrayMemoryManagerTrait>(
        &mut self, dest: &mut T,
    ) {
        let size = self.get_size();

        // Safe because the dest size is set right later.
        unsafe {
            dest.drop_value();
            dest.set_size(size);
        }
        if size != 0 {
            // Safe because the old content in destination is already freed.
            unsafe {
                self.move_byte_array_dest_unchecked(
                    dest.get_in_place_byte_array_mut(),
                );
            }
        }
    }
}

#[derive(Default, Clone)]
pub struct FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
    SizeFieldType,
    SizeFieldGetterSetter: SizeFieldConverterTrait<SizeFieldType>,
    ByteArrayOffsetAccessor: ParallelFieldOffsetAccessor<Self, MaybeInPlaceByteArray>,
    SizeFieldOffsetAccessor: ParallelFieldOffsetAccessor<Self, SizeFieldType>,
> {
    _marker_size_type: PhantomData<SizeFieldType>,
    _marker_size_field_getter_setter: PhantomData<SizeFieldGetterSetter>,
    _marker_byte_array_accessor: PhantomData<ByteArrayOffsetAccessor>,
    _marker_size_field_accessor: PhantomData<SizeFieldOffsetAccessor>,
}

impl<
        SizeFieldType,
        SizeFieldGetterSetter: SizeFieldConverterTrait<SizeFieldType>,
        ByteArrayOffsetAccessor: ParallelFieldOffsetAccessor<Self, MaybeInPlaceByteArray>,
        SizeFieldOffsetAccessor: ParallelFieldOffsetAccessor<Self, SizeFieldType>,
    > Drop
    for FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
        SizeFieldType,
        SizeFieldGetterSetter,
        ByteArrayOffsetAccessor,
        SizeFieldOffsetAccessor,
    >
{
    fn drop(&mut self) {
        // Safe because on destruction it's not necessary to set size to 0
        unsafe {
            self.drop_value();
        }
    }
}

impl MaybeInPlaceByteArray {
    /// Take ptr out and clear ptr.
    pub unsafe fn ptr_into_vec(&mut self, size: usize) -> Vec<u8> {
        let vec = Vec::from_raw_parts(self.ptr, size, size);
        self.ptr = null_mut();
        vec
    }

    unsafe fn ptr_slice(&self, size: usize) -> &[u8] {
        slice::from_raw_parts(self.ptr, size)
    }

    unsafe fn ptr_slice_mut(&mut self, size: usize) -> &mut [u8] {
        slice::from_raw_parts_mut(self.ptr, size)
    }

    pub fn get_slice_mut(&mut self, size: usize) -> &mut [u8] {
        let is_ptr = size > Self::MAX_INPLACE_SIZE;
        unsafe {
            if is_ptr {
                self.ptr_slice_mut(size)
            } else {
                &mut self.in_place[0..size]
            }
        }
    }

    pub fn get_slice(&self, size: usize) -> &[u8] {
        let is_ptr = size > Self::MAX_INPLACE_SIZE;
        unsafe {
            if is_ptr {
                self.ptr_slice(size)
            } else {
                &self.in_place[0..size]
            }
        }
    }

    pub fn into_boxed_slice(&mut self, size: usize) -> Box<[u8]> {
        let is_ptr = size > Self::MAX_INPLACE_SIZE;
        unsafe {
            if is_ptr {
                self.ptr_into_vec(size)
            } else {
                Vec::from(&self.in_place[0..size])
            }
        }
        .into_boxed_slice()
    }

    pub fn new(mut value: Box<[u8]>, size: usize) -> Self {
        if size > Self::MAX_INPLACE_SIZE {
            let ptr = value.as_mut_ptr();
            Box::into_raw(value);
            Self { ptr }
        } else {
            let mut in_place: [u8; Self::MAX_INPLACE_SIZE];
            unsafe {
                in_place = std::mem::uninitialized();
            }
            in_place[0..size].copy_from_slice(&*value);
            Self { in_place }
        }
    }

    pub fn new_zeroed(size: usize) -> Self {
        Self::new(vec![0u8; size].into_boxed_slice(), size)
    }

    pub fn copy_from(value: &[u8], size: usize) -> Self {
        if size > Self::MAX_INPLACE_SIZE {
            let mut owned_copy = Box::<[u8]>::from(value);
            let ptr = owned_copy.as_mut_ptr();
            Box::into_raw(owned_copy);
            Self { ptr }
        } else {
            let mut x: Self = Self {
                in_place: Default::default(),
            };
            unsafe {
                x.in_place[0..size].copy_from_slice(value);
            }
            x
        }
    }

    pub fn clone(&self, size: usize) -> Self {
        if size > Self::MAX_INPLACE_SIZE {
            // Safety guaranteed by condition.
            Self::copy_from(unsafe { self.ptr_slice(size) }, size)
        } else {
            Self {
                in_place: unsafe { self.in_place }.clone(),
            }
        }
    }
}

pub trait ParallelFieldOffsetAccessor<FromFieldType, TargetFieldType> {
    fn get(m: &FromFieldType) -> &TargetFieldType;
    fn get_mut(m: &mut FromFieldType) -> &mut TargetFieldType;
}

pub trait SizeFieldConverterTrait<SizeFieldType> {
    fn max_size() -> usize;
    fn is_size_over_limit(size: usize) -> bool;
    fn get(size_field: &SizeFieldType) -> usize;
    fn set(size_field: &mut SizeFieldType, size: usize);
}

#[derive(Default)]
pub struct TrivialSizeFieldConverterU16 {}

impl SizeFieldConverterTrait<u16> for TrivialSizeFieldConverterU16 {
    fn max_size() -> usize {
        std::u16::MAX as usize
    }

    fn is_size_over_limit(size: usize) -> bool {
        size > std::u16::MAX as usize
    }

    fn get(size_field: &u16) -> usize {
        (*size_field) as usize
    }

    fn set(size_field: &mut u16, size: usize) {
        *size_field = size as u16;
    }
}

impl<
        SizeFieldType,
        SizeFieldGetterSetter: SizeFieldConverterTrait<SizeFieldType>,
        ByteArrayOffsetAccessor: ParallelFieldOffsetAccessor<Self, MaybeInPlaceByteArray>,
        SizeFieldOffsetAccessor: ParallelFieldOffsetAccessor<Self, SizeFieldType>,
    > MaybeInPlaceByteArrayMemoryManagerTrait
    for FieldsOffsetMaybeInPlaceByteArrayMemoryManager<
        SizeFieldType,
        SizeFieldGetterSetter,
        ByteArrayOffsetAccessor,
        SizeFieldOffsetAccessor,
    >
{
    fn get_size(&self) -> usize {
        SizeFieldGetterSetter::get(SizeFieldOffsetAccessor::get(self))
    }

    fn set_size(&mut self, size: usize) {
        SizeFieldGetterSetter::set(
            SizeFieldOffsetAccessor::get_mut(self),
            size,
        );
    }

    fn get_in_place_byte_array(&self) -> &MaybeInPlaceByteArray {
        ByteArrayOffsetAccessor::get(self)
    }

    fn get_in_place_byte_array_mut(&mut self) -> &mut MaybeInPlaceByteArray {
        ByteArrayOffsetAccessor::get_mut(self)
    }
}
