// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{ptr::null_mut, slice};

pub union MaybeInPlaceByteArray {
    in_place: [u8; 8],
    // TODO(yz): statically assert that the ptr has size of at most 8.
    // TODO(yz): to initialize and destruct, convert from/into Vec.
    // TODO(yz): introduce a type to pass into template which manages the
    // conversion from/to  Vec<A>. The type should also take the offset of
    // u16 size from the TrieNode struct to manage memory buffer, and
    // should offer a type for ptr here.
    /// Only raw pointer is 8B.
    ptr: *mut u8,
}

impl Default for MaybeInPlaceByteArray {
    fn default() -> Self {
        Self {
            in_place: Default::default(),
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

    fn new(mut value: Box<[u8]>, size: usize) -> Self {
        if size > Self::MAX_INPLACE_SIZE {
            let ptr = value.as_mut_ptr();
            Box::into_raw(value);
            Self { ptr }
        } else {
            let mut x = Self {
                in_place: Default::default(),
            };
            unsafe {
                x.in_place[0..size].copy_from_slice(&*value);
            }
            x
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
}

impl MaybeInPlaceByteArray {
    pub const MAX_INPLACE_SIZE: usize = 8;
    pub const MAX_SIZE_U16: usize = 0xffff;
    pub const MAX_SIZE_U32: usize = 0xffffffff;
}
