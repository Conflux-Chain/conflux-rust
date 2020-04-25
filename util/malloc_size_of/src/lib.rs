// Copyright 2016-2017 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A reduced fork of Firefox's malloc_size_of crate, for bundling with
//! WebRender.

use cfg_if::cfg_if;
use cfx_types::{H160, H256, H512, U256, U512};
use hashbrown::HashMap as FastHashMap;
use slab::Slab;
use std::{
    collections::{BinaryHeap, HashSet, VecDeque},
    hash::{BuildHasher, Hash},
    mem::{self, size_of},
    ops::Range,
    os::raw::c_void,
    sync::Arc,
};

/// A C function that takes a pointer to a heap allocation and returns its size.
type VoidPtrToSizeFn = unsafe extern "C" fn(ptr: *const c_void) -> usize;

/// Operations used when measuring heap usage of data structures.
pub struct MallocSizeOfOps {
    /// A function that returns the size of a heap allocation.
    pub size_of_op: VoidPtrToSizeFn,

    /// Like `size_of_op`, but can take an interior pointer. Optional because
    /// not all allocators support this operation. If it's not provided, some
    /// memory measurements will actually be computed estimates rather than
    /// real and accurate measurements.
    pub enclosing_size_of_op: Option<VoidPtrToSizeFn>,

    pub visited: HashSet<usize>,
}

impl MallocSizeOfOps {
    pub fn new(
        size_of: VoidPtrToSizeFn,
        malloc_enclosing_size_of: Option<VoidPtrToSizeFn>,
    ) -> Self
    {
        MallocSizeOfOps {
            size_of_op: size_of,
            enclosing_size_of_op: malloc_enclosing_size_of,
            visited: HashSet::new(),
        }
    }

    /// Check if an allocation is empty. This relies on knowledge of how Rust
    /// handles empty allocations, which may change in the future.
    fn is_empty<T: ?Sized>(ptr: *const T) -> bool {
        // The correct condition is this:
        //   `ptr as usize <= ::std::mem::align_of::<T>()`
        // But we can't call align_of() on a ?Sized T. So we approximate it
        // with the following. 256 is large enough that it should always be
        // larger than the required alignment, but small enough that it is
        // always in the first page of memory and therefore not a legitimate
        // address.
        ptr as *const usize as usize <= 256
    }

    /// Call `size_of_op` on `ptr`, first checking that the allocation isn't
    /// empty, because some types (such as `Vec`) utilize empty allocations.
    pub unsafe fn malloc_size_of<T: ?Sized>(&self, ptr: *const T) -> usize {
        if MallocSizeOfOps::is_empty(ptr) {
            0
        } else {
            (self.size_of_op)(ptr as *const c_void)
        }
    }

    /// Is an `enclosing_size_of_op` available?
    pub fn has_malloc_enclosing_size_of(&self) -> bool {
        self.enclosing_size_of_op.is_some()
    }

    /// Call `enclosing_size_of_op`, which must be available, on `ptr`, which
    /// must not be empty.
    pub unsafe fn malloc_enclosing_size_of<T>(&self, ptr: *const T) -> usize {
        assert!(!MallocSizeOfOps::is_empty(ptr));
        (self.enclosing_size_of_op.unwrap())(ptr as *const c_void)
    }
}

/// Trait for measuring the "deep" heap usage of a data structure. This is the
/// most commonly-used of the traits.
pub trait MallocSizeOf {
    /// Measure the heap usage of all descendant heap-allocated structures, but
    /// not the space taken up by the value itself.
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize;
}

/// Trait for measuring the "shallow" heap usage of a container.
pub trait MallocShallowSizeOf {
    /// Measure the heap usage of immediate heap-allocated descendant
    /// structures, but not the space taken up by the value itself. Anything
    /// beyond the immediate descendants must be measured separately, using
    /// iteration.
    fn shallow_size_of(&self, ops: &mut MallocSizeOfOps) -> usize;
}

impl MallocSizeOf for String {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        unsafe { ops.malloc_size_of(self.as_ptr()) }
    }
}

impl<T: ?Sized> MallocShallowSizeOf for Box<T> {
    fn shallow_size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        unsafe { ops.malloc_size_of(&**self) }
    }
}

impl<T: MallocSizeOf + ?Sized> MallocSizeOf for Box<T> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.shallow_size_of(ops) + (**self).size_of(ops)
    }
}

impl MallocSizeOf for () {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

impl<T1, T2> MallocSizeOf for (T1, T2)
where
    T1: MallocSizeOf,
    T2: MallocSizeOf,
{
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.0.size_of(ops) + self.1.size_of(ops)
    }
}

impl<T1, T2, T3> MallocSizeOf for (T1, T2, T3)
where
    T1: MallocSizeOf,
    T2: MallocSizeOf,
    T3: MallocSizeOf,
{
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.0.size_of(ops) + self.1.size_of(ops) + self.2.size_of(ops)
    }
}

impl<T1, T2, T3, T4> MallocSizeOf for (T1, T2, T3, T4)
where
    T1: MallocSizeOf,
    T2: MallocSizeOf,
    T3: MallocSizeOf,
    T4: MallocSizeOf,
{
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.0.size_of(ops)
            + self.1.size_of(ops)
            + self.2.size_of(ops)
            + self.3.size_of(ops)
    }
}

impl<T: MallocSizeOf> MallocSizeOf for Option<T> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        if let Some(val) = self.as_ref() {
            val.size_of(ops)
        } else {
            0
        }
    }
}

impl<T: MallocSizeOf, E: MallocSizeOf> MallocSizeOf for Result<T, E> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        match *self {
            Ok(ref x) => x.size_of(ops),
            Err(ref e) => e.size_of(ops),
        }
    }
}

impl<T: MallocSizeOf + Copy> MallocSizeOf for std::cell::Cell<T> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.get().size_of(ops)
    }
}

impl<T: MallocSizeOf> MallocSizeOf for std::cell::RefCell<T> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.borrow().size_of(ops)
    }
}

impl<'a, B: ?Sized + ToOwned> MallocSizeOf for std::borrow::Cow<'a, B>
where B::Owned: MallocSizeOf
{
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        match *self {
            std::borrow::Cow::Borrowed(_) => 0,
            std::borrow::Cow::Owned(ref b) => b.size_of(ops),
        }
    }
}

impl<T: MallocSizeOf> MallocSizeOf for [T] {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let mut n = 0;
        for elem in self.iter() {
            n += elem.size_of(ops);
        }
        n
    }
}

impl<T> MallocShallowSizeOf for Vec<T> {
    fn shallow_size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        unsafe { ops.malloc_size_of(self.as_ptr()) }
    }
}

impl<T: MallocSizeOf> MallocSizeOf for Vec<T> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let mut n = self.shallow_size_of(ops);
        for elem in self.iter() {
            n += elem.size_of(ops);
        }
        n
    }
}

#[allow(dead_code)]
#[derive(Clone)]
enum Entry<T> {
    Vacant(usize),
    Occupied(T),
}

impl<T> MallocShallowSizeOf for Slab<T> {
    fn shallow_size_of(&self, _ops: &mut MallocSizeOfOps) -> usize {
        mem::size_of::<Entry<T>>() * self.capacity()
    }
}

impl<T: MallocSizeOf> MallocSizeOf for Slab<T> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let mut n = self.shallow_size_of(ops);
        for (_, elem) in self.iter() {
            n += elem.size_of(ops);
        }
        n
    }
}

impl<T> MallocShallowSizeOf for BinaryHeap<T> {
    fn shallow_size_of(&self, _ops: &mut MallocSizeOfOps) -> usize {
        mem::size_of::<T>() * self.capacity()
    }
}

impl<T: MallocSizeOf> MallocSizeOf for BinaryHeap<T> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let mut n = self.shallow_size_of(ops);
        for elem in self.iter() {
            n += elem.size_of(ops);
        }
        n
    }
}

impl<T> MallocShallowSizeOf for VecDeque<T> {
    fn shallow_size_of(&self, _ops: &mut MallocSizeOfOps) -> usize {
        mem::size_of::<T>() * self.capacity()
    }
}

impl<T: MallocSizeOf> MallocSizeOf for VecDeque<T> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let mut n = self.shallow_size_of(ops);
        for elem in self.iter() {
            n += elem.size_of(ops);
        }
        n
    }
}

/// This is only for estimating memory size in Cache Manager
impl<T: MallocSizeOf> MallocSizeOf for Arc<T> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let ptr = self.as_ref() as *const T as usize;
        if ops.visited.contains(&ptr) {
            return 0;
        }
        ops.visited.insert(ptr);
        mem::size_of::<T>() + self.as_ref().size_of(ops)
    }
}

macro_rules! malloc_size_of_hash_set {
    ($ty:ty) => {
        impl<T, S> MallocShallowSizeOf for $ty
        where
            T: Eq + Hash,
            S: BuildHasher,
        {
            fn shallow_size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
                if ops.has_malloc_enclosing_size_of() {
                    // The first value from the iterator gives us an interior
                    // pointer. `ops.malloc_enclosing_size_of()`
                    // then gives us the storage size. This assumes
                    // that the `HashSet`'s contents (values and hashes)
                    // are all stored in a single contiguous heap allocation.
                    self.iter().next().map_or(0, |t| unsafe {
                        ops.malloc_enclosing_size_of(t)
                    })
                } else {
                    // An estimate.
                    self.capacity() * (size_of::<T>() + size_of::<usize>())
                }
            }
        }

        impl<T, S> MallocSizeOf for $ty
        where
            T: Eq + Hash + MallocSizeOf,
            S: BuildHasher,
        {
            fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
                let mut n = self.shallow_size_of(ops);
                for t in self.iter() {
                    n += t.size_of(ops);
                }
                n
            }
        }
    };
}

malloc_size_of_hash_set!(std::collections::HashSet<T, S>);

macro_rules! malloc_size_of_hash_map {
    ($ty:ty) => {
        impl<K, V, S> MallocShallowSizeOf for $ty
        where
            K: Eq + Hash,
            S: BuildHasher,
        {
            fn shallow_size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
                // See the implementation for std::collections::HashSet for
                // details.
                if ops.has_malloc_enclosing_size_of() {
                    self.values().next().map_or(0, |v| unsafe {
                        ops.malloc_enclosing_size_of(v)
                    })
                } else {
                    self.capacity()
                        * (size_of::<V>() + size_of::<K>() + size_of::<usize>())
                }
            }
        }

        impl<K, V, S> MallocSizeOf for $ty
        where
            K: Eq + Hash + MallocSizeOf,
            V: MallocSizeOf,
            S: BuildHasher,
        {
            fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
                let mut n = self.shallow_size_of(ops);
                for (k, v) in self.iter() {
                    n += k.size_of(ops);
                    n += v.size_of(ops);
                }
                n
            }
        }
    };
}

malloc_size_of_hash_map!(std::collections::HashMap<K, V, S>);
malloc_size_of_hash_map!(FastHashMap<K, V, S>);

// PhantomData is always 0.
impl<T> MallocSizeOf for std::marker::PhantomData<T> {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

/// For use on types where size_of() returns 0.
#[macro_export]
macro_rules! malloc_size_of_is_0(
    ($($ty:ty),+) => (
        $(
            impl $crate::MallocSizeOf for $ty {
                #[inline(always)]
                fn size_of(&self, _: &mut $crate::MallocSizeOfOps) -> usize {
                    0
                }
            }
        )+
    );
    ($($ty:ident<$($gen:ident),+>),+) => (
        $(
        impl<$($gen: $crate::MallocSizeOf),+> $crate::MallocSizeOf for $ty<$($gen),+> {
            #[inline(always)]
            fn size_of(&self, _: &mut $crate::MallocSizeOfOps) -> usize {
                0
            }
        }
        )+
    );
);

malloc_size_of_is_0!(bool, char, str);
malloc_size_of_is_0!(u8, u16, u32, u64, u128, usize);
malloc_size_of_is_0!(i8, i16, i32, i64, i128, isize);
malloc_size_of_is_0!(f32, f64);

malloc_size_of_is_0!(std::sync::atomic::AtomicBool);
malloc_size_of_is_0!(std::sync::atomic::AtomicIsize);
malloc_size_of_is_0!(std::sync::atomic::AtomicUsize);

malloc_size_of_is_0!(std::num::NonZeroUsize);
malloc_size_of_is_0!(std::num::NonZeroU32);

malloc_size_of_is_0!(std::time::Duration);
malloc_size_of_is_0!(std::time::Instant);
malloc_size_of_is_0!(std::time::SystemTime);

malloc_size_of_is_0!(
    Range<u8>,
    Range<u16>,
    Range<u32>,
    Range<u64>,
    Range<usize>
);
malloc_size_of_is_0!(
    Range<i8>,
    Range<i16>,
    Range<i32>,
    Range<i64>,
    Range<isize>
);
malloc_size_of_is_0!(Range<f32>, Range<f64>);

malloc_size_of_is_0!(H256, U256, H512, H160, U512);

mod usable_size {

    use super::*;

    cfg_if! {
        if #[cfg(target_os = "windows")] {

            // default windows allocator
            extern crate winapi;

            use self::winapi::um::heapapi::{GetProcessHeap, HeapSize, HeapValidate};

            /// Get the size of a heap block.
            /// Call windows allocator through `winapi` crate
            pub unsafe extern "C" fn malloc_usable_size(mut ptr: *const c_void) -> usize {

                let heap = GetProcessHeap();

                if HeapValidate(heap, 0, ptr) == 0 {
                    ptr = *(ptr as *const *const c_void).offset(-1);
                }

                HeapSize(heap, 0, ptr) as usize
            }

        } else if #[cfg(feature = "jemalloc-global")] {

            /// Use of jemalloc usable size C function through jemallocator crate call.
            pub unsafe extern "C" fn malloc_usable_size(ptr: *const c_void) -> usize {
                jemallocator::usable_size(ptr)
            }

        } else if #[cfg(target_os = "linux")] {

            /// Linux call system allocator (currently malloc).
            extern "C" {
                pub fn malloc_usable_size(ptr: *const c_void) -> usize;
            }

        } else if #[cfg(target_os = "macos")] {

            /// Linux call system allocator (currently malloc).
            extern "C" {
                #[link_name = "malloc_size"]
                pub fn malloc_usable_size(ptr: *const c_void) -> usize;
            }


        } else {
            pub unsafe extern "C" fn malloc_usable_size(_ptr: *const c_void) -> usize {
                unreachable!("estimate heapsize or feature allocator needed")
            }

        }

    }

    /// No enclosing function defined.
    #[inline]
    pub fn new_enclosing_size_fn() -> Option<VoidPtrToSizeFn> { None }
}

/// Get a new instance of a MallocSizeOfOps
pub fn new_malloc_size_ops() -> MallocSizeOfOps {
    MallocSizeOfOps::new(
        usable_size::malloc_usable_size,
        usable_size::new_enclosing_size_fn(),
    )
}
