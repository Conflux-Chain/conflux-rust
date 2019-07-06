// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Pre-allocated storage for a uniform data type.
//!
//! `Slab` provides pre-allocated storage for a single data type. If many values
//! of a single type are being allocated, it can be more efficient to
//! pre-allocate the necessary storage. Since the size of the type is uniform,
//! memory fragmentation can be avoided. Storing, clearing, and lookup
//! operations become very cheap.
//!
//! While `Slab` may look like other Rust collections, it is not intended to be
//! used as a general purpose collection. The primary difference between `Slab`
//! and `Vec` is that `Slab` returns the key when storing the value.
//!
//! It is important to note that keys may be reused. In other words, once a
//! value associated with a given key is removed from a slab, that key may be
//! returned from future calls to `insert`.
//!
//! # Examples
//!
//! Basic storing and retrieval.
//!
//! ```
//! # extern crate slab;
//! # use slab::*;
//! let mut slab = Slab::new();
//!
//! let hello = slab.insert("hello");
//! let world = slab.insert("world");
//!
//! assert_eq!(slab[hello], "hello");
//! assert_eq!(slab[world], "world");
//!
//! slab[world] = "earth";
//! assert_eq!(slab[world], "earth");
//! ```
//!
//! Sometimes it is useful to be able to associate the key with the value being
//! inserted in the slab. This can be done with the `vacant_entry` API as such:
//!
//! ```
//! # extern crate slab;
//! # use slab::*;
//! let mut slab = Slab::new();
//!
//! let hello = {
//!     let entry = slab.vacant_entry();
//!     let key = entry.key();
//!
//!     entry.insert((key, "hello"));
//!     key
//! };
//!
//! assert_eq!(hello, slab[hello].0);
//! assert_eq!("hello", slab[hello].1);
//! ```
//!
//! It is generally a good idea to specify the desired capacity of a slab at
//! creation time. Note that `Slab` will grow the internal capacity when
//! attempting to insert a new value once the existing capacity has been
//! reached. To avoid this, add a check.
//!
//! ```
//! # extern crate slab;
//! # use slab::*;
//! let mut slab = Slab::with_capacity(1024);
//!
//! // ... use the slab
//!
//! if slab.len() == slab.capacity() {
//!     panic!("slab full");
//! }
//!
//! slab.insert("the slab is not at capacity yet");
//! ```
//!
//! # Capacity and reallocation
//!
//! The capacity of a slab is the amount of space allocated for any future
//! values that will be inserted in the slab. This is not to be confused with
//! the *length* of the slab, which specifies the number of actual values
//! currently being inserted. If a slab's length is equal to its capacity, the
//! next value inserted into the slab will require growing the slab by
//! reallocating.
//!
//! For example, a slab with capacity 10 and length 0 would be an empty slab
//! with space for 10 more stored values. Storing 10 or fewer elements into the
//! slab will not change its capacity or cause reallocation to occur. However,
//! if the slab length is increased to 11 (due to another `insert`), it will
//! have to reallocate, which can be slow. For this reason, it is recommended to
//! use [`Slab::with_capacity`] whenever possible to specify how many values the
//! slab is expected to store.
//!
//! # Implementation
//!
//! `Slab` is backed by a `Vec` of slots. Each slot is either occupied or
//! vacant. `Slab` maintains a stack of vacant slots using a linked list. To
//! find a vacant slot, the stack is popped. When a slot is released, it is
//! pushed onto the stack.
//!
//! If there are no more available slots in the stack, then `Vec::reserve(1)` is
//! called and a new slot is created.
//!
//! [`Slab::with_capacity`]: struct.Slab.html#with_capacity

#![deny(warnings, missing_docs, missing_debug_implementations)]
#![doc(html_root_url = "https://docs.rs/slab/0.4.1")]

use super::super::errors::*;
use parking_lot::Mutex;
use std::{fmt, iter::IntoIterator, marker::PhantomData, mem, ops, ptr, slice};

/// Pre-allocated storage for a uniform data type.
/// The modified slab offers internal mutability which mimics the behavior of
/// independent pointer at best.
///
/// Resizing the slab itself requires &mut, other operatios can be done with &.
///
/// Gettting reference to allocated slot doesn't conflict with any other
/// operations. Slab doesn't check if user get &mut and & for the same slot.
/// User should maintain a layer which controls the mutability of each specific
/// slot. It can be done through the wrapper around the slot index, or in the
/// type which implements EntryTrait<T>.
///
/// Allocation and Deallocation are serialized by mutex because they modify the
/// slab link-list.
pub struct Slab<T, E: EntryTrait<T> = Entry<T>> {
    /// Chunk of memory
    // entries is always kept full in order to prevent changing vector
    // when allocating space for new element. We would like to keep the size of
    // initialized entry in AllocRelatedFields#size_initialized instead of
    // vector.
    entries: Vec<E>,

    /// Fields which are modified when allocate / delete an entry.
    alloc_fields: Mutex<AllocRelatedFields>,

    value_type: PhantomData<T>,
}

#[derive(Default)]
struct AllocRelatedFields {
    // Number of Filled elements currently in the slab
    used: usize,
    // Size of the memory where it's initialized with data or offset to next
    // available slot.
    size_initialized: usize,
    // Offset of the next available slot in the slab. Set to the slab's
    // capacity when the slab is full.
    next: usize,
}

/// Methods which check if the entry holds a value and return reference to the
/// value. The methods should ont panic.
pub trait IntoOption<T> {
    fn into_option_mut(&mut self) -> Option<&mut T>;
    fn into_option_ref(&self) -> Option<&T>;
}

/// Allow user to pass into any type which is convertible to T. The intention is
/// that we pass &T or &mut T cross the interfaces so that we only do memcpy
/// once.
pub trait FromInto<T>: Sized {
    fn from<U: Into<T>>(val: U) -> Self;
}

/// Slab physically stores a concrete type which implements EntryTrait<T> for
/// value type T. The EntryTrait<T> is responsible to hold the value type and
/// the next vacant link list for slab.
pub trait EntryTrait<T>: IntoOption<T> + FromInto<T> + Sized + Default {
    fn from_vacant_index(next: usize) -> Self;

    fn take_occupied_and_replace(&mut self, new: Self) -> T {
        unsafe {
            let ret = ptr::read(self.get_occupied_mut());
            // Semantically, val is moved into ret and self is dropped.

            ptr::write(self, new);
            // Semantically, new is dropped, self now holds new.

            ret
        }
    }

    fn get_next_vacant_index(&self) -> usize;
    fn get_occupied_ref(&self) -> &T;
    fn get_occupied_mut(&mut self) -> &mut T;
}

impl<T> EntryTrait<T> for Entry<T> {
    fn from_vacant_index(index: usize) -> Self { Entry::Vacant(index) }

    fn get_next_vacant_index(&self) -> usize {
        match *self {
            Entry::Vacant(index) => index,
            _ => unreachable!(),
        }
    }

    fn get_occupied_ref(&self) -> &T {
        match self {
            Entry::Occupied(val) => val,
            _ => unreachable!(),
        }
    }

    fn get_occupied_mut(&mut self) -> &mut T {
        match self {
            Entry::Occupied(val) => val,
            _ => unreachable!(),
        }
    }
}

impl<T> IntoOption<T> for Entry<T> {
    fn into_option_ref(&self) -> Option<&T> {
        match self {
            Entry::Occupied(ref val) => Some(val),
            Entry::Vacant(_index) => None,
        }
    }

    fn into_option_mut(&mut self) -> Option<&mut T> {
        match self {
            Entry::Occupied(ref mut val) => Some(val),
            Entry::Vacant(_index) => None,
        }
    }
}

impl<T> FromInto<T> for Entry<T> {
    fn from<U: Into<T>>(val: U) -> Self { Entry::Occupied(val.into()) }
}

/// A handle to a vacant entry in a `Slab`.
///
/// `VacantEntry` allows constructing values with the key that they will be
/// assigned to.
///
/// # Examples
///
/// ```
/// # extern crate slab;
/// # use slab::*;
/// let mut slab = Slab::new();
///
/// let hello = {
///     let entry = slab.vacant_entry();
///     let key = entry.key();
///
///     entry.insert((key, "hello"));
///     key
/// };
///
/// assert_eq!(hello, slab[hello].0);
/// assert_eq!("hello", slab[hello].1);
/// ```
#[derive(Debug)]
pub struct VacantEntry<'a, T: 'a, E: 'a + EntryTrait<T>> {
    slab: &'a Slab<T, E>,
    key: usize,
    // Panic if insert is not called at all because the allocated slot must be
    // initialized.
    inserted: bool,
}

impl<'a, T: 'a, E: 'a + EntryTrait<T>> Drop for VacantEntry<'a, T, E> {
    fn drop(&mut self) { assert_eq!(self.inserted, true) }
}

/// An iterator over the values stored in the `Slab`
pub struct Iter<'a, T: 'a, E: 'a + EntryTrait<T>> {
    entries: slice::Iter<'a, E>,
    curr: usize,
    value_type: PhantomData<T>,
}

/// A mutable iterator over the values stored in the `Slab`
pub struct IterMut<'a, T: 'a, E: 'a + EntryTrait<T>> {
    entries: slice::IterMut<'a, E>,
    curr: usize,
    value_type: PhantomData<T>,
}

#[derive(Clone, Debug)]
pub enum Entry<T> {
    Vacant(usize),
    Occupied(T),
}

impl<T> Default for Entry<T> {
    fn default() -> Self { Entry::Vacant(0) }
}

impl<T, E: EntryTrait<T>> Default for Slab<T, E> {
    fn default() -> Self {
        Self {
            entries: Default::default(),
            alloc_fields: Default::default(),
            value_type: PhantomData,
        }
    }
}

impl<T, E: EntryTrait<T>> Slab<T, E> {
    /// Construct a new, empty `Slab` with the specified capacity.
    ///
    /// The returned slab will be able to store exactly `capacity` without
    /// reallocating. If `capacity` is 0, the slab will not allocate.
    ///
    /// It is important to note that this function does not specify the *length*
    /// of the returned slab, but only the capacity. For an explanation of the
    /// difference between length and capacity, see [Capacity and
    /// reallocation](index.html#capacity-and-reallocation).
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::with_capacity(10);
    ///
    /// // The slab contains no values, even though it has capacity for more
    /// assert_eq!(slab.len(), 0);
    ///
    /// // These are all done without reallocating...
    /// for i in 0..10 {
    ///     slab.insert(i);
    /// }
    ///
    /// // ...but this may make the slab reallocate
    /// slab.insert(11);
    /// ```
    pub fn with_capacity(capacity: usize) -> Self {
        let mut new = Slab::default();
        new.reserve(capacity).unwrap();
        new
    }

    /// Return the number of values the slab can store without reallocating.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let slab: Slab<i32> = Slab::with_capacity(10);
    /// assert_eq!(slab.capacity(), 10);
    /// ```
    pub fn capacity(&self) -> usize { self.entries.capacity() }

    /// Reserve capacity for at least `additional` more values to be stored
    /// without allocating.
    ///
    /// `reserve` does nothing if the slab already has sufficient capacity for
    /// `additional` more values. If more capacity is required, a new segment of
    /// memory will be allocated and all existing values will be copied into it.
    /// As such, if the slab is already very large, a call to `reserve` can end
    /// up being expensive.
    ///
    /// The slab may reserve more than `additional` extra space in order to
    /// avoid frequent reallocations. Use `reserve_exact` instead to guarantee
    /// that only the requested space is allocated.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity overflows `usize`.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    /// slab.insert("hello");
    /// slab.reserve(10);
    /// assert!(slab.capacity() >= 11);
    /// ```
    pub fn reserve(&mut self, additional: usize) -> Result<()> {
        let old_capacity = self.capacity();
        if old_capacity - self.len() >= additional {
            return Ok(());
        }
        let need_add = self.len() + additional - old_capacity;
        self.entries.reserve(need_add);
        // TODO(yz): should return error instead of panic, however, try_reserve*
        // is only in nightly.        self.entries.
        // try_reserve(need_add).chain_err(|| ErrorKind::OutOfMem)?;
        let capacity = self.capacity();
        self.resize_up(old_capacity, capacity);
        Ok(())
    }

    /// Reserve the minimum capacity required to store exactly `additional`
    /// more values.
    ///
    /// `reserve_exact` does nothing if the slab already has sufficient capacity
    /// for `additional` more valus. If more capacity is required, a new segment
    /// of memory will be allocated and all existing values will be copied into
    /// it.  As such, if the slab is already very large, a call to `reserve` can
    /// end up being expensive.
    ///
    /// Note that the allocator may give the slab more space than it requests.
    /// Therefore capacity can not be relied upon to be precisely minimal.
    /// Prefer `reserve` if future insertions are expected.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity overflows `usize`.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    /// slab.insert("hello");
    /// slab.reserve_exact(10);
    /// assert!(slab.capacity() >= 11);
    /// ```
    pub fn reserve_exact(&mut self, additional: usize) -> Result<()> {
        let old_capacity = self.capacity();
        if old_capacity - self.len() >= additional {
            return Ok(());
        }
        let need_add = self.len() + additional - old_capacity;
        // TODO(yz): should return error instead of panic, however, try_reserve*
        // is only in nightly.        self.entries.
        // try_reserve_exact(need_add).chain_err(|| ErrorKind::OutOfMem)?;
        self.entries.reserve_exact(need_add);
        let capacity = self.capacity();
        self.resize_up(old_capacity, capacity);
        Ok(())
    }

    // TODO(yz): resize_default is nightly only.
    fn resize_up(&mut self, capacity: usize, new_capacity: usize) {
        for _i in capacity..new_capacity {
            self.entries.push(E::default());
        }
    }

    fn resize_down(&mut self, capacity: usize, new_capacity: usize) {
        for _i in new_capacity..capacity {
            self.entries.pop();
        }
    }

    /// Shrink the capacity of the slab as much as possible.
    ///
    /// It will drop down as close as possible to the length but the allocator
    /// may still inform the vector that there is space for a few more elements.
    /// Also, since values are not moved, the slab cannot shrink past any stored
    /// values.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::with_capacity(10);
    ///
    /// for i in 0..3 {
    ///     slab.insert(i);
    /// }
    ///
    /// assert_eq!(slab.capacity(), 10);
    /// slab.shrink_to_fit();
    /// assert!(slab.capacity() >= 3);
    /// ```
    ///
    /// In this case, even though two values are removed, the slab cannot shrink
    /// past the last value.
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::with_capacity(10);
    ///
    /// for i in 0..3 {
    ///     slab.insert(i);
    /// }
    ///
    /// slab.remove(0);
    /// slab.remove(1);
    ///
    /// assert_eq!(slab.capacity(), 10);
    /// slab.shrink_to_fit();
    /// assert!(slab.capacity() >= 3);
    /// ```
    pub fn shrink_to_fit(&mut self) {
        let capacity = self.capacity();
        let new_capacity = self.alloc_fields.get_mut().size_initialized;

        self.resize_down(capacity, new_capacity);
        self.entries.shrink_to_fit();
    }

    /// Clear the slab of all values.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    ///
    /// for i in 0..3 {
    ///     slab.insert(i);
    /// }
    ///
    /// slab.clear();
    /// assert!(slab.is_empty());
    /// ```
    pub fn clear(&mut self) { mem::replace(self, Self::default()); }

    /// Return the number of stored values.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    ///
    /// for i in 0..3 {
    ///     slab.insert(i);
    /// }
    ///
    /// assert_eq!(3, slab.len());
    /// ```
    pub fn len(&self) -> usize { self.alloc_fields.lock().used }

    /// Return `true` if there are no values stored in the slab.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    /// assert!(slab.is_empty());
    ///
    /// slab.insert(1);
    /// assert!(!slab.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Return an iterator over the slab.
    ///
    /// This function should generally be **avoided** as it is not efficient.
    /// Iterators must iterate over every slot in the slab even if it is
    /// vacant. As such, a slab with a capacity of 1 million but only one
    /// stored value must still iterate the million slots.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    ///
    /// for i in 0..3 {
    ///     slab.insert(i);
    /// }
    ///
    /// let mut iterator = slab.iter();
    ///
    /// assert_eq!(iterator.next(), Some((0, &0)));
    /// assert_eq!(iterator.next(), Some((1, &1)));
    /// assert_eq!(iterator.next(), Some((2, &2)));
    /// assert_eq!(iterator.next(), None);
    /// ```
    // TODO(yz): let the iter stop at the size_initialized.
    pub fn iter(&self) -> Iter<T, E> {
        Iter {
            entries: self.entries.iter(),
            curr: 0,
            value_type: PhantomData,
        }
    }

    /// Return an iterator that allows modifying each value.
    ///
    /// This function should generally be **avoided** as it is not efficient.
    /// Iterators must iterate over every slot in the slab even if it is
    /// vacant. As such, a slab with a capacity of 1 million but only one
    /// stored value must still iterate the million slots.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    ///
    /// let key1 = slab.insert(0);
    /// let key2 = slab.insert(1);
    ///
    /// for (key, val) in slab.iter_mut() {
    ///     if key == key1 {
    ///         *val += 2;
    ///     }
    /// }
    ///
    /// assert_eq!(slab[key1], 2);
    /// assert_eq!(slab[key2], 1);
    /// ```
    // TODO(yz): let the iter stop at the size_initialized.
    pub fn iter_mut(&mut self) -> IterMut<T, E> {
        IterMut {
            entries: self.entries.iter_mut(),
            curr: 0,
            value_type: PhantomData,
        }
    }

    /// Return a reference to the value associated with the given key.
    ///
    /// If the given key is not associated with a value, then `None` is
    /// returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    /// let key = slab.insert("hello");
    ///
    /// assert_eq!(slab.get(key), Some(&"hello"));
    /// assert_eq!(slab.get(123), None);
    /// ```
    pub fn get(&self, key: usize) -> Option<&T> {
        self.entries
            .get(key)
            .and_then(|entry| entry.into_option_ref())
    }

    /// Return a mutable reference to the value associated with the given key.
    ///
    /// If the given key is not associated with a value, then `None` is
    /// returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    /// let key = slab.insert("hello");
    ///
    /// *slab.get_mut(key).unwrap() = "world";
    ///
    /// assert_eq!(slab[key], "world");
    /// assert_eq!(slab.get_mut(123), None);
    /// ```
    // This method is unsafe because user may pass the same key to get_mut at
    // the same time.
    pub unsafe fn get_mut(&self, key: usize) -> Option<&mut T> {
        self.entries.get(key).and_then(|entry| {
            Self::cast_element_ref_mut(entry).into_option_mut()
        })
    }

    /// Return a reference to the value associated with the given key without
    /// performing bounds checking.
    ///
    /// This function should be used with care.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    /// let key = slab.insert(2);
    ///
    /// unsafe {
    ///     assert_eq!(slab.get_unchecked(key), &2);
    /// }
    /// ```
    pub unsafe fn get_unchecked(&self, key: usize) -> &T {
        self.get_element_at(key).get_occupied_ref()
    }

    /// Return a mutable reference to the value associated with the given key
    /// without performing bounds checking.
    ///
    /// This function should be used with care.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    /// let key = slab.insert(2);
    ///
    /// unsafe {
    ///     let val = slab.get_unchecked_mut(key);
    ///     *val = 13;
    /// }
    ///
    /// assert_eq!(slab[key], 13);
    /// ```
    pub unsafe fn get_unchecked_mut(&self, key: usize) -> &mut T {
        self.get_element_at(key).get_occupied_mut()
    }

    fn cast_element_ref_mut(r: &E) -> &mut E {
        unsafe { &mut *((r as *const E) as *mut E) }
    }

    fn get_element_at(&self, key: usize) -> &mut E {
        unsafe { Self::cast_element_ref_mut(self.entries.get_unchecked(key)) }
    }

    /// Insert a value in the slab, returning key assigned to the value.
    ///
    /// The returned key can later be used to retrieve or remove the value using
    /// indexed lookup and `remove`. Additional capacity is allocated if
    /// needed. See [Capacity and
    /// reallocation](index.html#capacity-and-reallocation).
    ///
    /// # Panics
    ///
    /// Panics if the number of elements in the vector overflows a `usize`.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    /// let key = slab.insert("hello");
    /// assert_eq!(slab[key], "hello");
    /// ```
    pub fn insert<U: Into<T>>(&self, val: U) -> Result<usize> {
        let key = self.allocate()?;
        self.insert_at(key, val);
        Ok(key)
    }

    pub fn allocate(&self) -> Result<usize> {
        let mut alloc_fields = self.alloc_fields.lock();
        let key = alloc_fields.next;
        if key == self.entries.capacity() {
            Err(Error::from_kind(ErrorKind::OutOfMem))
        } else {
            alloc_fields.used += 1;
            if key == alloc_fields.size_initialized {
                alloc_fields.next = key + 1;
                alloc_fields.size_initialized = alloc_fields.next;
            } else {
                alloc_fields.next = self.entries[key].get_next_vacant_index();
            }
            Ok(key)
        }
    }

    fn insert_at<U: Into<T>>(&self, key: usize, val: U) {
        *self.get_element_at(key) = E::from(val);
    }

    /// Return a handle to a vacant entry allowing for further manipulation.
    ///
    /// This function is useful when creating values that must contain their
    /// slab key. The returned `VacantEntry` reserves a slot in the slab and is
    /// able to query the associated key.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    ///
    /// let hello = {
    ///     let entry = slab.vacant_entry();
    ///     let key = entry.key();
    ///
    ///     entry.insert((key, "hello"));
    ///     key
    /// };
    ///
    /// assert_eq!(hello, slab[hello].0);
    /// assert_eq!("hello", slab[hello].1);
    /// ```
    pub fn vacant_entry(&self) -> Result<VacantEntry<T, E>> {
        Ok(VacantEntry {
            key: self.allocate()?,
            slab: self,
            inserted: false,
        })
    }

    /// Remove and return the value associated with the given key.
    ///
    /// The key is then released and may be associated with future stored
    /// values.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not associated with a value.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    ///
    /// let hello = slab.insert("hello");
    ///
    /// assert_eq!(slab.remove(hello), "hello");
    /// assert!(!slab.contains(hello));
    /// ```
    pub fn remove(&self, key: usize) -> Result<T> {
        let mut alloc_fields = self.alloc_fields.lock();
        let next = alloc_fields.next;
        let old_value = match self.entries.get(key) {
            Some(ref val) => {
                alloc_fields.used -= 1;
                alloc_fields.next = key;
                Self::cast_element_ref_mut(val)
                    .take_occupied_and_replace(E::from_vacant_index(next))
            }
            None => {
                // Index out of range.
                return Err(Error::from_kind(ErrorKind::SlabKeyError));
            }
        };

        Ok(old_value)
    }

    /// Return `true` if a value is associated with the given key.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    ///
    /// let hello = slab.insert("hello");
    /// assert!(slab.contains(hello));
    ///
    /// slab.remove(hello);
    ///
    /// assert!(!slab.contains(hello));
    /// ```
    pub fn contains(&self, key: usize) -> bool { self.get(key).is_some() }

    /// Retain only the elements specified by the predicate.
    ///
    /// In other words, remove all elements `e` such that `f(usize, &mut e)`
    /// returns false. This method operates in place and preserves the key
    /// associated with the retained values.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    ///
    /// let k1 = slab.insert(0);
    /// let k2 = slab.insert(1);
    /// let k3 = slab.insert(2);
    ///
    /// slab.retain(|key, val| key == k1 || *val == 1);
    ///
    /// assert!(slab.contains(k1));
    /// assert!(slab.contains(k2));
    /// assert!(!slab.contains(k3));
    ///
    /// assert_eq!(2, slab.len());
    /// ```
    pub fn retain<F>(&mut self, mut f: F)
    where F: FnMut(usize, &mut T) -> bool {
        for i in 0..self.entries.len() {
            let keep = unsafe { self.get_mut(i).map_or(true, |v| f(i, v)) };

            if !keep {
                self.remove(i).unwrap();
            }
        }
    }
}

impl<T, E: EntryTrait<T>> ops::Index<usize> for Slab<T, E> {
    type Output = T;

    fn index(&self, key: usize) -> &T { self.entries[key].get_occupied_ref() }
}

impl<'a, T, E: EntryTrait<T>> IntoIterator for &'a Slab<T, E> {
    type IntoIter = Iter<'a, T, E>;
    type Item = (usize, &'a T);

    fn into_iter(self) -> Iter<'a, T, E> { self.iter() }
}

impl<'a, T, E: EntryTrait<T>> IntoIterator for &'a mut Slab<T, E> {
    type IntoIter = IterMut<'a, T, E>;
    type Item = (usize, &'a mut T);

    fn into_iter(self) -> IterMut<'a, T, E> { self.iter_mut() }
}

impl<T, E: EntryTrait<T>> fmt::Debug for Slab<T, E>
where T: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "Slab {{ len: {}, cap: {} }}",
            self.len(),
            self.capacity()
        )
    }
}

impl<'a, T: 'a, E: EntryTrait<T>> fmt::Debug for Iter<'a, T, E>
where T: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("Iter")
            .field("curr", &self.curr)
            .field("remaining", &self.entries.len())
            .finish()
    }
}

impl<'a, T: 'a, E: EntryTrait<T>> fmt::Debug for IterMut<'a, T, E>
where T: fmt::Debug
{
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("IterMut")
            .field("curr", &self.curr)
            .field("remaining", &self.entries.len())
            .finish()
    }
}

// ===== VacantEntry =====

impl<'a, T, E: EntryTrait<T>> VacantEntry<'a, T, E> {
    /// Insert a value in the entry, returning a mutable reference to the value.
    ///
    /// To get the key associated with the value, use `key` prior to calling
    /// `insert`.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    ///
    /// let hello = {
    ///     let entry = slab.vacant_entry();
    ///     let key = entry.key();
    ///
    ///     entry.insert((key, "hello"));
    ///     key
    /// };
    ///
    /// assert_eq!(hello, slab[hello].0);
    /// assert_eq!("hello", slab[hello].1);
    /// ```
    pub fn insert<U>(mut self, val: U) -> &'a mut T
    where T: From<U> {
        self.inserted = true;
        self.slab.insert_at(self.key, val);
        unsafe { self.slab.get_unchecked_mut(self.key) }
    }

    /// Return the key associated with this entry.
    ///
    /// A value stored in this entry will be associated with this key.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate slab;
    /// # use slab::*;
    /// let mut slab = Slab::new();
    ///
    /// let hello = {
    ///     let entry = slab.vacant_entry();
    ///     let key = entry.key();
    ///
    ///     entry.insert((key, "hello"));
    ///     key
    /// };
    ///
    /// assert_eq!(hello, slab[hello].0);
    /// assert_eq!("hello", slab[hello].1);
    /// ```
    pub fn key(&self) -> usize { self.key }
}

// ===== Iter =====

impl<'a, T, E: EntryTrait<T>> Iterator for Iter<'a, T, E> {
    type Item = (usize, &'a T);

    fn next(&mut self) -> Option<(usize, &'a T)> {
        while let Some(entry) = self.entries.next() {
            let curr = self.curr;
            self.curr += 1;

            if let Some(ref_v) = entry.into_option_ref() {
                return Some((curr, ref_v));
            }
        }

        None
    }
}

// ===== IterMut =====

impl<'a, T, E: EntryTrait<T>> Iterator for IterMut<'a, T, E> {
    type Item = (usize, &'a mut T);

    fn next(&mut self) -> Option<(usize, &'a mut T)> {
        while let Some(entry) = self.entries.next() {
            let curr = self.curr;
            self.curr += 1;

            if let Some(ref_mut_v) = entry.into_option_mut() {
                return Some((curr, ref_mut_v));
            }
        }

        None
    }
}
