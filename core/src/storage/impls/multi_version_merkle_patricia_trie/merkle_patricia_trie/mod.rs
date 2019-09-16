// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[macro_use]
pub(self) mod maybe_in_place_byte_array_macro;

pub mod children_table;
pub(self) mod compressed_path;
pub mod cow_node_ref;
pub(self) mod maybe_in_place_byte_array;
pub mod merkle;
pub mod mpt_cursor;
pub mod mpt_merger;
pub mod mpt_value;
pub mod node_ref;
pub mod subtrie_visitor;
pub mod trie_node;
pub mod trie_proof;
pub(self) mod walk;

#[cfg(test)]
mod tests;

/// The purpose of this trait is to create a new value of a passed object,
/// when the passed object is the value, simply move the value;
/// when the passed object is the reference, create the new value by clone.
/// Other extension is possible.
///
/// The trait is used by ChildrenTable and slab.
pub trait WrappedCreateFrom<FromType, ToType> {
    fn take(x: FromType) -> ToType;
    /// Unoptimized default implementation.
    fn take_from(dest: &mut ToType, x: FromType) {
        std::mem::replace(dest, Self::take(x));
    }
}

/*
/// This is correct but we don't use this implementation.
impl<T> WrappedCreateFrom<T, UnsafeCell<T>> for UnsafeCell<T> {
    fn take(val: T) -> UnsafeCell<T> { UnsafeCell::new(val) }
}
*/

impl<'x, T: Clone> WrappedCreateFrom<&'x T, UnsafeCell<T>> for UnsafeCell<T> {
    fn take(val: &'x T) -> UnsafeCell<T> { UnsafeCell::new(val.clone()) }

    fn take_from(dest: &mut UnsafeCell<T>, x: &'x T) {
        dest.get_mut().clone_from(x);
    }
}

pub trait UnsafeCellExtension<T: Sized> {
    fn get_ref(&self) -> &T;
    fn get_mut(&mut self) -> &mut T;
    unsafe fn get_as_mut(&self) -> &mut T;
}

impl<T: Sized> UnsafeCellExtension<T> for UnsafeCell<T> {
    fn get_ref(&self) -> &T { unsafe { &*self.get() } }

    fn get_mut(&mut self) -> &mut T { unsafe { &mut *self.get() } }

    unsafe fn get_as_mut(&self) -> &mut T { &mut *self.get() }
}

pub use self::{
    children_table::CHILDREN_COUNT,
    compressed_path::{
        CompressedPathRaw, CompressedPathRef, CompressedPathTrait,
    },
    cow_node_ref::CowNodeRef,
    node_ref::{NodeRefDeltaMpt, NodeRefDeltaMptCompact},
    subtrie_visitor::SubTrieVisitor,
    trie_node::{MemOptimizedTrieNode, TrieNodeTrait, VanillaTrieNode},
};
use std::cell::UnsafeCell;
