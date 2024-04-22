// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

//! Lru-cache related utilities as quick-and-dirty wrappers around the lru-cache
//! crate.
use lru_cache::LruCache;
use malloc_size_of::{new_malloc_size_ops, MallocSizeOf, MallocSizeOfOps};

use std::hash::Hash;

const INITIAL_CAPACITY: usize = 4;

/// An LRU-cache which operates on memory used.
pub struct MemoryLruCache<K: Eq + Hash, V> {
    inner: LruCache<K, V>,
    malloc_size_of_ops: MallocSizeOfOps,
    cur_size: usize,
    max_size: usize,
}

impl<K: Eq + Hash, V: MallocSizeOf> MemoryLruCache<K, V> {
    // amount of memory used when the item will be put on the heap.
    fn heap_size_of(&mut self, val: &V) -> usize {
        ::std::mem::size_of::<V>() + val.size_of(&mut self.malloc_size_of_ops)
    }
}

impl<K: Eq + Hash, V: MallocSizeOf> MemoryLruCache<K, V> {
    /// Create a new cache with a maximum size in bytes.
    pub fn new(max_size: usize) -> Self {
        MemoryLruCache {
            inner: LruCache::new(INITIAL_CAPACITY),
            malloc_size_of_ops: new_malloc_size_ops(),
            max_size,
            cur_size: 0,
        }
    }

    /// Insert an item.
    pub fn insert(&mut self, key: K, val: V) {
        let cap = self.inner.capacity();

        // grow the cache as necessary; it operates on amount of items
        // but we're working based on memory usage.
        if self.inner.len() == cap && self.cur_size < self.max_size {
            self.inner.set_capacity(cap * 2);
        }

        self.cur_size += self.heap_size_of(&val);

        // account for any element displaced from the cache.
        if let Some(lru) = self.inner.insert(key, val) {
            self.cur_size -= self.heap_size_of(&lru);
        }

        // remove elements until we are below the memory target.
        while self.cur_size > self.max_size {
            match self.inner.remove_lru() {
                Some((_, v)) => self.cur_size -= self.heap_size_of(&v),
                _ => break,
            }
        }
    }

    /// Get a reference to an item in the cache. It is a logic error for its
    /// heap size to be altered while borrowed.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.get_mut(key)
    }

    /// Currently-used size of values in bytes.
    pub fn current_size(&self) -> usize { self.cur_size }

    /// Get backing LRU cache instance (read only)
    pub fn backstore(&self) -> &LruCache<K, V> { &self.inner }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let mut cache = MemoryLruCache::new(256);
        let val1 = vec![0u8; 100];
        let size1 = cache.heap_size_of(&val1);
        cache.insert("hello", val1);

        assert_eq!(cache.current_size(), size1);

        let val2 = vec![0u8; 210];
        let size2 = cache.heap_size_of(&val2);
        cache.insert("world", val2);

        assert!(cache.get_mut(&"hello").is_none());
        assert!(cache.get_mut(&"world").is_some());

        assert_eq!(cache.current_size(), size2);
    }
}
