// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use rand::{Rng, ThreadRng};
use std::{collections::HashMap, hash::Hash};

/// HashMap that provide sampling in O(1) complexity.
#[derive(Default)]
pub struct SampleHashMap<K: Hash + Eq, V> {
    items: Vec<(K, V)>,
    index: HashMap<K, usize>,
}

impl<K: Hash + Eq + Clone, V> SampleHashMap<K, V> {
    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        let pos = self.index.get(k)?;
        Some(&mut self.items[*pos].1)
    }

    pub fn get_mut_or_insert_with<F: FnOnce() -> V>(
        &mut self, k: K, default: F,
    ) -> &mut V {
        let pos = match self.index.get(&k) {
            Some(pos) => *pos,
            None => {
                self.index.insert(k.clone(), self.items.len());
                self.items.push((k, default()));
                self.items.len() - 1
            }
        };

        &mut self.items[pos].1
    }

    pub fn remove(&mut self, k: &K) -> Option<V> {
        let index = self.index.remove(k)?;
        let (_, removed) = self.items.swap_remove(index);

        if let Some((swapped, _)) = self.items.get(index) {
            self.index.insert(swapped.clone(), index);
        }

        Some(removed)
    }

    pub fn sample(&self, rng: &mut ThreadRng) -> Option<&V> {
        if self.items.is_empty() {
            return None;
        }

        let index = rng.gen_range(0, self.items.len());
        Some(&self.items[index].1)
    }

    pub fn is_empty(&self) -> bool { self.items.is_empty() }
}

/// HashSet that provide sampling in O(1) complexity.
#[derive(Default)]
pub struct SampleHashSet<T: Hash + Eq> {
    items: Vec<T>,
    index: HashMap<T, usize>,
}

impl<T: Hash + Eq + Clone> SampleHashSet<T> {
    pub fn insert(&mut self, value: T) -> bool {
        if self.index.contains_key(&value) {
            return false;
        }

        self.index.insert(value.clone(), self.items.len());
        self.items.push(value);

        true
    }

    pub fn remove(&mut self, value: &T) -> bool {
        let index = match self.index.remove(value) {
            Some(pos) => pos,
            None => return false,
        };

        self.items.swap_remove(index);

        if let Some(swapped) = self.items.get(index) {
            self.index.insert(swapped.clone(), index);
        }

        true
    }

    pub fn sample(&self, rng: &mut ThreadRng) -> Option<T> {
        if self.items.is_empty() {
            return None;
        }

        let index = rng.gen_range(0, self.items.len());
        Some(self.items[index].clone())
    }

    pub fn is_empty(&self) -> bool { self.items.is_empty() }
}
