#[cfg(test)]
mod tests;

use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use std::{cmp::Ordering, collections::HashMap, fmt::Debug, hash};

/// The `HeapMap` maintain a max heap along with a hash map to support
/// additional `remove` and `update` operations.
#[derive(DeriveMallocSizeOf)]
pub struct HeapMap<K: hash::Hash + Eq + Copy + Debug, V: Eq + Ord + Clone> {
    data: Vec<Node<K, V>>,
    mapping: HashMap<K, usize>,
}

#[derive(Clone, DeriveMallocSizeOf)]
pub struct Node<K, V: Eq + Ord> {
    key: K,
    value: V,
}

impl<K, V: Eq + Ord> Node<K, V> {
    pub fn new(key: K, value: V) -> Self { Node { key, value } }
}

impl<K, V: Eq + Ord> PartialEq for Node<K, V> {
    fn eq(&self, other: &Self) -> bool { self.value.eq(&other.value) }
}

impl<K, V: Eq + Ord> Eq for Node<K, V> {}

impl<K, V: Eq + Ord> PartialOrd for Node<K, V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<K, V: Eq + Ord> Ord for Node<K, V> {
    fn cmp(&self, other: &Self) -> Ordering { self.value.cmp(&other.value) }
}

impl<K: hash::Hash + Eq + Copy + Debug, V: Eq + Ord + Clone> Default
    for HeapMap<K, V>
{
    fn default() -> Self { Self::new() }
}

impl<K: hash::Hash + Eq + Copy + Debug, V: Eq + Ord + Clone> HeapMap<K, V> {
    pub fn new() -> Self {
        Self {
            data: vec![],
            mapping: HashMap::new(),
        }
    }

    /// Insert a K-V into the HeapMap.
    /// Return the old value if `key` already exist. Return `None` otherwise.
    pub fn insert(&mut self, key: &K, value: V) -> Option<V> {
        if self.mapping.contains_key(key) {
            let old_value = self.update(key, value);
            Some(old_value)
        } else {
            self.append(key, value);
            None
        }
    }

    /// Remove `key` from the HeapMap.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let index = self.mapping.remove(key)?;
        let removed_node = self.data.swap_remove(index);
        if index != self.data.len() {
            // The last node has been swapped to index
            match self.data[index].cmp(&removed_node) {
                Ordering::Less => self.sift_down(index),
                Ordering::Greater => self.sift_up(index),
                Ordering::Equal => {
                    self.mapping.insert(self.data[index].key, index);
                }
            }
        }
        Some(removed_node.value)
    }

    /// In-place update some fields of a node's value.
    pub fn update_with<F>(&mut self, key: &K, mut update_fn: F)
    where F: FnMut(&mut V) -> () {
        let index = match self.mapping.get(&key) {
            None => {
                return;
            }
            Some(i) => *i,
        };
        let origin_node = self.data[index].clone();
        update_fn(&mut self.data[index].value);
        // The order of node is the opposite of the order of this tuple.
        match self.data[index].cmp(&origin_node) {
            Ordering::Less => self.sift_down(index),
            Ordering::Greater => self.sift_up(index),
            _ => {}
        }
    }

    /// Return the top K-V reference tuple.
    pub fn top(&self) -> Option<(&K, &V)> {
        self.data.get(0).map(|node| (&node.key, &node.value))
    }

    /// Pop the top node and return it as a K-V tuple.
    pub fn pop(&mut self) -> Option<(K, V)> {
        if self.is_empty() {
            return None;
        }
        let item = self.data.swap_remove(0);
        if !self.is_empty() {
            self.sift_down(0);
        }
        self.mapping.remove(&item.key);
        Some((item.key, item.value))
    }

    /// Get the value reference of `key`.
    pub fn get(&self, key: &K) -> Option<&V> {
        let index = *self.mapping.get(key)?;
        self.data.get(index).map(|node| &node.value)
    }

    /// Clear all key-values of the HeapMap.
    pub fn clear(&mut self) {
        self.mapping.clear();
        self.data.clear();
    }

    #[inline]
    pub fn is_empty(&self) -> bool { self.data.is_empty() }

    #[inline]
    pub fn len(&self) -> usize { self.data.len() }

    pub fn iter(&self) -> impl Iterator<Item = V> + '_ {
        self.data.iter().map(|f| f.value.clone())
    }

    fn update(&mut self, key: &K, value: V) -> V {
        let index = *self.mapping.get(key).unwrap();
        let origin_node = self.data[index].clone();
        self.data[index] = Node::new(*key, value);
        match self.data[index].cmp(&origin_node) {
            Ordering::Less => self.sift_down(index),
            Ordering::Greater => self.sift_up(index),
            _ => {}
        }
        origin_node.value
    }

    fn append(&mut self, key: &K, value: V) {
        self.data.push(Node::new(*key, value));
        self.sift_up(self.data.len() - 1);
    }

    fn sift_up(&mut self, index: usize) {
        let val = self.data[index].clone();
        let mut pos = index;
        while pos > 0 {
            let parent = (pos - 1) / 2;
            if self.data[parent] >= val {
                break;
            }
            self.data[pos] = self.data[parent].clone();
            self.mapping.insert(self.data[pos].key, pos);
            pos = parent;
        }

        self.mapping.insert(val.key, pos);
        self.data[pos] = val;
    }

    fn sift_down(&mut self, index: usize) {
        let val = self.data[index].clone();
        let mut pos = index;
        let mut child = pos * 2 + 1;
        while child < self.data.len() {
            let right = child + 1;
            if right < self.data.len() && self.data[right] > self.data[child] {
                child = right;
            }
            if val >= self.data[child] {
                break;
            }
            self.data[pos] = self.data[child].clone();
            self.mapping.insert(self.data[pos].key, pos);
            pos = child;
            child = pos * 2 + 1;
        }
        self.mapping.insert(val.key, pos);
        self.data[pos] = val;
    }
}
