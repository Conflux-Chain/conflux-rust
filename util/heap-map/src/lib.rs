use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use std::{cmp::Ordering, collections::HashMap, fmt::Debug, hash, ptr};

/// The `GarbageCollector` maintain a priority queue of `GarbageCollectorNode`,
/// the topmost node is the largest one.
#[derive(Default, DeriveMallocSizeOf)]
pub struct HeapMap<
    K: hash::Hash + Eq + Copy + Debug,
    V: PartialEq + Eq + Ord + Clone,
> {
    data: Vec<Node<K, V>>,
    mapping: HashMap<K, usize>,
}

#[derive(Clone, DeriveMallocSizeOf)]
pub struct Node<K, V: PartialEq + Eq + Ord> {
    key: K,
    value: V,
}

impl<K, V: PartialEq + Eq + Ord> Node<K, V> {
    pub fn new(key: K, value: V) -> Self { Node { key, value } }
}

impl<K, V: PartialEq + Eq + Ord> PartialEq for Node<K, V> {
    fn eq(&self, other: &Self) -> bool { self.value.eq(&other.value) }
}

impl<K, V: PartialEq + Eq + Ord> Eq for Node<K, V> {}

impl<K, V: PartialEq + Eq + Ord> PartialOrd for Node<K, V> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl<K, V: PartialEq + Eq + Ord> Ord for Node<K, V> {
    fn cmp(&self, other: &Self) -> Ordering { self.value.cmp(&other.value) }
}

impl<K: hash::Hash + Eq + Copy + Debug, V: PartialEq + Eq + Ord + Clone>
    HeapMap<K, V>
{
    pub fn insert(&mut self, key: &K, value: V) {
        if self.mapping.contains_key(key) {
            self.update(key, value);
        } else {
            self.append(key, value);
        }
    }

    /// In-place update some fields of a node's value.
    /// This is guaranteed to be called after `insert` is called.
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

    pub fn top(&self) -> Option<(&K, &V)> {
        self.data.get(0).map(|node| (&node.key, &node.value))
    }

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

    pub fn clear(&mut self) {
        self.mapping.clear();
        self.data.clear();
    }

    #[inline]
    pub fn is_empty(&self) -> bool { self.data.is_empty() }

    #[inline]
    #[allow(dead_code)]
    pub fn len(&self) -> usize { self.data.len() }

    fn update(&mut self, key: &K, value: V) {
        let index = *self.mapping.get(key).unwrap();
        let origin_node = self.data[index].clone();
        self.data[index] = Node::new(*key, value);
        match self.data[index].cmp(&origin_node) {
            Ordering::Less => self.sift_down(index),
            Ordering::Greater => self.sift_up(index),
            _ => {}
        }
    }

    fn append(&mut self, key: &K, value: V) {
        self.data.push(Node::new(*key, value));
        self.sift_up(self.data.len() - 1);
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        let index = *self.mapping.get(key)?;
        self.data.get(index).map(|node| &node.value)
    }

    #[inline]
    unsafe fn get_unchecked(&self, index: usize) -> &Node<K, V> {
        self.data.get_unchecked(index)
    }

    #[inline]
    unsafe fn get_mut(&mut self, index: usize) -> &mut Node<K, V> {
        self.data.get_unchecked_mut(index)
    }

    fn sift_up(&mut self, index: usize) {
        unsafe {
            let val = self.data.get_unchecked(index).clone();
            let mut pos = index;
            while pos > 0 {
                let parent = (pos - 1) / 2;
                if *self.get_unchecked(parent) >= val {
                    break;
                }
                let parent_ptr: *const _ = self.get_unchecked(parent);
                let hole_ptr = self.get_mut(pos);
                ptr::copy_nonoverlapping(parent_ptr, hole_ptr, 1);
                self.mapping.insert(self.get_unchecked(pos).key, pos);
                pos = parent;
            }
            ptr::copy_nonoverlapping(&val, self.get_mut(pos), 1);
            self.mapping.insert(val.key, pos);
        }
    }

    fn sift_down(&mut self, index: usize) {
        unsafe {
            let val = self.data.get_unchecked(index).clone();
            let mut pos = index;
            let mut child = pos * 2 + 1;
            while child < self.data.len() {
                let right = child + 1;
                if right < self.data.len()
                    && self.get_unchecked(right) > self.get_unchecked(child)
                {
                    child = right;
                }
                if val >= *self.get_unchecked(child) {
                    break;
                }
                let child_ptr: *const _ = self.get_unchecked(child);
                let hole_ptr = self.get_mut(pos);
                ptr::copy_nonoverlapping(child_ptr, hole_ptr, 1);
                self.mapping.insert(self.get_unchecked(pos).key, pos);
                pos = child;
                child = pos * 2 + 1;
            }
            ptr::copy_nonoverlapping(&val, self.get_mut(pos), 1);
            self.mapping.insert(val.key, pos);
        }
    }
}
