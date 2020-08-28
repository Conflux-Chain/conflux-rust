// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    collections::{BinaryHeap, HashSet},
    hash::Hash,
};

use super::missing_item::HasKey;

/// A data structure for storing unique elements and retrieving them according
/// to some priority criteria.
/// The value type `V` must implement `HasKey<K>`.
/// Uniqueness in guaranteed with respect to the associated key.
/// Priority is based on `Ord` (V::cmp/partial_cmp).
pub struct PriorityQueue<K, V> {
    keys: HashSet<K>,
    values: BinaryHeap<V>,
}

impl<K, V> PriorityQueue<K, V>
where
    K: Clone + Eq + Hash,
    V: HasKey<K> + Ord,
{
    pub fn new() -> Self {
        let keys = HashSet::new();
        let values = BinaryHeap::new();
        Self { keys, values }
    }

    #[inline]
    pub fn len(&self) -> usize {
        assert!(self.keys.len() == self.values.len());
        self.keys.len()
    }

    #[inline]
    pub fn push(&mut self, value: V) {
        if !self.keys.contains(&value.key()) {
            self.keys.insert(value.key());
            self.values.push(value);
        }
    }

    #[inline]
    pub fn pop(&mut self) -> Option<V> {
        match self.values.pop() {
            None => {
                assert!(self.keys.is_empty());
                None
            }
            Some(value) => {
                assert!(self.keys.remove(&value.key()));
                Some(value)
            }
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub fn contains(&self, key: &K) -> bool { self.keys.contains(key) }
}

impl<K, V> Extend<V> for PriorityQueue<K, V>
where
    K: Clone + Eq + Hash,
    V: Ord + HasKey<K>,
{
    fn extend<T: IntoIterator<Item = V>>(&mut self, iter: T) {
        for value in iter {
            self.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::missing_item::HasKey, PriorityQueue};
    use std::cmp::Ordering;

    #[derive(Debug, PartialEq, Eq)]
    struct Item {
        pub key: u64,
        pub value: u64,
    }

    impl Item {
        pub fn new(key: u64, value: u64) -> Item { Item { key, value } }
    }

    impl HasKey<u64> for Item {
        fn key(&self) -> u64 { self.key }
    }

    impl Ord for Item {
        fn cmp(&self, other: &Self) -> Ordering { self.value.cmp(&other.value) }
    }

    impl PartialOrd for Item {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    #[test]
    fn test_priority_queue() {
        let mut queue = PriorityQueue::new();

        // push items with unique keys
        queue.push(Item::new(0, 0));
        queue.push(Item::new(1, 4));
        queue.push(Item::new(2, 1));
        queue.push(Item::new(3, 3));
        queue.push(Item::new(4, 2));

        // push items with duplicate keys
        queue.push(Item::new(0, 5));
        queue.push(Item::new(1, 9));
        queue.push(Item::new(2, 6));
        queue.push(Item::new(3, 8));
        queue.push(Item::new(4, 7));

        // expect each key only once with values in descending order.
        assert_eq!(queue.pop(), Some(Item::new(1, 4)));
        assert_eq!(queue.pop(), Some(Item::new(3, 3)));
        assert_eq!(queue.pop(), Some(Item::new(4, 2)));
        assert_eq!(queue.pop(), Some(Item::new(2, 1)));
        assert_eq!(queue.pop(), Some(Item::new(0, 0)));
        assert_eq!(queue.pop(), None);
    }
}
