// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::Address;
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use std::{
    cmp::{Ord, Ordering, PartialEq, PartialOrd},
    collections::HashMap,
    ptr,
};

/// This is the internal node type of `GarbageCollector`.
/// A node `lhs` is considered as smaller than another node `rhs` if `lhs.count
/// < rhs.count` or `lhs.count == rhs.count && lhs.timestamp > rhs.timestamp`.
#[derive(Eq, Copy, Clone, DeriveMallocSizeOf)]
pub struct GarbageCollectorNode {
    /// This is the address of a sender.
    pub sender: Address,
    /// This indicates the number of transactions can be garbage collected.
    pub count: usize,
    /// This indicates the latest timestamp when a transaction was garbage
    /// collected.
    pub timestamp: u64,
}

impl Ord for GarbageCollectorNode {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.count.cmp(&other.count) {
            Ordering::Less => Ordering::Less,
            Ordering::Greater => Ordering::Greater,
            Ordering::Equal => other.timestamp.cmp(&self.timestamp),
        }
    }
}

impl PartialEq for GarbageCollectorNode {
    fn eq(&self, other: &Self) -> bool {
        self.count == other.count && self.timestamp == other.timestamp
    }
}

impl PartialOrd for GarbageCollectorNode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The `GarbageCollector` maintain a priority queue of `GarbageCollectorNode`,
/// the topmost node is the largest one.
#[derive(Default, DeriveMallocSizeOf)]
pub struct GarbageCollector {
    data: Vec<GarbageCollectorNode>,
    mapping: HashMap<Address, usize>,
    gc_size: usize,
}

impl GarbageCollector {
    pub fn insert(&mut self, sender: &Address, count: usize, timestamp: u64) {
        if self.mapping.contains_key(sender) {
            self.update(sender, count, timestamp);
        } else {
            self.append(sender, count, timestamp);
        }
    }

    pub fn top(&self) -> Option<&GarbageCollectorNode> {
        self.data.get(0)
    }

    pub fn pop(&mut self) -> Option<GarbageCollectorNode> {
        if self.is_empty() {
            return None;
        }
        let item = self.data.swap_remove(0);
        if !self.is_empty() {
            self.sift_down(0);
        }
        self.gc_size -= item.count;
        self.mapping.remove(&item.sender);
        Some(item)
    }

    pub fn clear(&mut self) {
        self.mapping.clear();
        self.data.clear();
        self.gc_size = 0;
    }

    pub fn get_timestamp(&self, sender: &Address) -> Option<u64> {
        self.mapping
            .get(sender)
            .map(|index| self.data[*index].timestamp)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[inline]
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    #[inline]
    pub fn gc_size(&self) -> usize {
        self.gc_size
    }

    fn update(&mut self, sender: &Address, count: usize, timestamp: u64) {
        let index = *self.mapping.get(sender).unwrap();
        let node = GarbageCollectorNode {
            sender: *sender,
            count,
            timestamp,
        };
        let origin_node = self.data[index];
        self.data[index].count = count;
        self.data[index].timestamp = timestamp;
        match node.cmp(&origin_node) {
            Ordering::Less => self.sift_down(index),
            Ordering::Greater => self.sift_up(index),
            _ => {}
        }
        self.gc_size -= origin_node.count;
        self.gc_size += count;
    }

    fn append(&mut self, sender: &Address, count: usize, timestamp: u64) {
        self.data.push(GarbageCollectorNode {
            sender: *sender,
            count,
            timestamp,
        });
        self.sift_up(self.data.len() - 1);
        self.gc_size += count;
    }

    #[inline]
    unsafe fn get(&self, index: usize) -> &GarbageCollectorNode {
        self.data.get_unchecked(index)
    }

    #[inline]
    unsafe fn get_mut(&mut self, index: usize) -> &mut GarbageCollectorNode {
        self.data.get_unchecked_mut(index)
    }

    fn sift_up(&mut self, index: usize) {
        unsafe {
            let val = *self.data.get_unchecked(index);
            let mut pos = index;
            while pos > 0 {
                let parent = (pos - 1) / 2;
                if *self.get(parent) >= val {
                    break;
                }
                let parent_ptr: *const _ = self.get(parent);
                let hole_ptr = self.get_mut(pos);
                ptr::copy_nonoverlapping(parent_ptr, hole_ptr, 1);
                self.mapping.insert(self.get(pos).sender, pos);
                pos = parent;
            }
            ptr::copy_nonoverlapping(&val, self.get_mut(pos), 1);
            self.mapping.insert(val.sender, pos);
        }
    }

    fn sift_down(&mut self, index: usize) {
        unsafe {
            let val = *self.data.get_unchecked(index);
            let mut pos = index;
            let mut child = pos * 2 + 1;
            while child < self.data.len() {
                let right = child + 1;
                if right < self.data.len() && self.get(right) > self.get(child)
                {
                    child = right;
                }
                if val >= *self.get(child) {
                    break;
                }
                let child_ptr: *const _ = self.get(child);
                let hole_ptr = self.get_mut(pos);
                ptr::copy_nonoverlapping(child_ptr, hole_ptr, 1);
                self.mapping.insert(self.get(pos).sender, pos);
                pos = child;
                child = pos * 2 + 1;
            }
            ptr::copy_nonoverlapping(&val, self.get_mut(pos), 1);
            self.mapping.insert(val.sender, pos);
        }
    }
}

#[cfg(test)]
mod garbage_collector_test {
    use super::{GarbageCollector, GarbageCollectorNode};
    use cfx_types::Address;
    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::collections::HashMap;

    #[test]
    fn test_basic_operation() {
        let mut gc = GarbageCollector::default();
        assert!(gc.is_empty());
        assert_eq!(gc.gc_size(), 0);
        assert!(gc.top().is_none());
        assert!(gc.pop().is_none());

        let mut addr = Vec::new();
        for _ in 0..10 {
            addr.push(Address::random());
        }
        gc.insert(&addr[0], 10, 10);
        assert_eq!(gc.len(), 1);
        assert_eq!(gc.gc_size(), 10);
        assert_eq!(gc.top().unwrap().sender, addr[0]);
        assert_eq!(gc.top().unwrap().count, 10);
        assert_eq!(gc.top().unwrap().timestamp, 10);

        gc.insert(&addr[1], 10, 5);
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 20);
        assert_eq!(gc.top().unwrap().sender, addr[1]);
        assert_eq!(gc.top().unwrap().count, 10);
        assert_eq!(gc.top().unwrap().timestamp, 5);

        gc.insert(&addr[2], 11, 5);
        assert_eq!(gc.len(), 3);
        assert_eq!(gc.gc_size(), 31);
        assert_eq!(gc.top().unwrap().sender, addr[2]);
        assert_eq!(gc.top().unwrap().count, 11);
        assert_eq!(gc.top().unwrap().timestamp, 5);

        gc.insert(&addr[0], 15, 0);
        assert_eq!(gc.len(), 3);
        assert_eq!(gc.gc_size(), 36);
        assert_eq!(gc.top().unwrap().sender, addr[0]);
        assert_eq!(gc.top().unwrap().count, 15);
        assert_eq!(gc.top().unwrap().timestamp, 0);

        assert_eq!(gc.get_timestamp(&addr[0]), Some(0));
        assert_eq!(gc.get_timestamp(&addr[1]), Some(5));
        assert_eq!(gc.get_timestamp(&addr[2]), Some(5));
        assert_eq!(gc.get_timestamp(&addr[3]), None);

        let top = gc.pop().unwrap();
        assert_eq!(top.sender, addr[0]);
        assert_eq!(top.count, 15);
        assert_eq!(top.timestamp, 0);
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 21);
        let top = gc.pop().unwrap();
        assert_eq!(top.sender, addr[2]);
        assert_eq!(top.count, 11);
        assert_eq!(top.timestamp, 5);
        assert_eq!(gc.len(), 1);
        assert_eq!(gc.gc_size(), 10);
        let top = gc.pop().unwrap();
        assert_eq!(top.sender, addr[1]);
        assert_eq!(top.count, 10);
        assert_eq!(top.timestamp, 5);
        assert_eq!(gc.len(), 0);
        assert_eq!(gc.gc_size(), 0);
        assert!(gc.pop().is_none());
    }

    fn get_max(
        mapping: &HashMap<Address, GarbageCollectorNode>,
    ) -> Option<GarbageCollectorNode> {
        mapping
            .iter()
            .max_by(|x, y| x.1.cmp(&y.1))
            .and_then(|x| Some(*x.1))
    }

    #[test]
    fn test_correctness() {
        let mut rng = XorShiftRng::from_entropy();
        let mut addr = Vec::new();
        for _ in 0..10000 {
            addr.push(Address::random());
        }

        let mut gc = GarbageCollector::default();
        let mut mapping = HashMap::new();
        let mut sum = 0;

        for _ in 0..100000 {
            let opt: usize = rng.next_u64() as usize % 4;
            if opt <= 2 {
                let idx: usize = rng.next_u64() as usize % 10000;
                let count: usize = rng.next_u64() as usize % 1000;
                let timestamp: u64 = rng.next_u64() % 1000;
                let node = GarbageCollectorNode {
                    sender: addr[idx],
                    count,
                    timestamp,
                };
                gc.insert(&addr[idx], count, timestamp);
                let old = mapping.insert(addr[idx], node);
                sum += count;
                if old.is_some() {
                    sum -= old.unwrap().count;
                }
            } else {
                if gc.is_empty() {
                    assert!(gc.pop().is_none());
                    assert_eq!(gc.gc_size(), 0);
                } else {
                    let max = get_max(&mapping).unwrap();
                    let gc_max = gc.pop().unwrap();
                    assert_eq!(gc_max.count, max.count);
                    assert_eq!(gc_max.timestamp, max.timestamp);
                    mapping.remove(&gc_max.sender);
                    sum -= gc_max.count;
                    assert_eq!(gc.len(), mapping.len());
                }
            }
            assert_eq!(gc.len(), mapping.len());
            assert_eq!(gc.gc_size(), sum);
            if gc.is_empty() {
                assert!(mapping.is_empty());
            } else {
                assert_eq!(
                    gc.top().unwrap().count,
                    get_max(&mapping).unwrap().count
                );
                assert_eq!(
                    gc.top().unwrap().timestamp,
                    get_max(&mapping).unwrap().timestamp
                );
            }
        }
        for (addr, value) in mapping.iter() {
            assert_eq!(value.timestamp, gc.get_timestamp(addr).unwrap());
        }
    }
}
