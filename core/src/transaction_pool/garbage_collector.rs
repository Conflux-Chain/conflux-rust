// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::Address;
use std::{cmp::Ordering, collections::HashMap, mem, ptr};

pub type GCType = (Address, usize);

#[derive(Default)]
pub struct GarbageCollector {
    data: Vec<GCType>,
    mapping: HashMap<Address, usize>,
    gc_size: usize,
}

impl GarbageCollector {
    pub fn insert(&mut self, sender: &Address, count: usize) {
        if self.mapping.contains_key(sender) {
            self.update(sender, count);
        } else {
            self.append(sender, count);
        }
    }

    #[allow(dead_code)]
    pub fn top(&self) -> Option<&GCType> {
        if !self.is_empty() {
            Some(&self.data[0])
        } else {
            None
        }
    }

    pub fn pop(&mut self) -> Option<GCType> {
        self.data.pop().map(|mut item| {
            if !self.is_empty() {
                mem::swap(&mut item, &mut self.data[0]);
                self.sift_down(0);
            }
            self.gc_size -= item.1;
            self.mapping.remove(&item.0);
            item
        })
    }

    pub fn clear(&mut self) {
        self.mapping.clear();
        self.data.clear();
        self.gc_size = 0;
    }

    #[inline]
    pub fn is_empty(&self) -> bool { self.data.is_empty() }

    #[inline]
    #[allow(dead_code)]
    pub fn len(&self) -> usize { self.data.len() }

    #[inline]
    pub fn gc_size(&self) -> usize { self.gc_size }

    fn update(&mut self, sender: &Address, count: usize) {
        let index = *self.mapping.get(sender).unwrap();
        let origin_count = self.data[index].1;
        self.data[index].1 = count;
        match count.cmp(&origin_count) {
            Ordering::Less => self.sift_down(index),
            Ordering::Greater => self.sift_up(index),
            _ => {}
        }
        self.gc_size += count - origin_count;
    }

    fn append(&mut self, sender: &Address, count: usize) {
        self.data.push((*sender, count));
        self.sift_up(self.data.len() - 1);
        self.gc_size += count;
    }

    #[inline]
    unsafe fn get(&self, index: usize) -> &GCType {
        self.data.get_unchecked(index)
    }

    #[inline]
    unsafe fn get_mut(&mut self, index: usize) -> &mut GCType {
        self.data.get_unchecked_mut(index)
    }

    fn sift_up(&mut self, index: usize) {
        unsafe {
            let val = *self.data.get_unchecked(index);
            let mut pos = index;
            while pos > 0 {
                let parent = (pos - 1) / 2;
                if self.get(parent).1 >= val.1 {
                    break;
                }
                let parent_ptr: *const _ = self.get(parent);
                let hole_ptr = self.get_mut(pos);
                ptr::copy_nonoverlapping(parent_ptr, hole_ptr, 1);
                self.mapping.insert(self.get(pos).0, pos);
                pos = parent;
            }
            ptr::copy_nonoverlapping(&val, self.get_mut(pos), 1);
            self.mapping.insert(val.0, pos);
        }
    }

    fn sift_down(&mut self, index: usize) {
        unsafe {
            let val = *self.data.get_unchecked(index);
            let mut pos = index;
            let mut child = pos * 2 + 1;
            while child < self.data.len() {
                let right = child + 1;
                if right < self.data.len()
                    && self.get(child).1 < self.get(right).1
                {
                    child = right;
                }
                if val.1 >= self.get(child).1 {
                    break;
                }
                let child_ptr: *const _ = self.get(child);
                let hole_ptr = self.get_mut(pos);
                ptr::copy_nonoverlapping(child_ptr, hole_ptr, 1);
                self.mapping.insert(self.get(pos).0, pos);
                pos = child;
                child = pos * 2 + 1;
            }
            ptr::copy_nonoverlapping(&val, self.get_mut(pos), 1);
            self.mapping.insert(val.0, pos);
        }
    }
}

#[cfg(test)]
mod garbage_collector_test {
    use super::GarbageCollector;
    use cfx_types::Address;
    use rand::{prng::XorShiftRng, FromEntropy, RngCore};
    use std::collections::HashMap;

    #[test]
    fn test_basic_operation() {
        let mut gc = GarbageCollector::default();
        assert!(gc.is_empty());
        assert_eq!(gc.gc_size(), 0);
        assert_eq!(gc.top(), None);
        assert_eq!(gc.pop(), None);

        let mut addr = Vec::new();
        for _ in 0..10 {
            addr.push(Address::random());
        }
        gc.insert(&addr[0], 10);
        assert_eq!(gc.len(), 1);
        assert_eq!(gc.gc_size(), 10);
        assert_eq!(*gc.top().unwrap(), (addr[0], 10));

        gc.insert(&addr[1], 6);
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 16);
        assert_eq!(*gc.top().unwrap(), (addr[0], 10));

        gc.insert(&addr[2], 11);
        assert_eq!(gc.len(), 3);
        assert_eq!(gc.gc_size(), 27);
        assert_eq!(*gc.top().unwrap(), (addr[2], 11));

        gc.insert(&addr[0], 15);
        assert_eq!(gc.len(), 3);
        assert_eq!(gc.gc_size(), 32);
        assert_eq!(*gc.top().unwrap(), (addr[0], 15));

        assert_eq!(gc.pop(), Some((addr[0], 15)));
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 17);
        assert_eq!(gc.pop(), Some((addr[2], 11)));
        assert_eq!(gc.len(), 1);
        assert_eq!(gc.gc_size(), 6);
        assert_eq!(gc.pop(), Some((addr[1], 6)));
        assert_eq!(gc.len(), 0);
        assert_eq!(gc.gc_size(), 0);
        assert_eq!(gc.pop(), None);
    }

    fn get_max(mapping: &HashMap<Address, usize>) -> Option<(Address, usize)> {
        mapping
            .iter()
            .max_by(|x, y| x.1.cmp(&y.1))
            .and_then(|x| Some((*x.0, *x.1)))
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
                gc.insert(&addr[idx], count);
                let old = mapping.insert(addr[idx], count);
                sum += count;
                if old.is_some() {
                    sum -= old.unwrap();
                }
            } else {
                if gc.is_empty() {
                    assert_eq!(gc.pop(), None);
                    assert_eq!(gc.gc_size(), 0);
                } else {
                    let max = get_max(&mapping).unwrap();
                    let gc_max = gc.pop().unwrap();
                    assert_eq!(gc_max.1, max.1);
                    mapping.remove(&gc_max.0);
                    sum -= gc_max.1;
                    assert_eq!(gc.len(), mapping.len());
                }
            }
            assert_eq!(gc.len(), mapping.len());
            assert_eq!(gc.gc_size(), sum);
            if gc.is_empty() {
                assert!(mapping.is_empty());
            } else {
                assert_eq!(gc.top().unwrap().1, get_max(&mapping).unwrap().1);
            }
        }
    }
}
