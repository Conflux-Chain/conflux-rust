// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{AddressWithSpace, U256};
use heap_map::HeapMap;
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use std::cmp::{Ord, Ordering, PartialEq, PartialOrd, Reverse};

/// This is the internal node value type of `GarbageCollector`.
/// A node `lhs` is considered as smaller than another node `rhs` if `lhs.count
/// < rhs.count` or `lhs.count == rhs.count && (lhs.has_ready_tx,
/// lhs.first_tx_gas_price, lhs.timestamp) > (rhs.has_ready_tx,
/// rhs.first_tx_gas_price, rhs.timestamp)`.
#[derive(Default, Eq, PartialEq, Copy, Clone, Debug, DeriveMallocSizeOf)]
pub struct GarbageCollectorValue {
    /// This indicates the number of transactions can be garbage collected.
    /// A higher count has a higher GC priority.
    pub count: usize,
    /// This indicates if the sender has a ready tx.
    /// Unready txs has a higher GC priority than ready txs.
    pub has_ready_tx: bool,
    /// This indicates the gas price of the lowest nonce transaction from the
    /// sender. This is only useful when `self.count == 0`.
    /// A higher gas price has a lower GC priority.
    pub first_tx_gas_price: U256,
    /// This indicates the latest timestamp when a transaction was garbage
    /// collected.
    /// A higher timestamp (the tx is newer) has a lower GC priority.
    pub timestamp: u64,
}

impl Ord for GarbageCollectorValue {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.count,
            Reverse(self.has_ready_tx),
            Reverse(self.first_tx_gas_price),
            Reverse(self.timestamp),
        )
            .cmp(&(
                other.count,
                Reverse(other.has_ready_tx),
                Reverse(other.first_tx_gas_price),
                Reverse(other.timestamp),
            ))
    }
}

impl PartialOrd for GarbageCollectorValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The `GarbageCollector` maintain a priority queue of `GarbageCollectorValue`,
/// the topmost node is the largest one.
#[derive(Default, DeriveMallocSizeOf)]
pub struct GarbageCollector {
    heap_map: HeapMap<AddressWithSpace, GarbageCollectorValue>,
    gc_size: usize,
}

impl GarbageCollector {
    /// Insert the latest txpool status of `sender` account into
    /// `GarbageCollector`.
    pub fn insert(
        &mut self, sender: &AddressWithSpace, count: usize, timestamp: u64,
        has_ready_tx: bool, first_tx_gas_price: U256,
    ) {
        let value = GarbageCollectorValue {
            count,
            has_ready_tx,
            first_tx_gas_price,
            timestamp,
        };
        if let Some(origin) = self.heap_map.get(sender) {
            self.gc_size -= origin.count;
        }
        self.gc_size += count;
        self.heap_map.insert(sender, value);
    }

    /// Pop the node with the highest GC priority.
    /// Note that each node corresponds to one account, so if the account still
    /// have transactions after this GC operation, it should be inserted
    /// back.
    pub fn pop(&mut self) -> Option<(AddressWithSpace, GarbageCollectorValue)> {
        let item = self.heap_map.pop();
        if let Some((_, v)) = &item {
            self.gc_size -= v.count;
        }
        item
    }

    pub fn clear(&mut self) {
        self.heap_map.clear();
        self.gc_size = 0;
    }

    pub fn get_timestamp(&self, sender: &AddressWithSpace) -> Option<u64> {
        self.heap_map.get(sender).map(|v| v.timestamp)
    }

    pub fn is_empty(&self) -> bool { self.heap_map.is_empty() }

    #[cfg(test)]
    pub fn len(&self) -> usize { self.heap_map.len() }

    #[inline]
    pub fn gc_size(&self) -> usize { self.gc_size }

    pub fn top(&self) -> Option<(&AddressWithSpace, &GarbageCollectorValue)> {
        self.heap_map.top()
    }
}

#[cfg(test)]
mod garbage_collector_test {
    use super::{GarbageCollector, GarbageCollectorValue};
    use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, U256};
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
            addr.push(Address::random().with_native_space());
        }
        gc.insert(&addr[0], 10, 10, false, 0.into());
        assert_eq!(gc.len(), 1);
        assert_eq!(gc.gc_size(), 10);
        assert_eq!(*gc.top().unwrap().0, addr[0]);
        assert_eq!(gc.top().unwrap().1.count, 10);
        assert_eq!(gc.top().unwrap().1.timestamp, 10);

        gc.insert(&addr[1], 10, 5, false, 0.into());
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 20);
        assert_eq!(*gc.top().unwrap().0, addr[1]);
        assert_eq!(gc.top().unwrap().1.count, 10);
        assert_eq!(gc.top().unwrap().1.timestamp, 5);

        gc.insert(&addr[2], 11, 5, false, 0.into());
        assert_eq!(gc.len(), 3);
        assert_eq!(gc.gc_size(), 31);
        assert_eq!(*gc.top().unwrap().0, addr[2]);
        assert_eq!(gc.top().unwrap().1.count, 11);
        assert_eq!(gc.top().unwrap().1.timestamp, 5);

        gc.insert(&addr[0], 15, 0, false, 0.into());
        assert_eq!(gc.len(), 3);
        assert_eq!(gc.gc_size(), 36);
        assert_eq!(*gc.top().unwrap().0, addr[0]);
        assert_eq!(gc.top().unwrap().1.count, 15);
        assert_eq!(gc.top().unwrap().1.timestamp, 0);

        assert_eq!(gc.get_timestamp(&addr[0]), Some(0));
        assert_eq!(gc.get_timestamp(&addr[1]), Some(5));
        assert_eq!(gc.get_timestamp(&addr[2]), Some(5));
        assert_eq!(gc.get_timestamp(&addr[3]), None);

        let top = gc.pop().unwrap();
        assert_eq!(top.0, addr[0]);
        assert_eq!(top.1.count, 15);
        assert_eq!(top.1.timestamp, 0);
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 21);
        let top = gc.pop().unwrap();
        assert_eq!(top.0, addr[2]);
        assert_eq!(top.1.count, 11);
        assert_eq!(top.1.timestamp, 5);
        assert_eq!(gc.len(), 1);
        assert_eq!(gc.gc_size(), 10);
        let top = gc.pop().unwrap();
        assert_eq!(top.0, addr[1]);
        assert_eq!(top.1.count, 10);
        assert_eq!(top.1.timestamp, 5);
        assert_eq!(gc.len(), 0);
        assert_eq!(gc.gc_size(), 0);
        assert!(gc.pop().is_none());
    }

    #[test]
    fn test_ready_accounts() {
        let mut gc = GarbageCollector::default();
        assert!(gc.is_empty());
        assert_eq!(gc.gc_size(), 0);
        assert!(gc.top().is_none());
        assert!(gc.pop().is_none());

        let mut addr = Vec::new();
        for _ in 0..10 {
            addr.push(Address::random().with_native_space());
        }
        gc.insert(&addr[0], 0, 10, false, 0.into());
        assert_eq!(gc.len(), 1);
        assert_eq!(gc.gc_size(), 0);
        assert_eq!(*gc.top().unwrap().0, addr[0]);
        assert_eq!(gc.top().unwrap().1.count, 0);
        assert_eq!(gc.top().unwrap().1.timestamp, 10);

        gc.insert(&addr[1], 0, 5, false, 0.into());
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 0);
        assert_eq!(*gc.top().unwrap().0, addr[1]);
        assert_eq!(gc.top().unwrap().1.count, 0);
        assert_eq!(gc.top().unwrap().1.timestamp, 5);

        gc.insert(&addr[1], 0, 5, false, 1.into());
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 0);
        assert_eq!(*gc.top().unwrap().0, addr[0]);
        assert_eq!(gc.top().unwrap().1.count, 0);
        assert_eq!(gc.top().unwrap().1.timestamp, 10);

        gc.insert(&addr[0], 0, 10, true, 1.into());
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 0);
        assert_eq!(*gc.top().unwrap().0, addr[1]);
        assert_eq!(gc.top().unwrap().1.count, 0);
        assert_eq!(gc.top().unwrap().1.timestamp, 5);

        gc.insert(&addr[1], 0, 5, true, 2.into());
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 0);
        assert_eq!(*gc.top().unwrap().0, addr[0]);
        assert_eq!(gc.top().unwrap().1.count, 0);
        assert_eq!(gc.top().unwrap().1.timestamp, 10);

        gc.insert(&addr[0], 0, 10, true, 3.into());
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 0);
        assert_eq!(*gc.top().unwrap().0, addr[1]);
        assert_eq!(gc.top().unwrap().1.count, 0);
        assert_eq!(gc.top().unwrap().1.timestamp, 5);

        gc.insert(&addr[0], 0, 10, false, 1.into());
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 0);
        assert_eq!(*gc.top().unwrap().0, addr[0]);
        assert_eq!(gc.top().unwrap().1.count, 0);
        assert_eq!(gc.top().unwrap().1.timestamp, 10);

        gc.insert(&addr[2], 1, 5, false, 0.into());
        assert_eq!(gc.len(), 3);
        assert_eq!(gc.gc_size(), 1);
        assert_eq!(*gc.top().unwrap().0, addr[2]);
        assert_eq!(gc.top().unwrap().1.count, 1);
        assert_eq!(gc.top().unwrap().1.timestamp, 5);

        let top = gc.pop().unwrap();
        assert_eq!(top.0, addr[2]);
        assert_eq!(top.1.count, 1);
        assert_eq!(top.1.timestamp, 5);
        assert_eq!(top.1.first_tx_gas_price, U256::from(0));
        assert_eq!(gc.len(), 2);
        assert_eq!(gc.gc_size(), 0);
        let top = gc.pop().unwrap();
        assert_eq!(top.0, addr[0]);
        assert_eq!(top.1.count, 0);
        assert_eq!(top.1.timestamp, 10);
        assert_eq!(top.1.first_tx_gas_price, U256::from(1));
        assert_eq!(top.1.has_ready_tx, false);
        assert_eq!(gc.len(), 1);
        assert_eq!(gc.gc_size(), 0);
        let top = gc.pop().unwrap();
        assert_eq!(top.0, addr[1]);
        assert_eq!(top.1.count, 0);
        assert_eq!(top.1.timestamp, 5);
        assert_eq!(top.1.first_tx_gas_price, U256::from(2));
        assert_eq!(top.1.has_ready_tx, true);
        assert_eq!(gc.len(), 0);
        assert_eq!(gc.gc_size(), 0);
        assert!(gc.pop().is_none());
    }

    fn get_max(
        mapping: &HashMap<AddressWithSpace, GarbageCollectorValue>,
    ) -> Option<GarbageCollectorValue> {
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
            addr.push(Address::random().with_native_space());
        }

        let mut gc = GarbageCollector::default();
        let mut mapping = HashMap::new();
        let mut sum = 0;

        for _ in 0..100000 {
            let opt: usize = rng.next_u64() as usize % 4;
            if opt <= 2 {
                let idx: usize = rng.next_u64() as usize % 10000;
                let count: usize = rng.next_u64() as usize % 10;
                let timestamp: u64 = rng.next_u64() % 1000;
                let has_ready_tx: bool = rng.next_u64() % 2 == 0;
                let first_tx_gas_price: u64 = rng.next_u64();
                let node = GarbageCollectorValue {
                    count,
                    has_ready_tx,
                    first_tx_gas_price: first_tx_gas_price.into(),
                    timestamp,
                };
                gc.insert(
                    &addr[idx],
                    count,
                    timestamp,
                    has_ready_tx,
                    first_tx_gas_price.into(),
                );
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
                    assert_eq!(gc_max.1.count, max.count);
                    assert_eq!(gc_max.1.timestamp, max.timestamp);
                    mapping.remove(&gc_max.0);
                    sum -= gc_max.1.count;
                    assert_eq!(gc.len(), mapping.len());
                }
            }
            assert_eq!(gc.len(), mapping.len());
            assert_eq!(gc.gc_size(), sum);
            if gc.is_empty() {
                assert!(mapping.is_empty());
            } else {
                assert_eq!(
                    gc.top().unwrap().1.count,
                    get_max(&mapping).unwrap().count
                );
                assert_eq!(
                    gc.top().unwrap().1.timestamp,
                    get_max(&mapping).unwrap().timestamp
                );
                assert_eq!(
                    gc.top().unwrap().1.has_ready_tx,
                    get_max(&mapping).unwrap().has_ready_tx
                );
                assert_eq!(
                    gc.top().unwrap().1.first_tx_gas_price,
                    get_max(&mapping).unwrap().first_tx_gas_price
                );
            }
        }
        for (addr, value) in mapping.iter() {
            assert_eq!(value.timestamp, gc.get_timestamp(addr).unwrap());
        }
    }
}
