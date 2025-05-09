// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use log::error;
use std::collections::VecDeque;

/// The goal of EpochQueue is to keep a distance from the tip of the ledger.
/// This way, we can ensure that the epoch being processed has already been
/// executed (deferred execution) and we can reduce the number of chain reorgs
/// that we need to notify subscribers about.

pub struct EpochQueue<T> {
    capacity: usize,
    queue: VecDeque<(u64, T)>,
}

impl<T> EpochQueue<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        let mut queue = VecDeque::new();
        queue.reserve(capacity);
        Self { capacity, queue }
    }

    pub fn push(&mut self, new: (u64, T)) -> Option<(u64, T)> {
        if self.capacity == 0 {
            return Some(new);
        }

        // remove epochs from queue that are greater or equal to the new one
        while matches!(self.queue.back(), Some((e, _)) if *e >= new.0) {
            self.queue.pop_back();
        }

        // we should not skip any epochs
        if let Some((e, _)) = self.queue.back() {
            if *e != new.0 - 1 {
                error!("Skipped epoch in epoch queue: {} --> {}", *e, new.0);
            }
        }

        // only return epoch if queue is full
        match self.queue.len() {
            n if n < self.capacity => {
                self.queue.push_back(new);
                return None;
            }
            n if n == self.capacity => {
                let e = self.queue.pop_front().unwrap();
                self.queue.push_back(new);
                return Some(e);
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_no_queue() {
        let mut queue = EpochQueue::with_capacity(0);

        assert_eq!(queue.push((0, 0)), Some((0, 0)));
        assert_eq!(queue.push((1, 1)), Some((1, 1)));
        assert_eq!(queue.push((2, 2)), Some((2, 2)));
        assert_eq!(queue.push((3, 3)), Some((3, 3)));
    }

    #[test]
    fn test_no_reorgs() {
        let mut queue = EpochQueue::with_capacity(5);

        assert_eq!(queue.push((0, 0)), None);
        assert_eq!(queue.push((1, 1)), None);
        assert_eq!(queue.push((2, 2)), None);
        assert_eq!(queue.push((3, 3)), None);
        assert_eq!(queue.push((4, 4)), None);
        assert_eq!(queue.push((5, 5)), Some((0, 0)));
        assert_eq!(queue.push((6, 6)), Some((1, 1)));
        assert_eq!(queue.push((7, 7)), Some((2, 2)));
        assert_eq!(queue.push((8, 8)), Some((3, 3)));
    }

    #[test]
    fn test_shallow_reorgs() {
        let mut queue = EpochQueue::with_capacity(5);

        assert_eq!(queue.push((0, 0)), None);
        assert_eq!(queue.push((1, 1)), None);
        assert_eq!(queue.push((2, 2)), None);
        assert_eq!(queue.push((1, 3)), None); // reorg: 2 --> 1
        assert_eq!(queue.push((2, 4)), None);
        assert_eq!(queue.push((3, 5)), None);
        assert_eq!(queue.push((4, 6)), None);
        assert_eq!(queue.push((1, 7)), None); // reorg: 4 --> 1
        assert_eq!(queue.push((2, 8)), None);
        assert_eq!(queue.push((3, 9)), None);
        assert_eq!(queue.push((4, 10)), None);
        assert_eq!(queue.push((5, 11)), Some((0, 0)));
        assert_eq!(queue.push((6, 12)), Some((1, 7)));
        assert_eq!(queue.push((4, 13)), None); // reorg: 6 --> 4
        assert_eq!(queue.push((5, 14)), None);
        assert_eq!(queue.push((6, 15)), None);
        assert_eq!(queue.push((7, 16)), Some((2, 8)));
        assert_eq!(queue.push((8, 17)), Some((3, 9)));
    }

    #[test]
    fn test_deep_reorgs() {
        let mut queue = EpochQueue::with_capacity(5);

        assert_eq!(queue.push((0, 0)), None);
        assert_eq!(queue.push((1, 1)), None);
        assert_eq!(queue.push((2, 2)), None);
        assert_eq!(queue.push((3, 3)), None);
        assert_eq!(queue.push((4, 4)), None);
        assert_eq!(queue.push((5, 5)), Some((0, 0)));
        assert_eq!(queue.push((6, 6)), Some((1, 1)));
        assert_eq!(queue.push((7, 7)), Some((2, 2)));
        assert_eq!(queue.push((8, 8)), Some((3, 3)));
        assert_eq!(queue.push((0, 9)), None); // reorg: 8 --> 0
        assert_eq!(queue.push((1, 10)), None);
        assert_eq!(queue.push((2, 11)), None);
        assert_eq!(queue.push((3, 12)), None);
        assert_eq!(queue.push((4, 13)), None);
        assert_eq!(queue.push((5, 14)), Some((0, 9)));
        assert_eq!(queue.push((6, 15)), Some((1, 10)));
        assert_eq!(queue.push((7, 16)), Some((2, 11)));
        assert_eq!(queue.push((8, 17)), Some((3, 12)));
    }
}
