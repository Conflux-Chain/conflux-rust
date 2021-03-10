// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    cmp::Ordering,
    collections::{binary_heap::PeekMut, BinaryHeap, HashMap},
    hash::Hash,
    time::{Duration, Instant},
};

pub struct TimeWindowBucket<KEY: Eq + Hash + Clone> {
    interval: Duration,
    limit: usize,
    timeouts: BinaryHeap<Item<KEY>>,
    counters: HashMap<KEY, usize>,
}

impl<KEY: Eq + Hash + Clone> TimeWindowBucket<KEY> {
    pub fn new(interval: Duration, limit: usize) -> Self {
        TimeWindowBucket {
            interval,
            limit,
            timeouts: BinaryHeap::new(),
            counters: HashMap::new(),
        }
    }

    fn refresh(&mut self) {
        while let Some(item) = self.timeouts.peek_mut() {
            if item.time.elapsed() <= self.interval {
                break;
            }

            let item = PeekMut::pop(item);
            let counter = self
                .counters
                .get_mut(&item.data)
                .expect("data inconsistent");
            if *counter <= 1 {
                self.counters.remove(&item.data);
            } else {
                *counter -= 1;
            }
        }
    }

    pub fn try_acquire(&mut self, key: KEY) -> bool {
        self.refresh();

        let counter = self.counters.entry(key.clone()).or_default();
        if *counter >= self.limit {
            return false;
        }

        *counter += 1;
        self.timeouts.push(Item::new(key));

        true
    }
}

struct Item<T> {
    time: Instant,
    data: T,
}

impl<T> Item<T> {
    fn new(data: T) -> Self {
        Item {
            time: Instant::now(),
            data,
        }
    }
}

impl<T> PartialEq for Item<T> {
    fn eq(&self, other: &Self) -> bool {
        self.time.eq(&other.time)
    }
}

impl<T> Eq for Item<T> {}

impl<T> PartialOrd for Item<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.time.partial_cmp(&self.time)
    }
}

impl<T> Ord for Item<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        other.time.cmp(&self.time)
    }
}

#[cfg(test)]
mod tests {
    use crate::time_window_bucket::TimeWindowBucket;
    use std::{thread::sleep, time::Duration};

    #[test]
    fn test_acquire() {
        let interval = Duration::from_millis(10);
        let mut bucket = TimeWindowBucket::new(interval, 2);

        assert_eq!(bucket.try_acquire(3), true);
        assert_eq!(bucket.try_acquire(3), true);
        assert_eq!(bucket.try_acquire(3), false);
        assert_eq!(bucket.try_acquire(4), true);

        sleep(interval + Duration::from_millis(1));

        assert_eq!(bucket.try_acquire(3), true);
        assert_eq!(bucket.try_acquire(3), true);
        assert_eq!(bucket.try_acquire(3), false);
    }
}
