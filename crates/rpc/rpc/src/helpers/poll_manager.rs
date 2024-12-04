#![allow(dead_code)]
// Copyright 2015-2019 Parity Technologies (UK) Ltd.
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

//! Indexes all rpc poll requests.

use cfx_types::H128;
use transient_hashmap::{StandardTimer, Timer, TransientHashMap};

pub type PollId = H128;

/// Indexes all poll requests.
///
/// Lazily garbage collects unused polls info.
pub struct PollManager<F, T = StandardTimer>
where T: Timer
{
    polls: TransientHashMap<PollId, F, T>,
}

impl<F> PollManager<F, StandardTimer> {
    /// Creates new instance of indexer
    pub fn new(lifetime: u32) -> Self {
        PollManager::new_with_timer(Default::default(), lifetime)
    }
}

impl<F, T> PollManager<F, T>
where T: Timer
{
    pub fn new_with_timer(timer: T, lifetime: u32) -> Self {
        PollManager {
            polls: TransientHashMap::new_with_timer(lifetime, timer),
        }
    }

    /// Returns id which can be used for new poll.
    ///
    /// Stores information when last poll happend.
    pub fn create_poll(&mut self, filter: F) -> PollId {
        self.polls.prune();

        let id = loop {
            let id = PollId::random();
            if self.polls.contains_key(&id) {
                continue;
            }

            break id;
        };

        self.polls.insert(id, filter);

        id
    }

    // Implementation is always using `poll_mut`
    /// Get a reference to stored poll filter
    pub fn poll(&mut self, id: &PollId) -> Option<&F> {
        self.polls.prune();
        self.polls.get(id)
    }

    /// Get a mutable reference to stored poll filter
    pub fn poll_mut(&mut self, id: &PollId) -> Option<&mut F> {
        self.polls.prune();
        self.polls.get_mut(id)
    }

    /// Removes poll info.
    pub fn remove_poll(&mut self, id: &PollId) -> bool {
        self.polls.remove(id).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::PollManager;
    use std::cell::Cell;
    use transient_hashmap::Timer;

    struct TestTimer<'a> {
        time: &'a Cell<i64>,
    }

    impl<'a> Timer for TestTimer<'a> {
        fn get_time(&self) -> i64 { self.time.get() }
    }

    #[test]
    fn test_poll_indexer() {
        let time = Cell::new(0);
        let timer = TestTimer { time: &time };

        let mut indexer = PollManager::new_with_timer(timer, 60);
        let id1 = indexer.create_poll(20);
        let id2 = indexer.create_poll(20);
        assert_ne!(id1, id2);

        time.set(10);
        *indexer.poll_mut(&id1).unwrap() = 21;
        assert_eq!(*indexer.poll(&id1).unwrap(), 21);
        assert_eq!(*indexer.poll(&id2).unwrap(), 20);

        time.set(30);
        *indexer.poll_mut(&id2).unwrap() = 23;
        assert_eq!(*indexer.poll(&id2).unwrap(), 23);

        time.set(75);
        assert!(indexer.poll(&id1).is_none());
        assert_eq!(*indexer.poll(&id2).unwrap(), 23);

        indexer.remove_poll(&id2);
        assert!(indexer.poll(&id2).is_none());
    }
}
