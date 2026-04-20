// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// Indexes all rpc poll requests.

use cfx_types::H128;
use transient_hashmap::{StandardTimer, Timer, TransientHashMap};

pub type PollId = H128;

/// Indexes all poll requests. Lazily garbage collects unused polls info.
pub struct PollManager<F, T = StandardTimer>
where T: Timer
{
    polls: TransientHashMap<PollId, F, T>,
}

impl<F> PollManager<F, StandardTimer> {
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

    pub fn create_poll(&mut self, filter: F) -> PollId {
        self.polls.prune();
        let id = loop {
            let id = PollId::random();
            if !self.polls.contains_key(&id) {
                break id;
            }
        };
        self.polls.insert(id, filter);
        id
    }

    pub fn poll(&mut self, id: &PollId) -> Option<&F> {
        self.polls.prune();
        self.polls.get(id)
    }

    pub fn poll_mut(&mut self, id: &PollId) -> Option<&mut F> {
        self.polls.prune();
        self.polls.get_mut(id)
    }

    pub fn remove_poll(&mut self, id: &PollId) -> bool {
        self.polls.remove(id).is_some()
    }
}
