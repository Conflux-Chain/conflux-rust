// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use parking_lot::RwLock;
use std::{
    cmp::Ord,
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    light_protocol::{
        common::{FullPeerState, Peers},
        Error,
    },
    network::PeerId,
};

use super::{HasKey, PriorityQueue};

#[derive(Debug)]
struct InFlightRequest<T> {
    pub item: T,
    pub sent_at: Instant,
}

impl<T> InFlightRequest<T> {
    pub fn new(item: T) -> Self {
        InFlightRequest {
            item,
            sent_at: Instant::now(),
        }
    }
}

pub struct SyncManager<Key, Item> {
    // headers requested but not received yet
    in_flight: RwLock<HashMap<Key, InFlightRequest<Item>>>,

    // collection of all peers available
    peers: Arc<Peers<FullPeerState>>,

    // priority queue of headers we need excluding the ones in `in_flight`
    waiting: RwLock<PriorityQueue<Key, Item>>,
}

impl<Key, Item> SyncManager<Key, Item>
where
    Key: Clone + Eq + Hash,
    Item: Debug + Clone + HasKey<Key> + Ord,
{
    pub fn new(peers: Arc<Peers<FullPeerState>>) -> Self {
        let in_flight = RwLock::new(HashMap::new());
        let waiting = RwLock::new(PriorityQueue::new());

        SyncManager {
            in_flight,
            peers,
            waiting,
        }
    }

    #[inline]
    pub fn num_waiting(&self) -> usize { self.waiting.read().len() }

    #[inline]
    pub fn num_in_flight(&self) -> usize { self.in_flight.read().len() }

    #[inline]
    pub fn insert_in_flight<I>(&self, missing: I)
    where I: Iterator<Item = Item> {
        let new = missing.map(|item| (item.key(), InFlightRequest::new(item)));
        self.in_flight.write().extend(new);
    }

    #[inline]
    pub fn remove_in_flight(&self, key: &Key) {
        self.in_flight.write().remove(&key);
    }

    #[inline]
    pub fn insert_waiting<I>(&self, items: I)
    where I: Iterator<Item = Item> {
        let in_flight = self.in_flight.read();
        let mut waiting = self.waiting.write();
        let missing = items.filter(|item| !in_flight.contains_key(&item.key()));
        waiting.extend(missing);
    }

    #[inline]
    pub fn collect_to_request(&self, num_to_request: usize) -> Vec<Item> {
        if num_to_request == 0 {
            return vec![];
        }

        let in_flight = self.in_flight.read();
        let mut waiting = self.waiting.write();

        let mut items = vec![];

        // NOTE: cannot use iterator on BinaryHeap as
        // it returns elements in arbitrary order!
        while let Some(item) = waiting.pop() {
            if !in_flight.contains_key(&item.key()) {
                items.push(item);
            }

            if items.len() == num_to_request {
                break;
            }
        }

        items
    }

    pub fn sync(
        &self, max_in_flight: usize, batch_size: usize,
        request: impl Fn(PeerId, Vec<Key>) -> Result<(), Error>,
    )
    {
        // check if there are any peers available
        if self.peers.is_empty() {
            warn!("No peers available; aborting sync");
            return;
        }

        // choose set of hashes to request
        let num_to_request = max_in_flight - self.num_in_flight();

        let items = match self.collect_to_request(num_to_request) {
            ref hs if hs.is_empty() => return,
            hs => hs,
        };

        // request items in batches from random peers
        for batch in items.chunks(batch_size) {
            let peer = match self.peers.random_peer() {
                Some(peer) => peer,
                None => {
                    warn!("No peers available");
                    self.insert_waiting(batch.to_owned().into_iter());

                    // NOTE: cannot do early return as that way items
                    // in subsequent batches would be lost
                    continue;
                }
            };

            let keys = batch.iter().map(|h| h.key()).collect();

            match request(peer, keys) {
                Ok(_) => {
                    self.insert_in_flight(batch.to_owned().into_iter());
                }
                Err(e) => {
                    warn!(
                        "Failed to request items {:?} from peer {:?}: {:?}",
                        batch, peer, e
                    );

                    self.insert_waiting(batch.to_owned().into_iter());
                }
            }
        }
    }

    #[inline]
    pub fn remove_timeout_requests(&self, timeout: Duration) -> Vec<Item> {
        let mut in_flight = self.in_flight.write();

        // collect timed-out requests
        let items: Vec<_> = in_flight
            .iter()
            .filter_map(|(_hash, req)| match req.sent_at {
                t if t.elapsed() < timeout => None,
                _ => Some(req.item.clone()),
            })
            .collect();

        // remove requests from `in_flight`
        for item in &items {
            in_flight.remove(&item.key());
        }

        items
    }

    #[inline]
    pub fn request_now<I>(
        &self, items: I,
        request: impl Fn(PeerId, Vec<Key>) -> Result<(), Error>,
    ) where
        I: Iterator<Item = Item>,
    {
        let peer = match self.peers.random_peer() {
            Some(peer) => peer,
            None => {
                warn!("No peers available");
                self.insert_waiting(items);
                return;
            }
        };

        self.request_now_from_peer(items, peer, request);
    }

    #[inline]
    pub fn request_now_from_peer<I>(
        &self, items: I, peer: PeerId,
        request: impl Fn(PeerId, Vec<Key>) -> Result<(), Error>,
    ) where
        I: Iterator<Item = Item>,
    {
        let items: Vec<_> = items.collect();
        let keys = items.iter().map(|h| h.key()).collect();

        match request(peer, keys) {
            Ok(_) => self.insert_in_flight(items.into_iter()),
            Err(e) => {
                warn!("Failed to request {:?} from {:?}: {:?}", items, peer, e);
                self.insert_waiting(items.into_iter());
            }
        }
    }
}
