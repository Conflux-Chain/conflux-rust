// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{HasKey, PriorityQueue};
use crate::{
    light_protocol::{
        common::{FullPeerFilter, FullPeerState, Peers},
        Error, ErrorKind,
    },
    message::{MsgId, RequestId},
};
use network::node_table::NodeId;
use parking_lot::{Mutex, RwLock};
use std::{
    cmp::Ord,
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    sync::Arc,
    time::{Duration, Instant},
};
use throttling::token_bucket::ThrottleResult;

#[derive(Debug)]
struct InFlightRequest<T> {
    pub item: T,
    pub request_id: RequestId,
    pub sent_at: Instant,
}

impl<T> InFlightRequest<T> {
    pub fn new(item: T, request_id: RequestId) -> Self {
        InFlightRequest {
            item,
            request_id,
            sent_at: Instant::now(),
        }
    }
}

pub struct SyncManager<Key, Item> {
    // headers requested but not received yet
    in_flight: RwLock<HashMap<Key, InFlightRequest<Item>>>,

    // collection of all peers available
    peers: Arc<Peers<FullPeerState>>,

    // mutex used to make sure at most one thread drives sync at any given time
    sync_lock: Mutex<()>,

    // priority queue of headers we need excluding the ones in `in_flight`
    waiting: RwLock<PriorityQueue<Key, Item>>,

    // used to filter peer to send request
    request_msg_id: MsgId,
}

impl<Key, Item> SyncManager<Key, Item>
where
    Key: Clone + Eq + Hash,
    Item: Debug + Clone + HasKey<Key> + Ord,
{
    pub fn new(
        peers: Arc<Peers<FullPeerState>>, request_msg_id: MsgId,
    ) -> Self {
        let in_flight = RwLock::new(HashMap::new());
        let sync_lock = Default::default();
        let waiting = RwLock::new(PriorityQueue::new());

        SyncManager {
            in_flight,
            peers,
            sync_lock,
            waiting,
            request_msg_id,
        }
    }

    #[inline]
    pub fn num_waiting(&self) -> usize { self.waiting.read().len() }

    #[inline]
    pub fn num_in_flight(&self) -> usize { self.in_flight.read().len() }

    #[inline]
    #[allow(dead_code)]
    pub fn contains(&self, key: &Key) -> bool {
        self.in_flight.read().contains_key(key)
            || self.waiting.read().contains(&key)
    }

    #[inline]
    fn get_existing_peer_state(
        &self, peer: &NodeId,
    ) -> Result<Arc<RwLock<FullPeerState>>, Error> {
        match self.peers.get(peer) {
            Some(state) => Ok(state),
            None => {
                bail!(ErrorKind::InternalError(format!(
                    "Received message from unknown peer={:?}",
                    peer
                )));
            }
        }
    }

    #[inline]
    pub fn check_if_requested(
        &self, peer: &NodeId, request_id: RequestId, key: &Key,
    ) -> Result<Option<RequestId>, Error> {
        let id = match self.in_flight.read().get(&key).map(|req| req.request_id)
        {
            Some(id) if id == request_id => return Ok(Some(id)),
            x => x,
        };

        let peer = self.get_existing_peer_state(peer)?;

        let bucket_name = self.request_msg_id.to_string();
        let bucket = match peer.read().unexpected_msgs.get(&bucket_name) {
            Some(bucket) => bucket,
            None => return Ok(id),
        };

        let result = bucket.lock().throttle_default();

        match result {
            ThrottleResult::Success => Ok(id),
            ThrottleResult::Throttled(_) => Ok(id),
            ThrottleResult::AlreadyThrottled => {
                bail!(ErrorKind::UnexpectedResponse {
                    expected: id,
                    received: request_id,
                });
            }
        }
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

    pub fn sync(
        &self, max_in_flight: usize, batch_size: usize,
        request: impl Fn(&NodeId, Vec<Key>) -> Result<Option<RequestId>, Error>,
    )
    {
        let _guard = match self.sync_lock.try_lock() {
            None => return,
            Some(g) => g,
        };

        // check if there are any peers available
        if self.peers.is_empty() {
            debug!("No peers available; aborting sync");
            return;
        }

        loop {
            // unlock after each batch so that we do not block other threads
            let mut in_flight = self.in_flight.write();
            let mut waiting = self.waiting.write();

            // collect batch
            let max_to_request = max_in_flight.saturating_sub(in_flight.len());
            let num_to_request = std::cmp::min(max_to_request, batch_size);

            if num_to_request == 0 {
                return;
            }

            let mut batch: Vec<Item> = vec![];

            // NOTE: cannot use iterator on BinaryHeap as
            // it returns elements in arbitrary order!
            while let Some(item) = waiting.pop() {
                // skip occasional items already in flight
                // this can happen if an item is inserted using
                // `insert_waiting`, then inserted again using
                // `request_now`
                if !in_flight.contains_key(&item.key()) {
                    batch.push(item);
                }

                if batch.len() == num_to_request {
                    break;
                }
            }

            // we're finished when there's nothing more to request
            if batch.is_empty() {
                return;
            }

            // select peer for batch
            let peer = match FullPeerFilter::new(self.request_msg_id)
                .select(self.peers.clone())
            {
                Some(peer) => peer,
                None => {
                    warn!("No peers available");
                    waiting.extend(batch.to_owned().into_iter());
                    return;
                }
            };

            let keys = batch.iter().map(|h| h.key()).collect();

            match request(&peer, keys) {
                Ok(None) => {}
                Ok(Some(request_id)) => {
                    let new_in_flight =
                        batch.to_owned().into_iter().map(|item| {
                            (item.key(), InFlightRequest::new(item, request_id))
                        });

                    in_flight.extend(new_in_flight);
                }
                Err(e) => {
                    warn!(
                        "Failed to request items {:?} from peer {:?}: {:?}",
                        batch, peer, e
                    );

                    waiting.extend(batch.to_owned().into_iter());
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
        request: impl Fn(&NodeId, Vec<Key>) -> Result<Option<RequestId>, Error>,
    ) where
        I: Iterator<Item = Item>,
    {
        let peer = match FullPeerFilter::new(self.request_msg_id)
            .select(self.peers.clone())
        {
            Some(peer) => peer,
            None => {
                warn!("No peers available");
                self.insert_waiting(items);
                return;
            }
        };

        self.request_now_from_peer(items, &peer, request);
    }

    #[inline]
    pub fn request_now_from_peer<I>(
        &self, items: I, peer: &NodeId,
        request: impl Fn(&NodeId, Vec<Key>) -> Result<Option<RequestId>, Error>,
    ) where
        I: Iterator<Item = Item>,
    {
        let mut in_flight = self.in_flight.write();

        let missing = items
            .filter(|item| !in_flight.contains_key(&item.key()))
            .collect::<Vec<_>>();

        let keys = missing.iter().map(|h| h.key()).collect();

        match request(peer, keys) {
            Ok(None) => {}
            Ok(Some(request_id)) => {
                let new_in_flight = missing.into_iter().map(|item| {
                    (item.key(), InFlightRequest::new(item, request_id))
                });

                in_flight.extend(new_in_flight);
            }
            Err(e) => {
                warn!(
                    "Failed to request {:?} from {:?}: {:?}",
                    missing, peer, e
                );

                self.insert_waiting(missing.into_iter());
            }
        }
    }
}
