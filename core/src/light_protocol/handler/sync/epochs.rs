// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use parking_lot::RwLock;
use std::{
    cmp,
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use super::{super::FullPeerState, max_of_collection, Peers};
use crate::{
    consensus::ConsensusGraph,
    message::RequestId,
    parameters::light::{
        EPOCH_REQUEST_TIMEOUT_MS, MAX_PARALLEL_EPOCH_REQUESTS,
        NUM_EPOCHS_TO_REQUEST,
    },
};

#[derive(Debug)]
struct EpochRequest {
    pub epochs: Vec<u64>,
    pub sent_at: Instant,
}

impl EpochRequest {
    pub fn new(epochs: Vec<u64>) -> Self {
        EpochRequest {
            epochs,
            sent_at: Instant::now(),
        }
    }
}

pub(super) struct Epochs {
    // shared consensus graph
    consensus: Arc<ConsensusGraph>,

    // epochs requested but not received yet
    in_flight: RwLock<HashMap<RequestId, EpochRequest>>,

    // latest epoch number requested so far
    latest: AtomicU64,

    // collection of all peers available
    peers: Arc<Peers<FullPeerState>>,
}

impl Epochs {
    pub fn new(
        consensus: Arc<ConsensusGraph>, peers: Arc<Peers<FullPeerState>>,
    ) -> Self {
        Epochs {
            consensus,
            in_flight: RwLock::new(HashMap::new()),
            latest: AtomicU64::new(0),
            peers,
        }
    }

    #[inline]
    pub fn best_peer_epoch(&self) -> u64 {
        self.peers.fold(0, |current_best, state| {
            let best_for_peer = state.read().best_epoch;
            cmp::max(current_best, best_for_peer)
        })
    }

    pub fn num_requests_in_flight(&self) -> usize {
        self.in_flight.read().len()
    }

    pub fn insert_in_flight(&self, id: RequestId, epochs: Vec<u64>) {
        if let Some(max_epoch) = max_of_collection(epochs.iter()).cloned() {
            let mut in_flight = self.in_flight.write();
            in_flight.insert(id, EpochRequest::new(epochs));

            let old = self.latest.load(Ordering::Relaxed);
            let new = cmp::max(old, max_epoch);
            let res = self.latest.compare_and_swap(old, new, Ordering::Relaxed);

            // NOTE: `latest` is only changed here and this
            // update is protected by a lock, so it should be fine
            assert!(res == old);
        };
    }

    pub fn remove_in_flight(&self, id: &RequestId) {
        self.in_flight.write().remove(&id);
    }

    pub fn collect_epochs_to_request(&self) -> Vec<u64> {
        if self.num_requests_in_flight() >= MAX_PARALLEL_EPOCH_REQUESTS {
            return vec![];
        }

        let my_best = self.consensus.best_epoch_number();
        let requested = self.latest.load(Ordering::Relaxed);
        let start_from = cmp::max(my_best, requested) + 1;
        let peer_best = self.best_peer_epoch();

        (start_from..peer_best)
            .take(NUM_EPOCHS_TO_REQUEST)
            .collect()
    }

    pub fn clean_up(&self) {
        let mut in_flight = self.in_flight.write();
        let timeout = Duration::from_millis(EPOCH_REQUEST_TIMEOUT_MS);

        // collect timed-out requests
        let ids: Vec<_> = in_flight
            .iter()
            .filter_map(|(id, req)| match req.sent_at {
                t if t.elapsed() < timeout => None,
                _ => Some(id.clone()),
            })
            .collect();

        // remove requests from `in_flight`
        for id in &ids {
            in_flight.remove(&id);
        }
    }
}
