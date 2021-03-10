// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{max_of_collection, FullPeerFilter, FullPeerState, Peers},
        handler::sync::headers::Headers,
        message::{msgid, GetBlockHashesByEpoch},
        Error, LightNodeConfiguration,
    },
    message::{Message, RequestId},
    UniqueId,
};
use cfx_parameters::light::{
    EPOCH_REQUEST_BATCH_SIZE, EPOCH_REQUEST_TIMEOUT,
    MAX_PARALLEL_EPOCH_REQUESTS, NUM_EPOCHS_TO_REQUEST,
    NUM_WAITING_HEADERS_THRESHOLD,
};
use network::{node_table::NodeId, NetworkContext};
use parking_lot::{Mutex, RwLock};
use std::{
    cmp,
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

#[derive(Debug)]
struct Statistics {
    in_flight: usize,
    received: u64,
    unexpected: u64,
    timeout: u64,
    latest_requested: u64,
    peer_best: u64,
}

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

pub struct Epochs {
    // light node configuration
    config: LightNodeConfiguration,

    // shared consensus graph
    consensus: SharedConsensusGraph,

    // header sync manager
    headers: Arc<Headers>,

    // epochs requested but not received yet
    in_flight: RwLock<HashMap<RequestId, EpochRequest>>,

    // latest epoch number requested so far
    latest: AtomicU64,

    // collection of all peers available
    peers: Arc<Peers<FullPeerState>>,

    // number of epochs received
    received_count: AtomicU64,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,

    // mutex used to make sure at most one thread drives sync at any given time
    sync_lock: Mutex<()>,

    // number of timeout epoch requests
    timeout_count: AtomicU64,

    // number of unexpected epoch responses received
    // these are mostly responses for timeout requests
    unexpected_count: AtomicU64,
}

impl Epochs {
    pub fn new(
        consensus: SharedConsensusGraph, headers: Arc<Headers>,
        peers: Arc<Peers<FullPeerState>>, request_id_allocator: Arc<UniqueId>,
        config: LightNodeConfiguration,
    ) -> Self {
        let in_flight = RwLock::new(HashMap::new());
        let latest = AtomicU64::new(0);
        let received_count = AtomicU64::new(0);
        let sync_lock = Mutex::new(());
        let timeout_count = AtomicU64::new(0);
        let unexpected_count = AtomicU64::new(0);

        Epochs {
            config,
            consensus,
            headers,
            in_flight,
            latest,
            peers,
            received_count,
            request_id_allocator,
            sync_lock,
            timeout_count,
            unexpected_count,
        }
    }

    #[inline]
    pub fn receive(&self, id: &RequestId) {
        match self.in_flight.write().remove(&id) {
            Some(hashes) => {
                self.received_count
                    .fetch_add(hashes.epochs.len() as u64, Ordering::Relaxed);
            }
            None => {
                trace!(
                    "Received unexpected GetBlockHashesResponse, id = {:?}",
                    id
                );
                self.unexpected_count.fetch_add(1, Ordering::Relaxed);
                // TODO(thegaram): add throttling
            }
        }
    }

    #[inline]
    pub fn best_peer_epoch(&self) -> u64 {
        self.peers.fold(0, |current_best, state| {
            let best_for_peer = state.read().best_epoch;
            cmp::max(current_best, best_for_peer)
        })
    }

    #[inline]
    pub fn print_stats(&self) {
        debug!(
            "epoch sync statistics: {:?}",
            Statistics {
                in_flight: self.in_flight.read().len(),
                received: self.received_count.load(Ordering::Relaxed),
                unexpected: self.unexpected_count.load(Ordering::Relaxed),
                timeout: self.timeout_count.load(Ordering::Relaxed),
                latest_requested: self.latest.load(Ordering::Relaxed),
                peer_best: self.best_peer_epoch(),
            }
        );
    }

    fn insert_in_flight(&self, id: RequestId, epochs: Vec<u64>) {
        if let Some(max_epoch) = max_of_collection(epochs.iter()).cloned() {
            let mut in_flight = self.in_flight.write();
            in_flight.insert(id, EpochRequest::new(epochs));

            let old = self.latest.load(Ordering::Relaxed);
            let new = cmp::max(old, max_epoch);
            let res = self
                .latest
                .compare_exchange(
                    old,
                    new,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .unwrap_or_else(|mismatch| mismatch);

            // NOTE: `latest` is only changed here and this
            // update is protected by a lock, so it should be fine
            assert!(res == old);
        };
    }

    fn collect_epochs_to_request(&self) -> Vec<u64> {
        let max_parallel = self
            .config
            .max_parallel_epochs_to_request
            .unwrap_or(MAX_PARALLEL_EPOCH_REQUESTS);

        let num_to_request = self
            .config
            .num_epochs_to_request
            .unwrap_or(NUM_EPOCHS_TO_REQUEST);

        if self.in_flight.read().len() >= max_parallel {
            return vec![];
        }

        let my_best = self.consensus.best_epoch_number();
        let requested = self.latest.load(Ordering::Relaxed);
        let start_from = cmp::max(my_best, requested) + 1;
        let peer_best = self.best_peer_epoch();

        (start_from..peer_best).take(num_to_request).collect()
    }

    pub fn clean_up(&self) {
        let mut in_flight = self.in_flight.write();

        let timeout = self
            .config
            .epoch_request_timeout
            .unwrap_or(*EPOCH_REQUEST_TIMEOUT);

        // collect timed-out requests
        let ids: Vec<_> = in_flight
            .iter()
            .filter_map(|(id, req)| match req.sent_at {
                t if t.elapsed() < timeout => None,
                _ => Some(id.clone()),
            })
            .collect();

        trace!("Timeout epochs ({}): {:?}", ids.len(), ids);

        self.timeout_count
            .fetch_add(ids.len() as u64, Ordering::Relaxed);

        // remove requests from `in_flight`
        for id in &ids {
            in_flight.remove(&id);
        }
    }

    #[inline]
    fn request_epochs(
        &self, io: &dyn NetworkContext, peer: &NodeId, epochs: Vec<u64>,
    ) -> Result<Option<RequestId>, Error> {
        if epochs.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();

        trace!(
            "send_request GetBlockHashesByEpoch peer={:?} id={:?} epochs={:?}",
            peer,
            request_id,
            epochs
        );

        let msg: Box<dyn Message> =
            Box::new(GetBlockHashesByEpoch { request_id, epochs });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    pub fn sync(&self, io: &dyn NetworkContext) {
        let _guard = match self.sync_lock.try_lock() {
            None => return,
            Some(g) => g,
        };

        let threshold = self
            .config
            .num_waiting_headers_threshold
            .unwrap_or(NUM_WAITING_HEADERS_THRESHOLD);

        if self.headers.num_waiting() >= threshold {
            return;
        }

        // choose set of epochs to request
        let epochs = self.collect_epochs_to_request();

        // request epochs in batches from random peers
        let batch_size = self
            .config
            .epoch_request_batch_size
            .unwrap_or(EPOCH_REQUEST_BATCH_SIZE);

        for batch in epochs.chunks(batch_size) {
            // find maximal epoch number in this chunk
            let max = max_of_collection(batch.iter()).expect("chunk not empty");

            // choose random peer that has the epochs we need
            let matched_peer =
                FullPeerFilter::new(msgid::GET_BLOCK_HASHES_BY_EPOCH)
                    .with_min_best_epoch(*max)
                    .select(self.peers.clone());

            let peer = match matched_peer {
                Some(peer) => peer,
                None => {
                    warn!("No peers available; aborting sync");
                    break;
                }
            };

            // request epoch batch
            match self.request_epochs(io, &peer, batch.to_vec()) {
                Ok(None) => {}
                Ok(Some(id)) => {
                    self.insert_in_flight(id, batch.to_vec());
                }
                Err(e) => {
                    warn!(
                        "Failed to request epochs {:?} from peer {:?}: {:?}",
                        batch, peer, e
                    );
                }
            }
        }
    }
}
