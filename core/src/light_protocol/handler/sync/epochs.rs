// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        common::{max_of_collection, FullPeerFilter, FullPeerState, Peers},
        handler::sync::headers::Headers,
        message::{msgid, GetBlockHashesByEpoch},
        Error,
    },
    message::{Message, RequestId},
    network::{NetworkContext, PeerId},
    parameters::light::{
        EPOCH_REQUEST_BATCH_SIZE, EPOCH_REQUEST_TIMEOUT,
        MAX_PARALLEL_EPOCH_REQUESTS, NUM_EPOCHS_TO_REQUEST,
        NUM_WAITING_HEADERS_THRESHOLD,
    },
    UniqueId,
};
use parking_lot::RwLock;
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
    // shared consensus graph
    consensus: Arc<ConsensusGraph>,

    // header sync manager
    headers: Arc<Headers>,

    // epochs requested but not received yet
    in_flight: RwLock<HashMap<RequestId, EpochRequest>>,

    // latest epoch number requested so far
    latest: AtomicU64,

    // collection of all peers available
    peers: Arc<Peers<FullPeerState>>,

    // series of unique request ids
    request_id_allocator: Arc<UniqueId>,
}

impl Epochs {
    pub fn new(
        consensus: Arc<ConsensusGraph>, headers: Arc<Headers>,
        peers: Arc<Peers<FullPeerState>>, request_id_allocator: Arc<UniqueId>,
    ) -> Self
    {
        let in_flight = RwLock::new(HashMap::new());
        let latest = AtomicU64::new(0);

        Epochs {
            consensus,
            headers,
            in_flight,
            latest,
            peers,
            request_id_allocator,
        }
    }

    #[inline]
    pub fn receive(&self, id: &RequestId) {
        self.in_flight.write().remove(&id);
    }

    #[inline]
    fn best_peer_epoch(&self) -> u64 {
        self.peers.fold(0, |current_best, state| {
            let best_for_peer = state.read().best_epoch;
            cmp::max(current_best, best_for_peer)
        })
    }

    #[inline]
    fn get_statistics(&self) -> Statistics {
        Statistics {
            in_flight: self.in_flight.read().len(),
        }
    }

    fn insert_in_flight(&self, id: RequestId, epochs: Vec<u64>) {
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

    fn collect_epochs_to_request(&self) -> Vec<u64> {
        if self.in_flight.read().len() >= MAX_PARALLEL_EPOCH_REQUESTS {
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
        let timeout = *EPOCH_REQUEST_TIMEOUT;

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

    #[inline]
    fn request_epochs(
        &self, io: &dyn NetworkContext, peer: PeerId, epochs: Vec<u64>,
    ) -> Result<Option<RequestId>, Error> {
        info!("request_epochs peer={:?} epochs={:?}", peer, epochs);

        if epochs.is_empty() {
            return Ok(None);
        }

        let request_id = self.request_id_allocator.next();

        let msg: Box<dyn Message> =
            Box::new(GetBlockHashesByEpoch { request_id, epochs });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    pub fn sync(&self, io: &dyn NetworkContext) {
        info!("epoch sync statistics: {:?}", self.get_statistics());

        if self.headers.num_waiting() >= NUM_WAITING_HEADERS_THRESHOLD {
            return;
        }

        // choose set of epochs to request
        let epochs = self.collect_epochs_to_request();

        // request epochs in batches from random peers
        for batch in epochs.chunks(EPOCH_REQUEST_BATCH_SIZE) {
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
            match self.request_epochs(io, peer, batch.to_vec()) {
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
