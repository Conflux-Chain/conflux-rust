// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod epochs;
mod headers;

use rlp::Rlp;
use std::{
    cmp,
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use cfx_types::H256;

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        message::{
            BlockHashes as GetBlockHashesResponse,
            BlockHeaders as GetBlockHeadersResponse, GetBlockHashesByEpoch,
            GetBlockHeaders, NewBlockHashes,
        },
        peers::Peers,
        Error,
    },
    message::{Message, RequestId},
    network::{NetworkContext, PeerId},
    parameters::light::{
        CATCH_UP_EPOCH_LAG_THRESHOLD, EPOCH_REQUEST_BATCH_SIZE,
        HEADER_REQUEST_BATCH_SIZE, NUM_WAITING_HEADERS_THRESHOLD,
    },
    primitives::BlockHeader,
    sync::SynchronizationGraph,
};

use super::handler::FullPeerState;

use epochs::Epochs;
use headers::{HashSource, Headers};

fn max_of_collection<I, T: Ord>(collection: I) -> Option<T>
where I: Iterator<Item = T> {
    collection.fold(None, |max_so_far, x| match max_so_far {
        None => Some(x),
        Some(max_so_far) => Some(cmp::max(max_so_far, x)),
    })
}

#[derive(Debug)]
struct Statistics {
    catch_up_mode: bool,
    duplicate_count: u64,
    epochs_in_flight: usize,
    headers_in_flight: usize,
    headers_waiting: usize,
    latest_epoch: u64,
}

pub(super) struct SyncHandler {
    // shared consensus graph
    consensus: Arc<ConsensusGraph>,

    // number of headers received multiple times
    duplicate_count: AtomicU64,

    // epoch request manager
    epochs: Epochs,

    // shared synchronization graph
    graph: Arc<SynchronizationGraph>,

    // header request manager
    headers: Headers,

    // the next request id to be used when sending messages
    next_request_id: Arc<AtomicU64>,

    // collection of all peers available
    peers: Arc<Peers<FullPeerState>>,
}

impl SyncHandler {
    pub(super) fn new(
        consensus: Arc<ConsensusGraph>, graph: Arc<SynchronizationGraph>,
        next_request_id: Arc<AtomicU64>, peers: Arc<Peers<FullPeerState>>,
    ) -> Self
    {
        graph.recover_graph_from_db(true /* header_only */);

        let duplicate_count = AtomicU64::new(0);
        let epochs = Epochs::new(consensus.clone(), peers.clone());
        let headers = Headers::new(graph.clone());

        SyncHandler {
            consensus,
            duplicate_count,
            epochs,
            graph,
            headers,
            next_request_id,
            peers,
        }
    }

    #[inline]
    fn next_request_id(&self) -> RequestId {
        self.next_request_id.fetch_add(1, Ordering::Relaxed).into()
    }

    #[inline]
    pub fn median_peer_epoch(&self) -> Option<u64> {
        let mut best_epochs = self.peers.fold(vec![], |mut res, state| {
            res.push(state.read().best_epoch);
            res
        });

        best_epochs.sort();

        match best_epochs.len() {
            0 => None,
            n => Some(best_epochs[n / 2]),
        }
    }

    #[inline]
    fn catch_up_mode(&self) -> bool {
        match self.median_peer_epoch() {
            None => true,
            Some(epoch) => {
                let my_epoch = self.consensus.best_epoch_number();
                my_epoch < epoch - CATCH_UP_EPOCH_LAG_THRESHOLD
            }
        }
    }

    #[inline]
    fn get_statistics(&self) -> Statistics {
        Statistics {
            catch_up_mode: self.catch_up_mode(),
            duplicate_count: self.duplicate_count.load(Ordering::Relaxed),
            epochs_in_flight: self.epochs.num_requests_in_flight(),
            headers_in_flight: self.headers.num_in_flight(),
            headers_waiting: self.headers.num_waiting(),
            latest_epoch: self.consensus.best_epoch_number(),
        }
    }

    #[inline]
    fn collect_terminals(&self) {
        let terminals = self.peers.fold(vec![], |mut res, state| {
            let mut state = state.write();
            res.extend(state.terminals.iter());
            state.terminals.clear();
            res
        });

        let terminals = terminals.into_iter();
        self.headers.insert_waiting(terminals, HashSource::NewHash);
    }

    #[inline]
    fn request_epochs(
        &self, io: &NetworkContext, peer: PeerId, epochs: Vec<u64>,
    ) -> Result<Option<RequestId>, Error> {
        info!("request_epochs peer={:?} epochs={:?}", peer, epochs);

        if epochs.is_empty() {
            return Ok(None);
        }

        let request_id = self.next_request_id();

        let msg: Box<dyn Message> =
            Box::new(GetBlockHashesByEpoch { request_id, epochs });

        msg.send(io, peer)?;
        Ok(Some(request_id))
    }

    #[inline]
    fn request_headers(
        &self, io: &NetworkContext, peer: PeerId, hashes: Vec<H256>,
    ) -> Result<(), Error> {
        info!("request_headers peer={:?} hashes={:?}", peer, hashes);

        if hashes.is_empty() {
            return Ok(());
        }

        let msg: Box<dyn Message> = Box::new(GetBlockHeaders {
            request_id: self.next_request_id(),
            hashes,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    fn handle_headers(&self, headers: Vec<BlockHeader>) {
        let mut missing = HashSet::new();

        // TODO(thegaram): validate header timestamps
        for header in headers {
            let hash = header.hash();

            // signal receipt
            self.headers.remove_in_flight(&hash);

            // check duplicates
            if self.graph.contains_block_header(&hash) {
                self.duplicate_count.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            // insert into graph
            let (valid, _) = self.graph.insert_block_header(
                &mut header.clone(),
                true,  /* need_to_verify */
                false, /* bench_mode */
                true,  /* insert_to_consensus */
                true,  /* persistent */
            );

            if !valid {
                continue;
            }

            // store missing dependencies
            missing.insert(*header.parent_hash());

            for referee in header.referee_hashes() {
                missing.insert(*referee);
            }
        }

        let missing = missing.into_iter();
        self.headers.insert_waiting(missing, HashSource::Reference);
    }

    fn sync_headers(&self, io: &NetworkContext) {
        info!("sync_headers; statistics: {:?}", self.get_statistics());

        // check if there are any peers available
        if self.peers.is_empty() {
            warn!("No peers available; aborting sync");
            return;
        }

        // choose set of hashes to request
        let headers = self.headers.collect_headers_to_request();

        // request headers in batches from random peers
        for batch in headers.chunks(HEADER_REQUEST_BATCH_SIZE) {
            let peer = match self.peers.random_peer() {
                Some(peer) => peer,
                None => {
                    warn!("No peers available");
                    self.headers.reinsert_waiting(batch.to_owned().into_iter());

                    // NOTE: cannot do early return as that way headers
                    // in subsequent batches would be lost
                    continue;
                }
            };

            let hashes = batch.iter().map(|h| h.hash.clone()).collect();

            match self.request_headers(io, peer, hashes) {
                Ok(_) => {
                    self.headers.insert_in_flight(batch.to_owned().into_iter());
                }
                Err(e) => {
                    warn!(
                        "Failed to request headers {:?} from peer {:?}: {:?}",
                        batch, peer, e
                    );

                    self.headers.reinsert_waiting(batch.to_owned().into_iter());
                }
            }
        }
    }

    fn sync_epochs(&self, io: &NetworkContext) {
        info!("sync_epochs; statistics: {:?}", self.get_statistics());

        // return if we already have enough hashes in the pipeline
        if self.headers.num_waiting() >= NUM_WAITING_HEADERS_THRESHOLD {
            return;
        }

        // choose set of epochs to request
        let epochs = self.epochs.collect_epochs_to_request();

        // request epochs in batches from random peers
        for batch in epochs.chunks(EPOCH_REQUEST_BATCH_SIZE) {
            // find maximal epoch number in this chunk
            let max = max_of_collection(batch.iter()).expect("chunk not empty");

            // choose random peer that has the epochs we need
            let predicate = |s: &FullPeerState| s.best_epoch >= *max;
            let peer = match self.peers.random_peer_satisfying(predicate) {
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
                    self.epochs.insert_in_flight(id, batch.to_vec());
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

    pub(super) fn on_block_hashes(
        &self, io: &NetworkContext, _peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetBlockHashesResponse = rlp.as_val()?;
        info!("on_block_hashes resp={:?}", resp);

        self.epochs.remove_in_flight(&resp.request_id);

        let hashes = resp.hashes.into_iter();
        self.headers.insert_waiting(hashes, HashSource::Epoch);

        self.start_sync(io);
        Ok(())
    }

    pub(super) fn on_block_headers(
        &self, io: &NetworkContext, _peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetBlockHeadersResponse = rlp.as_val()?;
        info!("on_block_headers resp={:?}", resp);

        self.handle_headers(resp.headers);

        self.start_sync(io);
        Ok(())
    }

    pub(super) fn on_new_block_hashes(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let msg: NewBlockHashes = rlp.as_val()?;
        info!("on_new_block_hashes msg={:?}", msg);

        if self.catch_up_mode() {
            if let Some(state) = self.peers.get(&peer) {
                let mut state = state.write();
                state.terminals.extend(msg.hashes);
            }
            return Ok(());
        }

        let hashes = msg.hashes.into_iter();
        self.headers.insert_waiting(hashes, HashSource::NewHash);

        self.start_sync(io);
        Ok(())
    }

    pub(super) fn start_sync(&self, io: &NetworkContext) {
        info!("start_sync; statistics: {:?}", self.get_statistics());

        match self.catch_up_mode() {
            true => {
                self.sync_headers(io);
                self.sync_epochs(io);
            }
            false => {
                self.collect_terminals();
                self.sync_headers(io);
            }
        };
    }

    pub(super) fn clean_up_requests(&self) {
        info!("clean_up_requests");
        self.epochs.clean_up();
        self.headers.clean_up();
    }
}
