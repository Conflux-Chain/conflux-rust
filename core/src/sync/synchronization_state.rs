// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use message::{
    GetBlockHeaders, GetBlockTxn, GetBlocks, GetCompactBlocks,
    GetTerminalBlockHashes, GetTransactions, Message, TransIndex,
};
use network::PeerId;
//use slab::Slab;
use crate::sync::{
    random, synchronization_protocol_handler::TimedSyncRequests,
};
use parking_lot::RwLock;
use primitives::{SignedTransaction, TxPropagateId};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    mem,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const RECEIVED_TRANSACTION_CONTAINER_WINDOW_SIZE: usize = 64;

#[derive(Debug)]
pub enum RequestMessage {
    Headers(GetBlockHeaders),
    Blocks(GetBlocks),
    Compact(GetCompactBlocks),
    BlockTxn(GetBlockTxn),
    Terminals(GetTerminalBlockHashes),
    Transactions(GetTransactions),
}

impl RequestMessage {
    pub fn set_request_id(&mut self, request_id: u64) {
        match self {
            RequestMessage::Headers(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::Blocks(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::Compact(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::BlockTxn(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::Terminals(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::Transactions(ref mut msg) => {
                msg.set_request_id(request_id)
            }
        }
    }

    pub fn get_msg(&self) -> &Message {
        match self {
            RequestMessage::Headers(ref msg) => msg,
            RequestMessage::Blocks(ref msg) => msg,
            RequestMessage::Compact(ref msg) => msg,
            RequestMessage::BlockTxn(ref msg) => msg,
            RequestMessage::Terminals(ref msg) => msg,
            RequestMessage::Transactions(ref msg) => msg,
        }
    }
}

#[derive(Debug)]
pub struct SynchronizationPeerRequest {
    pub message: Box<RequestMessage>,
    pub timed_req: Arc<TimedSyncRequests>,
}

struct ReceivedTransactionContainerInner {
    window_size: usize,
    container: HashSet<TxPropagateId>,
    slot_duration_as_secs: u64,
    time_windowed_indices: Vec<Option<(u64, Vec<TxPropagateId>)>>,
}

impl ReceivedTransactionContainerInner {
    pub fn new(window_size: usize, slot_duration_as_secs: u64) -> Self {
        let mut time_windowed_indices = Vec::new();
        for _ in 0..window_size {
            time_windowed_indices.push(None);
        }
        ReceivedTransactionContainerInner {
            window_size,
            container: HashSet::new(),
            slot_duration_as_secs,
            time_windowed_indices,
        }
    }
}

pub struct ReceivedTransactionContainer {
    inner: ReceivedTransactionContainerInner,
}

impl ReceivedTransactionContainer {
    pub fn new(timeout: u64) -> Self {
        let slot_duration_as_secs =
            timeout / RECEIVED_TRANSACTION_CONTAINER_WINDOW_SIZE as u64;
        ReceivedTransactionContainer {
            inner: ReceivedTransactionContainerInner::new(
                RECEIVED_TRANSACTION_CONTAINER_WINDOW_SIZE,
                slot_duration_as_secs,
            ),
        }
    }

    pub fn contains(&self, key: &TxPropagateId) -> bool {
        let inner = &self.inner;
        inner.container.contains(key)
    }

    pub fn append_transaction_ids(&mut self, tx_ids: Vec<TxPropagateId>) {
        let inner = &mut self.inner;

        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH);
        let secs = duration.ok().unwrap().as_secs();
        let window_index =
            (secs / inner.slot_duration_as_secs) as usize % inner.window_size;

        let indices = if inner.time_windowed_indices[window_index].is_none() {
            let indices = Vec::new();
            inner.time_windowed_indices[window_index] = Some((secs, indices));
            &mut inner.time_windowed_indices[window_index]
                .as_mut()
                .unwrap()
                .1
        } else {
            let mut indices_with_time =
                inner.time_windowed_indices[window_index].as_mut().unwrap();
            if indices_with_time.0 + inner.slot_duration_as_secs <= secs {
                for key_to_remove in &indices_with_time.1 {
                    inner.container.remove(key_to_remove);
                }
                let indices = Vec::new();
                indices_with_time.0 = secs;
                indices_with_time.1 = indices;
            }
            &mut indices_with_time.1
        };

        for tx_id in tx_ids {
            if !inner.container.contains(&tx_id) {
                inner.container.insert(tx_id.clone());
                indices.push(tx_id);
            }
        }
    }
}

struct SentTransactionContainerInner {
    window_size: usize,
    base_time_tick: usize,
    next_time_tick: usize,
    time_windowed_indices: Vec<Option<Vec<Arc<SignedTransaction>>>>,
}

impl SentTransactionContainerInner {
    pub fn new(window_size: usize) -> Self {
        let mut time_windowed_indices = Vec::new();
        for _ in 0..window_size {
            time_windowed_indices.push(None);
        }

        SentTransactionContainerInner {
            window_size,
            base_time_tick: 0,
            next_time_tick: 0,
            time_windowed_indices,
        }
    }
}

/// This struct is not implemented as thread-safe since
/// currently it is only used under protection of lock
/// on SynchronizationState. Later we may refine the
/// locking design to make it thread-safe.
pub struct SentTransactionContainer {
    inner: SentTransactionContainerInner,
}

impl SentTransactionContainer {
    pub fn new(window_size: usize) -> Self {
        SentTransactionContainer {
            inner: SentTransactionContainerInner::new(window_size),
        }
    }

    pub fn get_transaction(
        &self, index: &TransIndex,
    ) -> Option<Arc<SignedTransaction>> {
        let inner = &self.inner;
        if index.first() >= inner.base_time_tick {
            if index.first() - inner.base_time_tick >= inner.window_size {
                return None;
            }
        } else {
            if index.first() + 1 + std::usize::MAX - inner.base_time_tick
                >= inner.window_size
            {
                return None;
            }
        }

        let window_index = index.first() % inner.window_size;
        assert!(window_index < inner.time_windowed_indices.len());

        let transactions = inner.time_windowed_indices[window_index].as_ref();
        if transactions.is_none() {
            return None;
        }

        let transactions = transactions.unwrap();
        if index.second() >= transactions.len() {
            return None;
        }

        Some(transactions[index.second()].clone())
    }

    pub fn append_transactions(
        &mut self, transactions: Vec<Arc<SignedTransaction>>,
    ) -> usize {
        let inner = &mut self.inner;

        let base_window_index = inner.base_time_tick % inner.window_size;
        let next_time_tick = inner.next_time_tick;
        let next_window_index = next_time_tick % inner.window_size;
        inner.time_windowed_indices[next_window_index] = Some(transactions);
        if (next_window_index + 1) % inner.window_size == base_window_index {
            inner.base_time_tick += 1;
        }
        inner.next_time_tick += 1;
        next_time_tick
    }
}

pub struct SynchronizationPeerState {
    pub id: PeerId,
    pub protocol_version: u8,
    pub genesis_hash: H256,
    pub inflight_requests: Vec<Option<SynchronizationPeerRequest>>,
    /// lowest = next if there is no inflight requests
    pub lowest_request_id: u64,
    pub next_request_id: u64,
    pub best_epoch: u64,

    pub max_inflight_request_count: u64,
    pub pending_requests: VecDeque<Box<RequestMessage>>,

    /// The following fields are used to control how to
    /// propagate transactions in normal case.
    /// Holds a set of transactions recently sent to this peer to avoid
    /// spamming.
    pub last_sent_transaction_hashes: HashSet<H256>,
    pub sent_transactions: SentTransactionContainer,

    /// The following fields are used to control how to handle
    /// transaction propagation for nodes in catch-up mode.
    pub received_transaction_count: usize,
    pub need_prop_trans: bool,
    pub notified_mode: Option<bool>,
}

impl SynchronizationPeerState {
    /// If new request will be allowed to send, advance the request id now,
    /// otherwise, actual new request id will be given to this request
    /// when it is moved from pending to inflight queue.
    pub fn get_next_request_id(&mut self) -> Option<u64> {
        if self.next_request_id
            < self.lowest_request_id + self.max_inflight_request_count
        {
            let id = self.next_request_id;
            self.next_request_id += 1;
            Some(id)
        } else {
            None
        }
    }

    pub fn append_inflight_request(
        &mut self, request_id: u64, message: Box<RequestMessage>,
        timed_req: Arc<TimedSyncRequests>,
    )
    {
        self.inflight_requests
            [(request_id % self.max_inflight_request_count) as usize] =
            Some(SynchronizationPeerRequest { message, timed_req });
    }

    pub fn append_pending_request(&mut self, msg: Box<RequestMessage>) {
        self.pending_requests.push_back(msg);
    }

    #[allow(unused)]
    pub fn is_inflight_request(&self, request_id: u64) -> bool {
        request_id < self.next_request_id
            && request_id >= self.lowest_request_id
            && self.inflight_requests
                [(request_id % self.max_inflight_request_count) as usize]
                .is_some()
    }

    pub fn has_pending_requests(&self) -> bool {
        !self.pending_requests.is_empty()
    }

    pub fn pop_pending_request(&mut self) -> Option<Box<RequestMessage>> {
        self.pending_requests.pop_front()
    }

    pub fn remove_inflight_request(
        &mut self, request_id: u64,
    ) -> Option<SynchronizationPeerRequest> {
        if request_id < self.next_request_id
            && request_id >= self.lowest_request_id
        {
            let save_req = mem::replace(
                &mut self.inflight_requests
                    [(request_id % self.max_inflight_request_count) as usize],
                None,
            );
            // Advance lowest_request_id to the next in-flight request
            if request_id == self.lowest_request_id {
                while self.inflight_requests[(self.lowest_request_id
                    % self.max_inflight_request_count)
                    as usize]
                    .is_none()
                    && self.lowest_request_id < self.next_request_id
                {
                    self.lowest_request_id += 1;
                }
            }
            save_req
        } else {
            warn!("Remove out of bound request peer={} request_id={} low={} next={}", self.id, request_id, self.lowest_request_id, self.next_request_id);
            None
        }
    }
}

pub type SynchronizationPeers =
    HashMap<PeerId, Arc<RwLock<SynchronizationPeerState>>>;

pub struct SynchronizationState {
    pub catch_up_mode: bool,
    pub peers: SynchronizationPeers,
    pub handshaking_peers: HashMap<PeerId, Instant>,
    pub received_transactions: ReceivedTransactionContainer,
    pub inflight_requested_transactions: HashSet<TxPropagateId>,
}

impl SynchronizationState {
    pub fn new(catch_up_mode: bool, received_tx_index_timeout: u64) -> Self {
        SynchronizationState {
            catch_up_mode,
            peers: HashMap::new(),
            handshaking_peers: HashMap::new(),
            received_transactions: ReceivedTransactionContainer::new(
                received_tx_index_timeout,
            ),
            inflight_requested_transactions: HashSet::new(),
        }
    }

    /// Choose one random peer excluding the given `exclude` set.
    /// Return None if there is no peer to choose from
    pub fn get_random_peer(&self, exclude: &HashSet<PeerId>) -> Option<PeerId> {
        let peer_set: HashSet<PeerId> = self.peers.keys().cloned().collect();
        let choose_from: Vec<&PeerId> = peer_set.difference(exclude).collect();
        let mut rand = random::new();
        rand.choose(&choose_from).cloned().cloned()
    }
}
