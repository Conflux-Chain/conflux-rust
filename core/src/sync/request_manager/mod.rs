use super::{
    synchronization_protocol_handler::ProtocolConfiguration,
    synchronization_state::SynchronizationState,
};
use crate::{
    parameters::sync::REQUEST_START_WAITING_TIME,
    sync::{
        message::{
            msgid, GetBlockHashesByEpoch, GetBlockHeaders, GetBlockTxn,
            GetBlocks, GetCompactBlocks, GetTransactions, Key, KeyContainer,
            TransactionDigests,
        },
        synchronization_state::PeerFilter,
        Error,
    },
};
use cfx_types::H256;
use metrics::{register_meter_with_group, Meter, MeterTimer};
use network::{NetworkContext, PeerId};
use parking_lot::{Mutex, RwLock};
use primitives::{SignedTransaction, TransactionWithSignature, TxPropagateId};
pub use request_handler::{
    Request, RequestHandler, RequestMessage, SynchronizationPeerRequest,
};
use std::{
    cmp::Ordering,
    collections::{binary_heap::BinaryHeap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tx_handler::{ReceivedTransactionContainer, SentTransactionContainer};

mod request_handler;
pub mod tx_handler;

lazy_static! {
    static ref TX_REQUEST_METER: Arc<dyn Meter> =
        register_meter_with_group("system_metrics", "tx_diff_set_size");
    static ref REQUEST_MANAGER_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "request_manager::request_not_tx");
    static ref REQUEST_MANAGER_TX_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "request_manager::request_tx");
    static ref TX_RECEIVED_POOL_METER: Arc<dyn Meter> =
        register_meter_with_group("system_metrics", "tx_received_pool_size");
    static ref INFLIGHT_TX_POOL_METER: Arc<dyn Meter> =
        register_meter_with_group("system_metrics", "inflight_tx_pool_size");
}

#[derive(Debug)]
struct WaitingRequest(Box<dyn Request>, Duration); // (request, delay)

/// When a header or block is requested by the `RequestManager`, it is ensured
/// that if it's not fully received, its hash exists
/// in `in_flight` after every function call.
///
/// The thread who removes a hash from `in_flight` is responsible to request it
/// again if it's not received.
///
/// No lock is held when we call another function in this struct, and all locks
/// are acquired in the same order, so there should exist no deadlocks.
// TODO A non-existing block request will remain in the struct forever, and we
// need garbage collect
pub struct RequestManager {
    // used to avoid send duplicated requests.
    inflight_keys: KeyContainer,

    /// Each element is (timeout_time, request, chosen_peer)
    waiting_requests: Mutex<BinaryHeap<TimedWaitingRequest>>,

    /// The following fields are used to control how to
    /// propagate transactions in normal case.
    /// Holds a set of transactions recently sent to this peer to avoid
    /// spamming.
    sent_transactions: RwLock<SentTransactionContainer>,
    pub received_transactions: Arc<RwLock<ReceivedTransactionContainer>>,

    /// This is used to handle request_id matching
    request_handler: Arc<RequestHandler>,
    syn: Arc<SynchronizationState>,
}

impl RequestManager {
    pub fn new(
        protocol_config: &ProtocolConfiguration, syn: Arc<SynchronizationState>,
    ) -> Self {
        let received_tx_index_maintain_timeout =
            protocol_config.received_tx_index_maintain_timeout;

        // FIXME: make sent_transaction_window_size to be 2^pow.
        let sent_transaction_window_size =
            protocol_config.tx_maintained_for_peer_timeout.as_millis()
                / protocol_config.send_tx_period.as_millis();
        Self {
            received_transactions: Arc::new(RwLock::new(
                ReceivedTransactionContainer::new(
                    received_tx_index_maintain_timeout.as_secs(),
                ),
            )),
            sent_transactions: RwLock::new(SentTransactionContainer::new(
                sent_transaction_window_size as usize,
            )),
            inflight_keys: Default::default(),
            waiting_requests: Default::default(),
            request_handler: Arc::new(RequestHandler::new(protocol_config)),
            syn,
        }
    }

    pub fn num_epochs_in_flight(&self) -> u64 {
        self.inflight_keys
            .read(msgid::GET_BLOCK_HASHES_BY_EPOCH)
            .len() as u64
    }

    /// Send request to remote peer with delay mechanism. If failed,
    /// add the request to waiting queue to resend later.
    pub fn request_with_delay(
        &self, io: &dyn NetworkContext, mut request: Box<dyn Request>,
        peer: Option<PeerId>, delay: Option<Duration>,
    )
    {
        // retain the request items that not in flight.
        request.with_inflight(&self.inflight_keys);

        if request.is_empty() {
            return;
        }

        // increase delay for resent request.
        let (cur_delay, next_delay) = match delay {
            Some(d) => (d, d + *REQUEST_START_WAITING_TIME),
            None => (*REQUEST_START_WAITING_TIME, *REQUEST_START_WAITING_TIME),
        };

        // delay if no peer available or delay required
        if peer.is_none() || delay.is_some() {
            // todo remove the request if waiting time is too long?
            // E.g. attacker may broadcast many many invalid block hashes,
            // and no peer could return the corresponding block header.
            debug!("request_with_delay: add request to waiting_requests, peer={:?}, request={:?}, delay={:?}", peer, request, cur_delay);
            self.waiting_requests.lock().push(TimedWaitingRequest::new(
                Instant::now() + cur_delay,
                WaitingRequest(request, next_delay),
                peer,
            ));

            return;
        }

        if let Err(e) = self.request_handler.send_request(
            io,
            peer,
            request,
            Some(next_delay),
        ) {
            debug!("request_with_delay: send_request fails, peer={:?}, request={:?}", peer, e);
            self.waiting_requests.lock().push(TimedWaitingRequest::new(
                Instant::now() + cur_delay,
                WaitingRequest(e, next_delay),
                None,
            ));
        }
    }

    pub fn request_block_headers(
        &self, io: &dyn NetworkContext, peer_id: Option<PeerId>,
        hashes: Vec<H256>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        debug!("request_block_headers: {:?}", hashes);

        let request = GetBlockHeaders {
            request_id: 0,
            hashes,
        };

        self.request_with_delay(io, Box::new(request), peer_id, None);
    }

    pub fn request_epoch_hashes(
        &self, io: &dyn NetworkContext, peer_id: Option<PeerId>,
        epochs: Vec<u64>,
    )
    {
        let request = GetBlockHashesByEpoch {
            request_id: 0,
            epochs,
        };

        self.request_with_delay(io, Box::new(request), peer_id, None);
    }

    pub fn request_blocks(
        &self, io: &dyn NetworkContext, peer_id: Option<PeerId>,
        hashes: Vec<H256>, with_public: bool,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        let request = GetBlocks {
            request_id: 0,
            with_public,
            hashes,
        };

        self.request_with_delay(io, Box::new(request), peer_id, None);
    }

    pub fn request_transactions(
        &self, io: &dyn NetworkContext, peer_id: PeerId,
        transaction_digests: TransactionDigests,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TX_TIMER.as_ref());

        let window_index: usize = transaction_digests.window_index;
        let random_position: u8 = transaction_digests.random_position;
        let (random_byte_vector, fixed_bytes_vector) =
            transaction_digests.get_decomposed_short_ids();

        if fixed_bytes_vector.is_empty() {
            return;
        }

        let mut inflight_keys =
            self.inflight_keys.write(msgid::GET_TRANSACTIONS);
        let received_transactions = self.received_transactions.read();

        INFLIGHT_TX_POOL_METER.mark(inflight_keys.len());
        TX_RECEIVED_POOL_METER.mark(received_transactions.get_length());

        let (indices, tx_ids) = {
            let mut tx_ids = HashSet::new();
            let mut indices = Vec::new();

            for i in 0..fixed_bytes_vector.len() {
                if received_transactions.contains_txid(
                    fixed_bytes_vector[i],
                    random_byte_vector[i],
                    random_position,
                ) {
                    // Already received
                    continue;
                }

                if !inflight_keys.insert(Key::Id(fixed_bytes_vector[i])) {
                    // Already being requested
                    continue;
                }

                indices.push(i);
                tx_ids.insert(fixed_bytes_vector[i]);
            }

            (indices, tx_ids)
        };
        TX_REQUEST_METER.mark(tx_ids.len());
        debug!("Request {} tx from peer={}", tx_ids.len(), peer_id);

        let request = GetTransactions {
            request_id: 0,
            window_index,
            indices,
            tx_ids: tx_ids.clone(),
        };

        if request.is_empty() {
            return;
        }

        if self
            .request_handler
            .send_request(io, Some(peer_id), Box::new(request), None)
            .is_err()
        {
            for id in tx_ids {
                inflight_keys.remove(&Key::Id(id));
            }
        }
    }

    pub fn request_compact_blocks(
        &self, io: &dyn NetworkContext, peer_id: Option<PeerId>,
        hashes: Vec<H256>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        let request = GetCompactBlocks {
            request_id: 0,
            hashes,
        };

        self.request_with_delay(io, Box::new(request), peer_id, None);
    }

    pub fn request_blocktxn(
        &self, io: &dyn NetworkContext, peer_id: PeerId, block_hash: H256,
        indexes: Vec<usize>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        let request = GetBlockTxn {
            request_id: 0,
            block_hash: block_hash.clone(),
            indexes,
        };

        self.request_with_delay(io, Box::new(request), Some(peer_id), None);
    }

    pub fn send_request_again(
        &self, io: &dyn NetworkContext, msg: &RequestMessage,
    ) {
        debug!("send_request_again, request={:?}", msg.request);
        if let Some(request) = msg.request.resend() {
            let mut filter = PeerFilter::new(request.msg_id());
            if let Some(cap) = request.required_capability() {
                filter = filter.with_cap(cap);
            }
            let chosen_peer = filter.select(&self.syn);
            debug!("send_request_again with new request, peer={:?}, new request={:?}", chosen_peer, request);
            self.request_with_delay(io, request, chosen_peer, msg.delay);
        }
    }

    pub fn remove_mismatch_request(
        &self, io: &dyn NetworkContext, req: &RequestMessage,
    ) {
        req.request.on_removed(&self.inflight_keys);
        self.send_request_again(io, req);
    }

    // Match request with given response.
    // No need to let caller handle request resending.
    pub fn match_request(
        &self, io: &dyn NetworkContext, peer_id: PeerId, request_id: u64,
    ) -> Result<RequestMessage, Error> {
        self.request_handler.match_request(io, peer_id, request_id)
    }

    /// Remove inflight keys when a header is received.
    ///
    /// If a request is removed from `req_hashes`, it's the caller's
    /// responsibility to ensure that the removed request either has already
    /// received or will be requested by the caller again.
    pub fn headers_received(
        &self, io: &dyn NetworkContext, req_hashes: HashSet<H256>,
        mut received_headers: HashSet<H256>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());
        debug!(
            "headers_received: req_hashes={:?} received_headers={:?}",
            req_hashes, received_headers
        );
        let missing_headers = {
            let mut inflight_keys =
                self.inflight_keys.write(msgid::GET_BLOCK_HEADERS);
            let mut missing_headers = Vec::new();
            for req_hash in &req_hashes {
                if !received_headers.remove(req_hash) {
                    // If `req_hash` is not in `headers_in_flight`, it may has
                    // been received or requested
                    // again by another thread, so we do not need to request it
                    // in that case
                    if inflight_keys.remove(&Key::Hash(*req_hash)) {
                        missing_headers.push(*req_hash);
                    }
                } else {
                    inflight_keys.remove(&Key::Hash(*req_hash));
                }
            }
            for h in &received_headers {
                inflight_keys.remove(&Key::Hash(*h));
            }
            missing_headers
        };
        if !missing_headers.is_empty() {
            let chosen_peer =
                PeerFilter::new(msgid::GET_BLOCK_HEADERS).select(&self.syn);
            self.request_block_headers(io, chosen_peer, missing_headers);
        }
    }

    /// Remove from inflight keys when a epoch is received.
    pub fn epochs_received(
        &self, io: &dyn NetworkContext, req_epochs: HashSet<u64>,
        mut received_epochs: HashSet<u64>,
    )
    {
        debug!(
            "epochs_received: req_epochs={:?} received_epochs={:?}",
            req_epochs, received_epochs
        );
        let missing_epochs = {
            let mut inflight_keys =
                self.inflight_keys.write(msgid::GET_BLOCK_HASHES_BY_EPOCH);
            let mut missing_epochs = Vec::new();
            for epoch_number in &req_epochs {
                if !received_epochs.remove(epoch_number) {
                    // If `epoch_number` is not in `epochs_in_flight`, it may
                    // has been received or requested
                    // again by another thread, so we do not need to request it
                    // in that case
                    if inflight_keys.remove(&Key::Num(*epoch_number)) {
                        missing_epochs.push(*epoch_number);
                    }
                } else {
                    inflight_keys.remove(&Key::Num(*epoch_number));
                }
            }
            for epoch_number in &received_epochs {
                inflight_keys.remove(&Key::Num(*epoch_number));
            }
            missing_epochs
        };
        if !missing_epochs.is_empty() {
            let chosen_peer = PeerFilter::new(msgid::GET_BLOCK_HASHES_BY_EPOCH)
                .select(&self.syn);
            self.request_epoch_hashes(io, chosen_peer, missing_epochs);
        }
    }

    /// Remove from inflight keys when a block is received.
    ///
    /// If a request is removed from `req_hashes`, it's the caller's
    /// responsibility to ensure that the removed request either has already
    /// received or will be requested by the caller again (the case for
    /// `Blocktxn`).
    pub fn blocks_received(
        &self, io: &dyn NetworkContext, req_hashes: HashSet<H256>,
        mut received_blocks: HashSet<H256>, ask_full_block: bool,
        peer: Option<PeerId>, with_public: bool,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());
        debug!(
            "blocks_received: req_hashes={:?} received_blocks={:?} peer={:?}",
            req_hashes, received_blocks, peer
        );
        let missing_blocks = {
            let mut inflight_keys = self.inflight_keys.write(msgid::GET_BLOCKS);
            let mut missing_blocks = Vec::new();
            for req_hash in &req_hashes {
                if !received_blocks.remove(req_hash) {
                    // If `req_hash` is not in `blocks_in_flight`, it may has
                    // been received or requested
                    // again by another thread, so we do not need to request it
                    // in that case
                    if inflight_keys.remove(&Key::Hash(*req_hash)) {
                        missing_blocks.push(*req_hash);
                    }
                } else {
                    inflight_keys.remove(&Key::Hash(*req_hash));
                }
            }
            for h in &received_blocks {
                inflight_keys.remove(&Key::Hash(*h));
            }
            missing_blocks
        };
        if !missing_blocks.is_empty() {
            // `peer` is passed in for the case that a compact block is received
            // and a full block is reconstructed, but the full block
            // is incorrect. We should ask the same peer for the
            // full block instead of choosing a random peer.
            let chosen_peer = peer.or_else(|| {
                let msg_id = if ask_full_block {
                    msgid::GET_BLOCKS
                } else {
                    msgid::GET_CMPCT_BLOCKS
                };

                PeerFilter::new(msg_id).select(&self.syn)
            });
            if ask_full_block {
                self.request_blocks(
                    io,
                    chosen_peer,
                    missing_blocks,
                    with_public,
                );
            } else {
                self.request_compact_blocks(io, chosen_peer, missing_blocks);
            }
        }
    }

    /// We do not need `io` in this function because we do not request missing
    /// transactions
    pub fn transactions_received(
        &self, received_transactions: &HashSet<TxPropagateId>,
        signed_transactions: Vec<Arc<SignedTransaction>>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TX_TIMER.as_ref());
        let mut inflight_keys =
            self.inflight_keys.write(msgid::GET_TRANSACTIONS);
        for tx in received_transactions {
            inflight_keys.remove(&Key::Id(*tx));
        }
        self.append_received_transactions(signed_transactions);
    }

    pub fn get_sent_transactions(
        &self, window_index: usize, indices: &Vec<usize>,
    ) -> Vec<TransactionWithSignature> {
        let sent_transactions = self.sent_transactions.read();
        let mut txs = Vec::with_capacity(indices.len());
        for index in indices {
            if let Some(tx) =
                sent_transactions.get_transaction(window_index, *index)
            {
                txs.push(tx.transaction.clone());
            }
        }
        txs
    }

    pub fn append_sent_transactions(
        &self, transactions: Vec<Arc<SignedTransaction>>,
    ) -> usize {
        self.sent_transactions
            .write()
            .append_transactions(transactions)
    }

    pub fn append_received_transactions(
        &self, transactions: Vec<Arc<SignedTransaction>>,
    ) {
        self.received_transactions
            .write()
            .append_transactions(transactions)
    }

    pub fn resend_timeout_requests(&self, io: &dyn NetworkContext) {
        debug!("resend_timeout_requests: start");
        let timeout_requests = self.request_handler.get_timeout_requests(io);
        for req in timeout_requests {
            debug!("Timeout requests: {:?}", req);
            self.remove_mismatch_request(io, &req);
        }
    }

    /// Send waiting requests that their backoff delay have passes
    pub fn resend_waiting_requests(&self, io: &dyn NetworkContext) {
        debug!("resend_waiting_requests: start");
        let mut waiting_requests = self.waiting_requests.lock();
        let now = Instant::now();

        while let Some(req) = waiting_requests.pop() {
            if req.time_to_send >= now {
                waiting_requests.push(req);
                break;
            }

            let maybe_peer = req.peer.or_else(|| {
                let msg_id = req.request.0.msg_id();
                let mut filter = PeerFilter::new(msg_id);
                if let Some(cap) = req.request.0.required_capability() {
                    filter = filter.with_cap(cap);
                }
                filter.select(&self.syn)
            });
            let chosen_peer = match maybe_peer {
                Some(p) => p,
                None => {
                    debug!("No peer to send request, wait for next time");
                    waiting_requests.push(req);
                    break;
                }
            };
            debug!("Send waiting req {:?} to peer={}", req, chosen_peer);

            // Waiting requests are already in-flight, so send them without
            // checking
            let WaitingRequest(request, delay) = req.request;
            let request = match request.resend() {
                Some(r) => r,
                None => continue,
            };
            let next_delay = delay + *REQUEST_START_WAITING_TIME;

            if let Err(req) = self.request_handler.send_request(
                io,
                Some(chosen_peer),
                request,
                Some(next_delay),
            ) {
                waiting_requests.push(TimedWaitingRequest::new(
                    Instant::now() + delay,
                    WaitingRequest(req, next_delay),
                    None,
                ));
            }
        }
    }

    pub fn on_peer_connected(&self, peer: PeerId) {
        self.request_handler.add_peer(peer);
    }

    pub fn on_peer_disconnected(&self, io: &dyn NetworkContext, peer: PeerId) {
        if let Some(mut unfinished_requests) =
            self.request_handler.remove_peer(peer)
        {
            {
                for msg in &unfinished_requests {
                    msg.request.on_removed(&self.inflight_keys);
                }
            }
            for msg in unfinished_requests.iter_mut() {
                msg.delay = None;
                self.send_request_again(io, &msg);
            }
        } else {
            debug!("Peer already removed form request manager when disconnected peer={}", peer);
        }
    }
}

#[derive(Debug)]
struct TimedWaitingRequest {
    time_to_send: Instant,
    request: WaitingRequest,
    peer: Option<PeerId>,
}

impl TimedWaitingRequest {
    fn new(
        time_to_send: Instant, request: WaitingRequest, peer: Option<PeerId>,
    ) -> Self {
        Self {
            time_to_send,
            request,
            peer,
        }
    }
}

impl Ord for TimedWaitingRequest {
    fn cmp(&self, other: &Self) -> Ordering {
        other.time_to_send.cmp(&self.time_to_send)
    }
}
impl PartialOrd for TimedWaitingRequest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.time_to_send.partial_cmp(&self.time_to_send)
    }
}
impl Eq for TimedWaitingRequest {}
impl PartialEq for TimedWaitingRequest {
    fn eq(&self, other: &Self) -> bool {
        self.time_to_send == other.time_to_send
    }
}
