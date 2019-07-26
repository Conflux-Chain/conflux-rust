use super::{
    synchronization_protocol_handler::{
        ProtocolConfiguration, REQUEST_START_WAITING_TIME,
    },
    synchronization_state::SynchronizationState,
};
use crate::sync::{
    message::{
        GetBlockHashesByEpoch, GetBlockHeaderChain, GetBlockHeaders,
        GetBlockTxn, GetBlocks, GetCompactBlocks, GetTransactions, Key,
        KeyContainer, MsgId, TransIndex,
    },
    Error,
};
use cfx_types::H256;
use metrics::{register_meter_with_group, Meter, MeterTimer};
use network::{NetworkContext, PeerId};
use parking_lot::{Mutex, RwLock};
use primitives::{SignedTransaction, TransactionWithSignature, TxPropagateId};
use priority_send_queue::SendQueuePriority;
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
    static ref TX_REQUEST_METER: Arc<Meter> =
        register_meter_with_group("system_metrics", "tx_diff_set_size");
    static ref REQUEST_MANAGER_TIMER: Arc<Meter> =
        register_meter_with_group("timer", "request_manager::request_not_tx");
    static ref REQUEST_MANAGER_TX_TIMER: Arc<Meter> =
        register_meter_with_group("timer", "request_manager::request_tx");
    static ref TX_RECEIVED_POOL_METER: Arc<Meter> =
        register_meter_with_group("system_metrics", "tx_received_pool_size");
    static ref INFLIGHT_TX_POOL_METER: Arc<Meter> =
        register_meter_with_group("system_metrics", "inflight_tx_pool_size");
}

#[derive(Debug)]
struct WaitingRequest(Box<Request>, Duration); // (request, delay)

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
    inflight_keys: Mutex<KeyContainer>,

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
            .lock()
            .len(MsgId::GET_BLOCK_HASHES_BY_EPOCH.into()) as u64
    }

    /// Send request to remote peer with delay mechanism. If failed,
    /// add the request to waiting queue to resend later.
    pub fn request_with_delay(
        &self, io: &NetworkContext, mut request: Box<Request>,
        peer: Option<PeerId>, delay: Option<Duration>,
    )
    {
        {
            // retain the request items that not in flight.
            let mut inflight_keys = self.inflight_keys.lock();
            request.with_inflight(&mut inflight_keys);
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
            self.waiting_requests.lock().push(TimedWaitingRequest::new(
                Instant::now() + cur_delay,
                WaitingRequest(request, next_delay),
                peer,
            ));

            return;
        }

        if request.is_empty() {
            return;
        }

        if let Err(e) = self.request_handler.send_general_request(
            io,
            peer,
            request,
            Some(next_delay),
        ) {
            self.waiting_requests.lock().push(TimedWaitingRequest::new(
                Instant::now() + cur_delay,
                WaitingRequest(e, next_delay),
                None,
            ));
        }
    }

    pub fn request_block_headers(
        &self, io: &NetworkContext, peer_id: Option<PeerId>, hashes: Vec<H256>,
    ) {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        let request = GetBlockHeaders {
            request_id: 0.into(),
            hashes,
        };

        self.request_with_delay(io, Box::new(request), peer_id, None);
    }

    /// Request a header if it's not already in_flight. The request is delayed
    /// if the header is requested before.
    pub fn request_block_header_chain(
        &self, io: &NetworkContext, peer_id: Option<PeerId>, hash: &H256,
        max_blocks: u64,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        let request = GetBlockHeaderChain {
            request_id: 0.into(),
            hash: *hash,
            max_blocks,
        };

        self.request_with_delay(io, Box::new(request), peer_id, None);
    }

    pub fn request_epoch_hashes(
        &self, io: &NetworkContext, peer_id: Option<PeerId>, epochs: Vec<u64>,
    ) {
        let request = GetBlockHashesByEpoch {
            request_id: 0.into(),
            epochs,
        };

        self.request_with_delay(io, Box::new(request), peer_id, None);
    }

    pub fn request_blocks(
        &self, io: &NetworkContext, peer_id: Option<PeerId>, hashes: Vec<H256>,
        with_public: bool,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        let request = GetBlocks {
            request_id: 0.into(),
            with_public,
            hashes,
        };

        self.request_with_delay(io, Box::new(request), peer_id, None);
    }

    pub fn request_transactions(
        &self, io: &NetworkContext, peer_id: PeerId, window_index: usize,
        received_tx_ids: &Vec<TxPropagateId>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TX_TIMER.as_ref());
        if received_tx_ids.is_empty() {
            return;
        }
        let mut inflight_keys = self.inflight_keys.lock();
        let received_transactions = self.received_transactions.read();

        let msg_type = MsgId::GET_TRANSACTIONS.into();
        INFLIGHT_TX_POOL_METER.mark(inflight_keys.len(msg_type));
        TX_RECEIVED_POOL_METER.mark(received_transactions.get_length());

        let (indices, tx_ids) = {
            let mut tx_ids = HashSet::new();
            let mut indices = Vec::new();

            for (idx, tx_id) in received_tx_ids.iter().enumerate() {
                if received_transactions.contains_txid(tx_id) {
                    // Already received
                    continue;
                }

                if !inflight_keys.add(msg_type, Key::Id(*tx_id)) {
                    // Already being requested
                    continue;
                }

                let index = TransIndex::new((window_index, idx));
                indices.push(index);
                tx_ids.insert(*tx_id);
            }

            (indices, tx_ids)
        };
        TX_REQUEST_METER.mark(tx_ids.len());
        debug!("Request {} tx from peer={}", tx_ids.len(), peer_id);

        let request = GetTransactions {
            request_id: 0.into(),
            indices,
            tx_ids: tx_ids.clone(),
        };

        if let Err(e) = self.request_handler.send_request(
            io,
            peer_id,
            RequestMessage::new(Box::new(request), None),
            SendQueuePriority::Normal,
        ) {
            warn!(
                "Error requesting transactions peer={:?} count={} err={:?}",
                peer_id,
                tx_ids.len(),
                e
            );
            for tx_id in tx_ids {
                inflight_keys.remove(msg_type, Key::Id(tx_id));
            }
        }
    }

    pub fn request_compact_blocks(
        &self, io: &NetworkContext, peer_id: Option<PeerId>, hashes: Vec<H256>,
    ) {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        let request = GetCompactBlocks {
            request_id: 0.into(),
            hashes,
        };

        self.request_with_delay(io, Box::new(request), peer_id, None);
    }

    pub fn request_blocktxn(
        &self, io: &NetworkContext, peer_id: PeerId, block_hash: H256,
        indexes: Vec<usize>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        let request = GetBlockTxn {
            request_id: 0.into(),
            block_hash: block_hash.clone(),
            indexes,
        };

        if let Err(e) = self.request_handler.send_request(
            io,
            peer_id,
            RequestMessage::new(Box::new(request), None),
            SendQueuePriority::High,
        ) {
            warn!(
                "Error requesting blocktxn peer={:?} hash={} err={:?}",
                peer_id, block_hash, e
            );
        } else {
            debug!(
                "Requesting blocktxn peer={:?} hash={}",
                peer_id, block_hash
            );
        }
    }

    pub fn send_request_again(
        &self, io: &NetworkContext, msg: &RequestMessage,
    ) {
        let chosen_peer = self.syn.get_random_peer(&HashSet::new());
        if let Some(request) = msg.request.resend() {
            self.request_with_delay(io, request, chosen_peer, msg.delay);
        }
    }

    pub fn remove_mismatch_request(
        &self, io: &NetworkContext, req: &RequestMessage,
    ) {
        {
            let mut inflight_keys = self.inflight_keys.lock();
            req.request.on_removed(&mut inflight_keys);
        }

        self.send_request_again(io, req);
    }

    // Match request with given response.
    // No need to let caller handle request resending.
    pub fn match_request(
        &self, io: &NetworkContext, peer_id: PeerId, request_id: u64,
    ) -> Result<RequestMessage, Error> {
        self.request_handler.match_request(io, peer_id, request_id)
    }

    /// Remove inflight keys when a header is received.
    ///
    /// If a request is removed from `req_hashes`, it's the caller's
    /// responsibility to ensure that the removed request either has already
    /// received or will be requested by the caller again.
    pub fn headers_received(
        &self, io: &NetworkContext, req_hashes: HashSet<H256>,
        mut received_headers: HashSet<H256>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());
        debug!(
            "headers_received: req_hashes={:?} received_headers={:?}",
            req_hashes, received_headers
        );
        let missing_headers = {
            let mut inflight_keys = self.inflight_keys.lock();
            let msg_type = MsgId::GET_BLOCK_HEADERS.into();
            let mut missing_headers = Vec::new();
            for req_hash in &req_hashes {
                if !received_headers.remove(req_hash) {
                    // If `req_hash` is not in `headers_in_flight`, it may has
                    // been received or requested
                    // again by another thread, so we do not need to request it
                    // in that case
                    if inflight_keys.remove(msg_type, Key::Hash(*req_hash)) {
                        missing_headers.push(*req_hash);
                    }
                } else {
                    inflight_keys.remove(msg_type, Key::Hash(*req_hash));
                }
            }
            for h in &received_headers {
                inflight_keys.remove(msg_type, Key::Hash(*h));
            }
            missing_headers
        };
        if !missing_headers.is_empty() {
            let chosen_peer = self.syn.get_random_peer(&HashSet::new());
            self.request_block_headers(io, chosen_peer, missing_headers);
        }
    }

    /// Remove from inflight keys when a epoch is received.
    pub fn epochs_received(
        &self, io: &NetworkContext, req_epochs: HashSet<u64>,
        mut received_epochs: HashSet<u64>,
    )
    {
        debug!(
            "epochs_received: req_epochs={:?} received_epochs={:?}",
            req_epochs, received_epochs
        );
        let missing_epochs = {
            let mut inflight_keys = self.inflight_keys.lock();
            let msg_type = MsgId::GET_BLOCK_HASHES_BY_EPOCH.into();
            let mut missing_epochs = Vec::new();
            for epoch_number in &req_epochs {
                if !received_epochs.remove(epoch_number) {
                    // If `epoch_number` is not in `epochs_in_flight`, it may
                    // has been received or requested
                    // again by another thread, so we do not need to request it
                    // in that case
                    if inflight_keys.remove(msg_type, Key::Num(*epoch_number)) {
                        missing_epochs.push(*epoch_number);
                    }
                } else {
                    inflight_keys.remove(msg_type, Key::Num(*epoch_number));
                }
            }
            for epoch_number in &received_epochs {
                inflight_keys.remove(msg_type, Key::Num(*epoch_number));
            }
            missing_epochs
        };
        if !missing_epochs.is_empty() {
            let chosen_peer = self.syn.get_random_peer(&HashSet::new());
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
        &self, io: &NetworkContext, req_hashes: HashSet<H256>,
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
            let mut inflight_keys = self.inflight_keys.lock();
            let msg_type = MsgId::GET_BLOCKS.into();
            let mut missing_blocks = Vec::new();
            for req_hash in &req_hashes {
                if !received_blocks.remove(req_hash) {
                    // If `req_hash` is not in `blocks_in_flight`, it may has
                    // been received or requested
                    // again by another thread, so we do not need to request it
                    // in that case
                    if inflight_keys.remove(msg_type, Key::Hash(*req_hash)) {
                        missing_blocks.push(*req_hash);
                    }
                } else {
                    inflight_keys.remove(msg_type, Key::Hash(*req_hash));
                }
            }
            for h in &received_blocks {
                inflight_keys.remove(msg_type, Key::Hash(*h));
            }
            missing_blocks
        };
        if !missing_blocks.is_empty() {
            // `peer` is passed in for the case that a compact block is received
            // and a full block is reconstructed, but the full block
            // is incorrect. We should ask the same peer for the
            // full block instead of choosing a random peer.
            let chosen_peer =
                peer.or_else(|| self.syn.get_random_peer(&HashSet::new()));
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
    ) {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TX_TIMER.as_ref());
        let mut inflight_keys = self.inflight_keys.lock();
        let msg_type = MsgId::GET_TRANSACTIONS.into();
        for tx in received_transactions {
            inflight_keys.remove(msg_type, Key::Id(*tx));
        }
    }

    pub fn get_sent_transactions(
        &self, indices: &Vec<TransIndex>,
    ) -> Vec<TransactionWithSignature> {
        let sent_transactions = self.sent_transactions.read();
        let mut txs = Vec::with_capacity(indices.len());
        for index in indices {
            if let Some(tx) = sent_transactions.get_transaction(index) {
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

    pub fn resend_timeout_requests(&self, io: &NetworkContext) {
        debug!("resend_timeout_requests: start");
        let timeout_requests = self.request_handler.get_timeout_requests(io);
        for req in timeout_requests {
            debug!("Timeout requests: {:?}", req);
            self.remove_mismatch_request(io, &req);
        }
    }

    /// Send waiting requests that their backoff delay have passes
    pub fn resend_waiting_requests(&self, io: &NetworkContext) {
        debug!("resend_waiting_requests: start");
        let mut waiting_requests = self.waiting_requests.lock();
        let now = Instant::now();

        while let Some(req) = waiting_requests.pop() {
            if req.time_to_send >= now {
                waiting_requests.push(req);
                break;
            }

            let maybe_peer = req
                .peer
                .or_else(|| self.syn.get_random_peer(&HashSet::new()));
            let chosen_peer = match maybe_peer {
                Some(p) => p,
                None => {
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

            if let Err(req) = self.request_handler.send_general_request(
                io,
                Some(chosen_peer),
                request,
                Some(next_delay),
            ) {
                self.waiting_requests.lock().push(TimedWaitingRequest::new(
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

    pub fn on_peer_disconnected(&self, io: &NetworkContext, peer: PeerId) {
        if let Some(mut unfinished_requests) =
            self.request_handler.remove_peer(peer)
        {
            {
                let mut inflight_keys = self.inflight_keys.lock();
                for msg in &unfinished_requests {
                    msg.request.on_removed(&mut inflight_keys);
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
