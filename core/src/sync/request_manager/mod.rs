// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    synchronization_protocol_handler::ProtocolConfiguration,
    synchronization_state::SynchronizationState,
};
use crate::{
    alliance_tree_graph::hsb_sync_protocol::sync_protocol::RpcResponse,
    parameters::sync::REQUEST_START_WAITING_TIME,
    sync::{
        message::{
            msgid, GetBlockHashesByEpoch, GetBlockHeaders, GetBlockTxn,
            GetBlocks, GetCompactBlocks, GetTransactions,
            GetTransactionsFromTxHashes, Key, KeyContainer, TransactionDigests,
        },
        request_manager::request_batcher::RequestBatcher,
        synchronization_state::PeerFilter,
        Error,
    },
};
use cfx_types::H256;
use futures::{channel::oneshot, future::Future};
use metrics::{
    register_meter_with_group, Gauge, GaugeUsize, Meter, MeterTimer,
};
use network::{NetworkContext, PeerId};
use parking_lot::{Mutex, RwLock};
use primitives::{SignedTransaction, TransactionWithSignature};
pub use request_handler::{
    AsAny, Request, RequestHandler, RequestMessage, SynchronizationPeerRequest,
};
use std::{
    cmp::Ordering,
    collections::{binary_heap::BinaryHeap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tx_handler::{
    InflightPendingTransactionContainer, InflightPendingTrasnactionItem,
    ReceivedTransactionContainer, SentTransactionContainer,
};

mod request_batcher;
mod request_handler;
pub mod tx_handler;

lazy_static! {
    static ref TX_REQUEST_METER: Arc<dyn Meter> =
        register_meter_with_group("system_metrics", "tx_diff_set_size");
    static ref TX_REQUEST_TX_HASHES_METER: Arc<dyn Meter> =
        register_meter_with_group(
            "system_metrics",
            "tx_request_tx_hashes_size"
        );
    static ref REQUEST_MANAGER_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "request_manager::request_not_tx");
    static ref REQUEST_MANAGER_TX_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "request_manager::request_tx");
    static ref TX_RECEIVED_POOL_METER: Arc<dyn Meter> =
        register_meter_with_group("system_metrics", "tx_received_pool_size");
    static ref INFLIGHT_TX_POOL_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group(
            "system_metrics",
            "inflight_tx_pool_size"
        );
    static ref TX_HASHES_INFLIGHT_TX_POOL_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group(
            "system_metrics",
            "tx_hashes_inflight_tx_pool_size"
        );
    static ref INFLIGHT_TX_PENDING_POOL_METER: Arc<dyn Meter> =
        register_meter_with_group(
            "system_metrics",
            "inflight_tx_pending_pool_size"
        );
    static ref INFLIGHT_TX_REJECT_METER: Arc<dyn Meter> =
        register_meter_with_group("system_metrics", "inflight_tx_reject_size");
    static ref REQUEST_TX_FROM_INFLIGHT_PENDING_POOL_METER: Arc<dyn Meter> =
        register_meter_with_group(
            "system_metrics",
            "request_tx_from_inflight_pending_pool"
        );

    /// Delay is increased by 1 second each time, so it costs at least 90*91/2 = 4095s to reach
    /// this upper bound. And requests will be discarded after reaching this upper bound.
    static ref DEFAULT_REQUEST_DELAY_UPPER_BOUND: Duration =
        Duration::from_secs(90);
    static ref DEFAULT_REQUEST_BATCH_BUCKET_SIZE: Duration =
        Duration::from_secs(2);
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
    // used to avoid send duplicated requests.
    pub inflight_pending_transactions:
        Arc<RwLock<InflightPendingTransactionContainer>>,

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
        let inflight_pending_tx_index_maintain_timeout =
            protocol_config.inflight_pending_tx_index_maintain_timeout;

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
            inflight_pending_transactions: Arc::new(RwLock::new(
                InflightPendingTransactionContainer::new(
                    inflight_pending_tx_index_maintain_timeout.as_secs(),
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

    /// Send a unary rpc request to remote peer `recipient`.
    pub async fn unary_rpc<'a>(
        &'a self, io: &'a dyn NetworkContext, recipient: Option<PeerId>,
        mut request: Box<dyn Request>,
    ) -> impl Future<Output = Result<Box<dyn RpcResponse>, Error>> + 'a
    {
        async move {
            // ask network to fulfill rpc request
            let (res_tx, res_rx) = oneshot::channel();
            request.set_response_notification(res_tx);

            self.request_with_delay(io, request, recipient, None);

            // wait for response
            let response = res_rx.await??;
            Ok(response)
        }
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
            request.notify_empty();
            return;
        }

        // increase delay for resent request.
        let (cur_delay, next_delay) = match delay {
            Some(d) => (d, d + *REQUEST_START_WAITING_TIME),
            None => (*REQUEST_START_WAITING_TIME, *REQUEST_START_WAITING_TIME),
        };

        // delay if no peer available or delay required
        if peer.is_none() || delay.is_some() {
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
        hashes: Vec<H256>, delay: Option<Duration>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        debug!("request_block_headers: {:?}, peer {:?}", hashes, &peer_id);

        let request = GetBlockHeaders {
            request_id: 0,
            hashes,
        };

        self.request_with_delay(io, Box::new(request), peer_id, delay);
    }

    pub fn request_epoch_hashes(
        &self, io: &dyn NetworkContext, peer_id: Option<PeerId>,
        epochs: Vec<u64>, delay: Option<Duration>,
    )
    {
        let request = GetBlockHashesByEpoch {
            request_id: 0,
            epochs,
        };

        self.request_with_delay(io, Box::new(request), peer_id, delay);
    }

    pub fn request_blocks(
        &self, io: &dyn NetworkContext, peer_id: Option<PeerId>,
        hashes: Vec<H256>, with_public: bool, delay: Option<Duration>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());
        debug!("request_blocks: hashes={:?}", hashes);

        let request = GetBlocks {
            request_id: 0,
            with_public,
            hashes,
        };

        self.request_with_delay(io, Box::new(request), peer_id, delay);
    }

    pub fn request_transactions_from_digest(
        &self, io: &dyn NetworkContext, peer_id: PeerId,
        transaction_digests: &TransactionDigests,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TX_TIMER.as_ref());

        let window_index: usize = transaction_digests.window_index;
        let key1 = transaction_digests.key1;
        let key2 = transaction_digests.key2;
        let (random_byte_vector, fixed_bytes_vector) =
            transaction_digests.get_decomposed_short_ids();

        if fixed_bytes_vector.is_empty()
            && transaction_digests.tx_hashes.is_empty()
        {
            return;
        }

        let mut tx_from_short_id_inflight_keys =
            self.inflight_keys.write(msgid::GET_TRANSACTIONS);
        let mut tx_from_hashes_inflight_keys = self
            .inflight_keys
            .write(msgid::GET_TRANSACTIONS_FROM_TX_HASHES);
        let received_transactions = self.received_transactions.read();

        INFLIGHT_TX_POOL_GAUGE.update(tx_from_short_id_inflight_keys.len());
        TX_HASHES_INFLIGHT_TX_POOL_GAUGE
            .update(tx_from_hashes_inflight_keys.len());
        TX_RECEIVED_POOL_METER.mark(received_transactions.get_length());

        let (
            short_ids,
            tx_hashes,
            tx_request_indices,
            hashes_request_indices,
            inflight_pending_items,
        ) = {
            let mut short_ids = HashSet::new();
            let mut tx_hashes = HashSet::new();
            let mut tx_request_indices = Vec::new();
            let mut hashes_request_indices = Vec::new();
            let mut inflight_pending_items: Vec<
                InflightPendingTrasnactionItem,
            > = Vec::new();

            //process short ids
            for i in 0..fixed_bytes_vector.len() {
                let fixed_bytes = fixed_bytes_vector[i];
                let random_bytes = random_byte_vector[i];

                if received_transactions.contains_short_id(
                    fixed_bytes,
                    random_bytes,
                    key1,
                    key2,
                ) {
                    if received_transactions.group_overflow(&fixed_bytes) {
                        hashes_request_indices.push(i);
                    }
                    // Already received or need to request long id
                    continue;
                }

                if tx_from_short_id_inflight_keys.insert(Key::Id(fixed_bytes)) {
                    tx_request_indices.push(i);
                    short_ids.insert(fixed_bytes);
                } else {
                    // Already being requested, put in inflight pending queue
                    inflight_pending_items.push(
                        InflightPendingTrasnactionItem::new(
                            fixed_bytes,
                            random_bytes,
                            window_index,
                            key1,
                            key2,
                            i,
                            peer_id,
                        ),
                    );
                    INFLIGHT_TX_PENDING_POOL_METER.mark(1);
                }
            }

            //process tx hashes
            let base_index = fixed_bytes_vector.len();
            for i in 0..transaction_digests.tx_hashes.len() {
                let tx_hash = transaction_digests.tx_hashes[i];
                if received_transactions.contains_tx_hash(&tx_hash) {
                    continue;
                }
                if tx_from_hashes_inflight_keys.insert(Key::Hash(tx_hash)) {
                    tx_request_indices.push(base_index + i);
                    tx_hashes.insert(tx_hash);
                } else {
                    // Already being requested
                    INFLIGHT_TX_REJECT_METER.mark(1);
                }
            }

            (
                short_ids,
                tx_hashes,
                tx_request_indices,
                hashes_request_indices,
                inflight_pending_items,
            )
        };
        TX_REQUEST_METER.mark(tx_request_indices.len());
        TX_REQUEST_TX_HASHES_METER.mark(hashes_request_indices.len());
        debug!(
            "Request {} tx and {} tx hashes from peer={}",
            tx_request_indices.len(),
            hashes_request_indices.len(),
            peer_id
        );

        let request = GetTransactions {
            request_id: 0,
            window_index,
            indices: tx_request_indices,
            tx_hashes_indices: hashes_request_indices,
            short_ids: short_ids.clone(),
            tx_hashes: tx_hashes.clone(),
        };

        if request.is_empty() {
            return;
        }

        if self
            .request_handler
            .send_request(io, Some(peer_id), Box::new(request), None)
            .is_err()
        {
            for id in short_ids {
                tx_from_short_id_inflight_keys.remove(&Key::Id(id));
            }
            for id in tx_hashes {
                tx_from_hashes_inflight_keys.remove(&Key::Hash(id));
            }
            return;
        }

        self.inflight_pending_transactions
            .write()
            .append_inflight_pending_items(inflight_pending_items);
    }

    pub fn request_transactions_from_tx_hashes(
        &self, io: &dyn NetworkContext, peer_id: PeerId,
        responded_tx_hashes: Vec<H256>, window_index: usize,
        tx_hashes_indices: &Vec<usize>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TX_TIMER.as_ref());

        if responded_tx_hashes.is_empty() {
            return;
        }

        let mut tx_from_hashes_inflight_keys = self
            .inflight_keys
            .write(msgid::GET_TRANSACTIONS_FROM_TX_HASHES);
        let received_transactions = self.received_transactions.read();

        TX_HASHES_INFLIGHT_TX_POOL_GAUGE
            .update(tx_from_hashes_inflight_keys.len());
        TX_RECEIVED_POOL_METER.mark(received_transactions.get_length());

        let (tx_hashes, indices) = {
            let mut tx_hashes = HashSet::new();
            let mut indices = Vec::new();

            for i in 0..responded_tx_hashes.len() {
                let tx_hash = responded_tx_hashes[i];
                if received_transactions.contains_tx_hash(&tx_hash) {
                    // Already received
                    continue;
                }

                if tx_from_hashes_inflight_keys.insert(Key::Hash(tx_hash)) {
                    indices.push(tx_hashes_indices[i]);
                    tx_hashes.insert(tx_hash);
                } else {
                    // Already being requested
                    INFLIGHT_TX_REJECT_METER.mark(1);
                }
            }

            (tx_hashes, indices)
        };
        TX_REQUEST_METER.mark(tx_hashes.len());
        debug!(
            "Request {} tx using tx hashes from peer={}",
            indices.len(),
            peer_id
        );

        let request = GetTransactionsFromTxHashes {
            request_id: 0,
            window_index,
            indices,
            tx_hashes: tx_hashes.clone(),
        };

        if request.is_empty() {
            return;
        }

        if self
            .request_handler
            .send_request(io, Some(peer_id), Box::new(request), None)
            .is_err()
        {
            for id in tx_hashes {
                tx_from_hashes_inflight_keys.remove(&Key::Hash(id));
            }
        }
    }

    pub fn request_compact_blocks(
        &self, io: &dyn NetworkContext, peer_id: Option<PeerId>,
        hashes: Vec<H256>, delay: Option<Duration>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());
        debug!("request_compact_blocks: hashes={:?}", hashes);

        let request = GetCompactBlocks {
            request_id: 0,
            hashes,
        };

        self.request_with_delay(io, Box::new(request), peer_id, delay);
    }

    pub fn request_blocktxn(
        &self, io: &dyn NetworkContext, peer_id: PeerId, block_hash: H256,
        indexes: Vec<usize>, delay: Option<Duration>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        let request = GetBlockTxn {
            request_id: 0,
            block_hash: block_hash.clone(),
            indexes,
        };

        self.request_with_delay(io, Box::new(request), Some(peer_id), delay);
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
        mut received_headers: HashSet<H256>, delay: Option<Duration>,
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
            self.request_block_headers(io, chosen_peer, missing_headers, delay);
        }
    }

    /// Remove from inflight keys when a epoch is received.
    pub fn epochs_received(
        &self, io: &dyn NetworkContext, req_epochs: HashSet<u64>,
        mut received_epochs: HashSet<u64>, delay: Option<Duration>,
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
            self.request_epoch_hashes(io, chosen_peer, missing_epochs, delay);
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
        peer: Option<PeerId>, with_public: bool, delay: Option<Duration>,
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
                    delay,
                );
            } else {
                self.request_compact_blocks(
                    io,
                    chosen_peer,
                    missing_blocks,
                    delay,
                );
            }
        }
    }

    pub fn transactions_received_from_digests(
        &self, io: &dyn NetworkContext,
        get_transactions_request: &GetTransactions,
        signed_transactions: Vec<Arc<SignedTransaction>>,
    )
    {
        let mut short_id_inflight_keys =
            self.inflight_keys.write(msgid::GET_TRANSACTIONS);
        let mut tx_hash_inflight_keys = self
            .inflight_keys
            .write(msgid::GET_TRANSACTIONS_FROM_TX_HASHES);

        let (requests, keeped_short_ids) = self
            .inflight_pending_transactions
            .write()
            .generate_tx_requests_from_inflight_pending_pool(
                &signed_transactions,
            );

        self.append_received_transactions(signed_transactions);
        for tx in &get_transactions_request.short_ids {
            if !keeped_short_ids.contains(tx) {
                short_id_inflight_keys.remove(&Key::Id(*tx));
            }
        }
        for tx in &get_transactions_request.tx_hashes {
            tx_hash_inflight_keys.remove(&Key::Hash(*tx));
        }

        //request transactions from inflight pending pool
        if requests.is_empty() {
            return;
        }
        REQUEST_TX_FROM_INFLIGHT_PENDING_POOL_METER.mark(requests.len());
        for request in requests {
            let tx_request = GetTransactions {
                request_id: 0,
                window_index: request.peer_id,
                indices: vec![request.index],
                tx_hashes_indices: vec![],
                short_ids: {
                    let mut set = HashSet::new();
                    set.insert(request.fixed_byte_part);
                    set
                },
                tx_hashes: HashSet::new(),
            };
            if self
                .request_handler
                .send_request(
                    io,
                    Some(request.peer_id),
                    Box::new(tx_request),
                    None,
                )
                .is_err()
            {
                short_id_inflight_keys
                    .remove(&Key::Id(request.fixed_byte_part));
            }
        }
    }

    pub fn transactions_received_from_tx_hashes(
        &self, get_transactions_request: &GetTransactionsFromTxHashes,
        signed_transactions: Vec<Arc<SignedTransaction>>,
    )
    {
        let mut tx_hash_inflight_keys = self
            .inflight_keys
            .write(msgid::GET_TRANSACTIONS_FROM_TX_HASHES);
        for tx in &get_transactions_request.tx_hashes {
            tx_hash_inflight_keys.remove(&Key::Hash(*tx));
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
        let mut batcher =
            RequestBatcher::new(*DEFAULT_REQUEST_BATCH_BUCKET_SIZE);

        while let Some(req) = waiting_requests.pop() {
            if req.time_to_send >= now {
                waiting_requests.push(req);
                break;
            } else if req.request.1 > *DEFAULT_REQUEST_DELAY_UPPER_BOUND {
                // Discard stale requests
                warn!("Request is in-flight for over an hour: {:?}", req);
                req.request.0.on_removed(&self.inflight_keys);
                continue;
            }

            // Waiting requests are already in-flight, so send them without
            // checking
            let WaitingRequest(request, delay) = req.request;
            let request = match request.resend() {
                Some(r) => r,
                None => continue,
            };
            batcher.insert(delay, request);
        }

        for (next_delay, request) in batcher.get_batched_requests() {
            let mut filter = PeerFilter::new(request.msg_id());
            if let Some(cap) = request.required_capability() {
                filter = filter.with_cap(cap);
            }
            let chosen_peer = match filter.select(&self.syn) {
                Some(p) => p,
                None => {
                    debug!("No peer to send request, wait for next time");
                    waiting_requests.push(TimedWaitingRequest::new(
                        Instant::now() + next_delay,
                        WaitingRequest(request, next_delay),
                        None,
                    ));
                    continue;
                }
            };
            debug!(
                "Send waiting req {:?} to peer={} with next_delay={:?}",
                request, chosen_peer, next_delay
            );

            if let Err(request) = self.request_handler.send_request(
                io,
                Some(chosen_peer),
                request,
                Some(next_delay),
            ) {
                waiting_requests.push(TimedWaitingRequest::new(
                    Instant::now() + next_delay,
                    WaitingRequest(request, next_delay),
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
