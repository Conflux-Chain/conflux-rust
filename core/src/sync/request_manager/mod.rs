// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    synchronization_protocol_handler::ProtocolConfiguration,
    synchronization_state::SynchronizationState,
};
use crate::{
    parameters::sync::REQUEST_START_WAITING_TIME,
    sync::{
        message::{
            msgid, GetBlockHashesByEpoch, GetBlockHeaders, GetBlockTxn,
            GetBlocks, GetCompactBlocks, GetTransactions,
            GetTransactionsFromTxHashes, Key, KeyContainer, TransactionDigests,
        },
        node_type::NodeType,
        request_manager::request_batcher::RequestBatcher,
        synchronization_protocol_handler::{AsyncTaskQueue, RecoverPublicTask},
        synchronization_state::PeerFilter,
        Error,
    },
};
use cfx_types::H256;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use metrics::{
    register_meter_with_group, Gauge, GaugeUsize, Meter, MeterTimer,
};
use network::{node_table::NodeId, NetworkContext};
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

impl MallocSizeOf for WaitingRequest {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.0.size_of(ops) + self.1.size_of(ops)
    }
}

/// When a header or block is requested by the `RequestManager`, it is ensured
/// that if it's not fully received, its hash exists
/// in `in_flight` after every function call.
///
/// The thread who removes a hash from `in_flight` is responsible to request it
/// again if it's not received.
///
/// No lock is held when we call another function in this struct, and all locks
/// are acquired in the same order, so there should exist no deadlocks.
#[derive(DeriveMallocSizeOf)]
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

    #[ignore_malloc_size_of = "channels are not handled in MallocSizeOf"]
    recover_public_queue: Arc<AsyncTaskQueue<RecoverPublicTask>>,
}

impl RequestManager {
    pub fn new(
        protocol_config: &ProtocolConfiguration,
        syn: Arc<SynchronizationState>,
        recover_public_queue: Arc<AsyncTaskQueue<RecoverPublicTask>>,
    ) -> Self
    {
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
            recover_public_queue,
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
        mut peer: Option<NodeId>, delay: Option<Duration>,
    )
    {
        // retain the request items that not in flight.
        request.with_inflight(&self.inflight_keys);

        if request.is_empty() {
            request.notify_empty();
            return;
        }
        // Check block-related requests, and put them into waiting_requests
        // if we cannot process it.
        if peer.is_some()
            && delay.is_none()
            && !self.check_and_update_net_inflight_blocks(&request)
        {
            peer = None;
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
        &self, io: &dyn NetworkContext, peer_id: Option<NodeId>,
        hashes: Vec<H256>, delay: Option<Duration>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        debug!("request_block_headers: {:?}, peer {:?}", hashes, peer_id);

        let request = GetBlockHeaders {
            request_id: 0,
            hashes,
        };

        self.request_with_delay(io, Box::new(request), peer_id, delay);
    }

    pub fn request_epoch_hashes(
        &self, io: &dyn NetworkContext, peer_id: Option<NodeId>,
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
        &self, io: &dyn NetworkContext, peer_id: Option<NodeId>,
        hashes: Vec<H256>, with_public: bool, delay: Option<Duration>,
        preferred_node_type: Option<NodeType>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());
        debug!("request_blocks: hashes={:?}", hashes);

        let request = GetBlocks {
            request_id: 0,
            with_public,
            hashes,
            preferred_node_type,
        };

        self.request_with_delay(io, Box::new(request), peer_id, delay);
    }

    pub fn request_transactions_from_digest(
        &self, io: &dyn NetworkContext, peer_id: NodeId,
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
                            peer_id.clone(),
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
            peer_id.clone()
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
        &self, io: &dyn NetworkContext, peer_id: NodeId,
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
        &self, io: &dyn NetworkContext, peer_id: Option<NodeId>,
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
        &self, io: &dyn NetworkContext, peer_id: NodeId, block_hash: H256,
        index_skips: Vec<usize>, delay: Option<Duration>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());

        let request = GetBlockTxn {
            request_id: 0,
            block_hash: block_hash.clone(),
            index_skips,
        };

        self.request_with_delay(io, Box::new(request), Some(peer_id), delay);
    }

    fn send_request_again(
        &self, io: &dyn NetworkContext, msg: &RequestMessage,
    ) {
        debug!("send_request_again, request={:?}", msg.request);
        if let Some(request) = msg.request.resend() {
            let mut filter = PeerFilter::new(request.msg_id());
            if let Some(preferred_node_type) = request.preferred_node_type() {
                filter = filter.with_preferred_node_type(preferred_node_type);
            }
            if let Some(cap) = request.required_capability() {
                filter = filter.with_cap(cap);
            }
            let chosen_peer = filter.select(&self.syn);
            debug!("send_request_again with new request, peer={:?}, new request={:?}", chosen_peer, request);
            self.request_with_delay(io, request, chosen_peer, msg.delay);
        }
    }

    pub fn send_pending_requests(
        &self, io: &dyn NetworkContext, peer: &NodeId,
    ) {
        self.request_handler.send_pending_requests(io, peer)
    }

    pub fn resend_request_to_another_peer(
        &self, io: &dyn NetworkContext, req: &RequestMessage,
    ) {
        req.request.on_removed(&self.inflight_keys);
        self.send_request_again(io, req);
    }

    // Match request with given response.
    // No need to let caller handle request resending.
    pub fn match_request(
        &self, peer_id: &NodeId, request_id: u64,
    ) -> Result<RequestMessage, Error> {
        self.request_handler.match_request(peer_id, request_id)
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
        &self, io: &dyn NetworkContext, requested_hashes: HashSet<H256>,
        mut received_blocks: HashSet<H256>, ask_full_block: bool,
        peer: Option<NodeId>, with_public: bool, delay: Option<Duration>,
        preferred_node_type_for_block_request: Option<NodeType>,
    )
    {
        let _timer = MeterTimer::time_func(REQUEST_MANAGER_TIMER.as_ref());
        debug!(
            "blocks_received: req_hashes={:?} received_blocks={:?} peer={:?}",
            requested_hashes, received_blocks, peer
        );
        let missing_blocks = {
            let mut inflight_blocks =
                self.inflight_keys.write(msgid::GET_BLOCKS);
            let mut net_inflight_blocks =
                self.inflight_keys.write(msgid::NET_INFLIGHT_BLOCKS);
            let mut missing_blocks = Vec::new();
            for req_hash in &requested_hashes {
                net_inflight_blocks.remove(&Key::Hash(*req_hash));
                if !received_blocks.remove(req_hash) {
                    // If `req_hash` is not in `blocks_in_flight`, it may has
                    // been received or requested
                    // again by another thread, so we do not need to request it
                    // in that case
                    if inflight_blocks.remove(&Key::Hash(*req_hash)) {
                        missing_blocks.push(*req_hash);
                    }
                } else {
                    inflight_blocks.remove(&Key::Hash(*req_hash));
                }
            }
            for h in &received_blocks {
                net_inflight_blocks.remove(&Key::Hash(*h));
                inflight_blocks.remove(&Key::Hash(*h));
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
                    preferred_node_type_for_block_request,
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
                window_index: request.window_index,
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
        let timeout_requests =
            self.request_handler.process_timeout_requests(io);
        for req in timeout_requests {
            debug!("Timeout requests: {:?}", req);
            self.resend_request_to_another_peer(io, &req);
        }
    }

    /// Send waiting requests that their backoff delay have passes.
    /// Return the cancelled requests that have timeout too many times.
    pub fn resend_waiting_requests(
        &self, io: &dyn NetworkContext, remove_timeout_requests: bool,
    ) -> Vec<Box<dyn Request>> {
        debug!("resend_waiting_requests: start");
        let mut waiting_requests = self.waiting_requests.lock();
        let now = Instant::now();
        let mut batcher =
            RequestBatcher::new(*DEFAULT_REQUEST_BATCH_BUCKET_SIZE);

        let mut cancelled_requests = Vec::new();
        while let Some(req) = waiting_requests.pop() {
            if req.time_to_send >= now {
                waiting_requests.push(req);
                break;
            } else if remove_timeout_requests
                && req.request.1 > *DEFAULT_REQUEST_DELAY_UPPER_BOUND
            {
                // Discard stale requests
                warn!("Request is in-flight for over an hour: {:?}", req);
                req.request.0.on_removed(&self.inflight_keys);
                cancelled_requests.push(req.request.0);
                continue;
            }

            // Waiting requests are already in-flight, so send them without
            // checking
            let WaitingRequest(request, delay) = req.request;
            let request = match request.resend() {
                Some(r) => r,
                None => continue,
            };
            if !self.check_and_update_net_inflight_blocks(&request) {
                // Keep GetBlocks requests in queue
                // when we do not have the capability to process them.
                // We resend GetCompactBlocks as GetBlocks, so only check
                // GET_BLOCKS here.
                waiting_requests.push(TimedWaitingRequest::new(
                    now + delay,
                    // Do not increase delay because this is not a failure.
                    WaitingRequest(request, delay),
                    None,
                ));
                continue;
            }
            batcher.insert(delay, request);
        }

        let is_full_node = self.syn.is_full_node();
        for (next_delay, request) in batcher.get_batched_requests(is_full_node)
        {
            let mut filter = PeerFilter::new(request.msg_id());
            if let Some(cap) = request.required_capability() {
                filter = filter.with_cap(cap);
            }
            let chosen_peer = match filter.select(&self.syn) {
                Some(p) => p,
                None => {
                    debug!("No peer to send request, wait for next time");
                    // These requests are not actually sent,
                    // and they will not be inserted into requests_queue,
                    // so remove them from net_inflight_blocks.
                    if let Some(hashes) = try_get_block_hashes(&request) {
                        self.remove_net_inflight_blocks(hashes.iter())
                    }
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
        cancelled_requests
    }

    pub fn on_peer_connected(&self, peer: &NodeId) {
        self.request_handler.add_peer(*peer);
    }

    pub fn on_peer_disconnected(&self, io: &dyn NetworkContext, peer: &NodeId) {
        if let Some(unfinished_requests) =
            self.request_handler.remove_peer(peer)
        {
            for mut msg in unfinished_requests {
                msg.delay = None;
                self.resend_request_to_another_peer(io, &msg);
            }
        } else {
            debug!("Peer already removed form request manager when disconnected peer={}", peer);
        }
    }

    fn check_and_update_net_inflight_blocks(
        &self, request: &Box<dyn Request>,
    ) -> bool {
        if let Some(hashes) = try_get_block_hashes(request) {
            // Insert the request into waiting queue when the queue is
            // already full, to avoid requesting more blocks
            // than we can process. Requests will be
            // inserted to waiting queue if peer_id is None.
            let mut net_inflight_blocks =
                self.inflight_keys.write(msgid::NET_INFLIGHT_BLOCKS);
            if net_inflight_blocks.len()
                >= self.recover_public_queue.estimated_available_count()
            {
                trace!("queue is full, send block request later: inflight={} req={:?}",
                           net_inflight_blocks.len(), request);
                return false;
            } else {
                for hash in hashes {
                    net_inflight_blocks.insert(Key::Hash(*hash));
                }
                trace!("queue is not full, send block request now: inflight={} req={:?}",
                           net_inflight_blocks.len(), request);
            }
        }
        true
    }

    pub fn remove_net_inflight_blocks<'a, I: Iterator<Item = &'a H256>>(
        &self, blocks: I,
    ) {
        let mut net_inflight_blocks =
            self.inflight_keys.write(msgid::NET_INFLIGHT_BLOCKS);
        for block_hash in blocks {
            net_inflight_blocks.remove(&Key::Hash(*block_hash));
        }
    }
}

/// Return block hashes in `request` if it's requesting blocks.
/// Return None otherwise.
pub fn try_get_block_hashes(request: &Box<dyn Request>) -> Option<&Vec<H256>> {
    match request.msg_id() {
        msgid::GET_BLOCKS | msgid::GET_CMPCT_BLOCKS => {
            let hashes = if let Some(req) =
                request.as_any().downcast_ref::<GetBlocks>()
            {
                &req.hashes
            } else if let Some(req) =
                request.as_any().downcast_ref::<GetCompactBlocks>()
            {
                &req.hashes
            } else {
                panic!(
                    "MessageId and Request not match, request={:?}",
                    request
                );
            };
            Some(hashes)
        }
        _ => None,
    }
}

#[derive(Debug, DeriveMallocSizeOf)]
struct TimedWaitingRequest {
    time_to_send: Instant,
    request: WaitingRequest,
    peer: Option<NodeId>,
}

impl TimedWaitingRequest {
    fn new(
        time_to_send: Instant, request: WaitingRequest, peer: Option<NodeId>,
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
