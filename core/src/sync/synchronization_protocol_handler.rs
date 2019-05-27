// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    super::transaction_pool::SharedTransactionPool, random, Error, ErrorKind,
    SharedSynchronizationGraph, SynchronizationGraph, SynchronizationPeerState,
    SynchronizationState,
};
use crate::{
    bytes::Bytes, consensus::SharedConsensusGraph, pow::ProofOfWorkConfig,
};
use cfx_types::H256;
use io::TimerToken;
use message::{
    GetBlockHeaders, GetBlockHeadersResponse, GetBlockTxn, GetBlockTxnResponse,
    GetBlocks, GetBlocksResponse, GetBlocksWithPublicResponse,
    GetCompactBlocks, GetCompactBlocksResponse, GetTerminalBlockHashes,
    GetTerminalBlockHashesResponse, GetTransactions, GetTransactionsResponse,
    Message, MsgId, NewBlock, NewBlockHashes, Status, TransIndex,
    TransactionDigests, TransactionPropagationControl, Transactions,
};
use network::{
    throttling::THROTTLING_SERVICE, Error as NetworkError, HandlerWorkType,
    NetworkContext, NetworkProtocolHandler, PeerId,
};
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use rlp::Rlp;
//use slab::Slab;
use crate::{
    cache_manager::{CacheId, CacheManager},
    pow::WORKER_COMPUTATION_PARALLELISM,
    sync::synchronization_state::RequestMessage,
    verification::VerificationConfig,
};
use primitives::{
    Block, SignedTransaction, TransactionWithSignature, TxPropagateId,
};
use priority_send_queue::SendQueuePriority;
use rlp::DecoderError;
use std::{
    cmp::{self, Ordering},
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    iter::FromIterator,
    sync::{
        atomic::{AtomicBool, Ordering as AtomicOrdering},
        mpsc::channel,
        Arc,
    },
    time::{Duration, Instant},
};
use threadpool::ThreadPool;

const CATCH_UP_EPOCH_LAG_THRESHOLD: u64 = 3;

pub const SYNCHRONIZATION_PROTOCOL_VERSION: u8 = 0x01;

pub const MAX_HEADERS_TO_SEND: u64 = 512;
pub const MAX_BLOCKS_TO_SEND: u64 = 256;
const MAX_PACKET_SIZE: usize = 15 * 1024 * 1024 + 512 * 1024; // 15.5 MB
const MIN_PEERS_PROPAGATION: usize = 4;
const MAX_PEERS_PROPAGATION: usize = 128;
const DEFAULT_GET_HEADERS_NUM: u64 = 1;
const DEFAULT_GET_PARENT_HEADERS_NUM: u64 = 30;
const REQUEST_START_WAITING_TIME_SECONDS: u64 = 1;
//const REQUEST_WAITING_TIME_BACKOFF: u32 = 2;

const TX_TIMER: TimerToken = 0;
const CHECK_REQUEST_TIMER: TimerToken = 1;
const BLOCK_CACHE_GC_TIMER: TimerToken = 2;
const CHECK_CATCH_UP_MODE_TIMER: TimerToken = 3;
const LOG_STATISTIC_TIMER: TimerToken = 4;

const MAX_TXS_BYTES_TO_PROPAGATE: usize = 1024 * 1024; // 1MB

#[derive(Eq, PartialEq, PartialOrd, Ord)]
enum WaitingRequest {
    Header(H256),
    Block(H256),
}

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
enum SyncHandlerWorkType {
    RecoverPublic = 1,
}

struct RecoverPublicTask {
    blocks: Vec<Block>,
    requested: HashSet<H256>,
    failed_peer: PeerId,
    compact: bool,
}

pub struct SynchronizationProtocolHandler {
    protocol_config: ProtocolConfiguration,
    graph: SharedSynchronizationGraph,
    syn: RwLock<SynchronizationState>,
    headers_in_flight: Mutex<HashSet<H256>>,
    header_request_waittime: Mutex<HashMap<H256, Duration>>,
    blocks_in_flight: Mutex<HashSet<H256>>,
    block_request_waittime: Mutex<HashMap<H256, Duration>>,
    waiting_requests: Mutex<BinaryHeap<(Instant, WaitingRequest)>>,
    requests_queue: Mutex<BinaryHeap<Arc<TimedSyncRequests>>>,

    // Worker task queue for recover public
    recover_public_queue: Mutex<VecDeque<RecoverPublicTask>>,
}

pub struct ProtocolConfiguration {
    pub send_tx_period: Duration,
    pub check_request_period: Duration,
    pub block_cache_gc_period: Duration,
    pub persist_terminal_period: Duration,
    pub headers_request_timeout: Duration,
    pub blocks_request_timeout: Duration,
    pub transaction_request_timeout: Duration,
    pub tx_maintained_for_peer_timeout: Duration,
    pub max_inflight_request_count: u64,
    pub start_as_catch_up_mode: bool,
    pub received_tx_index_maintain_timeout: Duration,
    pub request_block_with_public: bool,
    pub max_trans_count_received_in_catch_up: u64,
}

#[derive(Debug)]
pub struct TimedSyncRequests {
    pub peer_id: PeerId,
    pub timeout_time: Instant,
    pub request_id: u64,
    pub removed: AtomicBool,
}

impl TimedSyncRequests {
    pub fn new(
        peer_id: PeerId, timeout: Duration, request_id: u64,
    ) -> TimedSyncRequests {
        TimedSyncRequests {
            peer_id,
            timeout_time: Instant::now() + timeout,
            request_id,
            removed: AtomicBool::new(false),
        }
    }

    pub fn from_request(
        peer_id: PeerId, request_id: u64, msg: &RequestMessage,
        conf: &ProtocolConfiguration,
    ) -> TimedSyncRequests
    {
        let timeout = match *msg {
            RequestMessage::Headers(_) => conf.headers_request_timeout,
            RequestMessage::Blocks(_)
            | RequestMessage::Compact(_)
            | RequestMessage::BlockTxn(_) => conf.blocks_request_timeout,
            RequestMessage::Transactions(_) => conf.transaction_request_timeout,
            _ => Duration::default(),
        };
        TimedSyncRequests::new(peer_id, timeout, request_id)
    }
}

impl Ord for TimedSyncRequests {
    fn cmp(&self, other: &Self) -> Ordering {
        other.timeout_time.cmp(&self.timeout_time)
    }
}
impl PartialOrd for TimedSyncRequests {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.timeout_time.partial_cmp(&self.timeout_time)
    }
}
impl Eq for TimedSyncRequests {}
impl PartialEq for TimedSyncRequests {
    fn eq(&self, other: &Self) -> bool {
        self.timeout_time == other.timeout_time
    }
}

impl SynchronizationProtocolHandler {
    pub fn new(
        protocol_config: ProtocolConfiguration,
        consensus_graph: SharedConsensusGraph,
        verification_config: VerificationConfig, pow_config: ProofOfWorkConfig,
        fast_recover: bool,
    ) -> Self
    {
        let start_as_catch_up_mode = protocol_config.start_as_catch_up_mode;
        let received_tx_index_maintain_timeout =
            protocol_config.received_tx_index_maintain_timeout;

        // FIXME: make sent_transaction_window_size to be 2^pow.
        let sent_transaction_window_size =
            protocol_config.tx_maintained_for_peer_timeout.as_millis()
                / protocol_config.send_tx_period.as_millis();

        SynchronizationProtocolHandler {
            protocol_config,
            graph: Arc::new(SynchronizationGraph::new(
                consensus_graph.clone(),
                verification_config,
                pow_config,
                fast_recover,
            )),
            syn: RwLock::new(SynchronizationState::new(
                start_as_catch_up_mode,
                received_tx_index_maintain_timeout.as_secs(),
                sent_transaction_window_size as usize,
            )),
            headers_in_flight: Default::default(),
            header_request_waittime: Default::default(),
            blocks_in_flight: Default::default(),
            block_request_waittime: Default::default(),
            waiting_requests: Default::default(),
            requests_queue: Default::default(),
            recover_public_queue: Mutex::new(VecDeque::new()),
        }
    }

    pub fn catch_up_mode(&self) -> bool { self.syn.read().catch_up_mode }

    pub fn get_synchronization_graph(&self) -> SharedSynchronizationGraph {
        self.graph.clone()
    }

    pub fn block_by_hash(&self, hash: &H256) -> Option<Arc<Block>> {
        self.graph.block_by_hash(hash)
    }

    fn send_message(
        &self, io: &NetworkContext, peer: PeerId, msg: &Message,
        priority: SendQueuePriority,
    ) -> Result<(), NetworkError>
    {
        self.send_message_with_throttling(io, peer, msg, priority, false)
    }

    fn send_message_with_throttling(
        &self, io: &NetworkContext, peer: PeerId, msg: &Message,
        priority: SendQueuePriority, throttling_disabled: bool,
    ) -> Result<(), NetworkError>
    {
        if !throttling_disabled && msg.is_size_sensitive() {
            if let Err(e) = THROTTLING_SERVICE.read().check_throttling() {
                debug!("Throttling failure: {:?}", e);
                return Err(e);
            }
        }

        let mut raw = Bytes::new();
        raw.push(msg.msg_id().into());
        raw.extend(msg.rlp_bytes().iter());
        if let Err(e) = io.send(peer, raw, priority) {
            debug!("Error sending message: {:?}", e);
            return Err(e);
        };
        debug!(
            "Send message({}) to {:?}",
            msg.msg_id(),
            io.get_peer_node_id(peer)
        );
        Ok(())
    }

    fn dispatch_message(
        &self, io: &NetworkContext, peer: PeerId, msg_id: MsgId, rlp: Rlp,
    ) {
        trace!("Dispatching message: peer={:?}, msgid={:?}", peer, msg_id);
        match msg_id {
            MsgId::STATUS => self.on_status(io, peer, &rlp),
            MsgId::GET_BLOCK_HEADERS_RESPONSE => {
                self.on_block_headers_response(io, peer, &rlp)
            }
            MsgId::GET_BLOCK_HEADERS => {
                self.on_get_block_headers(io, peer, &rlp)
            }
            MsgId::NEW_BLOCK => self.on_new_block(io, peer, &rlp),
            MsgId::NEW_BLOCK_HASHES => self.on_new_block_hashes(io, peer, &rlp),
            MsgId::GET_BLOCKS_RESPONSE => {
                self.on_blocks_response(io, peer, &rlp)
            }
            MsgId::GET_BLOCKS_WITH_PUBLIC_RESPONSE => {
                self.on_blocks_with_public_response(io, peer, &rlp)
            }
            MsgId::GET_BLOCKS => self.on_get_blocks(io, peer, &rlp),
            MsgId::GET_TERMINAL_BLOCK_HASHES_RESPONSE => {
                self.on_terminal_block_hashes_response(io, peer, &rlp)
            }
            MsgId::GET_TERMINAL_BLOCK_HASHES => {
                self.on_get_terminal_block_hashes(io, peer, &rlp)
            }
            MsgId::TRANSACTIONS => self.on_transactions(io, peer, &rlp),
            MsgId::GET_CMPCT_BLOCKS => {
                self.on_get_compact_blocks(io, peer, &rlp)
            }
            MsgId::GET_CMPCT_BLOCKS_RESPONSE => {
                self.on_get_compact_blocks_response(io, peer, &rlp)
            }
            MsgId::GET_BLOCK_TXN => self.on_get_blocktxn(io, peer, &rlp),
            MsgId::GET_BLOCK_TXN_RESPONSE => {
                self.on_get_blocktxn_response(io, peer, &rlp)
            }
            MsgId::TRANSACTION_PROPAGATION_CONTROL => {
                self.on_trans_prop_ctrl(peer, &rlp)
            }
            MsgId::TRANSACTION_DIGESTS => self.on_trans_digests(io, peer, &rlp),
            MsgId::GET_TRANSACTIONS => self.on_get_transactions(io, peer, &rlp),
            MsgId::GET_TRANSACTIONS_RESPONSE => {
                self.on_get_transactions_response(io, peer, &rlp)
            }
            _ => {
                warn!("Unknown message: peer={:?} msgid={:?}", peer, msg_id);
                Ok(())
            }
        }
        .unwrap_or_else(|e| {
            warn!(
                "Error while handling message msgid={:?}, error={:?}",
                msg_id, e
            );
        });
    }

    fn on_get_compact_blocks(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        if !self.syn.read().peers.contains_key(&peer) {
            warn!("Unexpected message from unrecognized peer: peer={:?} msg=GET_CMPCT_BLOCKS", peer);
            return Ok(());
        }

        let req: GetCompactBlocks = rlp.as_val()?;
        let mut compact_blocks = Vec::with_capacity(req.hashes.len());
        let mut blocks = Vec::new();
        debug!("on_get_compact_blocks, msg=:{:?}", req);
        for hash in &req.hashes {
            if let Some(compact_block) = self.graph.compact_block_by_hash(hash)
            {
                if (compact_blocks.len() as u64) < MAX_HEADERS_TO_SEND {
                    compact_blocks.push(compact_block);
                }
            } else if let Some(block) = self.graph.block_by_hash(hash) {
                debug!("Have complete block but no compact block, return complete block instead");
                if (blocks.len() as u64) < MAX_BLOCKS_TO_SEND {
                    blocks.push(block);
                }
            } else {
                warn!(
                    "Peer {} requested non-existent compact block {}",
                    peer, hash
                );
            }
        }
        let resp = GetCompactBlocksResponse {
            request_id: req.request_id,
            compact_blocks,
            blocks: blocks.iter().map(|b| b.as_ref().clone()).collect(),
        };
        self.send_message(io, peer, &resp, SendQueuePriority::High)?;
        Ok(())
    }

    fn on_get_compact_blocks_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetCompactBlocksResponse = rlp.as_val()?;
        debug!("on_get_compact_blocks_response {:?}", resp);
        let req = self.match_request(io, peer, resp.request_id())?;
        let mut failed_blocks = Vec::new();
        let mut completed_blocks = Vec::new();
        let mut requested_blocks: HashSet<H256> = match req {
            RequestMessage::Compact(request) => {
                HashSet::from_iter(request.hashes.iter().cloned())
            }
            _ => {
                warn!("Get response not matching the request! req={:?}, resp={:?}", req, resp);
                return Err(ErrorKind::UnexpectedResponse.into());
            }
        };
        for mut cmpct in resp.compact_blocks {
            let hash = cmpct.hash();
            if !requested_blocks.remove(&hash) {
                warn!("Response has not requested compact block {:?}", hash);
                continue;
            }
            if self.graph.contains_block(&hash) {
                debug!(
                    "Get cmpct block, but full block already received, hash={}",
                    hash
                );
                self.blocks_in_flight.lock().remove(&hash);
                continue;
            } else {
                if let Some(header) = self.graph.block_header_by_hash(&hash) {
                    if self.graph.contains_compact_block(&hash) {
                        debug!("Cmpct block already received, hash={}", hash);
                        self.blocks_in_flight.lock().remove(&hash);
                        continue;
                    } else {
                        debug!("Cmpct block Processing, hash={}", hash);
                        let missing = cmpct.build_partial(
                            &*self
                                .get_transaction_pool()
                                .transaction_pubkey_cache
                                .read(),
                        );
                        if !missing.is_empty() {
                            debug!(
                                "Request {} missing tx in {}",
                                missing.len(),
                                hash
                            );
                            self.graph.insert_compact_block(cmpct);
                            if self
                                .request_blocktxn(io, peer, hash, missing)
                                .is_err()
                            {
                                self.blocks_in_flight.lock().remove(&hash);
                                failed_blocks.push(hash.clone());
                            }
                        } else {
                            let trans = cmpct
                                .reconstructed_txes
                                .into_iter()
                                .map(|tx| tx.unwrap())
                                .collect();
                            self.blocks_in_flight.lock().remove(&hash);
                            let (success, to_relay) = self.graph.insert_block(
                                Block::new(header, trans),
                                true,  // need_to_verify
                                true,  // persistent
                                false, // sync_graph_only
                            );

                            // May fail due to transactions hash collision
                            if !success {
                                failed_blocks.push(hash.clone());
                            }
                            if to_relay {
                                completed_blocks.push(hash);
                            }
                        }
                    }
                } else {
                    warn!(
                        "Get cmpct block, but header not received, hash={}",
                        hash
                    );
                    self.blocks_in_flight.lock().remove(&hash);
                    continue;
                }
            }
        }

        self.dispatch_recover_public_task(
            io,
            resp.blocks,
            requested_blocks,
            peer,
            true,
        );

        // Request full block if reconstruction fails
        if !failed_blocks.is_empty() {
            self.request_blocks(io, Some(peer), failed_blocks);
        }

        // Broadcast completed block_header_ready blocks
        if !completed_blocks.is_empty() && !self.syn.read().catch_up_mode {
            let new_block_hash_msg: Box<dyn Message> =
                Box::new(NewBlockHashes {
                    block_hashes: completed_blocks,
                });
            self.broadcast_message(
                io,
                PeerId::max_value(),
                new_block_hash_msg.as_ref(),
                SendQueuePriority::High,
            )?;
        }

        Ok(())
    }

    fn on_get_transactions_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp = rlp.as_val::<GetTransactionsResponse>()?;
        debug!("on_get_transactions_response {:?}", resp);

        self.match_request(io, peer, resp.request_id())?;
        // FIXME: Do some check based on transaction request.

        let transactions = resp.transactions;
        debug!(
            "Received {:?} transactions from Peer {:?}",
            transactions.len(),
            peer
        );

        let tx_ids = transactions
            .iter()
            .map(|tx| TxPropagateId::from(tx.hash()))
            .collect::<Vec<_>>();
        self.syn
            .write()
            .received_transactions
            .append_transaction_ids(tx_ids);

        self.get_transaction_pool().insert_new_transactions(
            self.graph.consensus.best_state_block_hash(),
            &transactions,
        );
        debug!("Transactions successfully inserted to transaction pool");

        Ok(())
    }

    fn on_get_transactions(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let get_transactions = rlp.as_val::<GetTransactions>()?;

        let resp = {
            let transactions = {
                let syn = self.syn.read();
                get_transactions
                    .indices
                    .iter()
                    .filter_map(|tx_idx| {
                        if let Some(tx) =
                            syn.sent_transactions.get_transaction(tx_idx)
                        {
                            Some(tx.transaction.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            };

            GetTransactionsResponse {
                request_id: get_transactions.request_id,
                transactions,
            }
        };

        self.send_message(io, peer, &resp, SendQueuePriority::Normal)?;
        Ok(())
    }

    fn on_trans_digests(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let transaction_digests = rlp.as_val::<TransactionDigests>()?;

        let peer_info = self.syn.read().get_peer_info(&peer)?;
        let should_disconnect = {
            let mut peer_info = peer_info.write();
            if peer_info.notified_mode.is_some()
                && (peer_info.notified_mode.unwrap() == true)
            {
                peer_info.received_transaction_count +=
                    transaction_digests.trans_short_ids.len();
                if peer_info.received_transaction_count
                    > self.protocol_config.max_trans_count_received_in_catch_up
                        as usize
                {
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };

        if should_disconnect {
            io.disconnect_peer(peer);
            return Err(ErrorKind::TooManyTrans.into());
        }

        let (indices, tx_ids) = {
            let mut indices = Vec::new();
            let mut tx_ids = HashSet::new();

            let mut syn = self.syn.write();
            for (idx, tx_id) in
                transaction_digests.trans_short_ids.iter().enumerate()
            {
                if syn.inflight_requested_transactions.contains(tx_id) {
                    // Already being requested
                    continue;
                }

                if syn.received_transactions.contains(tx_id) {
                    // Already received
                    continue;
                }

                syn.inflight_requested_transactions.insert(*tx_id);

                let index =
                    TransIndex::new((transaction_digests.window_index, idx));
                indices.push(index);
                tx_ids.insert(*tx_id);
            }

            (indices, tx_ids)
        };

        match self.request_transactions(io, peer, indices, tx_ids.clone()) {
            Ok(_) => Ok(()),
            Err(e) => {
                let mut syn = self.syn.write();
                for tx_id in tx_ids {
                    syn.inflight_requested_transactions.remove(&tx_id);
                }
                Err(e)
            }
        }
    }

    fn on_get_blocktxn(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        if !self.syn.read().peers.contains_key(&peer) {
            warn!("Unexpected message from unrecognized peer: peer={:?} msg=GET_BLOCK_TXN", peer);
            return Ok(());
        }

        let req: GetBlockTxn = rlp.as_val()?;
        debug!("on_get_blocktxn");
        match self.graph.block_by_hash(&req.block_hash) {
            Some(block) => {
                debug!("Process get_blocktxn hash={:?}", block.hash());
                let mut tx_resp = Vec::with_capacity(req.indexes.len());
                let mut last = 0;
                for index in req.indexes {
                    last += index;
                    if last >= block.transactions.len() {
                        warn!(
                            "Request tx index out of bound, peer={}, hash={}",
                            peer,
                            block.hash()
                        );
                        return Err(ErrorKind::Invalid.into());
                    }
                    tx_resp.push(block.transactions[last].transaction.clone());
                    last += 1;
                }
                let resp = GetBlockTxnResponse {
                    request_id: req.request_id,
                    block_hash: req.block_hash,
                    block_txn: tx_resp,
                };
                self.send_message(io, peer, &resp, SendQueuePriority::High)?;
            }
            None => {
                warn!(
                    "Get blocktxn request of non-existent block, hash={}",
                    req.block_hash
                );

                let resp = GetBlockTxnResponse {
                    request_id: req.request_id,
                    block_hash: H256::default(),
                    block_txn: Vec::new(),
                };
                self.send_message(io, peer, &resp, SendQueuePriority::High)?;
            }
        }
        Ok(())
    }

    fn on_get_blocktxn_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetBlockTxnResponse = rlp.as_val()?;
        debug!("on_get_blocktxn_response");
        let hash = resp.block_hash;
        let req = self.match_request(io, peer, resp.request_id())?;
        let req = match req {
            RequestMessage::BlockTxn(request) => request,
            _ => {
                warn!("Get response not matching the request! req={:?}, resp={:?}", req, resp);
                return Err(ErrorKind::UnexpectedResponse.into());
            }
        };
        let mut request_again = false;
        if hash != req.block_hash {
            warn!("Response blocktxn is not the requested block, req={:?}, resp={:?}", req.block_hash, hash);
            request_again = true;
        } else {
            if self.graph.contains_block(&hash) {
                debug!(
                    "Get blocktxn, but full block already received, hash={}",
                    hash
                );
            } else {
                if let Some(header) = self.graph.block_header_by_hash(&hash) {
                    debug!("Process blocktxn hash={:?}", hash);
                    let signed_txes = Self::batch_recover_with_cache(
                        &resp.block_txn,
                        &mut *self
                            .get_transaction_pool()
                            .transaction_pubkey_cache
                            .write(),
                        &mut *self.graph.cache_man.lock(),
                    )?;
                    match self.graph.compact_block_by_hash(&hash) {
                        Some(cmpct) => {
                            let mut trans = Vec::with_capacity(
                                cmpct.reconstructed_txes.len(),
                            );
                            let mut index = 0;
                            for tx in cmpct.reconstructed_txes {
                                match tx {
                                    Some(tx) => trans.push(tx),
                                    None => {
                                        trans.push(signed_txes[index].clone());
                                        index += 1;
                                    }
                                }
                            }
                            // FIXME Should check if hash matches

                            let (success, to_relay) = self.graph.insert_block(
                                Block::new(header, trans),
                                true,
                                true,
                                false,
                            );

                            let mut blocks = Vec::new();
                            blocks.push(hash);
                            if success {
                                self.block_request_waittime
                                    .lock()
                                    .remove(&hash);
                            } else {
                                // If the peer is honest, may still fail due to
                                // tx hash collision
                                self.request_blocks(
                                    io,
                                    Some(peer),
                                    blocks.clone(),
                                );
                            }
                            if to_relay && !self.syn.read().catch_up_mode {
                                let new_block_hash_msg: Box<dyn Message> =
                                    Box::new(NewBlockHashes {
                                        block_hashes: blocks,
                                    });
                                self.broadcast_message(
                                    io,
                                    PeerId::max_value(),
                                    new_block_hash_msg.as_ref(),
                                    SendQueuePriority::High,
                                )?;
                            }
                        }
                        None => {
                            request_again = true;
                            warn!("Get blocktxn, but misses compact block, hash={}", hash);
                        }
                    }
                } else {
                    request_again = true;
                    warn!(
                        "Get blocktxn, but header not received, hash={}",
                        hash
                    );
                }
            }
        }
        if request_again {
            let chosen_peer = self.choose_peer_after_failure(peer);
            self.request_blocks(io, chosen_peer, vec![req.block_hash]);
        }
        Ok(())
    }

    fn on_transactions(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let transactions = rlp.as_val::<Transactions>()?;
        let transactions = transactions.transactions;
        debug!(
            "Received {:?} transactions from Peer {:?}",
            transactions.len(),
            peer
        );

        let peer_info = self.syn.read().get_peer_info(&peer)?;
        let should_disconnect = {
            let mut peer_info = peer_info.write();
            if peer_info.notified_mode.is_some()
                && (peer_info.notified_mode.unwrap() == true)
            {
                peer_info.received_transaction_count += transactions.len();
                if peer_info.received_transaction_count
                    > self.protocol_config.max_trans_count_received_in_catch_up
                        as usize
                {
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };

        if should_disconnect {
            io.disconnect_peer(peer);
            return Err(ErrorKind::TooManyTrans.into());
        }

        self.get_transaction_pool().insert_new_transactions(
            self.graph.consensus.best_state_block_hash(),
            &transactions,
        );
        debug!("Transactions successfully inserted to transaction pool");

        Ok(())
    }

    fn on_get_block_headers(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        if !self.syn.read().peers.contains_key(&peer) {
            warn!("Unexpected message from unrecognized peer: peer={:?} msg=GET_BLOCK_HEADERS", peer);
            return Ok(());
        }

        let req = rlp.as_val::<GetBlockHeaders>()?;
        debug!("on_get_block_headers, msg=:{:?}", req);

        let mut hash = req.hash;
        let mut block_headers_resp = GetBlockHeadersResponse::default();
        block_headers_resp.set_request_id(req.request_id());

        for _n in 0..cmp::min(MAX_HEADERS_TO_SEND, req.max_blocks) {
            let header = self.graph.block_header_by_hash(&hash);
            if header.is_none() {
                break;
            }
            let header = header.unwrap();
            block_headers_resp.headers.push(header.clone());
            if hash == self.graph.genesis_hash() {
                break;
            }
            hash = header.parent_hash().clone();
        }
        debug!(
            "Returned {:?} block headers to peer {:?}",
            block_headers_resp.headers.len(),
            peer
        );

        let msg: Box<dyn Message> = Box::new(block_headers_resp);
        self.send_message(io, peer, msg.as_ref(), SendQueuePriority::High)?;
        Ok(())
    }

    fn on_trans_prop_ctrl(&self, peer: PeerId, rlp: &Rlp) -> Result<(), Error> {
        let trans_prop_ctrl = rlp.as_val::<TransactionPropagationControl>()?;
        debug!(
            "on_trans_prop_ctrl, peer {}, msg=:{:?}",
            peer, trans_prop_ctrl
        );

        let peer_info = self.syn.read().get_peer_info(&peer)?;
        peer_info.write().need_prop_trans = !trans_prop_ctrl.catch_up_mode;

        Ok(())
    }

    fn on_get_blocks(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        if !self.syn.read().peers.contains_key(&peer) {
            warn!("Unexpected message from unrecognized peer: peer={:?} msg=GET_BLOCKS", peer);
            return Ok(());
        }

        let req = rlp.as_val::<GetBlocks>()?;
        debug!("on_get_blocks, msg=:{:?}", req);
        if req.hashes.is_empty() {
            debug!("Received empty getblocks message: peer={:?}", peer);
        } else if req.with_public {
            let mut blocks = Vec::new();
            let mut packet_size_left = MAX_PACKET_SIZE;
            for hash in req.hashes.iter() {
                if let Some(block) = self.graph.block_by_hash(hash) {
                    if packet_size_left
                        >= block.approximated_rlp_size_with_public()
                    {
                        packet_size_left -=
                            block.approximated_rlp_size_with_public();
                        let block = block.as_ref().clone();
                        blocks.push(block);
                    } else {
                        break;
                    }
                }
            }

            let mut msg = Box::new(GetBlocksWithPublicResponse {
                request_id: req.request_id().into(),
                blocks,
            });

            loop {
                // The number of blocks will keep decreasing for each iteration
                // in the loop. when `msg.blocks.len() == 0`, we
                // should not get `OversizedPacket` error, and
                // we will break out of the loop then.
                if let Err(e) = self.send_message(
                    io,
                    peer,
                    msg.as_ref(),
                    SendQueuePriority::High,
                ) {
                    match e.kind() {
                        network::ErrorKind::OversizedPacket => {
                            let block_count = msg.blocks.len() / 2;
                            msg.blocks.truncate(block_count);
                        }
                        _ => {
                            return Err(e.into());
                        }
                    }
                } else {
                    break;
                }
            }
        } else {
            let mut blocks = Vec::new();
            let mut packet_size_left = MAX_PACKET_SIZE;
            for hash in req.hashes.iter() {
                if let Some(block) = self.graph.block_by_hash(hash) {
                    if packet_size_left >= block.approximated_rlp_size() {
                        packet_size_left -= block.approximated_rlp_size();
                        let block = block.as_ref().clone();
                        blocks.push(block);
                    } else {
                        break;
                    }
                }
            }

            let mut msg = Box::new(GetBlocksResponse {
                request_id: req.request_id().into(),
                blocks,
            });

            loop {
                // The number of blocks will keep decreasing for each iteration
                // in the loop. when `msg.blocks.len() == 0`, we
                // should not get `OversizedPacket` error, and
                // we will break out of the loop then.
                if let Err(e) = self.send_message(
                    io,
                    peer,
                    msg.as_ref(),
                    SendQueuePriority::High,
                ) {
                    match e.kind() {
                        network::ErrorKind::OversizedPacket => {
                            let block_count = msg.blocks.len() / 2;
                            msg.blocks.truncate(block_count);
                        }
                        _ => {
                            return Err(e.into());
                        }
                    }
                } else {
                    break;
                }
            }
        }

        Ok(())
    }

    fn on_get_terminal_block_hashes(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        if !self.syn.read().peers.contains_key(&peer) {
            warn!("Unexpected message from unrecognized peer: peer={:?} msg=GET_TERMINAL_BLOCK_HASHES", peer);
            return Ok(());
        }

        let req = rlp.as_val::<GetTerminalBlockHashes>()?;
        debug!("on_get_terminal_block_hashes, msg=:{:?}", req);
        let (_guard, best_info) = self.graph.get_best_info().into();
        let msg: Box<dyn Message> = Box::new(GetTerminalBlockHashesResponse {
            request_id: req.request_id().into(),
            hashes: best_info.terminal_block_hashes,
        });
        self.send_message(io, peer, msg.as_ref(), SendQueuePriority::High)?;
        Ok(())
    }

    fn on_terminal_block_hashes_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let terminal_block_hashes =
            rlp.as_val::<GetTerminalBlockHashesResponse>()?;
        debug!(
            "on_terminal_block_hashes_response, msg=:{:?}",
            terminal_block_hashes
        );
        self.match_request(io, peer, terminal_block_hashes.request_id())?;

        for hash in &terminal_block_hashes.hashes {
            if !self.graph.contains_block_header(&hash) {
                self.request_block_headers(
                    io,
                    Some(peer),
                    hash,
                    DEFAULT_GET_HEADERS_NUM,
                );
            }
        }
        Ok(())
    }

    fn on_status(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        {
            let mut syn = self.syn.write();

            if !syn.handshaking_peers.contains_key(&peer)
                || syn.peers.contains_key(&peer)
            {
                debug!("Unexpected status message: peer={:?}", peer);
            }
            syn.handshaking_peers.remove(&peer);
        }

        let mut status = rlp.as_val::<Status>()?;
        debug!("on_status, msg=:{:?}", status);
        let genesis_hash = self.graph.genesis_hash();
        if genesis_hash != status.genesis_hash {
            debug!(
                "Peer {:?} genesis hash mismatches (ours: {:?}, theirs: {:?})",
                peer, genesis_hash, status.genesis_hash
            );
            return Err(ErrorKind::Invalid.into());
        }

        let mut requests_vec = Vec::with_capacity(
            self.protocol_config.max_inflight_request_count as usize,
        );
        for _i in 0..self.protocol_config.max_inflight_request_count {
            requests_vec.push(None);
        }

        let peer_state = SynchronizationPeerState {
            id: peer,
            protocol_version: status.protocol_version,
            genesis_hash: status.genesis_hash,
            inflight_requests: requests_vec,
            lowest_request_id: 0,
            next_request_id: 0,
            best_epoch: status.best_epoch,
            max_inflight_request_count: self
                .protocol_config
                .max_inflight_request_count,
            pending_requests: VecDeque::new(),
            received_transaction_count: 0,
            need_prop_trans: true,
            notified_mode: None,
        };

        debug!(
            "New peer (pv={:?}, gh={:?})",
            status.protocol_version, status.genesis_hash
        );

        debug!("Peer {:?} connected", peer);
        {
            let mut syn = self.syn.write();
            syn.peers
                .insert(peer.clone(), Arc::new(RwLock::new(peer_state)));
        }

        {
            let mut missed_hashes =
                self.graph.initial_missed_block_hashes.lock();
            if !missed_hashes.is_empty() {
                status
                    .terminal_block_hashes
                    .extend(missed_hashes.iter().clone());
                missed_hashes.clear();
            }
        };

        // FIXME Need better design.
        // Should be refactored with on_new_block_hashes.
        for terminal_block_hash in status.terminal_block_hashes {
            if !self.graph.contains_block_header(&terminal_block_hash) {
                self.request_block_headers(
                    io,
                    Some(peer),
                    &terminal_block_hash,
                    DEFAULT_GET_HEADERS_NUM,
                );
            }
        }

        Ok(())
    }

    fn on_block_headers_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let mut block_headers = rlp.as_val::<GetBlockHeadersResponse>()?;
        debug!("on_block_headers_response, msg=:{:?}", block_headers);
        let req = self.match_request(io, peer, block_headers.request_id())?;
        let (req_hash, max_blocks) = match req {
            RequestMessage::Headers(header_req) => {
                (header_req.hash, header_req.max_blocks)
            }
            _ => {
                warn!("Get response not matching the request! req={:?}, resp={:?}", req, block_headers);
                return Err(ErrorKind::UnexpectedResponse.into());
            }
        };

        // FIXME Should request again, and should check if hash matches
        if block_headers.headers.is_empty() {
            trace!("Received empty GetBlockHeadersResponse message");
            return Ok(());
        }

        let mut parent_hash = H256::default();
        let mut parent_height = 0;
        let mut hashes = Vec::default();
        let mut dependent_hashes = Vec::new();
        let mut need_to_relay = Vec::new();

        let mut responsed = false;
        for header in &mut block_headers.headers {
            let hash = header.hash();
            if hash == req_hash {
                responsed = true;
            }

            let res = self.graph.insert_block_header(header, true);

            if res.0 {
                // Valid block based on header
                if !self.graph.contains_block(&hash) {
                    hashes.push(hash);
                }

                need_to_relay.extend(res.1);

                for referee in header.referee_hashes() {
                    dependent_hashes.push(*referee);
                }
            }
        }

        {
            let mut headers_in_flight = self.headers_in_flight.lock();
            let mut header_request_waittime =
                self.header_request_waittime.lock();
            for header in &block_headers.headers {
                let hash = header.hash();
                headers_in_flight.remove(&hash);
                header_request_waittime.remove(&hash);
                if parent_hash != H256::default() && parent_hash != hash {
                    return Err(ErrorKind::Invalid.into());
                }
                parent_hash = header.parent_hash().clone();
                parent_height = header.height();
            }
        }
        dependent_hashes.push(parent_hash);

        if !responsed {
            warn!("Header response from peer={} does not match the requested {:?}", peer, req_hash);
            let chosen_peer = self.choose_peer_after_failure(peer);
            self.request_block_headers(io, chosen_peer, &req_hash, max_blocks);
        }

        let header_hashes: Vec<H256> = block_headers
            .headers
            .iter()
            .map(|header| header.hash())
            .collect();
        debug!(
            "get headers response of hashes:{:?}, requesting block:{:?}",
            header_hashes, hashes
        );

        for past_hash in &dependent_hashes {
            if *past_hash != H256::default()
                && !self.graph.contains_block_header(past_hash)
            {
                let num = if *past_hash == parent_hash {
                    let current_height =
                        self.graph.consensus.best_epoch_number() as u64;
                    // Without fork, we only need to request missing blocks
                    // since current_height
                    if parent_height > current_height {
                        cmp::min(
                            DEFAULT_GET_PARENT_HEADERS_NUM,
                            parent_height - current_height,
                        )
                    } else {
                        DEFAULT_GET_HEADERS_NUM
                    }
                } else {
                    DEFAULT_GET_HEADERS_NUM
                };
                self.request_block_headers(io, Some(peer), past_hash, num);
            }
        }

        let catch_up_mode = self.syn.read().catch_up_mode;

        if !hashes.is_empty() {
            // FIXME: This is a naive strategy. Need to
            // make it more sophisticated.
            if catch_up_mode {
                self.request_blocks(io, Some(peer), hashes);
            } else {
                self.request_compact_block(io, Some(peer), hashes);
            }
        }

        if !need_to_relay.is_empty() && !catch_up_mode {
            let new_block_hash_msg: Box<dyn Message> =
                Box::new(NewBlockHashes {
                    block_hashes: need_to_relay,
                });
            self.broadcast_message(
                io,
                PeerId::max_value(),
                new_block_hash_msg.as_ref(),
                SendQueuePriority::High,
            )?;
        }

        Ok(())
    }

    fn on_blocks_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let blocks = rlp.as_val::<GetBlocksResponse>()?;
        debug!(
            "on_blocks_response, get block hashes {:?}",
            blocks
                .blocks
                .iter()
                .map(|b| b.block_header.hash())
                .collect::<Vec<H256>>()
        );
        let req = self.match_request(io, peer, blocks.request_id())?;
        let req_hashes_vec = match req {
            RequestMessage::Blocks(request) => request.hashes,
            RequestMessage::Compact(request) => request.hashes,
            _ => {
                warn!("Get response not matching the request! req={:?}, resp={:?}", req, blocks);
                return Err(ErrorKind::UnexpectedResponse.into());
            }
        };
        let requested_blocks: HashSet<H256> =
            req_hashes_vec.into_iter().collect();
        self.dispatch_recover_public_task(
            io,
            blocks.blocks,
            requested_blocks,
            peer,
            false,
        );

        Ok(())
    }

    fn on_blocks_with_public_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let blocks = rlp.as_val::<GetBlocksWithPublicResponse>()?;
        debug!(
            "on_blocks_with_public_response, get block hashes {:?}",
            blocks
                .blocks
                .iter()
                .map(|b| b.block_header.hash())
                .collect::<Vec<H256>>()
        );
        let req = self.match_request(io, peer, blocks.request_id())?;
        let req_hashes_vec = match req {
            RequestMessage::Blocks(request) => request.hashes,
            RequestMessage::Compact(request) => request.hashes,
            _ => {
                warn!("Get response not matching the request! req={:?}, resp={:?}", req, blocks);
                return Err(ErrorKind::UnexpectedResponse.into());
            }
        };
        let requested_blocks: HashSet<H256> =
            req_hashes_vec.into_iter().collect();

        self.dispatch_recover_public_task(
            io,
            blocks.blocks,
            requested_blocks,
            peer,
            false,
        );

        Ok(())
    }

    fn on_blocks_inner(
        &self, io: &NetworkContext, mut task: RecoverPublicTask,
    ) -> Result<(), Error> {
        let mut need_to_relay = Vec::new();
        for mut block in task.blocks {
            let hash = block.hash();
            if !task.requested.contains(&hash) {
                warn!("Response has not requested block {:?}", hash);
                continue;
            }

            if Self::recover_public(
                &mut block,
                self.get_transaction_pool(),
                &mut *self
                    .get_transaction_pool()
                    .transaction_pubkey_cache
                    .write(),
                &mut *self.graph.cache_man.lock(),
                &*self.get_transaction_pool().worker_pool.lock(),
            )
            .is_err()
            {
                continue;
            }

            match self.graph.block_header_by_hash(&hash) {
                Some(header) => block.block_header = header,
                None => {
                    let res = self
                        .graph
                        .insert_block_header(&mut block.block_header, true);
                    if res.0 {
                        need_to_relay.extend(res.1);
                    } else {
                        continue;
                    }
                }
            }

            let (success, to_relay) =
                self.graph.insert_block(block, true, true, false);
            if success {
                // The requested block is correctly received
                self.blocks_in_flight.lock().remove(&hash);
                self.block_request_waittime.lock().remove(&hash);
                task.requested.remove(&hash);
            }
            if to_relay {
                need_to_relay.push(hash);
            }
        }

        if task.compact {
            // Request missing compact blocks from another random peer
            if !task.requested.is_empty() {
                {
                    // If request is for compact block, the request will not be
                    // cleared from blocks_in_flight in
                    // match_request(). We need to explicitly
                    // clear it here.
                    let mut blocks_in_flight = self.blocks_in_flight.lock();
                    for hash in &task.requested {
                        blocks_in_flight.remove(hash);
                    }
                }
                let chosen_peer =
                    self.choose_peer_after_failure(task.failed_peer);
                self.request_compact_block(
                    io,
                    chosen_peer,
                    task.requested.into_iter().collect(),
                );
            }
        } else {
            // Request missing blocks from another random peer
            if !task.requested.is_empty() {
                let chosen_peer =
                    self.choose_peer_after_failure(task.failed_peer);
                self.request_blocks(
                    io,
                    chosen_peer,
                    task.requested.into_iter().collect(),
                );
            }
        }

        if !need_to_relay.is_empty() && !self.syn.read().catch_up_mode {
            let new_block_hash_msg: Box<dyn Message> =
                Box::new(NewBlockHashes {
                    block_hashes: need_to_relay,
                });
            self.broadcast_message(
                io,
                PeerId::max_value(),
                new_block_hash_msg.as_ref(),
                SendQueuePriority::High,
            )?;
        }

        Ok(())
    }

    fn on_blocks_inner_task(&self, io: &NetworkContext) -> Result<(), Error> {
        let task = self.recover_public_queue.lock().pop_front().unwrap();
        self.on_blocks_inner(io, task)
    }

    pub fn on_mined_block(&self, mut block: Block) -> Vec<H256> {
        let hash = block.block_header.hash();
        info!("Mined block {:?} header={:?}", hash, block.block_header);
        let parent_hash = *block.block_header.parent_hash();

        assert!(self.graph.contains_block_header(&parent_hash));
        assert!(!self.graph.contains_block_header(&hash));
        let res = self
            .graph
            .insert_block_header(&mut block.block_header, false);
        assert!(res.0);

        assert!(!self.graph.contains_block(&hash));
        // Do not need to look at the result since this new block will be
        // broadcast to peers.
        self.graph.insert_block(block, false, true, false);
        res.1
    }

    pub fn on_new_decoded_block(
        &self, mut block: Block, need_to_verify: bool, persistent: bool,
    ) -> Result<Vec<H256>, Error> {
        let hash = block.block_header.hash();
        let mut need_to_relay = Vec::new();
        match self.graph.block_header_by_hash(&hash) {
            Some(header) => block.block_header = header,
            None => {
                let res = self.graph.insert_block_header(
                    &mut block.block_header,
                    need_to_verify,
                );
                if res.0 {
                    need_to_relay.extend(res.1);
                } else {
                    return Err(Error::from_kind(ErrorKind::Invalid));
                }
            }
        }

        let (_, to_relay) =
            self.graph
                .insert_block(block, need_to_verify, persistent, false);
        if to_relay {
            need_to_relay.push(hash);
        }
        Ok(need_to_relay)
    }

    fn on_new_block(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        if !self.syn.read().peers.contains_key(&peer) {
            warn!("Unexpected message from unrecognized peer: peer={:?} msg=NEW_BLOCK", peer);
            return Ok(());
        }
        let new_block = rlp.as_val::<NewBlock>()?;
        let mut block = new_block.block;
        Self::recover_public(
            &mut block,
            self.get_transaction_pool(),
            &mut *self.get_transaction_pool().transaction_pubkey_cache.write(),
            &mut *self.graph.cache_man.lock(),
            &*self.get_transaction_pool().worker_pool.lock(),
        )?;
        debug!(
            "on_new_block, header={:?} tx_number={}",
            block.block_header,
            block.transactions.len()
        );
        let hash = block.block_header.hash();

        self.headers_in_flight.lock().remove(&hash);
        self.blocks_in_flight.lock().remove(&hash);

        let parent_hash = block.block_header.parent_hash().clone();
        let referee_hashes = block.block_header.referee_hashes().clone();

        let need_to_relay = self.on_new_decoded_block(block, true, true)?;

        debug_assert!(!self.graph.verified_invalid(&parent_hash));
        if !self.graph.contains_block_header(&parent_hash) {
            self.request_block_headers(
                io,
                Some(peer),
                &parent_hash,
                DEFAULT_GET_HEADERS_NUM,
            );
        }
        for hash in referee_hashes {
            debug_assert!(!self.graph.verified_invalid(&hash));
            if !self.graph.contains_block_header(&hash) {
                self.request_block_headers(
                    io,
                    Some(peer),
                    &hash,
                    DEFAULT_GET_HEADERS_NUM,
                );
            }
        }

        // broadcast the hash of the newly got block
        if !need_to_relay.is_empty() && !self.syn.read().catch_up_mode {
            let new_block_hash_msg: Box<dyn Message> =
                Box::new(NewBlockHashes {
                    block_hashes: need_to_relay,
                });
            self.broadcast_message(
                io,
                PeerId::max_value(),
                new_block_hash_msg.as_ref(),
                SendQueuePriority::High,
            )?;
        }
        Ok(())
    }

    fn on_new_block_hashes(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        if !self.syn.read().peers.contains_key(&peer) {
            warn!("Unexpected message from unrecognized peer: peer={:?} msg=NEW_BLOCK_HASHES", peer);
            return Ok(());
        }

        let new_block_hashes = rlp.as_val::<NewBlockHashes>()?;
        debug!("on_new_block_hashes, msg={:?}", new_block_hashes);

        for hash in new_block_hashes.block_hashes.iter() {
            if !self.graph.contains_block_header(hash) {
                self.request_block_headers(
                    io,
                    Some(peer),
                    hash,
                    DEFAULT_GET_HEADERS_NUM,
                );
            }
        }
        Ok(())
    }

    fn broadcast_message(
        &self, io: &NetworkContext, skip_id: PeerId, msg: &Message,
        priority: SendQueuePriority,
    ) -> Result<(), NetworkError>
    {
        let locked_syn = self.syn.read();
        let mut peer_ids: Vec<PeerId> = locked_syn
            .peers
            .keys()
            .filter(|&id| *id != skip_id)
            .map(|x| *x)
            .collect();

        let throttle_ratio = THROTTLING_SERVICE.read().get_throttling_ratio();
        let num_total = peer_ids.len();
        let num_allowed = (num_total as f64 * throttle_ratio) as usize;

        if num_total > num_allowed {
            debug!("apply throttling for broadcast_message, total: {}, allowed: {}", num_total, num_allowed);
            random::new().shuffle(&mut peer_ids);
            peer_ids.truncate(num_allowed);
        }

        for id in peer_ids {
            self.send_message(io, id, msg, priority)?;
        }

        Ok(())
    }

    fn send_status(
        &self, io: &NetworkContext, peer: PeerId,
    ) -> Result<(), NetworkError> {
        debug!("Sending status message to {:?}", peer);

        let (_guard, best_info) = self.graph.get_best_info().into();

        let msg: Box<dyn Message> = Box::new(Status {
            protocol_version: SYNCHRONIZATION_PROTOCOL_VERSION,
            network_id: 0x0,
            genesis_hash: self.graph.genesis_hash(),
            best_epoch: best_info.best_epoch_number as u64,
            terminal_block_hashes: best_info.terminal_block_hashes,
        });
        self.send_message(io, peer, msg.as_ref(), SendQueuePriority::High)
    }

    /// Remove in-flight blocks.
    /// Delay blocks requested before.
    fn preprocess_block_request(
        &self, hashes: &mut Vec<H256>, blocks_in_flight: &mut HashSet<H256>,
    ) {
        let mut block_request_waittime = self.block_request_waittime.lock();
        hashes.retain(|hash| {
            if blocks_in_flight.contains(hash) {
                false
            } else {
                blocks_in_flight.insert(*hash);
                match block_request_waittime.get_mut(hash) {
                    None => {
                        block_request_waittime.insert(
                            *hash,
                            Duration::new(
                                REQUEST_START_WAITING_TIME_SECONDS,
                                0,
                            ),
                        );
                        true
                    }
                    Some(t) => {
                        // It is requested before. To prevent possible attacks,
                        // we wait for more time to start
                        // the next request.
                        debug!(
                            "Block {:?} is requested again, delay for {:?}",
                            hash, t
                        );
                        self.waiting_requests.lock().push((
                            Instant::now() + *t,
                            WaitingRequest::Block(*hash),
                        ));
                        *t += Duration::new(
                            REQUEST_START_WAITING_TIME_SECONDS,
                            0,
                        );
                        false
                    }
                }
            }
        });
    }

    fn request_block_headers(
        &self, io: &NetworkContext, peer_id: Option<PeerId>, hash: &H256,
        max_blocks: u64,
    )
    {
        {
            let mut headers_in_flight = self.headers_in_flight.lock();
            let mut header_request_waittime =
                self.header_request_waittime.lock();
            if headers_in_flight.contains(hash) {
                return;
            } else {
                headers_in_flight.insert(hash.clone());
            }

            if peer_id.is_none() {
                let t = header_request_waittime
                    .entry(*hash)
                    .or_insert(Duration::new(0, 0));
                self.waiting_requests
                    .lock()
                    .push((Instant::now() + *t, WaitingRequest::Header(*hash)));
                *t += Duration::new(REQUEST_START_WAITING_TIME_SECONDS, 0);
                return;
            }

            match header_request_waittime.get_mut(hash) {
                None => header_request_waittime.insert(
                    *hash,
                    Duration::new(REQUEST_START_WAITING_TIME_SECONDS, 0),
                ),
                Some(t) => {
                    // It is requested before. To prevent possible attacks, we
                    // wait for more time to start the next
                    // request.
                    debug!(
                        "Header {:?} is requested again, delay for {:?}",
                        hash, t
                    );
                    self.waiting_requests.lock().push((
                        Instant::now() + *t,
                        WaitingRequest::Header(*hash),
                    ));
                    *t += Duration::new(REQUEST_START_WAITING_TIME_SECONDS, 0);
                    return;
                }
            };
        }

        if self
            .request_block_headers_unchecked(
                io,
                peer_id.unwrap(),
                hash,
                max_blocks,
            )
            .is_err()
        {
            let mut header_request_waittime =
                self.header_request_waittime.lock();
            let t = header_request_waittime
                .entry(*hash)
                .or_insert(Duration::new(0, 0));
            self.waiting_requests
                .lock()
                .push((Instant::now() + *t, WaitingRequest::Header(*hash)));
            *t += Duration::new(REQUEST_START_WAITING_TIME_SECONDS, 0);
        }
    }

    fn request_block_headers_unchecked(
        &self, io: &NetworkContext, peer_id: PeerId, hash: &H256,
        max_blocks: u64,
    ) -> Result<(), Error>
    {
        match self.send_request(
            io,
            peer_id,
            Box::new(RequestMessage::Headers(GetBlockHeaders {
                request_id: 0.into(),
                hash: *hash,
                max_blocks,
            })),
            SendQueuePriority::High,
        ) {
            Ok(timed_req) => {
                if let Some(timed_req) = timed_req {
                    debug!(
                       "Requesting {:?} block headers starting at {:?} from peer {:?} request_id={:?}",
                       max_blocks,
                       hash,
                       peer_id,
                       timed_req.request_id
                   );
                    self.requests_queue.lock().push(timed_req);
                } else {
                    debug!("Header request is added in pending queue. peer {}, hash {:?}", peer_id, *hash);
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn request_blocks(
        &self, io: &NetworkContext, peer_id: Option<PeerId>,
        mut hashes: Vec<H256>,
    )
    {
        {
            let mut blocks_in_flight = self.blocks_in_flight.lock();

            if peer_id.is_none() {
                let mut block_request_waittime =
                    self.block_request_waittime.lock();
                for hash in hashes {
                    if blocks_in_flight.contains(&hash) {
                        continue;
                    } else {
                        blocks_in_flight.insert(hash);
                    }

                    let t = block_request_waittime
                        .entry(hash)
                        .or_insert(Duration::new(0, 0));
                    self.waiting_requests.lock().push((
                        Instant::now() + *t,
                        WaitingRequest::Block(hash),
                    ));
                    *t += Duration::new(REQUEST_START_WAITING_TIME_SECONDS, 0);
                }
                return;
            }

            self.preprocess_block_request(&mut hashes, &mut *blocks_in_flight);
            if hashes.is_empty() {
                return;
            }
        }

        if self
            .request_blocks_unchecked(
                io,
                peer_id.unwrap(),
                &hashes,
                self.request_block_need_public(self.syn.read().catch_up_mode),
            )
            .is_err()
        {
            let mut block_request_waittime = self.block_request_waittime.lock();
            for hash in hashes {
                let t = block_request_waittime
                    .entry(hash)
                    .or_insert(Duration::new(0, 0));
                self.waiting_requests
                    .lock()
                    .push((Instant::now() + *t, WaitingRequest::Block(hash)));
                *t += Duration::new(REQUEST_START_WAITING_TIME_SECONDS, 0);
            }
        }
    }

    fn request_transactions(
        &self, io: &NetworkContext, peer_id: PeerId, indices: Vec<TransIndex>,
        tx_ids: HashSet<TxPropagateId>,
    ) -> Result<(), Error>
    {
        if indices.is_empty() {
            return Ok(());
        }

        match self.send_request(
            io,
            peer_id,
            Box::new(RequestMessage::Transactions(GetTransactions {
                request_id: 0.into(),
                indices,
                tx_ids,
            })),
            SendQueuePriority::Normal,
        ) {
            Ok(timed_req) => {
                if let Some(timed_req) = timed_req {
                    debug!(
                        "Requesting transactions from {:?} request_id={}",
                        peer_id, timed_req.request_id
                    );
                    self.requests_queue.lock().push(timed_req);
                } else {
                    debug!("Transactions request is added in pending queue. peer {}", peer_id);
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn request_blocks_unchecked(
        &self, io: &NetworkContext, peer_id: PeerId, hashes: &Vec<H256>,
        with_public: bool,
    ) -> Result<(), Error>
    {
        match self.send_request(
            io,
            peer_id,
            Box::new(RequestMessage::Blocks(GetBlocks {
                request_id: 0.into(),
                with_public,
                hashes: hashes.clone(),
            })),
            SendQueuePriority::High,
        ) {
            Ok(timed_req) => {
                if let Some(timed_req) = timed_req {
                    debug!(
                        "Requesting blocks {:?} from {:?} request_id={}",
                        hashes, peer_id, timed_req.request_id
                    );
                    self.requests_queue.lock().push(timed_req);
                } else {
                    debug!("Blocks request is added in pending queue. peer {}, hashes {:?}", peer_id, hashes);
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn request_compact_block(
        &self, io: &NetworkContext, peer_id: Option<PeerId>,
        mut hashes: Vec<H256>,
    )
    {
        {
            let mut blocks_in_flight = self.blocks_in_flight.lock();

            if peer_id.is_none() {
                let mut block_request_waittime =
                    self.block_request_waittime.lock();
                for hash in hashes {
                    if blocks_in_flight.contains(&hash) {
                        continue;
                    } else {
                        blocks_in_flight.insert(hash);
                    }

                    let t = block_request_waittime
                        .entry(hash)
                        .or_insert(Duration::new(0, 0));
                    self.waiting_requests.lock().push((
                        Instant::now() + *t,
                        WaitingRequest::Block(hash),
                    ));
                    *t += Duration::new(REQUEST_START_WAITING_TIME_SECONDS, 0);
                }
                return;
            }

            self.preprocess_block_request(&mut hashes, &mut *blocks_in_flight);
            if hashes.is_empty() {
                return;
            }
        }
        if self
            .request_compact_block_unchecked(io, peer_id.unwrap(), &hashes)
            .is_err()
        {
            let mut block_request_waittime = self.block_request_waittime.lock();
            for hash in hashes {
                let t = block_request_waittime
                    .entry(hash)
                    .or_insert(Duration::new(0, 0));
                self.waiting_requests
                    .lock()
                    .push((Instant::now() + *t, WaitingRequest::Block(hash)));
                *t += Duration::new(REQUEST_START_WAITING_TIME_SECONDS, 0);
            }
        }
    }

    fn request_compact_block_unchecked(
        &self, io: &NetworkContext, peer_id: PeerId, hashes: &Vec<H256>,
    ) -> Result<(), Error> {
        match self.send_request(
            io,
            peer_id,
            Box::new(RequestMessage::Compact(GetCompactBlocks {
                request_id: 0.into(),
                hashes: hashes.clone(),
            })),
            SendQueuePriority::High,
        ) {
            Ok(timed_req) => {
                if let Some(timed_req) = timed_req {
                    debug!(
                        "Requesting compact blocks {:?} from {:?} request_id={}",
                        hashes, peer_id, timed_req.request_id
                    );
                    self.requests_queue.lock().push(timed_req);
                } else {
                    debug!("Compact block request is added in pending queue. peer {}, hashes {:?}", peer_id, hashes);
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn request_blocktxn(
        &self, io: &NetworkContext, peer_id: PeerId, block_hash: H256,
        indexes: Vec<usize>,
    ) -> Result<(), Error>
    {
        match self.send_request(
            io,
            peer_id,
            Box::new(RequestMessage::BlockTxn(GetBlockTxn {
                request_id: 0.into(),
                block_hash: block_hash.clone(),
                indexes: indexes.clone(),
            })),
            SendQueuePriority::High,
        ) {
            Ok(timed_req) => {
                if let Some(timed_req) = timed_req {
                    debug!(
                        "Requesting blocktxn {:?} from {:?} request_id={}",
                        block_hash, peer_id, timed_req.request_id
                    );
                    self.requests_queue.lock().push(timed_req);
                } else {
                    debug!("request_blocktxn is added in pending queue. peer {}, hash {:?}", peer_id, block_hash);
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn send_request(
        &self, io: &NetworkContext, peer: PeerId, mut msg: Box<RequestMessage>,
        priority: SendQueuePriority,
    ) -> Result<Option<Arc<TimedSyncRequests>>, Error>
    {
        let peer_info = self.syn.read().get_peer_info(&peer)?;
        let result = {
            let mut peer_info = peer_info.write();
            if let Some(request_id) = peer_info.get_next_request_id() {
                msg.set_request_id(request_id);
                self.send_message(io, peer, msg.get_msg(), priority)
                    .unwrap_or_else(|e| {
                        warn!("Error while send_message, err={:?}", e);
                    });
                let timed_req = Arc::new(TimedSyncRequests::from_request(
                    peer,
                    request_id,
                    &msg,
                    &self.protocol_config,
                ));
                peer_info.append_inflight_request(
                    request_id,
                    msg,
                    timed_req.clone(),
                );
                Ok(Some(timed_req))
            } else {
                trace!("Append requests for later:{:?}", msg);
                peer_info.append_pending_request(msg);
                Ok(None)
            }
        };

        {
            let syn = self.syn.read();
            let cur_peer_info =
                syn.peers.get(&peer).ok_or(ErrorKind::UnknownPeer)?;

            if !Arc::ptr_eq(&cur_peer_info, &peer_info) {
                return Err(ErrorKind::UnknownPeer.into());
            }
        }

        result
    }

    fn match_request(
        &self, io: &NetworkContext, peer: PeerId, request_id: u64,
    ) -> Result<RequestMessage, Error> {
        let peer_info = self.syn.read().get_peer_info(&peer)?;
        let mut peer_info = peer_info.write();
        let removed_req = self.remove_request(&mut *peer_info, request_id);
        if let Some(removed_req) = removed_req {
            while peer_info.has_pending_requests() {
                if let Some(new_request_id) = peer_info.get_next_request_id() {
                    let mut pending_msg =
                        peer_info.pop_pending_request().unwrap();
                    pending_msg.set_request_id(new_request_id);
                    // FIXME: May need to set priority more precisely.
                    // Simply treat request as high priority for now.
                    let send_res = self.send_message(
                        io,
                        peer,
                        pending_msg.get_msg(),
                        SendQueuePriority::High,
                    );

                    if send_res.is_err() {
                        warn!("Error while send_message, err={:?}", send_res);
                        peer_info.append_pending_request(pending_msg);
                        return Err(send_res.err().unwrap().into());
                    }

                    let timed_req = Arc::new(TimedSyncRequests::from_request(
                        peer,
                        new_request_id,
                        &pending_msg,
                        &self.protocol_config,
                    ));
                    peer_info.append_inflight_request(
                        new_request_id,
                        pending_msg,
                        timed_req.clone(),
                    );
                    self.requests_queue.lock().push(timed_req);
                } else {
                    break;
                }
            }
            Ok(removed_req)
        } else {
            Err(ErrorKind::UnexpectedResponse.into())
        }
    }

    fn choose_peer_after_failure(&self, failed_peer: PeerId) -> Option<PeerId> {
        let syn = self.syn.read();
        if syn.peers.len() <= 1 {
            Some(failed_peer)
        } else {
            let mut exclude = HashSet::new();
            exclude.insert(failed_peer);
            syn.get_random_peer(&exclude)
        }
    }

    pub fn announce_new_blocks(&self, io: &NetworkContext, hashes: &[H256]) {
        let syn = self.syn.read();
        for hash in hashes {
            let block = self.graph.block_by_hash(hash).unwrap();
            let msg: Box<dyn Message> = Box::new(NewBlock {
                block: (*block).clone().into(),
            });
            for (id, _) in syn.peers.iter() {
                self.send_message_with_throttling(
                    io,
                    *id,
                    msg.as_ref(),
                    SendQueuePriority::High,
                    true,
                )
                .unwrap_or_else(|e| {
                    warn!("Error sending new blocks, err={:?}", e);
                });
            }
        }
    }

    pub fn relay_blocks(
        &self, io: &NetworkContext, need_to_relay: Vec<H256>,
    ) -> Result<(), Error> {
        if !need_to_relay.is_empty() && !self.syn.read().catch_up_mode {
            let new_block_hash_msg: Box<dyn Message> =
                Box::new(NewBlockHashes {
                    block_hashes: need_to_relay,
                });
            self.broadcast_message(
                io,
                PeerId::max_value(),
                new_block_hash_msg.as_ref(),
                SendQueuePriority::High,
            )?;
        }

        Ok(())
    }

    fn get_transaction_pool(&self) -> SharedTransactionPool {
        self.graph.consensus.txpool.clone()
    }

    fn select_peers_for_transactions<F>(
        &self, syn: &mut SynchronizationState, filter: F,
    ) -> Vec<PeerId>
    where F: Fn(&PeerId) -> bool {
        let num_peers = syn.peers.len() as f64;
        let throttle_ratio = THROTTLING_SERVICE.read().get_throttling_ratio();

        // min(sqrt(x)/x, throttle_ratio)
        let chosen_size = (num_peers.powf(-0.5).min(throttle_ratio) * num_peers)
            .round() as usize;
        let mut peer_vec = syn.get_random_peer_vec(
            chosen_size.max(MIN_PEERS_PROPAGATION),
            filter,
        );
        peer_vec.truncate(MAX_PEERS_PROPAGATION);
        peer_vec
    }

    fn propagate_transactions_to_peers(
        &self, io: &NetworkContext, peers: Vec<PeerId>,
        transactions: HashMap<H256, Arc<SignedTransaction>>,
    )
    {
        if transactions.is_empty() {
            return;
        }
        let lucky_peers = {
            peers
                .into_iter()
                .filter_map(|peer_id| {
                    let peer_info =
                        match self.syn.read().get_peer_info(&peer_id) {
                            Ok(peer_info) => peer_info,
                            Err(_) => {
                                return None;
                            }
                        };
                    if !peer_info.read().need_prop_trans {
                        return None;
                    }
                    Some(peer_id)
                })
                .collect::<Vec<_>>()
        };
        if lucky_peers.is_empty() {
            return;
        }
        let mut tx_msg = Box::new(TransactionDigests {
            window_index: 0,
            trans_short_ids: Vec::new(),
        });
        {
            let mut syn = self.syn.write();
            let mut total_tx_bytes = 0;
            let mut new_last_sent_transaction_hashes =
                HashSet::with_capacity(transactions.len());
            let mut keep_adding = true;
            let mut sent_transactions = Vec::new();

            // After the iteration,
            // sent_transactions =
            // transactions.difference(last_sent_transaction_hashes)
            // and `sent_transactions` is bounded by
            // `MAX_TXS_BYTES_TO_PROPAGATE`
            //
            // new_last_sent_transaction_hashes =
            // last_sent_transaction_hashes.intersect(transactions).
            // union(sent_transactions)
            for (h, tx) in transactions {
                if syn.last_sent_transaction_hashes.contains(&h) {
                    // Intersection part
                    new_last_sent_transaction_hashes.insert(h);
                } else if keep_adding {
                    // Difference part for sent_transactions
                    total_tx_bytes += tx.rlp_size();
                    if total_tx_bytes >= MAX_TXS_BYTES_TO_PROPAGATE {
                        keep_adding = false;
                        continue;
                    }
                    sent_transactions.push(tx.clone());
                    tx_msg.trans_short_ids.push(TxPropagateId::from(h));
                    new_last_sent_transaction_hashes.insert(h);
                }
            }

            syn.last_sent_transaction_hashes = new_last_sent_transaction_hashes;
            tx_msg.window_index =
                syn.sent_transactions.append_transactions(sent_transactions);
        }
        if tx_msg.trans_short_ids.is_empty() {
            return;
        }

        debug!(
            "Sent {} transaction ids to {} peers.",
            tx_msg.trans_short_ids.len(),
            lucky_peers.len()
        );
        for peer_id in lucky_peers {
            match self.send_message(
                io,
                peer_id,
                tx_msg.as_ref(),
                SendQueuePriority::Normal,
            ) {
                Ok(_) => {
                    trace!(
                        "{:02} <- Transactions ({} entries)",
                        peer_id,
                        tx_msg.trans_short_ids.len()
                    );
                }
                Err(e) => {
                    warn!(
                        "failed to propagate transaction ids to peer, id: {}, err: {}",
                        peer_id, e
                    );
                }
            }
        }
    }

    pub fn propagate_new_transactions(&self, io: &NetworkContext) {
        {
            let syn = self.syn.read();
            if syn.peers.is_empty() || syn.catch_up_mode {
                return;
            }
        }

        let transactions =
            self.get_transaction_pool().transactions_to_propagate();
        if transactions.is_empty() {
            return;
        }

        let peers = {
            let mut syn = self.syn.write();
            self.select_peers_for_transactions(&mut *syn, |_| true)
        };

        self.propagate_transactions_to_peers(io, peers, transactions);
    }

    pub fn remove_expired_flying_request(&self, io: &NetworkContext) {
        // Check if in-flight requests timeout
        let now = Instant::now();
        let mut timeout_requests = Vec::new();
        {
            let mut requests = self.requests_queue.lock();
            loop {
                if requests.is_empty() {
                    break;
                }
                let sync_req = requests.pop().expect("queue not empty");
                if sync_req.removed.load(AtomicOrdering::Relaxed) == true {
                    continue;
                }
                if sync_req.timeout_time >= now {
                    requests.push(sync_req);
                    break;
                } else {
                    // TODO And should handle timeout peers.
                    timeout_requests.push(sync_req);
                }
            }
        }
        for sync_req in timeout_requests {
            warn!("Timeout sync_req: {:?}", sync_req);
            let req =
                self.match_request(io, sync_req.peer_id, sync_req.request_id);
            match req {
                Ok(request) => {
                    // TODO may have better choice than random peer
                    debug!("Timeout request: {:?}", request);
                    self.send_request_again(request, io);
                }
                Err(e) => {
                    debug!("Timeout a removed request err={:?}", e);
                }
            }
        }

        // Send waiting requests that their backoff delay have passes
        let mut waiting_requests = self.waiting_requests.lock();
        loop {
            if waiting_requests.is_empty() {
                break;
            }
            let peek_req = waiting_requests.peek().expect("queue not empty");
            if peek_req.0 >= now {
                break;
            } else {
                let (chosen_peer, catch_up_mode) = {
                    let syn = self.syn.read();
                    let chosen_peer = match syn.get_random_peer(&HashSet::new())
                    {
                        Some(p) => p,
                        None => {
                            break;
                        }
                    };
                    (chosen_peer, syn.catch_up_mode)
                };

                // Waiting requests are already in-flight, so send them without
                // checking
                match &peek_req.1 {
                    WaitingRequest::Header(h) => {
                        if self
                            .request_block_headers_unchecked(
                                io,
                                chosen_peer,
                                h,
                                1,
                            )
                            .is_err()
                        {
                            // Failed due to no peer.
                            break;
                        }
                    }
                    WaitingRequest::Block(h) => {
                        let blocks = vec![h.clone()];
                        if self
                            .request_blocks_unchecked(
                                io,
                                chosen_peer,
                                &blocks,
                                self.request_block_need_public(catch_up_mode),
                            )
                            .is_err()
                        {
                            // Failed due to no peer.
                            break;
                        }
                    }
                }
                waiting_requests.pop().expect("queue not empty");
            }
        }
    }

    fn send_request_again(&self, request: RequestMessage, io: &NetworkContext) {
        let chosen_peer = self.syn.read().get_random_peer(&HashSet::new());
        match request {
            RequestMessage::Headers(get_headers) => {
                self.request_block_headers(
                    io,
                    chosen_peer,
                    &get_headers.hash,
                    get_headers.max_blocks,
                );
            }
            RequestMessage::Blocks(get_blocks) => {
                self.request_blocks(io, chosen_peer, get_blocks.hashes);
            }
            RequestMessage::Compact(get_compact) => {
                {
                    let mut blocks_in_flight = self.blocks_in_flight.lock();
                    for hash in &get_compact.hashes {
                        blocks_in_flight.remove(hash);
                    }
                }
                self.request_blocks(io, chosen_peer, get_compact.hashes);
            }
            RequestMessage::BlockTxn(blocktxn) => {
                let mut hashes = Vec::new();
                hashes.push(blocktxn.block_hash);
                self.request_blocks(io, chosen_peer, hashes);
            }
            _ => {}
        }
    }

    pub fn remove_request(
        &self, peer_info: &mut SynchronizationPeerState, request_id: u64,
    ) -> Option<RequestMessage> {
        if let Some(req) = peer_info.remove_inflight_request(request_id) {
            match *req.message {
                RequestMessage::Headers(ref get_headers) => {
                    self.headers_in_flight.lock().remove(&get_headers.hash);
                }
                RequestMessage::Blocks(ref get_blocks) => {
                    let mut blocks = self.blocks_in_flight.lock();
                    for hash in &get_blocks.hashes {
                        blocks.remove(hash);
                    }
                }
                RequestMessage::BlockTxn(ref blocktxn) => {
                    self.blocks_in_flight.lock().remove(&blocktxn.block_hash);
                }
                RequestMessage::Transactions(ref get_transactions) => {
                    let mut syn = self.syn.write();
                    for tx_id in &get_transactions.tx_ids {
                        syn.inflight_requested_transactions.remove(tx_id);
                    }
                }
                _ => {}
            }
            req.timed_req.removed.store(true, AtomicOrdering::Relaxed);
            Some(*req.message)
        } else {
            None
        }
    }

    pub fn batch_recover_with_cache(
        transactions: &Vec<TransactionWithSignature>,
        tx_cache: &mut HashMap<H256, Arc<SignedTransaction>>,
        cache_man: &mut CacheManager<CacheId>,
    ) -> Result<Vec<Arc<SignedTransaction>>, DecoderError>
    {
        let mut recovered_transactions = Vec::with_capacity(transactions.len());
        for transaction in transactions {
            match tx_cache.get(&transaction.hash()) {
                Some(tx) => recovered_transactions.push(tx.clone()),
                None => match transaction.recover_public() {
                    Ok(public) => {
                        let tx = Arc::new(SignedTransaction::new(
                            public,
                            transaction.clone(),
                        ));
                        recovered_transactions.push(tx.clone());
                        cache_man
                            .note_used(CacheId::TransactionPubkey(tx.hash()));
                        tx_cache.insert(tx.hash(), tx);
                    }
                    Err(_) => {
                        return Err(DecoderError::Custom(
                            "Cannot recover public key",
                        ));
                    }
                },
            }
        }

        Ok(recovered_transactions)
    }

    pub fn recover_public(
        block: &mut Block, tx_pool: SharedTransactionPool,
        tx_cache: &mut HashMap<H256, Arc<SignedTransaction>>,
        cache_man: &mut CacheManager<CacheId>, worker_pool: &ThreadPool,
    ) -> Result<(), DecoderError>
    {
        debug!("recover public for block started.");
        let mut recovered_transactions =
            Vec::with_capacity(block.transactions.len());
        let mut uncached_trans = Vec::with_capacity(block.transactions.len());
        for (idx, transaction) in block.transactions.iter().enumerate() {
            match tx_cache.get(&transaction.hash()) {
                Some(tx) => recovered_transactions.push(tx.clone()),
                None => match tx_pool.get_transaction(&transaction.hash()) {
                    Some(tx) => recovered_transactions.push(tx.clone()),
                    None => {
                        uncached_trans.push((idx, transaction.clone()));
                        recovered_transactions.push(transaction.clone());
                    }
                },
            }
        }

        if uncached_trans.len() < WORKER_COMPUTATION_PARALLELISM * 8 {
            for (idx, tx) in uncached_trans {
                if tx.public.is_none() {
                    if let Ok(public) = tx.recover_public() {
                        recovered_transactions[idx] =
                            Arc::new(SignedTransaction::new(
                                public,
                                tx.transaction.clone(),
                            ));
                    } else {
                        info!(
                            "Unable to recover the public key of transaction {:?}",
                            tx.hash()
                        );
                        return Err(DecoderError::Custom(
                            "Cannot recover public key",
                        ));
                    }
                } else {
                    let res = tx.verify_public(true); // skip verification
                    if res.is_ok() && res.unwrap() {
                        recovered_transactions[idx] =
                            Arc::new(SignedTransaction::new(
                                tx.public.unwrap(),
                                tx.transaction.clone(),
                            ));
                    } else {
                        info!("Failed to verify the public key of transaction {:?}", tx.hash());
                        return Err(DecoderError::Custom(
                            "Cannot recover public key",
                        ));
                    }
                }
            }
        } else {
            let tx_num = uncached_trans.len();
            let tx_num_per_worker = tx_num / WORKER_COMPUTATION_PARALLELISM;
            let mut remainder =
                tx_num - (tx_num_per_worker * WORKER_COMPUTATION_PARALLELISM);
            let mut start_idx = 0;
            let mut end_idx = 0;
            let mut unsigned_trans = Vec::new();

            for tx in uncached_trans {
                if start_idx == end_idx {
                    // a new segment of transactions
                    end_idx = start_idx + tx_num_per_worker;
                    if remainder > 0 {
                        end_idx += 1;
                        remainder -= 1;
                    }
                    let unsigned_txes = Vec::new();
                    unsigned_trans.push(unsigned_txes);
                }

                unsigned_trans.last_mut().unwrap().push(tx);

                start_idx += 1;
            }

            let (sender, receiver) = channel();
            let n_thread = unsigned_trans.len();
            for unsigned_txes in unsigned_trans {
                let sender = sender.clone();
                worker_pool.execute(move || {
                    let mut signed_txes = Vec::new();
                    for (idx, tx) in unsigned_txes {
                        if tx.public.is_none() {
                            if let Ok(public) = tx.recover_public() {
                                signed_txes.push((idx, public));
                            } else {
                                info!(
                                    "Unable to recover the public key of transaction {:?}",
                                    tx.hash()
                                );
                                break;
                            }
                        } else {
                            let res = tx.verify_public(true); // skip verification
                            if res.is_ok() && res.unwrap() {
                                signed_txes.push((idx, tx.public.clone().unwrap()));
                            } else {
                                info!("Failed to verify the public key of transaction {:?}", tx.hash());
                                break;
                            }
                        }
                    }
                    sender.send(signed_txes).unwrap();
                });
            }
            worker_pool.join();

            let mut total_recovered_num = 0 as usize;
            for tx_publics in receiver.iter().take(n_thread) {
                total_recovered_num += tx_publics.len();
                for (idx, public) in tx_publics {
                    let tx = Arc::new(SignedTransaction::new(
                        public,
                        recovered_transactions[idx].transaction.clone(),
                    ));
                    cache_man.note_used(CacheId::TransactionPubkey(tx.hash()));
                    tx_cache.insert(tx.hash(), tx.clone());
                    recovered_transactions[idx] = tx;
                }
            }

            if total_recovered_num != tx_num {
                info!(
                    "Failed to recover public for block {:?}",
                    block.block_header.hash()
                );
                return Err(DecoderError::Custom("Cannot recover public key"));
            }
        }

        block.transactions = recovered_transactions;
        debug!("recover public for block finished.");
        Ok(())
    }

    fn block_cache_gc(&self) { self.graph.block_cache_gc(); }

    fn log_statistics(&self) { self.graph.log_statistics(); }

    fn update_catch_up_mode(&self, io: &NetworkContext) {
        let mut peer_best_epoches = {
            let syn = self.syn.read();
            syn.peers
                .iter()
                .map(|(_, state)| state.read().best_epoch)
                .collect::<Vec<_>>()
        };

        if peer_best_epoches.is_empty() {
            return;
        }

        peer_best_epoches.sort();
        let middle_epoch = peer_best_epoches[peer_best_epoches.len() / 2];

        let (need_notify, catch_up_mode) = {
            let mut syn = self.syn.write();
            if self.graph.best_epoch_number() + CATCH_UP_EPOCH_LAG_THRESHOLD
                >= middle_epoch
            {
                syn.catch_up_mode = false;
            } else {
                syn.catch_up_mode = true;
            }

            let catch_up_mode = syn.catch_up_mode;

            let mut need_notify = Vec::new();
            for (peer, state) in syn.peers.iter_mut() {
                let mut state = state.write();
                if state.notified_mode.is_none()
                    || (state.notified_mode.unwrap() != catch_up_mode)
                {
                    state.received_transaction_count = 0;
                    state.notified_mode = Some(catch_up_mode);
                    need_notify.push(*peer);
                }
            }

            (need_notify, catch_up_mode)
        };

        info!("Catch-up mode: {}", catch_up_mode);

        let trans_prop_ctrl_msg: Box<dyn Message> =
            Box::new(TransactionPropagationControl { catch_up_mode });

        for peer in need_notify {
            if self
                .send_message(
                    io,
                    peer,
                    trans_prop_ctrl_msg.as_ref(),
                    SendQueuePriority::High,
                )
                .is_err()
            {
                info!(
                    "Failed to send transaction control message to peer {}",
                    peer
                );
            }
        }
    }

    fn dispatch_recover_public_task(
        &self, io: &NetworkContext, blocks: Vec<Block>,
        requested: HashSet<H256>, failed_peer: PeerId, compact: bool,
    )
    {
        self.recover_public_queue
            .lock()
            .push_back(RecoverPublicTask {
                blocks,
                requested,
                failed_peer,
                compact,
            });

        io.dispatch_work(SyncHandlerWorkType::RecoverPublic as HandlerWorkType);
    }

    fn request_block_need_public(&self, catch_up_mode: bool) -> bool {
        catch_up_mode && self.protocol_config.request_block_with_public
    }
}

impl NetworkProtocolHandler for SynchronizationProtocolHandler {
    fn initialize(&self, io: &NetworkContext) {
        io.register_timer(TX_TIMER, self.protocol_config.send_tx_period)
            .expect("Error registering transactions timer");
        io.register_timer(
            CHECK_REQUEST_TIMER,
            self.protocol_config.check_request_period,
        )
        .expect("Error registering transactions timer");
        io.register_timer(
            BLOCK_CACHE_GC_TIMER,
            self.protocol_config.block_cache_gc_period,
        )
        .expect("Error registering block_cache_gc timer");
        io.register_timer(
            CHECK_CATCH_UP_MODE_TIMER,
            Duration::from_millis(5000),
        )
        .expect("Error registering check_catch_up_mode timer");
        io.register_timer(LOG_STATISTIC_TIMER, Duration::from_millis(5000))
            .expect("Error registering log_statistics timer");
    }

    fn on_message(&self, io: &NetworkContext, peer: PeerId, raw: &[u8]) {
        let msg_id = raw[0];
        let rlp = Rlp::new(&raw[1..]);
        debug!("on_message: peer={:?}, msgid={:?}", peer, msg_id);
        self.dispatch_message(io, peer, msg_id.into(), rlp);
    }

    fn on_work_dispatch(
        &self, io: &NetworkContext, work_type: HandlerWorkType,
    ) {
        if work_type == SyncHandlerWorkType::RecoverPublic as HandlerWorkType {
            if let Err(e) = self.on_blocks_inner_task(io) {
                warn!("Error processing RecoverPublic task: {:?}", e);
            }
        } else {
            warn!("Unknown SyncHandlerWorkType");
        }
    }

    fn on_peer_connected(&self, io: &NetworkContext, peer: PeerId) {
        let mut syn = self.syn.write();

        info!("Peer connected: peer={:?}", peer);
        if let Err(e) = self.send_status(io, peer) {
            debug!("Error sending status message: {:?}", e);
            io.disconnect_peer(peer);
        } else {
            syn.handshaking_peers.insert(peer, Instant::now());
        }
    }

    fn on_peer_disconnected(&self, io: &NetworkContext, peer: PeerId) {
        info!("Peer disconnected: peer={:?}", peer);
        let mut unfinished_requests = Vec::new();
        {
            let mut syn = self.syn.write();
            if let Some(peer_state) = syn.peers.remove(&peer) {
                let mut peer_state = peer_state.write();
                while let Some(maybe_req) = peer_state.inflight_requests.pop() {
                    if let Some(req) = maybe_req {
                        req.timed_req
                            .removed
                            .store(true, AtomicOrdering::Relaxed);
                        unfinished_requests.push(req.message);
                    }
                }

                while let Some(req) = peer_state.pending_requests.pop_front() {
                    unfinished_requests.push(req);
                }
            }
            syn.handshaking_peers.remove(&peer);
        }

        for request in unfinished_requests {
            match &*request {
                RequestMessage::Headers(get_headers) => {
                    self.headers_in_flight.lock().remove(&get_headers.hash);
                    self.header_request_waittime
                        .lock()
                        .remove(&get_headers.hash);
                }
                RequestMessage::Blocks(get_blocks) => {
                    for hash in get_blocks.hashes.iter() {
                        self.blocks_in_flight.lock().remove(hash);
                        self.block_request_waittime.lock().remove(hash);
                    }
                }
                RequestMessage::Compact(get_compact) => {
                    for hash in &get_compact.hashes {
                        self.blocks_in_flight.lock().remove(hash);
                        self.block_request_waittime.lock().remove(hash);
                    }
                }
                RequestMessage::BlockTxn(blocktxn) => {
                    self.blocks_in_flight.lock().remove(&blocktxn.block_hash);
                    self.block_request_waittime
                        .lock()
                        .remove(&blocktxn.block_hash);
                }
                RequestMessage::Transactions(get_transactions) => {
                    let mut syn = self.syn.write();
                    for tx_id in &get_transactions.tx_ids {
                        syn.inflight_requested_transactions.remove(tx_id);
                    }
                }
                _ => {}
            }

            self.send_request_again(*request, io);
        }
    }

    fn on_timeout(&self, io: &NetworkContext, timer: TimerToken) {
        trace!("Timeout: timer={:?}", timer);

        match timer {
            TX_TIMER => {
                self.propagate_new_transactions(io);
            }
            CHECK_REQUEST_TIMER => {
                self.remove_expired_flying_request(io);
            }
            BLOCK_CACHE_GC_TIMER => {
                self.block_cache_gc();
            }
            CHECK_CATCH_UP_MODE_TIMER => {
                self.update_catch_up_mode(io);
            }
            LOG_STATISTIC_TIMER => {
                self.log_statistics();
            }
            _ => warn!("Unknown timer {} triggered.", timer),
        }
    }
}
