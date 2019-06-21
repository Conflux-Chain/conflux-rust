// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    super::transaction_pool::SharedTransactionPool, random, Error, ErrorKind,
    SharedSynchronizationGraph, SynchronizationGraph, SynchronizationPeerState,
    SynchronizationState,
};
use crate::{consensus::SharedConsensusGraph, pow::ProofOfWorkConfig};
use cfx_types::H256;
use io::TimerToken;
use message::{
    GetBlockHashesByEpoch, GetBlockHashesResponse, GetBlockHeaders,
    GetBlockHeadersResponse, GetBlockTxn, GetBlockTxnResponse, GetBlocks,
    GetBlocksResponse, GetBlocksWithPublicResponse, GetCompactBlocks,
    GetCompactBlocksResponse, GetTerminalBlockHashes,
    GetTerminalBlockHashesResponse, GetTransactions, GetTransactionsResponse,
    Message, MsgId, NewBlock, NewBlockHashes, Status, TransactionDigests,
    TransactionPropagationControl, Transactions,
};
use network::{
    throttling::THROTTLING_SERVICE, Error as NetworkError, HandlerWorkType,
    NetworkContext, NetworkProtocolHandler, PeerId, UpdateNodeOperation,
};
use parking_lot::Mutex;
use rand::Rng;
use rlp::Rlp;
//use slab::Slab;
use super::{
    msg_sender::{send_message, send_message_with_throttling},
    request_manager::{RequestManager, RequestMessage},
};
use crate::{
    cache_manager::{CacheId, CacheManager},
    pow::WORKER_COMPUTATION_PARALLELISM,
    verification::VerificationConfig,
};
use metrics::Gauge;
use primitives::{
    Block, SignedTransaction, TransactionWithSignature, TxPropagateId,
};
use priority_send_queue::SendQueuePriority;
use rlp::DecoderError;
use std::{
    cmp,
    collections::{HashMap, HashSet, VecDeque},
    iter::FromIterator,
    sync::{atomic::Ordering as AtomicOrdering, mpsc::channel, Arc},
    time::{Duration, Instant},
};
use threadpool::ThreadPool;
lazy_static! {
    static ref TX_PROPAGATE_GAUGE: Gauge =
        Gauge::register("tx_propagate_set_size");
}

const CATCH_UP_EPOCH_LAG_THRESHOLD: u64 = 3;

pub const SYNCHRONIZATION_PROTOCOL_VERSION: u8 = 0x01;

pub const MAX_HEADERS_TO_SEND: u64 = 512;
pub const MAX_BLOCKS_TO_SEND: u64 = 256;
const MAX_PACKET_SIZE: usize = 15 * 1024 * 1024 + 512 * 1024; // 15.5 MB
const DEFAULT_GET_HEADERS_NUM: u64 = 1;
const DEFAULT_GET_PARENT_HEADERS_NUM: u64 = 30;
lazy_static! {
    pub static ref REQUEST_START_WAITING_TIME: Duration =
        Duration::from_secs(1);
}
//const REQUEST_WAITING_TIME_BACKOFF: u32 = 2;

const TX_TIMER: TimerToken = 0;
const CHECK_REQUEST_TIMER: TimerToken = 1;
const BLOCK_CACHE_GC_TIMER: TimerToken = 2;
const CHECK_CATCH_UP_MODE_TIMER: TimerToken = 3;
const LOG_STATISTIC_TIMER: TimerToken = 4;
const TOTAL_WEIGHT_IN_PAST_TIMER: TimerToken = 5;

const MAX_TXS_BYTES_TO_PROPAGATE: usize = 1024 * 1024; // 1MB

pub const EPOCH_RETRY_TIME_SECONDS: u64 = 1;
const EPOCH_SYNC_MAX_INFLIGHT: u64 = 10;

// make sure we do not request overlapping regions of the DAG
const EPOCH_SYNC_STRIDE: u64 = DEFAULT_GET_PARENT_HEADERS_NUM;

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
    syn: Arc<SynchronizationState>,
    request_manager: Arc<RequestManager>,
    latest_epoch_requested: Mutex<u64>,

    // Worker task queue for recover public
    recover_public_queue: Mutex<VecDeque<RecoverPublicTask>>,
}

#[derive(Clone)]
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
    pub min_peers_propagation: usize,
    pub max_peers_propagation: usize,
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

        let syn = Arc::new(SynchronizationState::new(start_as_catch_up_mode));

        let request_manager =
            Arc::new(RequestManager::new(&protocol_config, syn.clone()));

        Self {
            protocol_config,
            graph: Arc::new(SynchronizationGraph::new(
                consensus_graph.clone(),
                verification_config,
                pow_config,
                fast_recover,
            )),
            syn,
            request_manager,
            latest_epoch_requested: Mutex::new(0),
            recover_public_queue: Mutex::new(VecDeque::new()),
        }
    }

    fn get_to_propagate_trans(&self) -> HashMap<H256, Arc<SignedTransaction>> {
        self.graph.get_to_propagate_trans()
    }

    fn set_to_propagate_trans(
        &self, transactions: HashMap<H256, Arc<SignedTransaction>>,
    ) {
        self.graph.set_to_propagate_trans(transactions);
    }

    pub fn catch_up_mode(&self) -> bool {
        self.syn.catch_up_mode.load(AtomicOrdering::Relaxed)
    }

    pub fn get_synchronization_graph(&self) -> SharedSynchronizationGraph {
        self.graph.clone()
    }

    pub fn append_received_transactions(
        &self, transactions: Vec<Arc<SignedTransaction>>,
    ) {
        self.request_manager
            .append_received_transactions(transactions);
    }

    pub fn block_by_hash(&self, hash: &H256) -> Option<Arc<Block>> {
        self.graph.block_by_hash(hash)
    }

    fn best_peer_epoch(&self) -> Option<u64> {
        self.syn
            .peers
            .read()
            .iter()
            .map(|(_, state)| state.read().best_epoch)
            .fold(None, |max, x| match max {
                None => Some(x),
                Some(max) => Some(if x > max { x } else { max }),
            })
    }

    fn dispatch_message(
        &self, io: &NetworkContext, peer: PeerId, msg_id: MsgId, rlp: Rlp,
    ) {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);
        if !self.syn.contains_peer(&peer) {
            debug!(
                "dispatch_message: Peer does not exist: peer={} msg_id={}",
                peer, msg_id
            );
            // We may only receive status message from a peer not in
            // `syn.peers`, and this peer should be in
            // `syn.handshaking_peers`
            if !self.syn.handshaking_peers.read().contains_key(&peer)
                || msg_id != MsgId::STATUS
            {
                warn!("Message from unknown peer {:?}", msg_id);
                return;
            }
        }
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
            MsgId::TRANSACTIONS => self.on_transactions(peer, &rlp),
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
            MsgId::GET_BLOCK_HASHES_BY_EPOCH => {
                self.on_get_block_hashes_by_epoch(io, peer, &rlp)
            }
            MsgId::GET_BLOCK_HASHES_RESPONSE => {
                self.on_block_hashes_response(io, peer, &rlp)
            }
            _ => {
                warn!("Unknown message: peer={:?} msgid={:?}", peer, msg_id);
                io.disconnect_peer(peer, Some(UpdateNodeOperation::Remove));
                Ok(())
            }
        }
        .unwrap_or_else(|e| self.handle_error(io, peer, msg_id, e));
    }

    /// Error handling for dispatched messages.
    fn handle_error(
        &self, io: &NetworkContext, peer: PeerId, msg_id: MsgId, e: Error,
    ) {
        warn!(
            "Error while handling message, peer={}, msgid={:?}, error={:?}",
            peer, msg_id, e
        );

        let mut disconnect = true;
        let mut op = None;

        // NOTE, DO NOT USE WILDCARD IN THE FOLLOWING MATCH STATEMENT!
        // COMPILER WILL HELP TO FIND UNHANDLED ERROR CASES.
        match e.0 {
            ErrorKind::Invalid => op = Some(UpdateNodeOperation::Demotion),
            ErrorKind::UnknownPeer => op = Some(UpdateNodeOperation::Failure),
            // TODO handle the unexpected response case (timeout or real invalid
            // message type)
            ErrorKind::UnexpectedResponse => disconnect = false,
            ErrorKind::TooManyTrans => {}
            ErrorKind::Decoder(_) => op = Some(UpdateNodeOperation::Remove),
            ErrorKind::Network(kind) => match kind {
                network::ErrorKind::AddressParse => disconnect = false,
                network::ErrorKind::AddressResolve(_) => disconnect = false,
                network::ErrorKind::Auth => disconnect = false,
                network::ErrorKind::BadProtocol => {
                    op = Some(UpdateNodeOperation::Remove)
                }
                network::ErrorKind::BadAddr => disconnect = false,
                network::ErrorKind::Decoder => {
                    op = Some(UpdateNodeOperation::Remove)
                }
                network::ErrorKind::Expired => disconnect = false,
                network::ErrorKind::Disconnect(_) => disconnect = false,
                network::ErrorKind::InvalidNodeId => disconnect = false,
                network::ErrorKind::OversizedPacket => disconnect = false,
                network::ErrorKind::Io(_) => disconnect = false,
                network::ErrorKind::Throttling(_) => disconnect = false,
                network::ErrorKind::SocketIo(_) => {
                    op = Some(UpdateNodeOperation::Failure)
                }
                network::ErrorKind::Msg(_) => {
                    op = Some(UpdateNodeOperation::Failure)
                }
                network::ErrorKind::__Nonexhaustive {} => {
                    op = Some(UpdateNodeOperation::Failure)
                }
            },
            ErrorKind::Msg(_) => op = Some(UpdateNodeOperation::Failure),
            ErrorKind::__Nonexhaustive {} => {
                op = Some(UpdateNodeOperation::Failure)
            }
        }

        if disconnect {
            io.disconnect_peer(peer, op);
        }
    }

    fn on_get_compact_blocks(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        if !self.syn.contains_peer(&peer) {
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
        send_message(io, peer, &resp, SendQueuePriority::High)?;
        Ok(())
    }

    /// For requested compact block,
    ///     if a compact block is returned
    ///         if it is recoverable and reconstructed block is valid,
    ///             it's removed from requested_manager
    ///         if it is recoverable and reconstructed block is not valid,
    ///             it's sent to requested_manager as requested but not received
    /// block, and the full block
    fn on_get_compact_blocks_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetCompactBlocksResponse = rlp.as_val()?;
        debug!(
            "on_get_compact_blocks_response request_id={} compact={} block={}",
            resp.request_id(),
            resp.compact_blocks.len(),
            resp.blocks.len()
        );
        let req =
            self.request_manager
                .match_request(io, peer, resp.request_id())?;
        let mut failed_blocks = HashSet::new();
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
                continue;
            } else {
                if let Some(header) = self.graph.block_header_by_hash(&hash) {
                    if self.graph.contains_compact_block(&hash) {
                        debug!("Cmpct block already received, hash={}", hash);
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
                            self.request_manager
                                .request_blocktxn(io, peer, hash, missing);
                        } else {
                            let trans = cmpct
                                .reconstructed_txes
                                .into_iter()
                                .map(|tx| tx.unwrap())
                                .collect();
                            let (success, to_relay) = self.graph.insert_block(
                                Block::new(header, trans),
                                true,  // need_to_verify
                                true,  // persistent
                                false, // sync_graph_only
                            );
                            // May fail due to transactions hash collision
                            if !success {
                                failed_blocks.insert(hash);
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
                    continue;
                }
            }
        }
        self.blocks_received(
            io,
            failed_blocks,
            completed_blocks.clone().into_iter().collect(),
            true,
            Some(peer),
        );

        self.dispatch_recover_public_task(
            io,
            resp.blocks,
            requested_blocks,
            peer,
            true,
        );

        // Broadcast completed block_header_ready blocks
        if !completed_blocks.is_empty() && !self.catch_up_mode() {
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
        debug!("on_get_transactions_response {:?}", resp.request_id());

        let req =
            self.request_manager
                .match_request(io, peer, resp.request_id())?;
        let req_tx_ids: HashSet<TxPropagateId> = match req {
            RequestMessage::Transactions(request) => request.tx_ids,
            _ => {
                warn!("Get response not matching the request! req={:?}, resp={:?}", req, resp);
                return Err(ErrorKind::UnexpectedResponse.into());
            }
        };
        // FIXME: Do some check based on transaction request.

        let transactions = resp.transactions;
        debug!(
            "Received {:?} transactions from Peer {:?}",
            transactions.len(),
            peer
        );

        self.request_manager.transactions_received(&req_tx_ids);

        let (signed_trans, _) =
            self.get_transaction_pool().insert_new_transactions(
                self.graph.consensus.best_state_block_hash(),
                &transactions,
            );

        self.request_manager
            .append_received_transactions(signed_trans);

        debug!("Transactions successfully inserted to transaction pool");

        Ok(())
    }

    fn on_get_transactions(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let get_transactions = rlp.as_val::<GetTransactions>()?;
        let transactions = self
            .request_manager
            .get_sent_transactions(&get_transactions.indices);
        let resp = GetTransactionsResponse {
            request_id: get_transactions.request_id,
            transactions,
        };
        debug!(
            "on_get_transactions request {} txs, returned {} txs",
            get_transactions.indices.len(),
            resp.transactions.len()
        );

        send_message(io, peer, &resp, SendQueuePriority::Normal)?;
        Ok(())
    }

    fn on_trans_digests(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let transaction_digests = rlp.as_val::<TransactionDigests>()?;

        let peer_info = self.syn.get_peer_info(&peer)?;
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
            bail!(ErrorKind::TooManyTrans);
        }
        self.request_manager.request_transactions(
            io,
            peer,
            transaction_digests.window_index,
            &transaction_digests.trans_short_ids,
        );
        Ok(())
    }

    fn on_get_blocktxn(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
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
                send_message(io, peer, &resp, SendQueuePriority::High)?;
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
                send_message(io, peer, &resp, SendQueuePriority::High)?;
            }
        }
        Ok(())
    }

    fn on_get_blocktxn_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetBlockTxnResponse = rlp.as_val()?;
        debug!("on_get_blocktxn_response");
        let resp_hash = resp.block_hash;
        let req =
            self.request_manager
                .match_request(io, peer, resp.request_id())?;
        let req = match &req {
            RequestMessage::BlockTxn(request) => request,
            _ => {
                warn!("Get response not matching the request! req={:?}, resp={:?}", req, resp);
                self.request_manager.remove_mismatch_request(io, &req);
                return Err(ErrorKind::UnexpectedResponse.into());
            }
        };
        let mut request_again = false;
        let mut request_from_same_peer = false;
        if resp_hash != req.block_hash {
            warn!("Response blocktxn is not the requested block, req={:?}, resp={:?}", req.block_hash, resp_hash);
            request_again = true;
        } else {
            if self.graph.contains_block(&resp_hash) {
                debug!(
                    "Get blocktxn, but full block already received, hash={}",
                    resp_hash
                );
            } else {
                if let Some(header) =
                    self.graph.block_header_by_hash(&resp_hash)
                {
                    debug!("Process blocktxn hash={:?}", resp_hash);
                    let signed_txes = Self::batch_recover_with_cache(
                        &resp.block_txn,
                        &mut *self
                            .get_transaction_pool()
                            .transaction_pubkey_cache
                            .write(),
                        &mut *self.graph.cache_man.lock(),
                    )?;
                    match self.graph.compact_block_by_hash(&resp_hash) {
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
                            blocks.push(resp_hash);
                            if success {
                                request_again = false;
                            } else {
                                // If the peer is honest, may still fail due to
                                // tx hash collision
                                request_again = true;
                                request_from_same_peer = true;
                            }
                            if to_relay && !self.catch_up_mode() {
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
                            warn!("Get blocktxn, but misses compact block, hash={}", resp_hash);
                        }
                    }
                } else {
                    request_again = true;
                    warn!(
                        "Get blocktxn, but header not received, hash={}",
                        resp_hash
                    );
                }
            }
        }
        if request_again {
            let mut req_hashes = HashSet::new();
            req_hashes.insert(req.block_hash);
            let req_peer = if request_from_same_peer {
                Some(peer)
            } else {
                None
            };
            self.blocks_received(
                io,
                req_hashes,
                HashSet::new(),
                true,
                req_peer,
            );
        }
        Ok(())
    }

    fn on_transactions(&self, peer: PeerId, rlp: &Rlp) -> Result<(), Error> {
        let transactions = rlp.as_val::<Transactions>()?;
        let transactions = transactions.transactions;
        debug!(
            "Received {:?} transactions from Peer {:?}",
            transactions.len(),
            peer
        );

        let peer_info = self.syn.get_peer_info(&peer)?;
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
            bail!(ErrorKind::TooManyTrans);
        }

        let (signed_trans, _) =
            self.get_transaction_pool().insert_new_transactions(
                self.graph.consensus.best_state_block_hash(),
                &transactions,
            );

        self.request_manager
            .append_received_transactions(signed_trans);

        debug!("Transactions successfully inserted to transaction pool");

        Ok(())
    }

    fn on_get_block_headers(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
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
        send_message(io, peer, msg.as_ref(), SendQueuePriority::High)?;
        Ok(())
    }

    fn on_trans_prop_ctrl(&self, peer: PeerId, rlp: &Rlp) -> Result<(), Error> {
        let trans_prop_ctrl = rlp.as_val::<TransactionPropagationControl>()?;
        debug!(
            "on_trans_prop_ctrl, peer {}, msg=:{:?}",
            peer, trans_prop_ctrl
        );

        let peer_info = self.syn.get_peer_info(&peer)?;
        peer_info.write().need_prop_trans = !trans_prop_ctrl.catch_up_mode;

        Ok(())
    }

    fn on_get_blocks(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
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
                if let Err(e) = send_message(
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
                if let Err(e) = send_message(
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
        let req = rlp.as_val::<GetTerminalBlockHashes>()?;
        debug!("on_get_terminal_block_hashes, msg=:{:?}", req);
        let (_guard, best_info) = self.graph.get_best_info().into();
        let msg: Box<dyn Message> = Box::new(GetTerminalBlockHashesResponse {
            request_id: req.request_id().into(),
            hashes: best_info.terminal_block_hashes,
        });
        send_message(io, peer, msg.as_ref(), SendQueuePriority::High)?;
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
        self.request_manager.match_request(
            io,
            peer,
            terminal_block_hashes.request_id(),
        )?;

        for hash in &terminal_block_hashes.hashes {
            if !self.graph.contains_block_header(&hash) {
                self.request_manager.request_block_headers(
                    io,
                    Some(peer),
                    hash,
                    DEFAULT_GET_HEADERS_NUM,
                );
            }
        }
        Ok(())
    }

    fn on_get_block_hashes_by_epoch(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req = rlp.as_val::<GetBlockHashesByEpoch>()?;
        debug!("on_get_block_hashes_by_epoch, msg=:{:?}", req);

        let hashes = self.graph.get_block_hashes_by_epoch(req.epoch_number)?;
        debug!("on_get_block_hashes_by_epoch, hashes=:{:?}", hashes);

        let msg: Box<dyn Message> = Box::new(GetBlockHashesResponse {
            request_id: req.request_id().into(),
            hashes: hashes,
        });
        send_message(io, peer, msg.as_ref(), SendQueuePriority::High)?;
        Ok(())
    }

    fn on_block_hashes_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp = rlp.as_val::<GetBlockHashesResponse>()?;
        debug!("on_block_hashes_response, msg={:?}", resp);

        let req =
            self.request_manager
                .match_request(io, peer, resp.request_id())?;

        match req {
            RequestMessage::Epochs(epoch_req) => {
                self.request_manager
                    .epoch_received(io, epoch_req.epoch_number);
            }
            _ => {
                warn!("Get response not matching the request! req={:?}, resp={:?}", req, resp);
                self.request_manager.remove_mismatch_request(io, &req);
                return Err(ErrorKind::UnexpectedResponse.into());
            }
        };

        // NOTE: We may still follow the rule of requesting header
        // before requesting block even in catch-up mode.
        // request missing blocks
        //let missing_blocks: Vec<H256> = resp
        //    .hashes
        //    .iter()
        //    .filter(|h| !self.graph.contains_block(&h))
        //    .cloned()
        //    .collect();

        //debug!("requesting missing blocks: {:?}", missing_blocks);
        //self.request_blocks(io, Some(peer), missing_blocks);

        // request missing headers
        let missing_headers = resp
            .hashes
            .iter()
            .filter(|h| !self.graph.contains_block_header(&h));

        // NOTE: this is to make sure no section of the DAG is skipped
        // e.g. if the request for epoch 4 is lost or the reply is in-
        // correct, the request for epoch 5 should recursively request
        // all dependent blocks (see on_block_headers_response)
        missing_headers.for_each(|h| {
            self.request_manager
                .request_block_headers(io, Some(peer), h, 1);
        });

        // TODO: handle empty response

        // try requesting some more epochs
        self.start_sync(io);
        Ok(())
    }

    fn on_status(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let status = rlp.as_val::<Status>()?;
        if !self.syn.on_status(peer) {
            warn!("Unexpected Status message from peer={}", peer);
            return Err(ErrorKind::UnknownPeer.into());
        }
        debug!("on_status, msg=:{:?}", status);
        let genesis_hash = self.graph.genesis_hash();
        if genesis_hash != status.genesis_hash {
            debug!(
                "Peer {:?} genesis hash mismatches (ours: {:?}, theirs: {:?})",
                peer, genesis_hash, status.genesis_hash
            );
            return Err(ErrorKind::Invalid.into());
        }

        let mut latest: HashSet<H256> =
            status.terminal_block_hashes.into_iter().collect();
        latest.extend(self.graph.initial_missed_block_hashes.lock().drain());

        let peer_state = SynchronizationPeerState {
            id: peer,
            protocol_version: status.protocol_version,
            genesis_hash: status.genesis_hash,
            best_epoch: status.best_epoch,
            latest_block_hashes: latest,
            received_transaction_count: 0,
            need_prop_trans: true,
            notified_mode: None,
        };

        debug!(
            "New peer (pv={:?}, gh={:?})",
            status.protocol_version, status.genesis_hash
        );

        debug!("Peer {:?} connected", peer);
        self.syn.peer_connected(peer, peer_state);
        self.request_manager.on_peer_connected(peer);

        self.start_sync(io);
        Ok(())
    }

    fn start_sync(&self, io: &NetworkContext) {
        if self.catch_up_mode() {
            self.request_epochs(io);
        } else {
            self.request_missing_terminals(io);
        }
    }

    fn request_missing_terminals(&self, io: &NetworkContext) {
        let peers: Vec<PeerId> =
            self.syn.peers.read().keys().cloned().collect();
        let mut requested = HashSet::new();

        for peer in peers {
            if let Ok(info) = self.syn.get_peer_info(&peer) {
                let terminals = {
                    let mut info = info.write();
                    let ts = info.latest_block_hashes.clone();
                    info.latest_block_hashes.clear();
                    ts
                };

                for t in terminals {
                    if !requested.contains(&t)
                        && !self.graph.contains_block_header(&t)
                    {
                        self.request_manager.request_block_headers(
                            io,
                            Some(peer),
                            &t,
                            DEFAULT_GET_HEADERS_NUM,
                        );
                        requested.insert(t);
                    }
                }
            }
        }

        if requested.len() > 0 {
            debug!("{:?} missing terminal block(s) requested", requested.len());
        }
    }

    fn request_epochs(&self, io: &NetworkContext) {
        // make sure only one thread can request new epochs at a time
        let mut latest_requested = self.latest_epoch_requested.lock();
        let best_peer_epoch = self.best_peer_epoch().unwrap_or(0);

        while self.request_manager.num_epochs_in_flight()
            < EPOCH_SYNC_MAX_INFLIGHT
            && *latest_requested < best_peer_epoch
        {
            let next = {
                let my_best_epoch = self.graph.best_epoch_number();
                let last = (*latest_requested).max(my_best_epoch);

                // request one-by-one near the end to avoid getting stuck
                let stride = if last + EPOCH_SYNC_STRIDE > best_peer_epoch {
                    1
                } else {
                    EPOCH_SYNC_STRIDE
                };

                (last + stride).min(best_peer_epoch)
            };

            let peer = self.syn.get_random_peer_satisfying(|peer| {
                match self.syn.get_peer_info(&peer) {
                    Err(_) => false,
                    Ok(info) => info.read().best_epoch >= next,
                }
            });

            debug!(
                "requesting epoch {:?}/{:?} from peer {:?}",
                next, best_peer_epoch, peer
            );

            self.request_manager.request_epoch_hashes(io, peer, next);

            *latest_requested = next;
        }

        debug_assert!(
            self.request_manager.num_epochs_in_flight()
                <= EPOCH_SYNC_MAX_INFLIGHT
        );
    }

    fn on_block_headers_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let mut block_headers = rlp.as_val::<GetBlockHeadersResponse>()?;
        debug!("on_block_headers_response, msg=:{:?}", block_headers);
        let req = self.request_manager.match_request(
            io,
            peer,
            block_headers.request_id(),
        )?;
        let (req_hash, max_blocks) = match &req {
            RequestMessage::Headers(header_req) => {
                (header_req.hash, header_req.max_blocks)
            }
            _ => {
                warn!("Get response not matching the request! req={:?}, resp={:?}", req, block_headers);
                self.request_manager.remove_mismatch_request(io, &req);
                return Err(ErrorKind::UnexpectedResponse.into());
            }
        };

        let mut parent_hash = H256::default();
        let mut parent_height = 0;
        let mut hashes = Vec::default();
        let mut dependent_hashes = Vec::new();
        let mut need_to_relay = Vec::new();
        let mut returned_headers = HashSet::new();

        for header in &mut block_headers.headers {
            let hash = header.hash();
            if parent_hash != H256::default() && parent_hash != hash {
                return Err(ErrorKind::Invalid.into());
            }
            returned_headers.insert(hash);
            parent_hash = header.parent_hash().clone();
            parent_height = header.height();

            let (success, mut to_relay, is_old) =
                self.graph.insert_block_header(header, true, false);

            if success {
                // Valid block based on header
                if !self.graph.contains_block(&hash) {
                    if is_old {
                        // Create empty block and insert.
                        let empty_block =
                            Block::new(header.clone(), Vec::new());
                        let (_, me_to_relay) = self.graph.insert_block(
                            empty_block,
                            false,
                            true,
                            false,
                        );
                        if me_to_relay {
                            to_relay.push(header.hash());
                        }
                    } else {
                        hashes.push(hash);
                    }
                }
                need_to_relay.extend(to_relay);
                for referee in header.referee_hashes() {
                    dependent_hashes.push(*referee);
                }
            }
        }
        dependent_hashes.push(parent_hash);

        debug!(
            "get headers response of hashes:{:?}, requesting block:{:?}",
            returned_headers, hashes
        );
        self.request_manager.header_received(
            io,
            &req_hash,
            max_blocks,
            returned_headers,
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
                self.request_manager.request_block_headers(
                    io,
                    Some(peer),
                    past_hash,
                    num,
                );
            }
        }

        let catch_up_mode = self.catch_up_mode();

        if !hashes.is_empty() {
            // FIXME: This is a naive strategy. Need to
            // make it more sophisticated.
            if catch_up_mode {
                self.request_blocks(io, Some(peer), hashes);
            } else {
                self.request_manager.request_compact_blocks(
                    io,
                    Some(peer),
                    hashes,
                );
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
        let req = self.request_manager.match_request(
            io,
            peer,
            blocks.request_id(),
        )?;
        let req_hashes_vec = match req {
            RequestMessage::Blocks(request) => request.hashes,
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
        let req = self.request_manager.match_request(
            io,
            peer,
            blocks.request_id(),
        )?;
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
        &self, io: &NetworkContext, task: RecoverPublicTask,
    ) -> Result<(), Error> {
        let mut need_to_relay = Vec::new();
        let mut received_blocks = HashSet::new();
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
                    // This should not happen for correct peer
                    warn!("Received blocks with header not received {}", hash);
                    continue;
                }
            }

            let (success, to_relay) =
                self.graph.insert_block(block, true, true, false);
            if success {
                // The requested block is correctly received
                received_blocks.insert(hash);
            }
            if to_relay {
                need_to_relay.push(hash);
            }
        }

        let mut failed_peers = HashSet::new();
        failed_peers.insert(task.failed_peer);
        let chosen_peer = self.syn.get_random_peer(&failed_peers);
        self.blocks_received(
            io,
            task.requested,
            received_blocks,
            !task.compact,
            chosen_peer,
        );

        if !need_to_relay.is_empty() && !self.catch_up_mode() {
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
        let (success, to_relay, is_old) = self.graph.insert_block_header(
            &mut block.block_header,
            false,
            false,
        );
        assert!(success);
        assert!(!is_old);
        assert!(!self.graph.contains_block(&hash));
        // Do not need to look at the result since this new block will be
        // broadcast to peers.
        self.graph.insert_block(block, false, true, false);
        to_relay
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
                    false,
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

    // TODO This is only used in tests now. Maybe we can add a rpc to send full
    // block and remove NEW_BLOCK from p2p
    fn on_new_block(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
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
        let parent_hash = block.block_header.parent_hash().clone();
        let referee_hashes = block.block_header.referee_hashes().clone();

        let need_to_relay = self.on_new_decoded_block(block, true, true)?;

        debug_assert!(!self.graph.verified_invalid(&parent_hash));
        if !self.graph.contains_block_header(&parent_hash) {
            self.request_manager.request_block_headers(
                io,
                Some(peer),
                &parent_hash,
                DEFAULT_GET_HEADERS_NUM,
            );
        }
        for hash in referee_hashes {
            debug_assert!(!self.graph.verified_invalid(&hash));
            if !self.graph.contains_block_header(&hash) {
                self.request_manager.request_block_headers(
                    io,
                    Some(peer),
                    &hash,
                    DEFAULT_GET_HEADERS_NUM,
                );
            }
        }

        // broadcast the hash of the newly got block
        if !need_to_relay.is_empty() && !self.catch_up_mode() {
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
        let new_block_hashes = rlp.as_val::<NewBlockHashes>()?;
        debug!("on_new_block_hashes, msg={:?}", new_block_hashes);

        if self.catch_up_mode() {
            if let Ok(info) = self.syn.get_peer_info(&peer) {
                let mut info = info.write();
                new_block_hashes.block_hashes.iter().for_each(|h| {
                    info.latest_block_hashes.insert(h.clone());
                });
            }
            return Ok(());
        }

        for hash in new_block_hashes.block_hashes.iter() {
            if !self.graph.contains_block_header(hash) {
                self.request_manager.request_block_headers(
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
        let mut peer_ids: Vec<PeerId> = self
            .syn
            .peers
            .read()
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
            send_message(io, id, msg, priority)?;
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
        send_message(io, peer, msg.as_ref(), SendQueuePriority::High)
    }

    pub fn announce_new_blocks(&self, io: &NetworkContext, hashes: &[H256]) {
        for hash in hashes {
            let block = self.graph.block_by_hash(hash).unwrap();
            let msg: Box<dyn Message> = Box::new(NewBlock {
                block: (*block).clone().into(),
            });
            for id in self.syn.peers.read().keys() {
                send_message_with_throttling(
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
        if !need_to_relay.is_empty() && !self.catch_up_mode() {
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

    fn select_peers_for_transactions<F>(&self, filter: F) -> Vec<PeerId>
    where F: Fn(&PeerId) -> bool {
        let num_peers = self.syn.peers.read().len() as f64;
        let throttle_ratio = THROTTLING_SERVICE.read().get_throttling_ratio();

        // min(sqrt(x)/x, throttle_ratio)
        let chosen_size = (num_peers.powf(-0.5).min(throttle_ratio) * num_peers)
            .round() as usize;
        let mut peer_vec = self.syn.get_random_peer_vec(
            chosen_size.max(self.protocol_config.min_peers_propagation),
            filter,
        );
        peer_vec.truncate(self.protocol_config.max_peers_propagation);
        peer_vec
    }

    fn propagate_transactions_to_peers(
        &self, io: &NetworkContext, peers: Vec<PeerId>,
    ) {
        let lucky_peers = {
            peers
                .into_iter()
                .filter_map(|peer_id| {
                    let peer_info = match self.syn.get_peer_info(&peer_id) {
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

        let sent_transactions = {
            let mut transactions = self.get_to_propagate_trans();
            if transactions.is_empty() {
                return;
            }

            let mut total_tx_bytes = 0;
            let mut sent_transactions = Vec::new();

            for (h, tx) in transactions.iter() {
                total_tx_bytes += tx.rlp_size();
                if total_tx_bytes >= MAX_TXS_BYTES_TO_PROPAGATE {
                    break;
                }
                sent_transactions.push(tx.clone());
                tx_msg.trans_short_ids.push(TxPropagateId::from(*h));
            }

            if sent_transactions.len() != transactions.len() {
                for tx in sent_transactions.iter() {
                    transactions.remove(&tx.hash);
                }
                self.set_to_propagate_trans(transactions);
            }

            sent_transactions
        };

        tx_msg.window_index = self
            .request_manager
            .append_sent_transactions(sent_transactions);
        TX_PROPAGATE_GAUGE.update(tx_msg.trans_short_ids.len() as i64);

        if tx_msg.trans_short_ids.is_empty() {
            return;
        }

        debug!(
            "Sent {} transaction ids to {} peers.",
            tx_msg.trans_short_ids.len(),
            lucky_peers.len()
        );
        for peer_id in lucky_peers {
            match send_message(
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
        if self.syn.peers.read().is_empty() || self.catch_up_mode() {
            return;
        }

        let peers = self.select_peers_for_transactions(|_| true);
        self.propagate_transactions_to_peers(io, peers);
    }

    pub fn remove_expired_flying_request(&self, io: &NetworkContext) {
        self.request_manager.resend_timeout_requests(io);
        self.request_manager
            .resend_waiting_requests(io, self.request_block_need_public());
    }

    pub fn batch_recover_with_cache(
        transactions: &Vec<TransactionWithSignature>,
        tx_cache: &mut HashMap<H256, Arc<SignedTransaction>>,
        cache_man: &mut CacheManager<CacheId>,
    ) -> Result<Vec<Arc<SignedTransaction>>, DecoderError>
    {
        let mut recovered_transactions = Vec::with_capacity(transactions.len());
        for transaction in transactions {
            let tx_hash = transaction.hash();
            // Sample 1/128 transactions
            if tx_hash[0] & 254 == 0 {
                debug!("Sampled transaction {:?} in block", tx_hash);
            }
            match tx_cache.get(&tx_hash) {
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
            let tx_hash = transaction.hash();
            // Sample 1/128 transactions
            if tx_hash[0] & 254 == 0 {
                debug!("Sampled transaction {:?} in block", tx_hash);
            }
            match tx_cache.get(&tx_hash) {
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

    fn update_total_weight_in_past(&self) {
        self.graph.update_total_weight_in_past();
    }

    fn update_catch_up_mode(&self, io: &NetworkContext) {
        let mut peer_best_epoches = {
            let peers = self.syn.peers.read();
            peers
                .iter()
                .map(|(_, state)| state.read().best_epoch)
                .collect::<Vec<_>>()
        };

        if peer_best_epoches.is_empty() {
            return;
        }

        peer_best_epoches.sort();
        let middle_epoch = peer_best_epoches[peer_best_epoches.len() / 2];
        let catch_up_mode = self.graph.best_epoch_number()
            + CATCH_UP_EPOCH_LAG_THRESHOLD
            < middle_epoch;
        self.syn
            .catch_up_mode
            .store(catch_up_mode, AtomicOrdering::Relaxed);

        let mut need_notify = Vec::new();
        for (peer, state) in self.syn.peers.read().iter() {
            let mut state = state.write();
            if state.notified_mode.is_none()
                || (state.notified_mode.unwrap() != catch_up_mode)
            {
                state.received_transaction_count = 0;
                state.notified_mode = Some(catch_up_mode);
                need_notify.push(*peer);
            }
        }
        info!(
            "Catch-up mode: {}, latest epoch: {}",
            catch_up_mode,
            self.graph.best_epoch_number()
        );

        let trans_prop_ctrl_msg: Box<dyn Message> =
            Box::new(TransactionPropagationControl { catch_up_mode });

        for peer in need_notify {
            if send_message(
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

    pub fn request_blocks(
        &self, io: &NetworkContext, peer_id: Option<PeerId>, hashes: Vec<H256>,
    ) {
        self.request_manager.request_blocks(
            io,
            peer_id,
            hashes,
            self.request_block_need_public(),
        );
    }

    pub fn blocks_received(
        &self, io: &NetworkContext, req_hashes: HashSet<H256>,
        returned_blocks: HashSet<H256>, ask_full_block: bool,
        peer: Option<PeerId>,
    )
    {
        self.request_manager.blocks_received(
            io,
            req_hashes,
            returned_blocks,
            ask_full_block,
            peer,
            self.request_block_need_public(),
        )
    }

    fn request_block_need_public(&self) -> bool {
        self.catch_up_mode() && self.protocol_config.request_block_with_public
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
        io.register_timer(TOTAL_WEIGHT_IN_PAST_TIMER, Duration::from_secs(60))
            .expect("Error registering total_weight_in_past timer");
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
        info!("Peer connected: peer={:?}", peer);
        if let Err(e) = self.send_status(io, peer) {
            debug!("Error sending status message: {:?}", e);
            io.disconnect_peer(peer, Some(UpdateNodeOperation::Failure));
        } else {
            self.syn
                .handshaking_peers
                .write()
                .insert(peer, Instant::now());
        }
    }

    fn on_peer_disconnected(&self, io: &NetworkContext, peer: PeerId) {
        info!("Peer disconnected: peer={:?}", peer);
        self.syn.peers.write().remove(&peer);
        self.syn.handshaking_peers.write().remove(&peer);
        self.request_manager.on_peer_disconnected(io, peer);
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
                self.start_sync(io);
            }
            LOG_STATISTIC_TIMER => {
                self.log_statistics();
            }
            TOTAL_WEIGHT_IN_PAST_TIMER => {
                self.update_total_weight_in_past();
            }
            _ => warn!("Unknown timer {} triggered.", timer),
        }
    }
}
