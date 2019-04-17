// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    super::transaction_pool::SharedTransactionPool, random, Error, ErrorKind,
    SharedSynchronizationGraph, SynchronizationGraph, SynchronizationPeerState,
    SynchronizationState, MAX_INFLIGHT_REQUEST_COUNT,
};
use crate::{
    bytes::Bytes, consensus::SharedConsensusGraph, pow::ProofOfWorkConfig,
};
use cfx_types::H256;
use io::TimerToken;
use message::{
    GetBlockHeaders, GetBlockHeadersResponse, GetBlockTxn, GetBlockTxnResponce,
    GetBlocks, GetBlocksResponse, GetCompactBlocks, GetCompactBlocksResponse,
    GetTerminalBlockHashes, GetTerminalBlockHashesResponse, Message, MsgId,
    NewBlock, NewBlockHashes, Status, Transactions,
};
use network::{
    throttling::THROTTLING_SERVICE, Error as NetworkError, NetworkContext,
    NetworkProtocolHandler, PeerId,
};
use parking_lot::{Mutex, RwLock};
use primitives::{Block, SignedTransaction};
use rand::{Rng, RngCore};
use rlp::Rlp;
//use slab::Slab;
use crate::{
    cache_manager::{CacheId, CacheManager},
    pow::WORKER_COMPUTATION_PARALLELISM,
    sync::synchronization_state::RequestMessage,
    verification::VerificationConfig,
};
use primitives::TransactionWithSignature;
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

const CATCH_UP_EPOCH_LAG_THRESHOLD: u64 = 2;

pub const SYNCHRONIZATION_PROTOCOL_VERSION: u8 = 0x01;

pub const MAX_HEADERS_TO_SEND: u64 = 512;
pub const MAX_BLOCKS_TO_SEND: u64 = 256;
const MIN_PEERS_PROPAGATION: usize = 4;
const MAX_PEERS_PROPAGATION: usize = 128;
const DEFAULT_GET_HEADERS_NUM: u64 = 1;
const DEFAULT_GET_PARENT_HEADERS_NUM: u64 = 100;
const REQUEST_START_WAITING_TIME_SECONDS: u64 = 1;
//const REQUEST_WAITING_TIME_BACKOFF: u32 = 2;

const TX_TIMER: TimerToken = 0;
const CHECK_REQUEST_TIMER: TimerToken = 1;
const BLOCK_CACHE_GC_TIMER: TimerToken = 2;
const CHECK_CATCH_UP_MODE_TIMER: TimerToken = 3;

#[derive(Eq, PartialEq, PartialOrd, Ord)]
enum WaitingRequest {
    Header(H256),
    Block(H256),
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
}

pub struct ProtocolConfiguration {
    pub send_tx_period: Duration,
    pub check_request_period: Duration,
    pub block_cache_gc_period: Duration,
    pub persist_terminal_period: Duration,
    pub headers_request_timeout: Duration,
    pub blocks_request_timeout: Duration,
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
        SynchronizationProtocolHandler {
            protocol_config,
            graph: Arc::new(SynchronizationGraph::new(
                consensus_graph.clone(),
                verification_config,
                pow_config,
                fast_recover,
            )),
            syn: RwLock::new(SynchronizationState::new()),
            headers_in_flight: Default::default(),
            header_request_waittime: Default::default(),
            blocks_in_flight: Default::default(),
            block_request_waittime: Default::default(),
            waiting_requests: Default::default(),
            requests_queue: Default::default(),
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
            io.disconnect_peer(peer);
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
                            self.request_blocktxn(io, peer, hash, missing);
                        } else {
                            let trans = cmpct
                                .reconstructed_txes
                                .into_iter()
                                .map(|tx| tx.unwrap())
                                .collect();
                            self.blocks_in_flight.lock().remove(&hash);
                            let (success, to_relay) = self.graph.insert_block(
                                Block {
                                    block_header: header,
                                    transactions: trans,
                                },
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
        self.on_blocks_inner(resp.blocks, &mut requested_blocks, io)?;

        // Request full block if reconstruction fails
        if !failed_blocks.is_empty() {
            self.request_blocks(io, peer, failed_blocks);
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

        // Request missing compact blocks from another random peer
        if !requested_blocks.is_empty() {
            {
                let mut blocks_in_flight = self.blocks_in_flight.lock();
                for hash in &requested_blocks {
                    blocks_in_flight.remove(hash);
                }
            }
            let chosen_peer = self.choose_peer_after_failure(peer);
            self.request_compact_block(
                io,
                chosen_peer,
                requested_blocks.into_iter().collect(),
            );
        }
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
                let resp = GetBlockTxnResponce {
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

                let resp = GetBlockTxnResponce {
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
        let resp: GetBlockTxnResponce = rlp.as_val()?;
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
                                Block {
                                    block_header: header,
                                    transactions: trans,
                                },
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
                                self.request_blocks(io, peer, blocks.clone());
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

    fn on_transactions(&self, peer: PeerId, rlp: &Rlp) -> Result<(), Error> {
        if !self.syn.read().peers.contains_key(&peer) {
            warn!("Unexpected message from unrecognized peer: peer={:?} msg=GET_TERMINAL_BLOCK_HASHES", peer);
            return Ok(());
        }

        let transactions = rlp.as_val::<Transactions>()?;
        let transactions = transactions.transactions;
        debug!(
            "Received {:?} transactions from Peer {:?}",
            transactions.len(),
            peer
        );

        self.syn
            .write()
            .peers
            .get_mut(&peer)
            .ok_or(ErrorKind::UnknownPeer)?
            .last_sent_transactions
            .extend(transactions.iter().map(|tx| tx.hash()));

        self.get_transaction_pool().insert_new_transactions(
            self.graph.consensus.best_state_block_hash(),
            transactions,
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
            if hash == *self.graph.genesis_hash() {
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
        } else {
            let msg: Box<dyn Message> = Box::new(GetBlocksResponse {
                request_id: req.request_id().into(),
                blocks: req
                    .hashes
                    .iter()
                    .take(MAX_BLOCKS_TO_SEND as usize)
                    .filter_map(|hash| {
                        self.graph
                            .block_by_hash(hash)
                            .map(|b| b.as_ref().clone())
                    })
                    .collect(),
            });
            self.send_message(io, peer, msg.as_ref(), SendQueuePriority::High)?;
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
        let msg: Box<dyn Message> = Box::new(GetTerminalBlockHashesResponse {
            request_id: req.request_id().into(),
            hashes: self.graph.get_best_info().terminal_block_hashes,
        });
        self.send_message(io, peer, msg.as_ref(), SendQueuePriority::High)?;
        Ok(())
    }

    fn on_terminal_block_hashes_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        if !self.syn.read().peers.contains_key(&peer) {
            warn!("Unexpected message from unrecognized peer: peer={:?} msg=GET_TERMINAL_BLOCK_HASHES_RESPONSE", peer);
            return Ok(());
        }

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
                    peer,
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
        if *genesis_hash != status.genesis_hash {
            debug!(
                "Peer {:?} genesis hash mismatches (ours: {:?}, theirs: {:?})",
                peer, genesis_hash, status.genesis_hash
            );
            return Err(ErrorKind::Invalid.into());
        }

        let mut requests_vec =
            Vec::with_capacity(MAX_INFLIGHT_REQUEST_COUNT as usize);
        for _i in 0..MAX_INFLIGHT_REQUEST_COUNT {
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
            pending_requests: VecDeque::new(),
            last_sent_transactions: HashSet::new(),
        };

        debug!(
            "New peer (pv={:?}, gh={:?})",
            status.protocol_version, status.genesis_hash
        );

        debug!("Peer {:?} connected", peer);
        {
            let mut syn = self.syn.write();
            syn.peers.insert(peer.clone(), peer_state);
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
                    peer,
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
        if !self.syn.read().peers.contains_key(&peer) {
            warn!("Unexpected message from unrecognized peer: peer={:?} msg=GET_BLOCK_HEADERS_RESPONSE", peer);
            return Ok(());
        }

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
                self.request_block_headers(io, peer, past_hash, num);
            }
        }
        if !hashes.is_empty() {
            // TODO configure which path to use
            self.request_compact_block(io, peer, hashes);
            // self.request_blocks(io, peer, hashes);
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

    fn on_blocks_response(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        if !self.syn.read().peers.contains_key(&peer) {
            warn!("Unexpected message from unrecognized peer: peer={:?} msg=GET_BLOCKS_RESPONSE", peer);
            return Ok(());
        }

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
        let mut requested_blocks: HashSet<H256> =
            req_hashes_vec.into_iter().collect();
        self.on_blocks_inner(blocks.blocks, &mut requested_blocks, io)?;

        // Request missing blocks from another random peer
        if !requested_blocks.is_empty() {
            let chosen_peer = self.choose_peer_after_failure(peer);
            self.request_blocks(
                io,
                chosen_peer,
                requested_blocks.into_iter().collect(),
            );
        }

        Ok(())
    }

    fn on_blocks_inner(
        &self, blocks: Vec<Block>, requested_blocks: &mut HashSet<H256>,
        io: &NetworkContext,
    ) -> Result<(), Error>
    {
        let mut need_to_relay = Vec::new();
        for mut block in blocks {
            let hash = block.hash();
            if !requested_blocks.contains(&hash) {
                warn!("Response has not requested block {:?}", hash);
                continue;
            }
            Self::recover_public(
                &mut block,
                &mut *self
                    .get_transaction_pool()
                    .transaction_pubkey_cache
                    .write(),
                &mut *self.graph.cache_man.lock(),
                &*self.get_transaction_pool().worker_pool.lock(),
            )?;

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
                requested_blocks.remove(&hash);
            }
            if to_relay {
                need_to_relay.push(hash);
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
                peer,
                &parent_hash,
                DEFAULT_GET_HEADERS_NUM,
            );
        }
        for hash in referee_hashes {
            debug_assert!(!self.graph.verified_invalid(&hash));
            if !self.graph.contains_block_header(&hash) {
                self.request_block_headers(
                    io,
                    peer,
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
                    peer,
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

        let msg: Box<dyn Message> = Box::new(Status {
            protocol_version: SYNCHRONIZATION_PROTOCOL_VERSION,
            network_id: 0x0,
            genesis_hash: *self.graph.genesis_hash(),
            best_epoch: self.graph.best_epoch_number(),
            terminal_block_hashes: self
                .graph
                .get_best_info()
                .terminal_block_hashes,
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
        &self, io: &NetworkContext, peer_id: PeerId, hash: &H256,
        max_blocks: u64,
    )
    {
        let syn = &mut *self.syn.write();
        let mut headers_in_flight = self.headers_in_flight.lock();
        let mut header_request_waittime = self.header_request_waittime.lock();
        if headers_in_flight.contains(hash) {
            return;
        } else {
            headers_in_flight.insert(hash.clone());
        }

        match header_request_waittime.get_mut(hash) {
            None => header_request_waittime.insert(
                *hash,
                Duration::new(REQUEST_START_WAITING_TIME_SECONDS, 0),
            ),
            Some(t) => {
                // It is requested before. To prevent possible attacks, we wait
                // for more time to start the next request.
                debug!(
                    "Header {:?} is requested again, delay for {:?}",
                    hash, t
                );
                self.waiting_requests
                    .lock()
                    .push((Instant::now() + *t, WaitingRequest::Header(*hash)));
                *t += Duration::new(REQUEST_START_WAITING_TIME_SECONDS, 0);
                return;
            }
        };
        if !self
            .request_block_headers_unchecked(io, peer_id, hash, max_blocks, syn)
        {
            // TODO Should handle failure better
            headers_in_flight.remove(hash);
        }
    }

    fn request_block_headers_unchecked(
        &self, io: &NetworkContext, peer_id: PeerId, hash: &H256,
        max_blocks: u64, syn: &mut SynchronizationState,
    ) -> bool
    {
        if let Some(timed_req) = self.send_request(
            io,
            peer_id,
            Box::new(RequestMessage::Headers(GetBlockHeaders {
                request_id: 0.into(),
                hash: *hash,
                max_blocks,
            })),
            syn,
            SendQueuePriority::High,
        ) {
            debug!(
                "Requesting {:?} block headers starting at {:?} from peer {:?} request_id={:?}",
                max_blocks,
                hash,
                peer_id,
                timed_req.request_id
            );
            self.requests_queue.lock().push(timed_req);
            true
        } else {
            debug!("Fail to request header {:?} from peer={}", hash, peer_id);
            false
        }
    }

    fn request_blocks(
        &self, io: &NetworkContext, peer_id: PeerId, mut hashes: Vec<H256>,
    ) {
        let syn = &mut *self.syn.write();
        let mut blocks_in_flight = self.blocks_in_flight.lock();
        self.preprocess_block_request(&mut hashes, &mut *blocks_in_flight);
        if hashes.is_empty() {
            return;
        }
        if !self.request_blocks_unchecked(io, peer_id, &hashes, syn) {
            for h in hashes {
                blocks_in_flight.remove(&h);
            }
        }
    }

    fn request_blocks_unchecked(
        &self, io: &NetworkContext, peer_id: PeerId, hashes: &Vec<H256>,
        syn: &mut SynchronizationState,
    ) -> bool
    {
        if let Some(timed_req) = self.send_request(
            io,
            peer_id,
            Box::new(RequestMessage::Blocks(GetBlocks {
                request_id: 0.into(),
                hashes: hashes.clone(),
            })),
            syn,
            SendQueuePriority::High,
        ) {
            debug!(
                "Requesting blocks {:?} from {:?} request_id={}",
                hashes, peer_id, timed_req.request_id
            );
            self.requests_queue.lock().push(timed_req);
            true
        } else {
            debug!("Fail to request blocks {:?} from peer={}", hashes, peer_id);
            false
        }
    }

    fn request_compact_block(
        &self, io: &NetworkContext, peer_id: PeerId, mut hashes: Vec<H256>,
    ) {
        let syn = &mut *self.syn.write();
        let mut blocks_in_flight = self.blocks_in_flight.lock();
        self.preprocess_block_request(&mut hashes, &mut *blocks_in_flight);
        if hashes.is_empty() {
            return;
        }
        if !self.request_compact_block_unchecked(io, peer_id, &hashes, syn) {
            // TODO Should handle failure better
            for h in hashes {
                blocks_in_flight.remove(&h);
            }
        }
    }

    fn request_compact_block_unchecked(
        &self, io: &NetworkContext, peer_id: PeerId, hashes: &Vec<H256>,
        syn: &mut SynchronizationState,
    ) -> bool
    {
        if let Some(timed_req) = self.send_request(
            io,
            peer_id,
            Box::new(RequestMessage::Compact(GetCompactBlocks {
                request_id: 0.into(),
                hashes: hashes.clone(),
            })),
            syn,
            SendQueuePriority::High,
        ) {
            debug!(
                "Requesting compact blocks {:?} from {:?} request_id={}",
                hashes, peer_id, timed_req.request_id
            );
            self.requests_queue.lock().push(timed_req);
            true
        } else {
            debug!(
                "Fail to request compact blocks {:?} from peer={}",
                hashes, peer_id
            );
            false
        }
    }

    fn request_blocktxn(
        &self, io: &NetworkContext, peer_id: PeerId, block_hash: H256,
        indexes: Vec<usize>,
    )
    {
        let syn = &mut *self.syn.write();
        if let Some(timed_req) = self.send_request(
            io,
            peer_id,
            Box::new(RequestMessage::BlockTxn(GetBlockTxn {
                request_id: 0.into(),
                block_hash: block_hash.clone(),
                indexes: indexes.clone(),
            })),
            syn,
            SendQueuePriority::High,
        ) {
            debug!(
                "Requesting blocktxn {:?} from {:?} request_id={}",
                block_hash, peer_id, timed_req.request_id
            );
            self.requests_queue.lock().push(timed_req);
        } else {
            debug!(
                "Fail to request blocktxn {:?} from peer={}",
                block_hash, peer_id
            );
        }
    }

    fn send_request(
        &self, io: &NetworkContext, peer_id: PeerId,
        mut msg: Box<RequestMessage>, syn: &mut SynchronizationState,
        priority: SendQueuePriority,
    ) -> Option<Arc<TimedSyncRequests>>
    {
        if let Some(ref mut peer) = syn.peers.get_mut(&peer_id) {
            if let Some(request_id) = peer.get_next_request_id() {
                msg.set_request_id(request_id);
                self.send_message(io, peer_id, msg.get_msg(), priority)
                    .unwrap_or_else(|e| {
                        warn!("Error while send_message, err={:?}", e);
                    });
                let timed_req = Arc::new(TimedSyncRequests::from_request(
                    peer_id,
                    request_id,
                    &msg,
                    &self.protocol_config,
                ));
                peer.append_inflight_request(
                    request_id,
                    msg,
                    timed_req.clone(),
                );
                return Some(timed_req);
            } else {
                trace!("Append requests for later:{:?}", msg);
                peer.append_pending_request(msg);
                return None;
            }
        }
        warn!("No peer for request:{:?}", msg);
        None
    }

    fn match_request(
        &self, io: &NetworkContext, peer_id: PeerId, request_id: u64,
    ) -> Result<RequestMessage, Error> {
        let mut syn = self.syn.write();
        if let Some(ref mut peer) = syn.peers.get_mut(&peer_id) {
            if let Some(removed_req) = self.remove_request(peer, request_id) {
                while peer.has_pending_requests() {
                    if let Some(new_request_id) = peer.get_next_request_id() {
                        let mut pending_msg =
                            peer.pop_pending_request().unwrap();
                        pending_msg.set_request_id(new_request_id);
                        // FIXME: May need to set priority more precisely.
                        // Simply treat request as high priority for now.
                        self.send_message(
                            io,
                            peer_id,
                            pending_msg.get_msg(),
                            SendQueuePriority::High,
                        )?;
                        let timed_req =
                            Arc::new(TimedSyncRequests::from_request(
                                peer_id,
                                new_request_id,
                                &pending_msg,
                                &self.protocol_config,
                            ));
                        peer.append_inflight_request(
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
        } else {
            Err(ErrorKind::UnknownPeer.into())
        }
    }

    fn choose_peer_after_failure(&self, failed_peer: PeerId) -> PeerId {
        let syn = self.syn.read();
        if syn.peers.len() <= 1 {
            failed_peer
        } else {
            let mut exclude = HashSet::new();
            exclude.insert(failed_peer);
            syn.get_random_peer(&exclude).expect("Has available peer")
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
        let num_peers = syn.peers.len();
        let throttle_ratio = THROTTLING_SERVICE.read().get_throttling_ratio();

        // min(sqrt(x)/x, throttle_ratio) scaled to max u32
        let fraction = ((num_peers as f64).powf(-0.5).min(throttle_ratio)
            * (u32::max_value() as f64).round()) as u32;
        let small = num_peers < MIN_PEERS_PROPAGATION;

        let mut random = random::new();
        syn.peers
            .keys()
            .cloned()
            .filter(filter)
            .filter(|_| small || random.next_u32() < fraction)
            .take(MAX_PEERS_PROPAGATION)
            .collect()
    }

    fn propagate_transactions_to_peers(
        &self, syn: &mut SynchronizationState, io: &NetworkContext,
        peers: Vec<PeerId>, transactions: Vec<Arc<SignedTransaction>>,
    )
    {
        let all_transactions_hashes = transactions
            .iter()
            .map(|tx| tx.hash())
            .collect::<HashSet<H256>>();

        let lucky_peers = {
            peers.into_iter()
                .filter_map(|peer_id| {
                    let peer_info = syn.peers.get_mut(&peer_id)
                        .expect("peer_id is from peers; peers is result of select_peers_for_transactions; select_peers_for_transactions selects peers from syn.peers; qed");

                    // Send all transactions
                    if peer_info.last_sent_transactions.is_empty() {
                        let mut tx_msg = Box::new(Transactions { transactions: Vec::new() });
                        for tx in &transactions {
                            tx_msg.transactions.push(tx.transaction.clone());
                        }
                        peer_info.last_sent_transactions = all_transactions_hashes.clone();
                        return Some((peer_id, transactions.len(), tx_msg));
                    }

                    // Get hashes of all transactions to send to this peer
                    let to_send = all_transactions_hashes.difference(&peer_info.last_sent_transactions)
                        .cloned()
                        .collect::<HashSet<_>>();
                    if to_send.is_empty() {
                        return None;
                    }

                    let mut tx_msg = Box::new(Transactions { transactions: Vec::new() });
                    for tx in &transactions {
                        if to_send.contains(&tx.hash()) {
                            tx_msg.transactions.push(tx.transaction.clone());
                        }
                    }
                    peer_info.last_sent_transactions = all_transactions_hashes
                        .intersection(&peer_info.last_sent_transactions)
                        .chain(&to_send)
                        .cloned()
                        .collect();
                    Some((peer_id, tx_msg.transactions.len(), tx_msg))
                })
                .collect::<Vec<_>>()
        };

        if lucky_peers.len() > 0 {
            let mut max_sent = 0;
            let lucky_peers_len = lucky_peers.len();
            for (peer_id, sent, msg) in lucky_peers {
                match self.send_message(
                    io,
                    peer_id,
                    msg.as_ref(),
                    SendQueuePriority::Normal,
                ) {
                    Ok(_) => {
                        trace!(
                            "{:02} <- Transactions ({} entries)",
                            peer_id,
                            sent
                        );
                        max_sent = cmp::max(max_sent, sent);
                    }
                    Err(e) => {
                        warn!(
                            "failed to propagate txs to peer, id: {}, err: {}",
                            peer_id, e
                        );
                    }
                }
            }
            debug!(
                "Sent up to {} transactions to {} peers.",
                max_sent, lucky_peers_len
            );
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

        let mut syn = self.syn.write();
        let peers = self.select_peers_for_transactions(&mut *syn, |_| true);
        self.propagate_transactions_to_peers(
            &mut *syn,
            io,
            peers,
            transactions,
        );
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
        debug!("headers_in_flight: {:?}", *self.headers_in_flight.lock());
        debug!("blocks_in_flight: {:?}", *self.blocks_in_flight.lock());

        // Send waiting requests that their backoff delay have passes
        let syn = &mut *self.syn.write();
        let mut headers_in_flight = self.headers_in_flight.lock();
        let mut blocks_in_flight = self.blocks_in_flight.lock();
        let mut waiting_requests = self.waiting_requests.lock();
        loop {
            if waiting_requests.is_empty() {
                break;
            }
            let req = waiting_requests.pop().expect("queue not empty");
            if req.0 >= now {
                waiting_requests.push(req);
                break;
            } else {
                let chosen_peer = match syn.get_random_peer(&HashSet::new()) {
                    Some(p) => p,
                    None => {
                        // FIXME There is no peer to request, should store the
                        // requests and ask for them later
                        break;
                    }
                };
                // Waiting requests are already in-flight, so send them without
                // checking
                match req.1 {
                    WaitingRequest::Header(h) => {
                        if !self.request_block_headers_unchecked(
                            io,
                            chosen_peer,
                            &h,
                            1,
                            syn,
                        ) {
                            // TODO better handling
                            headers_in_flight.remove(&h);
                        }
                    }
                    WaitingRequest::Block(h) => {
                        let blocks = vec![h];
                        if !self.request_blocks_unchecked(
                            io,
                            chosen_peer,
                            &blocks,
                            syn,
                        ) {
                            // TODO better handling
                            blocks_in_flight.remove(&h);
                        }
                    }
                }
            }
        }
    }

    fn send_request_again(&self, request: RequestMessage, io: &NetworkContext) {
        let chosen_peer = match self.syn.read().get_random_peer(&HashSet::new())
        {
            Some(p) => p,
            None => {
                // FIXME There is no peer to request, should store
                // the requests and ask for them later
                return;
            }
        };
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
        &self, peer: &mut SynchronizationPeerState, request_id: u64,
    ) -> Option<RequestMessage> {
        peer.remove_inflight_request(request_id).map(|req| {
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
                _ => {}
            }
            req.timed_req.removed.store(true, AtomicOrdering::Relaxed);
            *req.message
        })
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
        block: &mut Block,
        tx_cache: &mut HashMap<H256, Arc<SignedTransaction>>,
        cache_man: &mut CacheManager<CacheId>, worker_pool: &ThreadPool,
    ) -> Result<(), DecoderError>
    {
        let mut recovered_transactions =
            Vec::with_capacity(block.transactions.len());
        let mut uncached_trans = Vec::with_capacity(block.transactions.len());
        for (idx, transaction) in block.transactions.iter().enumerate() {
            match tx_cache.get(&transaction.hash()) {
                Some(tx) => recovered_transactions.push(tx.clone()),
                None => {
                    uncached_trans.push((idx, transaction.clone()));
                    recovered_transactions.push(transaction.clone());
                }
            }
        }
        if uncached_trans.len() < WORKER_COMPUTATION_PARALLELISM * 8 {
            for (idx, tx) in uncached_trans {
                if let Ok(public) = tx.recover_public() {
                    recovered_transactions[idx] = Arc::new(
                        SignedTransaction::new(public, tx.transaction.clone()),
                    );
                } else {
                    debug!(
                        "Unable to recover the public key of transaction {:?}",
                        tx.hash()
                    );
                    return Err(DecoderError::Custom(
                        "Cannot recover public key",
                    ));
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
                        if let Ok(public) = tx.recover_public() {
                            signed_txes.push((idx, public));
                        } else {
                            debug!(
                                "Unable to recover the public key of transaction {:?}",
                                tx.hash()
                            );
                        }
                    }
                    sender.send(signed_txes).unwrap();
                });
            }
            worker_pool.join();

            for tx_publics in receiver.iter().take(n_thread) {
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
        }

        block.transactions = recovered_transactions;
        Ok(())
    }

    fn block_cache_gc(&self) { self.graph.block_cache_gc(); }

    fn update_catch_up_mode(&self) {
        let mut peer_best_epoches = {
            let syn = self.syn.read();
            syn.peers
                .iter()
                .map(|(_, state)| state.best_epoch)
                .collect::<Vec<_>>()
        };

        if peer_best_epoches.is_empty() {
            return;
        }

        peer_best_epoches.sort();
        let middle_epoch = peer_best_epoches[peer_best_epoches.len() / 2];

        if self.graph.best_epoch_number() + CATCH_UP_EPOCH_LAG_THRESHOLD
            >= middle_epoch
        {
            let mut syn = self.syn.write();
            syn.catch_up_mode = false;
        } else {
            let mut syn = self.syn.write();
            syn.catch_up_mode = true;
        }
        info!("Catch-up mode: {}", self.syn.read().catch_up_mode);
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
    }

    fn on_message(&self, io: &NetworkContext, peer: PeerId, raw: &[u8]) {
        let msg_id = raw[0];
        let rlp = Rlp::new(&raw[1..]);
        debug!("on_message: peer={:?}, msgid={:?}", peer, msg_id);
        self.dispatch_message(io, peer, msg_id.into(), rlp);
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
            let _requests = self.requests_queue.lock();
            if let Some(peer_state) = syn.peers.remove(&peer) {
                for maybe_req in peer_state.inflight_requests {
                    if let Some(req) = maybe_req {
                        req.timed_req
                            .removed
                            .store(true, AtomicOrdering::Relaxed);
                        unfinished_requests.push(req.message);
                    }
                }
                for req in peer_state.pending_requests {
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
                self.update_catch_up_mode();
            }
            _ => warn!("Unknown timer {} triggered.", timer),
        }
    }
}
