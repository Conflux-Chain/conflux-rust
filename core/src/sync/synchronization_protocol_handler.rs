// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    random, Error, ErrorKind, SharedSynchronizationGraph, SynchronizationState,
};
use crate::{
    consensus::SharedConsensusGraph,
    sync::message::{
        GetBlockHeadersResponse, Message, MsgId, NewBlock, NewBlockHashes,
        Status, TransactionDigests, TransactionPropagationControl,
    },
};
use cfx_types::H256;
use io::TimerToken;
use network::{
    throttling::THROTTLING_SERVICE, Error as NetworkError, HandlerWorkType,
    NetworkContext, NetworkProtocolHandler, PeerId, UpdateNodeOperation,
};
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use rlp::Rlp;
//use slab::Slab;
use super::{
    msg_sender::{send_message, send_message_with_throttling, NULL},
    request_manager::RequestManager,
};
use crate::{
    block_data_manager::BlockStatus,
    consensus::ConsensusGraphInner,
    sync::{
        message::Context,
        state::{SnapshotChunkSync, StateSync},
        synchronization_state::SyncPhase,
        SynchronizationGraphInner,
    },
};
use metrics::{register_meter_with_group, Meter};
use primitives::{Block, BlockHeader, SignedTransaction, TxPropagateId};
use priority_send_queue::SendQueuePriority;
use std::{
    cmp,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

lazy_static! {
    static ref TX_PROPAGATE_METER: Arc<Meter> =
        register_meter_with_group("system_metrics", "tx_propagate_set_size");
    static ref BLOCK_RECOVER_TIMER: Arc<Meter> =
        register_meter_with_group("timer", "sync:recover_block");
}

const CATCH_UP_EPOCH_LAG_THRESHOLD: u64 = 3;

pub const SYNCHRONIZATION_PROTOCOL_VERSION: u8 = 0x01;

pub const MAX_HEADERS_TO_SEND: u64 = 512;
pub const MAX_BLOCKS_TO_SEND: u64 = 256;
pub const MAX_EPOCHS_TO_SEND: u64 = 128;
pub const MAX_PACKET_SIZE: usize = 15 * 1024 * 1024 + 512 * 1024; // 15.5 MB
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
const CHECK_PEER_HEARTBEAT_TIMER: TimerToken = 6;
const CHECK_FUTURE_BLOCK_TIMER: TimerToken = 7;
const EXPIRE_BLOCK_GC_TIMER: TimerToken = 8;

const MAX_TXS_BYTES_TO_PROPAGATE: usize = 1024 * 1024; // 1MB

const EPOCH_SYNC_MAX_INFLIGHT: u64 = 300;
const EPOCH_SYNC_BATCH_SIZE: u64 = 30;

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub enum SyncHandlerWorkType {
    RecoverPublic = 1,
    LocalMessage = 2,
}

/// FIFO queue to async execute tasks.
pub struct AsyncTaskQueue<T> {
    tasks: Mutex<VecDeque<T>>,
    work_type: HandlerWorkType,
}

impl<T> AsyncTaskQueue<T> {
    fn new(work_type: SyncHandlerWorkType) -> Self {
        AsyncTaskQueue {
            tasks: Mutex::new(VecDeque::new()),
            work_type: work_type as HandlerWorkType,
        }
    }

    pub fn dispatch(&self, io: &NetworkContext, task: T) {
        self.tasks.lock().push_back(task);
        io.dispatch_work(self.work_type);
    }

    fn pop(&self) -> Option<T> { self.tasks.lock().pop_front() }
}

pub struct RecoverPublicTask {
    blocks: Vec<Block>,
    requested: HashSet<H256>,
    failed_peer: PeerId,
    compact: bool,
}

impl RecoverPublicTask {
    pub fn new(
        blocks: Vec<Block>, requested: HashSet<H256>, failed_peer: PeerId,
        compact: bool,
    ) -> Self
    {
        RecoverPublicTask {
            blocks,
            requested,
            failed_peer,
            compact,
        }
    }
}

pub struct LocalMessageTask {
    message: Vec<u8>,
}

struct FutureBlockContainerInner {
    capacity: usize,
    size: usize,
    container: BTreeMap<u64, HashMap<H256, BlockHeader>>,
}

impl FutureBlockContainerInner {
    pub fn new(capacity: usize) -> Self {
        FutureBlockContainerInner {
            capacity,
            size: 0,
            container: BTreeMap::new(),
        }
    }
}

pub struct FutureBlockContainer {
    inner: RwLock<FutureBlockContainerInner>,
}

impl FutureBlockContainer {
    pub fn new(capacity: usize) -> Self {
        FutureBlockContainer {
            inner: RwLock::new(FutureBlockContainerInner::new(capacity)),
        }
    }

    pub fn insert(&self, header: BlockHeader) {
        let mut inner = self.inner.write();
        let entry = inner
            .container
            .entry(header.timestamp())
            .or_insert(HashMap::new());
        if !entry.contains_key(&header.hash()) {
            entry.insert(header.hash(), header);
            inner.size += 1;
        }

        if inner.size > inner.capacity {
            let mut removed = false;
            let mut empty_slots = Vec::new();
            for entry in inner.container.iter_mut().rev() {
                if entry.1.is_empty() {
                    empty_slots.push(*entry.0);
                    continue;
                }

                let hash = *entry.1.iter().find(|_| true).unwrap().0;
                entry.1.remove(&hash);
                removed = true;

                if entry.1.is_empty() {
                    empty_slots.push(*entry.0);
                }
                break;
            }

            if removed {
                inner.size -= 1;
            }

            for slot in empty_slots {
                inner.container.remove(&slot);
            }
        }
    }

    pub fn get_before(&self, timestamp: u64) -> Vec<BlockHeader> {
        let mut inner = self.inner.write();
        let mut result = Vec::new();

        loop {
            let slot = if let Some(entry) = inner.container.iter().next() {
                Some(*entry.0)
            } else {
                None
            };

            if slot.is_none() || slot.unwrap() > timestamp {
                break;
            }

            let entry = inner.container.remove(&slot.unwrap()).unwrap();

            for (_, header) in entry {
                result.push(header);
            }
        }

        result
    }
}

pub struct SynchronizationProtocolHandler {
    pub protocol_config: ProtocolConfiguration,
    pub graph: SharedSynchronizationGraph,
    pub syn: Arc<SynchronizationState>,
    pub request_manager: Arc<RequestManager>,
    latest_epoch_requested: Mutex<u64>,
    pub future_blocks: FutureBlockContainer,

    // Worker task queue for recover public
    pub recover_public_queue: AsyncTaskQueue<RecoverPublicTask>,

    // Worker task queue for local message
    local_message: AsyncTaskQueue<LocalMessageTask>,

    // state sync for any checkpoint
    pub state_sync: Mutex<SnapshotChunkSync>,
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
    pub future_block_buffer_capacity: usize,
}

impl SynchronizationProtocolHandler {
    pub fn new(
        is_full_node: bool, protocol_config: ProtocolConfiguration,
        consensus_graph: SharedConsensusGraph,
        sync_graph: SharedSynchronizationGraph,
    ) -> Self
    {
        let syn = Arc::new(SynchronizationState::new(
            is_full_node,
            consensus_graph
                .data_man
                .get_cur_consensus_era_genesis_hash(),
        ));

        let request_manager =
            Arc::new(RequestManager::new(&protocol_config, syn.clone()));

        let future_block_buffer_capacity =
            protocol_config.future_block_buffer_capacity;

        Self {
            protocol_config,
            graph: sync_graph,
            syn: syn.clone(),
            request_manager,
            latest_epoch_requested: Mutex::new(0),
            future_blocks: FutureBlockContainer::new(
                future_block_buffer_capacity,
            ),
            recover_public_queue: AsyncTaskQueue::new(
                SyncHandlerWorkType::RecoverPublic,
            ),
            local_message: AsyncTaskQueue::new(
                SyncHandlerWorkType::LocalMessage,
            ),
            state_sync: Mutex::new(SnapshotChunkSync::new(syn)),
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
        self.syn.sync_phase.lock().catch_up_mode()
    }

    pub fn need_requesting_blocks(&self) -> bool {
        self.syn.sync_phase.lock().need_requesting_blocks()
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
    ) -> Result<(), Error> {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);
        if peer != NULL {
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
                    return Ok(());
                }
            } else {
                self.syn.update_heartbeat(&peer);
            }
        }

        self.syn.validate_msg_id(&msg_id);
        //        if !self.syn.validate_msg_id(&msg_id) {
        //            debug!(
        //                "Message {:?} from peer {:?} is not needed in current
        // phase",                msg_id, peer
        //            );
        //            return;
        //        }

        let ctx = Context {
            peer,
            io,
            manager: self,
        };

        if !msg_id.handle(&ctx, &rlp)? {
            warn!("Unknown message: peer={:?} msgid={:?}", peer, msg_id);
            io.disconnect_peer(peer, Some(UpdateNodeOperation::Remove));
        }

        Ok(())
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
            ErrorKind::UnexpectedResponse => disconnect = true,
            ErrorKind::RequestNotFound => disconnect = false,
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
            ErrorKind::InvalidTimestamp => {
                op = Some(UpdateNodeOperation::Demotion)
            }
        }

        if disconnect {
            io.disconnect_peer(peer, op);
        }
    }

    pub fn start_sync(&self, io: &NetworkContext) {
        let checkpoint = self.syn.sync_phase.lock().get_sync_checkpoint();

        if let Some(checkpoint) = checkpoint {
            self.state_sync
                .lock()
                .start(checkpoint, io, &self.request_manager);
        } else if self.catch_up_mode() {
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

                let to_request = terminals
                    .difference(&requested)
                    .filter(|h| !self.graph.contains_block_header(&h))
                    .cloned()
                    .collect::<Vec<H256>>();

                if terminals.len() > 0 {
                    debug!("Requesting terminals {:?}", to_request);
                }

                // self.request_manager.request_block_headers(
                //     io,
                //     Some(peer),
                //     to_request.clone(),
                // );

                self.request_block_headers(io, Some(peer), to_request.clone());

                requested.extend(to_request);
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
        let my_best_epoch = self.graph.consensus.best_epoch_number();

        while self.request_manager.num_epochs_in_flight()
            < EPOCH_SYNC_MAX_INFLIGHT
            && (*latest_requested < best_peer_epoch || best_peer_epoch == 0)
        {
            let from = cmp::max(my_best_epoch, *latest_requested) + 1;
            // Check epochs from db
            if let Some(epoch_hashes) =
                self.graph.data_man.epoch_set_hashes_from_db(from)
            {
                debug!("Recovered epoch {} from db", from);
                // FIXME better handle this in our event loop separately
                if self.need_requesting_blocks() {
                    self.request_blocks(io, None, epoch_hashes);
                } else {
                    self.request_block_headers(io, None, epoch_hashes);
                }
                *latest_requested += 1;
                continue;
            } else if best_peer_epoch == 0 {
                // We have recovered all epochs from db, and there is no peer to
                // request new epochs, so we should enter `Latest` phase
                if self.syn.is_full_node() {
                    // FIXME Consensus may have not finished processing all
                    // blocks
                    *self.syn.sync_phase.lock() = SyncPhase::SyncBlocks(
                        self.graph
                            .data_man
                            .get_cur_consensus_era_genesis_hash(),
                    );
                } else {
                    // As a archive node, blocks have already been requested
                    // while requesting headers
                    *self.syn.sync_phase.lock() = SyncPhase::Latest;
                }
                return;
            }

            // Epoch hashes are not in db, so should be requested from another
            // peer
            let peer = self.syn.get_random_peer_satisfying(|peer| {
                match self.syn.get_peer_info(&peer) {
                    Err(_) => false,
                    Ok(info) => info.read().best_epoch >= from,
                }
            });

            // no peer has the epoch we need; try later
            if peer.is_none() {
                break;
            }

            let until = {
                let max_to_send = EPOCH_SYNC_MAX_INFLIGHT
                    - self.request_manager.num_epochs_in_flight();

                let best_of_this_peer = self
                    .syn
                    .get_peer_info(&peer.unwrap())
                    .unwrap()
                    .read()
                    .best_epoch;

                let until = from + cmp::min(EPOCH_SYNC_BATCH_SIZE, max_to_send);
                cmp::min(until, best_of_this_peer + 1)
            };

            let epochs = (from..until).collect::<Vec<u64>>();

            debug!(
                "requesting epochs [{}..{}]/{:?} from peer {:?}",
                from,
                until - 1,
                best_peer_epoch,
                peer
            );

            self.request_manager.request_epoch_hashes(io, peer, epochs);
            *latest_requested = until - 1;
        }

        debug_assert!(
            self.request_manager.num_epochs_in_flight()
                <= EPOCH_SYNC_MAX_INFLIGHT
        );
    }

    // FIXME This is actually a recursive DFS to traverse all block headers in
    // the db
    pub fn request_block_headers(
        &self, io: &NetworkContext, peer: Option<usize>,
        mut header_hashes: Vec<H256>,
    )
    {
        header_hashes.retain(|hash| !self.try_request_header_from_db(io, hash));
        // Headers may have been inserted into sync graph before as dependent
        // blocks
        header_hashes.retain(|h| !self.graph.contains_block_header(h));
        self.request_manager
            .request_block_headers(io, peer, header_hashes);
    }

    /// Try to get the block header from db. Return `true` if the block header
    /// exists in db or is inserted before. Handle the block header if its
    /// seq_num is less than that of the current era genesis.
    fn try_request_header_from_db(
        &self, io: &NetworkContext, hash: &H256,
    ) -> bool {
        if self.graph.contains_block_header(hash) {
            return true;
        }
        if let Some(header) = self.graph.data_man.block_header_by_hash(hash) {
            debug!("Recovered header {:?} from db", hash);
            // Process headers from db
            if let Some(info) =
                self.graph.data_man.local_block_info_from_db(hash)
            {
                debug_assert!(match info.get_status() {
                    BlockStatus::Invalid => false,
                    _ => true,
                });
                if info.get_seq_num()
                    < self.graph.consensus.current_era_genesis_seq_num()
                {
                    debug!("Ignore header in old era hash={:?}, seq={}, cur_era_seq={}", hash, info.get_seq_num(), self.graph.consensus.current_era_genesis_seq_num());
                    // The block is ordered before current era genesis, so we do
                    // not need to process it
                    return true;
                }
            }
            let mut block_headers_resp = GetBlockHeadersResponse::default();
            block_headers_resp.set_request_id(0);
            let mut headers = Vec::new();
            headers.push((*header).clone());
            block_headers_resp.headers = headers;

            let ctx = Context {
                peer: NULL,
                io,
                manager: self,
            };

            ctx.send_response(&block_headers_resp)
                .expect("send response should not be error");
            return true;
        } else {
            return false;
        }
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
            if let Err(e) = self.graph.data_man.recover_block(&mut block) {
                warn!("Recover block {:?} with error {:?}", hash, e);
                continue;
            }

            match self.graph.block_header_by_hash(&hash) {
                Some(header) => block.block_header = header,
                None => {
                    // Blocks may be synced directly without inserting headers
                    // before. We can only enter this case
                    // if we are catching up, so we do not need to relay.
                    let (valid, _) = self.graph.insert_block_header(
                        &mut block.block_header,
                        true,  // need_to_verify
                        false, // bench_mode
                        false, // insert_into_consensus
                        true,  // persistent
                    );
                    if !valid {
                        received_blocks.insert(hash);
                        continue;
                    }
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

        self.relay_blocks(io, need_to_relay)
    }

    fn on_blocks_inner_task(&self, io: &NetworkContext) -> Result<(), Error> {
        let task = self.recover_public_queue.pop().unwrap();
        self.on_blocks_inner(io, task)
    }

    fn on_local_message_task(&self, io: &NetworkContext) {
        let task = self.local_message.pop().unwrap();
        self.on_message(io, NULL, task.message.as_slice());
    }

    pub fn on_mined_block(&self, mut block: Block) -> Vec<H256> {
        let hash = block.block_header.hash();
        info!("Mined block {:?} header={:?}", hash, block.block_header);
        let parent_hash = *block.block_header.parent_hash();

        assert!(self.graph.contains_block_header(&parent_hash));
        assert!(!self.graph.contains_block_header(&hash));
        let (success, to_relay) = self.graph.insert_block_header(
            &mut block.block_header,
            false,
            false,
            false,
            true,
        );
        assert!(success);
        assert!(!self.graph.contains_block(&hash));
        // Do not need to look at the result since this new block will be
        // broadcast to peers.
        self.graph.insert_block(block, false, true, false);
        to_relay
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

        let best_info = self.graph.consensus.get_best_info();

        let terminal_hashes = if let Some(x) = &best_info.terminal_block_hashes
        {
            x.clone()
        } else {
            best_info.bounded_terminal_block_hashes.clone()
        };
        let msg: Box<dyn Message> = Box::new(Status {
            protocol_version: SYNCHRONIZATION_PROTOCOL_VERSION,
            network_id: 0x0,
            genesis_hash: self.graph.genesis_hash(),
            best_epoch: best_info.best_epoch_number as u64,
            terminal_block_hashes: terminal_hashes,
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
            )
            .unwrap_or_else(|e| {
                warn!("Error broadcasting blocks, err={:?}", e);
            });
        }

        Ok(())
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
        TX_PROPAGATE_METER.mark(tx_msg.trans_short_ids.len());

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

    pub fn check_future_blocks(&self, io: &NetworkContext) {
        let now_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut missed_body_block_hashes = HashSet::new();
        let mut need_to_relay = HashSet::new();
        let headers = self.future_blocks.get_before(now_timestamp);

        if headers.is_empty() {
            return;
        }

        for mut header in headers {
            let hash = header.hash();
            let (valid, to_relay) = self.graph.insert_block_header(
                &mut header,
                true,
                false,
                self.insert_header_to_consensus(),
                true,
            );
            if valid {
                need_to_relay.extend(to_relay);

                // check block body
                if !self.graph.contains_block(&hash) {
                    missed_body_block_hashes.insert(hash);
                }
            }
        }

        let chosen_peer = self.syn.get_random_peer(&HashSet::new());

        // request missing blocks
        self.request_missing_blocks(
            io,
            chosen_peer,
            missed_body_block_hashes.into_iter().collect(),
        );

        // relay if necessary
        self.relay_blocks(io, need_to_relay.into_iter().collect())
            .ok();
    }

    /// If we are in `SyncHeaders` phase, we should insert graph-ready block
    /// headers to sync graph directly
    pub fn insert_header_to_consensus(&self) -> bool {
        match &*self.syn.sync_phase.lock() {
            SyncPhase::SyncHeaders(_) => true,
            _ => false,
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

    fn block_cache_gc(&self) { self.graph.data_man.gc_cache() }

    fn log_statistics(&self) { self.graph.log_statistics(); }

    fn update_total_weight_in_past(&self) {
        self.graph.update_total_weight_in_past();
    }

    pub fn update_sync_phase(&self, io: &NetworkContext) -> Option<()> {
        let sync_phase = &mut *self.syn.sync_phase.lock();
        // TODO handle the case where we need to switch back phase
        // TODO Do not acquire any consensus inner lock
        match sync_phase {
            SyncPhase::SyncHeaders(h) => {
                let middle_epoch = self.syn.get_middle_epoch()?;
                if self.graph.consensus.best_epoch_number()
                    + CATCH_UP_EPOCH_LAG_THRESHOLD
                    >= middle_epoch
                {
                    let _checkpoint = self
                        .graph
                        .data_man
                        .get_cur_consensus_era_genesis_hash();
                    // FIXME We should set it to `checkpoint` once we can
                    // retrieve checkpoint states
                    *sync_phase = SyncPhase::SyncCheckpoints(*h);
                    //                    *sync_phase =
                    // SyncPhase::SyncCheckpoints(checkpoint);
                }
            }
            SyncPhase::SyncCheckpoints(h) => {
                // TODO handle the case where the checkpoint changes before we
                // retrieve the state TODO handle checkpoint
                // timeout to try to retrieve the checkpoint
                // before this one FIXME We should
                // advance `SyncCheckpoints` to `SyncBlocks` in the handler of
                // the checkpoint state message
                *sync_phase = SyncPhase::SyncBlocks(h.clone());
                // Reset our states to sync blocks and insert them into
                // consensus again.
                let (cur_era_genesis_hash, cur_era_genesis_height) =
                    self.graph.get_genesis_hash_and_height_in_current_era();
                *self.latest_epoch_requested.lock() = cur_era_genesis_height;
                // Acquire both lock first to ensure consistency
                let old_consensus_inner =
                    &mut *self.graph.consensus.inner.write();
                let old_sync_inner = &mut *self.graph.inner.write();
                let new_consensus_inner =
                    ConsensusGraphInner::with_era_genesis_block(
                        old_consensus_inner.pow_config.clone(),
                        self.graph.data_man.clone(),
                        old_consensus_inner.inner_conf.clone(),
                        &cur_era_genesis_hash,
                    );
                self.graph.consensus.update_best_info(&new_consensus_inner);
                *old_consensus_inner = new_consensus_inner;
                let new_sync_inner =
                    SynchronizationGraphInner::with_genesis_block(
                        self.graph
                            .data_man
                            .block_header_by_hash(&cur_era_genesis_hash)
                            .expect("era genesis exists"),
                        old_sync_inner.pow_config.clone(),
                        old_sync_inner.data_man.clone(),
                    );
                *old_sync_inner = new_sync_inner;
            }
            SyncPhase::SyncBlocks(_) => {
                let middle_epoch = self.syn.get_middle_epoch()?;
                if self.graph.consensus.best_epoch_number()
                    + CATCH_UP_EPOCH_LAG_THRESHOLD
                    >= middle_epoch
                {
                    *sync_phase = SyncPhase::Latest;
                }
            }
            SyncPhase::Latest => {
                // TODO handle the case where we need to switch back phase
            }
        }

        let catch_up_mode = sync_phase.catch_up_mode();
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
            self.graph.consensus.best_epoch_number()
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
        Some(())
    }

    pub fn request_missing_blocks(
        &self, io: &NetworkContext, peer_id: Option<PeerId>, hashes: Vec<H256>,
    ) {
        // FIXME: This is a naive strategy. Need to
        // make it more sophisticated.
        let catch_up_mode = self.catch_up_mode();
        if catch_up_mode {
            self.request_blocks(io, peer_id, hashes);
        } else {
            self.request_manager
                .request_compact_blocks(io, peer_id, hashes);
        }
    }

    pub fn request_blocks(
        &self, io: &NetworkContext, peer_id: Option<PeerId>,
        mut hashes: Vec<H256>,
    )
    {
        hashes.retain(|hash| !self.try_request_block_from_db(io, hash));
        // Blocks may have been inserted into sync graph before as dependent
        // blocks
        hashes.retain(|h| !self.graph.contains_block(h));
        self.request_manager.request_blocks(
            io,
            peer_id,
            hashes,
            self.request_block_need_public(),
        );
    }

    /// Try to get the block from db. Return `true` if the block exists in db or
    /// is inserted before. Handle the block if its seq_num is less
    /// than that of the current era genesis.
    fn try_request_block_from_db(
        &self, io: &NetworkContext, hash: &H256,
    ) -> bool {
        if self.graph.contains_block(hash) {
            return true;
        }
        if let Some(block) = self.graph.data_man.block_by_hash(hash, false) {
            debug!("Recovered block {:?} from db", hash);
            // Process blocks from db
            if let Some(info) =
                self.graph.data_man.local_block_info_from_db(hash)
            {
                if info.get_seq_num()
                    < self.graph.consensus.current_era_genesis_seq_num()
                {
                    debug!("Ignore block in old era hash={:?}, seq={}, cur_era_seq={}", hash, info.get_seq_num(), self.graph.consensus.current_era_genesis_seq_num());
                    // The block is ordered before current era genesis, so we do
                    // not need to process it
                    return true;
                }
            }
            // The parameter `failed_peer` is only used when there exist some
            // blocks in `requested` but not in `blocks`.
            // Here `requested` and `blocks` have the same block, so it's okay
            // to set `failed_peer` to 0 since it will not be used.
            let mut requested = HashSet::new();
            requested.insert(block.hash());
            self.recover_public_queue.dispatch(
                io,
                RecoverPublicTask::new(
                    vec![block.as_ref().clone()],
                    requested,
                    0,
                    false,
                ),
            );
            return true;
        } else {
            return false;
        }
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

    fn expire_block_gc(&self, io: &NetworkContext) {
        // remove expire blocks every 450 seconds
        let need_to_relay = self.graph.remove_expire_blocks(15 * 30, true);
        self.relay_blocks(io, need_to_relay).ok();
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
            Duration::from_millis(1000),
        )
        .expect("Error registering check_catch_up_mode timer");
        io.register_timer(LOG_STATISTIC_TIMER, Duration::from_millis(5000))
            .expect("Error registering log_statistics timer");
        io.register_timer(TOTAL_WEIGHT_IN_PAST_TIMER, Duration::from_secs(60))
            .expect("Error registering total_weight_in_past timer");
        io.register_timer(CHECK_PEER_HEARTBEAT_TIMER, Duration::from_secs(60))
            .expect("Error registering CHECK_PEER_HEARTBEAT_TIMER");
        io.register_timer(
            CHECK_FUTURE_BLOCK_TIMER,
            Duration::from_millis(1000),
        )
        .expect("Error registering CHECK_FUTURE_BLOCK_TIMER");
        io.register_timer(EXPIRE_BLOCK_GC_TIMER, Duration::from_secs(60 * 15))
            .expect("Error registering EXPIRE_BLOCK_GC_TIMER");
    }

    fn send_local_message(&self, io: &NetworkContext, message: Vec<u8>) {
        self.local_message
            .dispatch(io, LocalMessageTask { message });
    }

    fn on_message(&self, io: &NetworkContext, peer: PeerId, raw: &[u8]) {
        let msg_id = raw[0];
        let rlp = Rlp::new(&raw[1..]);
        debug!("on_message: peer={:?}, msgid={:?}", peer, msg_id);
        self.dispatch_message(io, peer, msg_id.into(), rlp)
            .unwrap_or_else(|e| self.handle_error(io, peer, msg_id.into(), e));
    }

    fn on_work_dispatch(
        &self, io: &NetworkContext, work_type: HandlerWorkType,
    ) {
        if work_type == SyncHandlerWorkType::RecoverPublic as HandlerWorkType {
            if let Err(e) = self.on_blocks_inner_task(io) {
                warn!("Error processing RecoverPublic task: {:?}", e);
            }
        } else if work_type
            == SyncHandlerWorkType::LocalMessage as HandlerWorkType
        {
            self.on_local_message_task(io);
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
            CHECK_FUTURE_BLOCK_TIMER => {
                self.check_future_blocks(io);
            }
            CHECK_REQUEST_TIMER => {
                self.remove_expired_flying_request(io);
            }
            BLOCK_CACHE_GC_TIMER => {
                self.block_cache_gc();
            }
            CHECK_CATCH_UP_MODE_TIMER => {
                self.update_sync_phase(io);
                self.start_sync(io);
            }
            LOG_STATISTIC_TIMER => {
                self.log_statistics();
            }
            TOTAL_WEIGHT_IN_PAST_TIMER => {
                self.update_total_weight_in_past();
            }
            CHECK_PEER_HEARTBEAT_TIMER => {
                let timeout = Duration::from_secs(180);
                let timeout_peers =
                    self.syn.get_heartbeat_timeout_peers(timeout);
                for peer in timeout_peers {
                    io.disconnect_peer(
                        peer,
                        Some(UpdateNodeOperation::Failure),
                    );
                }
            }
            EXPIRE_BLOCK_GC_TIMER => {
                self.expire_block_gc(io);
            }
            _ => warn!("Unknown timer {} triggered.", timer),
        }
    }
}
