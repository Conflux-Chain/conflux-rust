// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    random, request_manager::RequestManager, Error, ErrorKind,
    SharedSynchronizationGraph, SynchronizationState,
};
use crate::{
    block_data_manager::BlockStatus,
    light_protocol::Provider as LightProvider,
    message::{decode_msg, Message, MsgId},
    parameters::sync::*,
    rand::Rng,
    sync::{
        message::{
            handle_rlp_message, msgid, Context, DynamicCapability,
            GetBlockHeadersResponse, NewBlockHashes, StatusDeprecatedV1,
            StatusV2, TransactionDigests,
        },
        state::SnapshotChunkSync,
        synchronization_phases::{SyncPhaseType, SynchronizationPhaseManager},
        synchronization_state::PeerFilter,
        StateSyncConfiguration,
        SYNCHRONIZATION_PROTOCOL_OLD_VERSIONS_TO_SUPPORT,
        SYNCHRONIZATION_PROTOCOL_VERSION, SYNC_PROTO_V1,
    },
};
use cfx_types::H256;
use io::TimerToken;
use malloc_size_of::{new_malloc_size_ops, MallocSizeOf};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use metrics::{register_meter_with_group, Meter, MeterTimer};
use network::{
    node_table::NodeId, service::ProtocolVersion,
    throttling::THROTTLING_SERVICE, Error as NetworkError, HandlerWorkType,
    NetworkContext, NetworkProtocolHandler, UpdateNodeOperation,
};
use parking_lot::{Mutex, RwLock};
use primitives::{Block, BlockHeader, EpochId, SignedTransaction};
use rand::prelude::SliceRandom;
use rlp::Rlp;
use std::{
    cmp,
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

lazy_static! {
    static ref TX_PROPAGATE_METER: Arc<dyn Meter> =
        register_meter_with_group("system_metrics", "tx_propagate_set_size");
    static ref TX_HASHES_PROPAGATE_METER: Arc<dyn Meter> =
        register_meter_with_group(
            "system_metrics",
            "tx_hashes_propagate_set_size"
        );
    static ref BLOCK_RECOVER_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "sync:recover_block");
    static ref PROPAGATE_TX_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "sync:propagate_tx_timer");
}

const TX_TIMER: TimerToken = 0;
const CHECK_REQUEST_TIMER: TimerToken = 1;
const BLOCK_CACHE_GC_TIMER: TimerToken = 2;
const CHECK_CATCH_UP_MODE_TIMER: TimerToken = 3;
const LOG_STATISTIC_TIMER: TimerToken = 4;
const TOTAL_WEIGHT_IN_PAST_TIMER: TimerToken = 5;
const CHECK_PEER_HEARTBEAT_TIMER: TimerToken = 6;
const CHECK_FUTURE_BLOCK_TIMER: TimerToken = 7;
const EXPIRE_BLOCK_GC_TIMER: TimerToken = 8;
const HEARTBEAT_TIMER: TimerToken = 9;
pub const CHECK_RPC_REQUEST_TIMER: TimerToken = 11;

const MAX_TXS_BYTES_TO_PROPAGATE: usize = 1024 * 1024; // 1MB

const EPOCH_SYNC_MAX_INFLIGHT: u64 = 300;
const EPOCH_SYNC_BATCH_SIZE: u64 = 30;

#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub enum SyncHandlerWorkType {
    RecoverPublic = 1,
    LocalMessage = 2,
}

pub trait TaskSize {
    fn size(&self) -> usize { 0 }

    fn count(&self) -> usize { 1 }
}

/// FIFO queue to async execute tasks.
pub struct AsyncTaskQueue<T: TaskSize> {
    inner: RwLock<AsyncTaskQueueInner<T>>,
    work_type: HandlerWorkType,

    // The maximum number of elements in the queue.
    // Note we do not drop elements even when the queue is full to
    // keep the behavior of this queue consistent.
    max_capacity: usize,

    // Alpha for computing moving average.
    alpha: f64,
}

struct AsyncTaskQueueInner<T: TaskSize> {
    tasks: VecDeque<T>,
    size: usize,
    moving_average: f64,
}

impl<T: TaskSize> AsyncTaskQueue<T> {
    fn new(work_type: SyncHandlerWorkType, max_capacity: usize) -> Self {
        AsyncTaskQueue {
            inner: RwLock::new(AsyncTaskQueueInner {
                tasks: VecDeque::new(),
                size: 0,
                moving_average: 1000.0, // Set to 1KB as initial size.
            }),
            work_type: work_type as HandlerWorkType,
            max_capacity,
            // TODO: set a proper value.
            alpha: 0.001,
        }
    }

    pub fn dispatch(&self, io: &dyn NetworkContext, task: T) {
        let mut inner = self.inner.write();
        inner.size += task.size();
        // Compute moving average.
        if task.count() != 0 {
            inner.moving_average = self.alpha
                * (task.size() / task.count()) as f64
                + (1.0 - self.alpha) * inner.moving_average;
        }
        io.dispatch_work(self.work_type);
        inner.tasks.push_back(task);
        trace!(
            "AsyncTaskQueue dispatch: size={} average={}",
            inner.size,
            inner.moving_average,
        );
    }

    fn pop(&self) -> Option<T> {
        let mut inner = self.inner.write();
        let task = inner.tasks.pop_front();
        task.as_ref().map(|task| {
            inner.size -= task.size();
        });
        trace!(
            "AsyncTaskQueue pop: size={} average={}",
            inner.size,
            inner.moving_average,
        );
        task
    }

    fn size(&self) -> usize { self.inner.read().size }

    pub fn is_full(&self) -> bool { self.size() >= self.max_capacity }

    /// Return `true` if inflight insertion is successful.
    pub fn estimated_available_count(&self) -> usize {
        let inner = self.inner.read();
        if inner.size >= self.max_capacity {
            0
        } else if inner.moving_average != 0.0 {
            ((self.max_capacity - inner.size) as f64 / inner.moving_average)
                as usize
        } else {
            // This should never happen.
            self.max_capacity
        }
    }
}

#[derive(DeriveMallocSizeOf)]
pub struct RecoverPublicTask {
    blocks: Vec<Block>,
    requested: HashSet<H256>,
    delay: Option<Duration>,
    failed_peer: NodeId,
    compact: bool,
}

impl RecoverPublicTask {
    pub fn new(
        blocks: Vec<Block>, requested: HashSet<H256>, failed_peer: NodeId,
        compact: bool, delay: Option<Duration>,
    ) -> Self
    {
        RecoverPublicTask {
            blocks,
            requested,
            failed_peer,
            compact,
            delay,
        }
    }
}

impl TaskSize for RecoverPublicTask {
    fn size(&self) -> usize {
        let mut ops = new_malloc_size_ops();
        self.size_of(&mut ops) + std::mem::size_of::<Self>()
    }

    fn count(&self) -> usize { self.blocks.len() }
}

pub struct LocalMessageTask {
    message: Vec<u8>,
}

impl TaskSize for LocalMessageTask {}

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
    pub protocol_version: ProtocolVersion,

    pub protocol_config: ProtocolConfiguration,
    pub graph: SharedSynchronizationGraph,
    pub syn: Arc<SynchronizationState>,
    pub request_manager: Arc<RequestManager>,
    pub latest_epoch_requested: Mutex<u64>,
    pub future_blocks: FutureBlockContainer,
    pub phase_manager: SynchronizationPhaseManager,
    pub phase_manager_lock: Mutex<u32>,

    // Worker task queue for recover public
    pub recover_public_queue: Arc<AsyncTaskQueue<RecoverPublicTask>>,

    // Worker task queue for local message
    local_message: AsyncTaskQueue<LocalMessageTask>,

    // state sync for any checkpoint
    pub state_sync: Arc<SnapshotChunkSync>,

    /// The epoch id of the remotely synchronized state.
    /// This is always `None` for archive nodes.
    pub synced_epoch_id: Mutex<Option<EpochId>>,

    // provider for serving light protocol queries
    light_provider: Arc<LightProvider>,
}

#[derive(Clone)]
pub struct ProtocolConfiguration {
    pub is_consortium: bool,
    pub send_tx_period: Duration,
    pub check_request_period: Duration,
    pub heartbeat_period_interval: Duration,
    pub heartbeat_timeout: Duration,
    pub block_cache_gc_period: Duration,
    pub expire_block_gc_period: Duration,
    pub sync_expire_block_timeout: Duration,
    pub headers_request_timeout: Duration,
    pub blocks_request_timeout: Duration,
    pub transaction_request_timeout: Duration,
    pub snapshot_candidate_request_timeout: Duration,
    pub snapshot_manifest_request_timeout: Duration,
    pub snapshot_chunk_request_timeout: Duration,
    pub tx_maintained_for_peer_timeout: Duration,
    pub max_inflight_request_count: u64,
    pub received_tx_index_maintain_timeout: Duration,
    pub inflight_pending_tx_index_maintain_timeout: Duration,
    pub request_block_with_public: bool,
    pub max_trans_count_received_in_catch_up: u64,
    pub min_peers_tx_propagation: usize,
    pub max_peers_tx_propagation: usize,
    pub future_block_buffer_capacity: usize,
    pub max_download_state_peers: usize,
    pub test_mode: bool,
    pub dev_mode: bool,
    pub throttling_config_file: Option<String>,
    pub chunk_size_byte: u64,
    pub timeout_observing_period_s: u64,
    pub max_allowed_timeout_in_observing_period: u64,
    pub demote_peer_for_timeout: bool,
    pub max_unprocessed_block_size: usize,
}

impl SynchronizationProtocolHandler {
    pub fn new(
        is_full_node: bool, protocol_config: ProtocolConfiguration,
        state_sync_config: StateSyncConfiguration,
        initial_sync_phase: SyncPhaseType,
        sync_graph: SharedSynchronizationGraph,
        light_provider: Arc<LightProvider>,
    ) -> Self
    {
        let sync_state = Arc::new(SynchronizationState::new(
            protocol_config.is_consortium,
            is_full_node,
            protocol_config.dev_mode || protocol_config.test_mode,
        ));
        let recover_public_queue = Arc::new(AsyncTaskQueue::new(
            SyncHandlerWorkType::RecoverPublic,
            protocol_config.max_unprocessed_block_size,
        ));
        let request_manager = Arc::new(RequestManager::new(
            &protocol_config,
            sync_state.clone(),
            recover_public_queue.clone(),
        ));

        let future_block_buffer_capacity =
            protocol_config.future_block_buffer_capacity;

        let state_sync = Arc::new(SnapshotChunkSync::new(state_sync_config));

        Self {
            protocol_version: SYNCHRONIZATION_PROTOCOL_VERSION,
            protocol_config,
            graph: sync_graph.clone(),
            syn: sync_state.clone(),
            request_manager,
            latest_epoch_requested: Mutex::new(0),
            future_blocks: FutureBlockContainer::new(
                future_block_buffer_capacity,
            ),
            phase_manager: SynchronizationPhaseManager::new(
                initial_sync_phase,
                sync_state.clone(),
                sync_graph.clone(),
                state_sync.clone(),
            ),
            phase_manager_lock: Mutex::new(0),
            recover_public_queue,
            local_message: AsyncTaskQueue::new(
                SyncHandlerWorkType::LocalMessage,
                10000000000, // TODO: Set a better capacity.
            ),
            state_sync,
            synced_epoch_id: Default::default(),
            light_provider,
        }
    }

    pub fn is_consortium(&self) -> bool { self.protocol_config.is_consortium }

    fn get_to_propagate_trans(&self) -> HashMap<H256, Arc<SignedTransaction>> {
        self.graph.get_to_propagate_trans()
    }

    fn set_to_propagate_trans(
        &self, transactions: HashMap<H256, Arc<SignedTransaction>>,
    ) {
        self.graph.set_to_propagate_trans(transactions);
    }

    pub fn catch_up_mode(&self) -> bool {
        self.phase_manager.get_current_phase().phase_type()
            != SyncPhaseType::Normal
    }

    pub fn in_recover_from_db_phase(&self) -> bool {
        let current_phase = self.phase_manager.get_current_phase();
        current_phase.phase_type()
            == SyncPhaseType::CatchUpRecoverBlockHeaderFromDB
            || current_phase.phase_type()
                == SyncPhaseType::CatchUpRecoverBlockFromDB
    }

    pub fn need_requesting_blocks(&self) -> bool {
        let current_phase = self.phase_manager.get_current_phase();
        current_phase.phase_type() == SyncPhaseType::CatchUpSyncBlock
            || current_phase.phase_type() == SyncPhaseType::Normal
    }

    pub fn get_synchronization_graph(&self) -> SharedSynchronizationGraph {
        self.graph.clone()
    }

    pub fn get_request_manager(&self) -> Arc<RequestManager> {
        self.request_manager.clone()
    }

    pub fn append_received_transactions(
        &self, transactions: Vec<Arc<SignedTransaction>>,
    ) {
        self.request_manager
            .append_received_transactions(transactions);
    }

    fn dispatch_message(
        &self, io: &dyn NetworkContext, peer: &NodeId, msg_id: MsgId, rlp: Rlp,
    ) -> Result<(), Error> {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);
        if !io.is_peer_self(peer) {
            if !self.syn.contains_peer(peer) {
                debug!(
                    "dispatch_message: Peer does not exist: peer={} msg_id={}",
                    peer, msg_id
                );
                // We may only receive status message from a peer not in
                // `syn.peers`, and this peer should be in
                // `syn.handshaking_peers`
                if !self.syn.handshaking_peers.read().contains_key(peer)
                    || (msg_id != msgid::STATUS_DEPRECATED
                        && msg_id != msgid::STATUS_V2)
                {
                    warn!("Message from unknown peer {:?}", msg_id);
                    return Ok(());
                }
            } else {
                self.syn.update_heartbeat(peer);
            }
        }

        let ctx = Context {
            node_id: *peer,
            io,
            manager: self,
        };

        if !handle_rlp_message(msg_id, &ctx, &rlp)? {
            warn!("Unknown message: peer={:?} msgid={:?}", peer, msg_id);
            let reason =
                format!("unknown sync protocol message id {:?}", msg_id);
            io.disconnect_peer(
                peer,
                Some(UpdateNodeOperation::Remove),
                reason.as_str(),
            );
        }

        Ok(())
    }

    /// Error handling for dispatched messages.
    fn handle_error(
        &self, io: &dyn NetworkContext, peer: &NodeId, msg_id: MsgId, e: Error,
    ) {
        warn!(
            "Error while handling message, peer={}, msgid={:?}, error={:?}",
            peer, msg_id, e
        );

        let mut disconnect = true;
        let reason = format!("{}", e.0);
        let mut op = None;

        // NOTE, DO NOT USE WILDCARD IN THE FOLLOWING MATCH STATEMENT!
        // COMPILER WILL HELP TO FIND UNHANDLED ERROR CASES.
        match e.0 {
            ErrorKind::InvalidBlock => op = Some(UpdateNodeOperation::Demotion),
            ErrorKind::InvalidGetBlockTxn(_) => {
                op = Some(UpdateNodeOperation::Demotion)
            }
            ErrorKind::InvalidStatus(_) => {
                op = Some(UpdateNodeOperation::Failure)
            }
            ErrorKind::InvalidMessageFormat => {
                // TODO: Shall we blacklist a node when the message format is
                // wrong? maybe it's a different version of sync protocol?
                op = Some(UpdateNodeOperation::Remove)
            }
            ErrorKind::UnknownPeer => op = Some(UpdateNodeOperation::Failure),
            // TODO handle the unexpected response case (timeout or real invalid
            // message type)
            ErrorKind::UnexpectedResponse => {
                op = Some(UpdateNodeOperation::Demotion)
            }
            ErrorKind::RequestNotFound => disconnect = false,
            ErrorKind::TooManyTrans => {}
            ErrorKind::InvalidTimestamp => {
                op = Some(UpdateNodeOperation::Demotion)
            }
            ErrorKind::InvalidSnapshotManifest(_) => {
                op = Some(UpdateNodeOperation::Demotion)
            }
            ErrorKind::InvalidSnapshotChunk(_) => {
                op = Some(UpdateNodeOperation::Demotion)
            }
            ErrorKind::AlreadyThrottled(_) => {
                op = Some(UpdateNodeOperation::Remove)
            }
            ErrorKind::Throttled(_, msg) => {
                disconnect = false;

                if let Err(e) = msg.send(io, peer) {
                    error!("failed to send throttled packet: {:?}", e);
                    disconnect = true;
                }
            }
            ErrorKind::Decoder(_) => op = Some(UpdateNodeOperation::Remove),
            ErrorKind::Io(_) => disconnect = false,
            ErrorKind::Network(kind) => match kind {
                network::ErrorKind::SendUnsupportedMessage { .. } => {
                    unreachable!(
                        "This is a bug in protocol version maintenance. {:?}",
                        kind
                    );
                }

                network::ErrorKind::MessageDeprecated { .. } => {
                    op = Some(UpdateNodeOperation::Failure);
                    error!(
                        "Peer sent us a deprecated message {:?}. Either it's a bug \
                        in protocol version maintenance or the peer is malicious.",
                        kind
                    );
                }

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
            ErrorKind::Storage(_) => disconnect = false,
            ErrorKind::Msg(_) => op = Some(UpdateNodeOperation::Failure),
            ErrorKind::__Nonexhaustive {} => {
                op = Some(UpdateNodeOperation::Failure)
            }
            ErrorKind::InternalError(_) => {}
            ErrorKind::RpcCancelledByDisconnection => {}
            ErrorKind::RpcTimeout => {}
            ErrorKind::UnexpectedMessage(_) => {
                op = Some(UpdateNodeOperation::Remove)
            }
            ErrorKind::NotSupported(_) => disconnect = false,
        }

        if disconnect {
            io.disconnect_peer(peer, op, reason.as_str());
        }
    }

    pub fn start_sync(&self, io: &dyn NetworkContext) {
        let current_phase_type =
            self.phase_manager.get_current_phase().phase_type();
        if current_phase_type == SyncPhaseType::CatchUpRecoverBlockHeaderFromDB
            || current_phase_type == SyncPhaseType::CatchUpRecoverBlockFromDB
        {
            return;
        }

        if current_phase_type != SyncPhaseType::Normal {
            self.request_epochs(io);
            let best_peer_epoch = self.syn.best_peer_epoch().unwrap_or(0);
            let my_best_epoch = self.graph.consensus.best_epoch_number();
            if my_best_epoch + REQUEST_TERMINAL_EPOCH_LAG_THRESHOLD
                >= best_peer_epoch
            {
                self.request_missing_terminals(io);
            }
        } else {
            self.request_missing_terminals(io);
        }
    }

    /// request missing blocked after `recover_graph_from_db` is called
    /// should be called in `start_sync`
    pub fn request_initial_missed_block(&self, io: &dyn NetworkContext) {
        let to_request;
        {
            let mut missing_hashes =
                self.graph.initial_missed_block_hashes.lock();
            if missing_hashes.is_empty() {
                return;
            }
            to_request = missing_hashes.drain().collect::<Vec<H256>>();
            missing_hashes.clear();
        }
        let chosen_peer =
            PeerFilter::new(msgid::GET_BLOCK_HEADERS).select(&self.syn);
        self.request_block_headers(
            io,
            chosen_peer,
            to_request,
            true, /* ignore_db */
        );
    }

    pub fn request_missing_terminals(&self, io: &dyn NetworkContext) {
        let peers: Vec<NodeId> =
            self.syn.peers.read().keys().cloned().collect();

        let mut requested = HashSet::new();

        let (_, era_genesis_height) =
            self.graph.get_genesis_hash_and_height_in_current_era();
        for peer in peers {
            if let Ok(info) = self.syn.get_peer_info(&peer) {
                if info.read().best_epoch < era_genesis_height {
                    // This peer is probably in catch-up mode, so we do not need
                    // to request these old terminal blocks.
                    continue;
                }
                let terminals = {
                    let mut info = info.write();
                    let ts = info.latest_block_hashes.clone();
                    info.latest_block_hashes.clear();
                    ts
                };

                let to_request = terminals
                    .difference(&requested)
                    // We cannot filter out block headers with `data_man` here,
                    // otherwise if we crash before inserting a terminal into
                    // consensus, we will never process it
                    // after restarting in the tests where
                    // no new blocks are generated.
                    .filter(|h| !self.graph.contains_block_header(&h))
                    .cloned()
                    .collect::<Vec<H256>>();

                if terminals.len() > 0 {
                    debug!("Requesting terminals {:?}", to_request);
                }

                self.request_block_headers(
                    io,
                    Some(peer),
                    to_request.clone(),
                    true, /* ignore_db */
                );

                requested.extend(to_request);
            }
        }

        if requested.len() > 0 {
            debug!("{:?} missing terminal block(s) requested", requested.len());
        }
    }

    pub fn request_epochs(&self, io: &dyn NetworkContext) {
        // make sure only one thread can request new epochs at a time
        let mut latest_requested = self.latest_epoch_requested.lock();
        let best_peer_epoch = self.syn.best_peer_epoch().unwrap_or(0);
        let my_best_epoch = self.graph.consensus.best_epoch_number();

        while self.request_manager.num_epochs_in_flight()
            < EPOCH_SYNC_MAX_INFLIGHT
            && (*latest_requested < best_peer_epoch || best_peer_epoch == 0)
        {
            let from = cmp::max(my_best_epoch, *latest_requested) + 1;
            // Check epochs from db
            if let Some(epoch_hashes) =
                self.graph.data_man.all_epoch_set_hashes_from_db(from)
            {
                debug!("Recovered epoch {} from db", from);
                // FIXME better handle this in our event loop separately
                if self.need_requesting_blocks() {
                    self.request_blocks(io, None, epoch_hashes);
                } else {
                    self.request_block_headers(
                        io,
                        None,
                        epoch_hashes,
                        true, /* ignore_db */
                    );
                }
                *latest_requested += 1;
                continue;
            } else if best_peer_epoch == 0 {
                // We have recovered all epochs from db, and there is no peer to
                // request new epochs, so we should enter `Latest` phase
                return;
            }

            // Epoch hashes are not in db, so should be requested from another
            // peer
            let peer = PeerFilter::new(msgid::GET_BLOCK_HASHES_BY_EPOCH)
                .with_min_best_epoch(from)
                .select(&self.syn);

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

            self.request_manager
                .request_epoch_hashes(io, peer, epochs, None);
            *latest_requested = until - 1;
        }
    }

    pub fn request_block_headers(
        &self, io: &dyn NetworkContext, peer: Option<NodeId>,
        mut header_hashes: Vec<H256>, ignore_db: bool,
    )
    {
        if !ignore_db {
            header_hashes
                .retain(|hash| !self.try_request_header_from_db(io, hash));
        }
        // Headers may have been inserted into sync graph before as dependent
        // blocks
        header_hashes.retain(|h| !self.graph.contains_block_header(h));
        self.request_manager.request_block_headers(
            io,
            peer,
            header_hashes,
            None,
        );
    }

    /// Try to get the block header from db. Return `true` if the block header
    /// exists in db or is inserted before. Handle the block header if its
    /// seq_num is less than that of the current era genesis.
    fn try_request_header_from_db(
        &self, io: &dyn NetworkContext, hash: &H256,
    ) -> bool {
        if self.graph.contains_block_header(hash) {
            return true;
        }

        if let Some(info) = self.graph.data_man.local_block_info_from_db(hash) {
            if info.get_status() == BlockStatus::Invalid {
                // this block was invalid before
                return true;
            }
            if info.get_seq_num()
                < self.graph.consensus.current_era_genesis_seq_num()
            {
                debug!("Ignore header in old era hash={:?}, seq={}, cur_era_seq={}", hash, info.get_seq_num(), self.graph.consensus.current_era_genesis_seq_num());
                // The block is ordered before current era genesis, so we do
                // not need to process it
                return true;
            }

            if info.get_instance_id() == self.graph.data_man.get_instance_id() {
                // This block header has already entered consensus
                // graph in this run.
                return true;
            }
        }

        // FIXME: If there is no block info in db, whether we need to fetch
        // block header from db?
        if let Some(header) = self.graph.data_man.block_header_by_hash(hash) {
            debug!("Recovered header {:?} from db", hash);
            // Process headers from db
            let mut block_headers_resp = GetBlockHeadersResponse::default();
            block_headers_resp.request_id = 0;
            let mut headers = Vec::new();
            headers.push((*header).clone());
            block_headers_resp.headers = headers;

            let ctx = Context {
                node_id: io.self_node_id(),
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
        &self, io: &dyn NetworkContext, task: RecoverPublicTask,
    ) -> Result<(), Error> {
        let mut need_to_relay = Vec::new();
        let mut received_blocks = HashSet::new();
        let mut dependent_hashes = HashSet::new();
        for mut block in task.blocks {
            let hash = block.hash();
            if self.graph.contains_block(&hash) {
                // A block might be loaded from db and sent to the local queue
                // multiple times, but we should only process it and request its
                // dependence once.
                continue;
            }
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
                    // before. We can only enter this case if we are catching
                    // up. We do not need to relay headers
                    // during catch-up.
                    let (insert_result, _) = self.graph.insert_block_header(
                        &mut block.block_header,
                        true,  // need_to_verify
                        false, // bench_mode
                        false, // insert_into_consensus
                        true,  // persistent
                    );
                    if !insert_result.is_new_valid() {
                        // If header is invalid or already processed, we do not
                        // need to request the block, so
                        // just mark it received
                        received_blocks.insert(hash);
                        continue;
                    }

                    // Request missing dependent blocks. This is needed because
                    // they may not be in any epoch_set because of out of stable
                    // era, so they will not be retrieved by
                    // request_epochs.
                    let parent = block.block_header.parent_hash();
                    if !self.graph.contains_block(parent) {
                        dependent_hashes.insert(*parent);
                    }
                    for referee in block.block_header.referee_hashes() {
                        if !self.graph.contains_block(referee) {
                            dependent_hashes.insert(*referee);
                        }
                    }
                }
            }
            let insert_result = self.graph.insert_block(
                block, true,  /* need_to_verify */
                true,  /* persistent */
                false, /* recover_from_db */
            );
            if insert_result.is_valid() {
                // The requested block is correctly received
                received_blocks.insert(hash);
            }
            if insert_result.should_relay() {
                need_to_relay.push(hash);
            }
        }
        let missing_dependencies = dependent_hashes
            .difference(&received_blocks)
            .map(Clone::clone)
            .collect();
        let chosen_peer = PeerFilter::new(msgid::GET_BLOCKS)
            .exclude(task.failed_peer)
            .select(&self.syn);

        self.blocks_received(
            io,
            task.requested,
            received_blocks,
            !task.compact,
            chosen_peer.clone(),
            task.delay,
        );
        self.request_blocks(io, chosen_peer, missing_dependencies);

        self.relay_blocks(io, need_to_relay)
    }

    fn on_blocks_inner_task(
        &self, io: &dyn NetworkContext,
    ) -> Result<(), Error> {
        let task = self.recover_public_queue.pop().unwrap();
        let received_blocks: Vec<H256> =
            task.blocks.iter().map(|block| block.hash()).collect();
        self.request_manager
            .remove_net_inflight_blocks(received_blocks.iter());
        self.request_manager
            .remove_net_inflight_blocks(task.requested.iter());
        self.on_blocks_inner(io, task)
    }

    fn on_local_message_task(&self, io: &dyn NetworkContext) {
        let task = self.local_message.pop().unwrap();
        self.on_message(io, &io.self_node_id(), task.message.as_slice());
    }

    pub fn on_mined_block(&self, mut block: Block) {
        let hash = block.block_header.hash();
        info!("Mined block {:?} header={:?}", hash, block.block_header);
        let parent_hash = *block.block_header.parent_hash();

        assert!(self.graph.contains_block_header(&parent_hash));
        assert!(!self.graph.contains_block_header(&hash));
        let (insert_result, _to_relay) = self.graph.insert_block_header(
            &mut block.block_header,
            false,
            false,
            false,
            true,
        );
        assert!(insert_result.is_new_valid());
        assert!(!self.graph.contains_block(&hash));
        // Do not need to look at the result since this new block will be
        // broadcast to peers.
        self.graph.insert_block(
            block, false, /* need_to_verify */
            true,  /* persistent */
            false, /* recover_from_db */
        );
    }

    fn broadcast_message(
        &self, io: &dyn NetworkContext, skip_id: &NodeId, msg: &dyn Message,
    ) -> Result<(), NetworkError> {
        let mut peer_ids: Vec<NodeId> = self
            .syn
            .peers
            .read()
            .keys()
            .filter(|&id| *id != *skip_id)
            .map(|x| *x)
            .collect();

        let throttle_ratio = THROTTLING_SERVICE.read().get_throttling_ratio();
        let num_total = peer_ids.len();
        let num_allowed = (num_total as f64 * throttle_ratio) as usize;

        if num_total > num_allowed {
            debug!("apply throttling for broadcast_message, total: {}, allowed: {}", num_total, num_allowed);
            peer_ids.shuffle(&mut random::new());
            peer_ids.truncate(num_allowed);
        }

        // We only broadcast message which version matches the peer.
        // When there two version of the same message to broadcast,
        // and their valid versions are disjoint, each peer will receive
        // at most one of the message.
        let msg_version_introduced = msg.version_introduced();
        let mut msg_version_valid_till = msg.version_valid_till();
        if msg_version_valid_till == self.protocol_version {
            msg_version_valid_till = ProtocolVersion(std::u8::MAX);
        }
        for id in peer_ids {
            let peer_version = self.syn.get_peer_version(&id)?;
            if peer_version >= msg_version_introduced
                && peer_version <= msg_version_valid_till
            {
                msg.send(io, &id)?;
            }
        }

        Ok(())
    }

    fn produce_status_message_deprecated(&self) -> StatusDeprecatedV1 {
        let best_info = self.graph.consensus.best_info();
        let terminal_hashes = best_info.bounded_terminal_block_hashes.clone();

        StatusDeprecatedV1 {
            protocol_version: SYNC_PROTO_V1.0,
            genesis_hash: self.graph.data_man.true_genesis.hash(),
            best_epoch: best_info.best_epoch_number,
            terminal_block_hashes: terminal_hashes,
        }
    }

    fn produce_status_message_v2(&self) -> StatusV2 {
        let best_info = self.graph.consensus.best_info();
        let chain_id = self.graph.consensus.get_config().chain_id.clone();
        let terminal_hashes = best_info.bounded_terminal_block_hashes.clone();

        StatusV2 {
            chain_id,
            genesis_hash: self.graph.data_man.true_genesis.hash(),
            best_epoch: best_info.best_epoch_number,
            terminal_block_hashes: terminal_hashes,
        }
    }

    fn send_status(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        peer_protocol_version: ProtocolVersion,
    ) -> Result<(), NetworkError>
    {
        if peer_protocol_version == SYNC_PROTO_V1 {
            let status_message = self.produce_status_message_deprecated();
            debug!("Sending status message to {}: {:?}", peer, status_message);
            status_message.send(io, peer)
        } else {
            let status_message = self.produce_status_message_v2();
            debug!("Sending status message to {}: {:?}", peer, status_message);
            status_message.send(io, peer)
        }
    }

    fn broadcast_status(&self, io: &dyn NetworkContext) {
        let status_message_v1 = self.produce_status_message_deprecated();
        let status_message_v2 = self.produce_status_message_v2();
        debug!(
            "Broadcasting status message v1 + v2: {:?}",
            status_message_v2
        );

        if self
            .broadcast_message(io, &Default::default(), &status_message_v1)
            .is_err()
        {
            warn!("Error broadcsting status message");
        }
        if self
            .broadcast_message(io, &Default::default(), &status_message_v2)
            .is_err()
        {
            warn!("Error broadcsting status message");
        }
    }

    pub fn relay_blocks(
        &self, io: &dyn NetworkContext, need_to_relay: Vec<H256>,
    ) -> Result<(), Error> {
        if !need_to_relay.is_empty() && !self.catch_up_mode() {
            let new_block_hash_msg: Box<dyn Message> =
                Box::new(NewBlockHashes {
                    block_hashes: need_to_relay.clone(),
                });
            self.broadcast_message(
                io,
                &Default::default(),
                new_block_hash_msg.as_ref(),
            )
            .unwrap_or_else(|e| {
                warn!("Error broadcasting blocks, err={:?}", e);
            });

            self.light_provider
                .relay_hashes(need_to_relay)
                .unwrap_or_else(|e| {
                    warn!("Error relaying blocks to light provider: {:?}", e);
                });
        }

        Ok(())
    }

    fn select_peers_for_transactions(&self) -> Vec<NodeId> {
        let num_peers = self.syn.peers.read().len() as f64;
        let throttle_ratio = THROTTLING_SERVICE.read().get_throttling_ratio();

        // min(sqrt(x)/x, throttle_ratio)
        let chosen_size = (num_peers.powf(-0.5).min(throttle_ratio) * num_peers)
            .round() as usize;

        let num_peers = chosen_size
            .max(self.protocol_config.min_peers_tx_propagation)
            .min(self.protocol_config.max_peers_tx_propagation);

        PeerFilter::new(msgid::TRANSACTION_DIGESTS)
            .select_n(num_peers, &self.syn)
    }

    fn propagate_transactions_to_peers(
        &self, io: &dyn NetworkContext, peers: Vec<NodeId>,
    ) {
        let _timer = MeterTimer::time_func(PROPAGATE_TX_TIMER.as_ref());
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
                    if !peer_info
                        .read()
                        .capabilities
                        .contains(DynamicCapability::NormalPhase(true))
                    {
                        return None;
                    }
                    Some(peer_id)
                })
                .collect::<Vec<_>>()
        };
        if lucky_peers.is_empty() {
            return;
        }

        // 29 since the remaining bytes is 29.
        let mut nonces: Vec<(u64, u64)> = (0..lucky_peers.len())
            .map(|_| (rand::thread_rng().gen(), rand::thread_rng().gen()))
            .collect();

        let mut short_ids_part: Vec<Vec<u8>> = vec![vec![]; lucky_peers.len()];
        let mut tx_hashes_part: Vec<H256> = vec![];
        let (short_ids_transactions, tx_hashes_transactions) = {
            let mut transactions = self.get_to_propagate_trans();
            if transactions.is_empty() {
                return;
            }

            let mut total_tx_bytes = 0;
            let mut short_ids_transactions: Vec<Arc<SignedTransaction>> =
                Vec::new();
            let mut tx_hashes_transactions: Vec<Arc<SignedTransaction>> =
                Vec::new();

            let received_pool =
                self.request_manager.received_transactions.read();
            for (_, tx) in transactions.iter() {
                total_tx_bytes += tx.rlp_size();
                if total_tx_bytes >= MAX_TXS_BYTES_TO_PROPAGATE {
                    break;
                }
                if received_pool.group_overflow_from_tx_hash(&tx.hash()) {
                    tx_hashes_transactions.push(tx.clone());
                } else {
                    short_ids_transactions.push(tx.clone());
                }
            }

            if short_ids_transactions.len() + tx_hashes_transactions.len()
                != transactions.len()
            {
                for tx in short_ids_transactions.iter() {
                    transactions.remove(&tx.hash);
                }
                for tx in tx_hashes_transactions.iter() {
                    transactions.remove(&tx.hash);
                }
                self.set_to_propagate_trans(transactions);
            }

            (short_ids_transactions, tx_hashes_transactions)
        };
        debug!(
            "Send short ids:{}, Send tx hashes:{}",
            short_ids_transactions.len(),
            tx_hashes_transactions.len()
        );
        for tx in &short_ids_transactions {
            for i in 0..lucky_peers.len() {
                //consist of [one random position byte, and last three
                // bytes]
                TransactionDigests::append_short_id(
                    &mut short_ids_part[i],
                    nonces[i].0,
                    nonces[i].1,
                    &tx.hash(),
                );
            }
        }
        let mut sent_transactions = short_ids_transactions;
        if !tx_hashes_transactions.is_empty() {
            TX_HASHES_PROPAGATE_METER.mark(tx_hashes_transactions.len());
            for tx in &tx_hashes_transactions {
                TransactionDigests::append_tx_hash(
                    &mut tx_hashes_part,
                    tx.hash(),
                );
            }
            sent_transactions.extend(tx_hashes_transactions);
        }

        TX_PROPAGATE_METER.mark(sent_transactions.len());

        if sent_transactions.len() == 0 {
            return;
        }

        debug!(
            "Sent {} transaction ids to {} peers.",
            sent_transactions.len(),
            lucky_peers.len()
        );

        let window_index = self
            .request_manager
            .append_sent_transactions(sent_transactions);

        for i in 0..lucky_peers.len() {
            let peer_id = lucky_peers[i];
            let (key1, key2) = nonces.pop().unwrap();
            let tx_msg = TransactionDigests::new(
                window_index,
                key1,
                key2,
                short_ids_part.pop().unwrap(),
                tx_hashes_part.clone(),
            );
            match tx_msg.send(io, &peer_id) {
                Ok(_) => {
                    trace!(
                        "{:02} <- Transactions ({} entries)",
                        peer_id,
                        tx_msg.len()
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

    pub fn check_future_blocks(&self, io: &dyn NetworkContext) {
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
            let (insert_result, to_relay) = self.graph.insert_block_header(
                &mut header,
                true,
                false,
                self.insert_header_to_consensus(),
                true,
            );
            if insert_result.is_new_valid() {
                need_to_relay.extend(to_relay);

                // check block body
                if !self.graph.contains_block(&hash) {
                    missed_body_block_hashes.insert(hash);
                }
            }
        }

        let chosen_peer = PeerFilter::new(msgid::GET_CMPCT_BLOCKS)
            .throttle(msgid::GET_BLOCKS)
            .select(&self.syn);

        // request missing blocks
        self.request_missing_blocks(
            io,
            chosen_peer,
            missed_body_block_hashes.into_iter().collect(),
        )
        .ok();

        // relay if necessary
        self.relay_blocks(io, need_to_relay.into_iter().collect())
            .ok();
    }

    /// If we are in `SyncHeaders` phase, we should insert graph-ready block
    /// headers to sync graph directly
    pub fn insert_header_to_consensus(&self) -> bool {
        let current_phase = self.phase_manager.get_current_phase();
        current_phase.phase_type() == SyncPhaseType::CatchUpSyncBlockHeader
    }

    pub fn propagate_new_transactions(&self, io: &dyn NetworkContext) {
        if self.syn.peers.read().is_empty() || self.catch_up_mode() {
            return;
        }

        let peers = self.select_peers_for_transactions();
        self.propagate_transactions_to_peers(io, peers);
    }

    pub fn remove_expired_flying_request(&self, io: &dyn NetworkContext) {
        self.request_manager.resend_timeout_requests(io);
        self.request_manager
            .resend_waiting_requests(io, !self.catch_up_mode());
    }

    pub fn send_heartbeat(&self, io: &dyn NetworkContext) {
        self.broadcast_status(io);
    }

    fn cache_gc(&self) { self.graph.data_man.cache_gc() }

    fn log_statistics(&self) { self.graph.log_statistics(); }

    fn update_total_weight_delta_heartbeat(&self) {
        self.graph.update_total_weight_delta_heartbeat();
    }

    pub fn update_sync_phase(&self, io: &dyn NetworkContext) {
        {
            let _pm_lock = self.phase_manager_lock.lock();
            self.phase_manager.try_initialize(io, self);
            let current_phase = self.phase_manager.get_current_phase();
            let next_phase_type = current_phase.next(io, self);
            if current_phase.phase_type() != next_phase_type {
                // Phase changed
                self.phase_manager
                    .change_phase_to(next_phase_type, io, self);
            }
        }

        let catch_up_mode = self.catch_up_mode();
        let mut need_notify = Vec::new();
        for (peer, state) in self.syn.peers.read().iter() {
            let mut state = state.write();
            if !state
                .notified_capabilities
                .contains(DynamicCapability::NormalPhase(!catch_up_mode))
            {
                state.received_transaction_count = 0;
                state
                    .notified_capabilities
                    .insert(DynamicCapability::NormalPhase(!catch_up_mode));
                need_notify.push(*peer);
            }
        }
        info!(
            "Catch-up mode: {}, latest epoch: {}",
            catch_up_mode,
            self.graph.consensus.best_epoch_number()
        );

        DynamicCapability::NormalPhase(!catch_up_mode)
            .broadcast_with_peers(io, need_notify);
    }

    pub fn request_missing_blocks(
        &self, io: &dyn NetworkContext, peer_id: Option<NodeId>,
        hashes: Vec<H256>,
    ) -> Result<(), Error>
    {
        let catch_up_mode = self.catch_up_mode();
        if catch_up_mode {
            self.request_blocks(io, peer_id, hashes);
        } else {
            self.request_manager
                .request_compact_blocks(io, peer_id, hashes, None);
        }
        Ok(())
    }

    pub fn request_blocks(
        &self, io: &dyn NetworkContext, peer_id: Option<NodeId>,
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
            None,
        );
    }

    /// Try to get the block from db. Return `true` if the block exists in db or
    /// is inserted before. Handle the block if its seq_num is less
    /// than that of the current era genesis.
    fn try_request_block_from_db(
        &self, io: &dyn NetworkContext, hash: &H256,
    ) -> bool {
        if self.graph.contains_block(hash) {
            return true;
        }

        if let Some(height) = self
            .graph
            .block_by_hash(hash)
            .map(|block| block.block_header.height())
        {
            let best_height = self.graph.consensus.best_epoch_number();
            if height > best_height
                || best_height - height <= LOCAL_BLOCK_INFO_QUERY_THRESHOLD
            {
                return false;
            }
        } else {
            return false;
        }

        if let Some(info) = self.graph.data_man.local_block_info_from_db(hash) {
            if info.get_status() == BlockStatus::Invalid {
                // this block is invalid before
                return true;
            }
            if info.get_seq_num()
                < self.graph.consensus.current_era_genesis_seq_num()
            {
                debug!(
                    "Ignore block in old era hash={:?}, seq={}, cur_era_seq={}",
                    hash,
                    info.get_seq_num(),
                    self.graph.consensus.current_era_genesis_seq_num()
                );
                // The block is ordered before current era genesis, so we do
                // not need to process it
                return true;
            }

            if info.get_instance_id() == self.graph.data_man.get_instance_id() {
                // This block has already entered consensus graph
                // in this run.
                return true;
            }
        }

        // FIXME: If there is no block info in db, whether we need to fetch
        // block from db?
        if let Some(block) = self
            .graph
            .data_man
            .block_by_hash(hash, false /* update_cache */)
        {
            debug!("Recovered block {:?} from db", hash);
            // Process blocks from db
            // The parameter `failed_peer` is only used when there exist some
            // blocks in `requested` but not in `blocks`.
            // Here `requested` and `blocks` have the same block, so it's okay
            // to set `failed_peer` to Default::default() since it will not be
            // used.
            let mut requested = HashSet::new();
            requested.insert(block.hash());
            self.recover_public_queue.dispatch(
                io,
                RecoverPublicTask::new(
                    vec![block.as_ref().clone()],
                    requested,
                    Default::default(),
                    false,
                    None,
                ),
            );
            return true;
        } else {
            return false;
        }
    }

    pub fn blocks_received(
        &self, io: &dyn NetworkContext, requested_hashes: HashSet<H256>,
        returned_blocks: HashSet<H256>, ask_full_block: bool,
        peer: Option<NodeId>, delay: Option<Duration>,
    )
    {
        self.request_manager.blocks_received(
            io,
            requested_hashes,
            returned_blocks,
            ask_full_block,
            peer,
            self.request_block_need_public(),
            delay,
        )
    }

    fn request_block_need_public(&self) -> bool {
        self.catch_up_mode() && self.protocol_config.request_block_with_public
    }

    pub fn expire_block_gc(
        &self, io: &dyn NetworkContext, timeout: u64,
    ) -> Result<(), Error> {
        if self.in_recover_from_db_phase() {
            // In recover_from_db phase, this will be done at the end of
            // recovery, and if we allow `resolve_outside_dependencies` here,
            // it will cause inconsistency.
            return Ok(());
        }
        // TODO This may not be needed now, but we should double check it.
        let need_to_relay = self.graph.resolve_outside_dependencies(
            false, /* recover_from_db */
            self.insert_header_to_consensus(),
        );
        self.graph.remove_expire_blocks(timeout);
        self.relay_blocks(io, need_to_relay)
    }

    pub fn is_block_queue_full(&self) -> bool {
        self.recover_public_queue.is_full()
    }
}

impl NetworkProtocolHandler for SynchronizationProtocolHandler {
    fn minimum_supported_version(&self) -> ProtocolVersion {
        let my_version = self.protocol_version.0;
        if my_version > SYNCHRONIZATION_PROTOCOL_OLD_VERSIONS_TO_SUPPORT {
            ProtocolVersion(
                my_version - SYNCHRONIZATION_PROTOCOL_OLD_VERSIONS_TO_SUPPORT,
            )
        } else {
            SYNC_PROTO_V1
        }
    }

    fn initialize(&self, io: &dyn NetworkContext) {
        io.register_timer(TX_TIMER, self.protocol_config.send_tx_period)
            .expect("Error registering transactions timer");
        io.register_timer(
            CHECK_REQUEST_TIMER,
            self.protocol_config.check_request_period,
        )
        .expect("Error registering check request timer");
        io.register_timer(
            HEARTBEAT_TIMER,
            self.protocol_config.heartbeat_period_interval,
        )
        .expect("Error registering heartbeat timer");
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
        io.register_timer(
            TOTAL_WEIGHT_IN_PAST_TIMER,
            Duration::from_secs(BLOCK_PROPAGATION_DELAY * 2),
        )
        .expect("Error registering total_weight_in_past timer");
        io.register_timer(CHECK_PEER_HEARTBEAT_TIMER, Duration::from_secs(60))
            .expect("Error registering CHECK_PEER_HEARTBEAT_TIMER");
        io.register_timer(
            CHECK_FUTURE_BLOCK_TIMER,
            Duration::from_millis(1000),
        )
        .expect("Error registering CHECK_FUTURE_BLOCK_TIMER");
        io.register_timer(
            EXPIRE_BLOCK_GC_TIMER,
            self.protocol_config.expire_block_gc_period,
        )
        .expect("Error registering EXPIRE_BLOCK_GC_TIMER");
    }

    fn send_local_message(&self, io: &dyn NetworkContext, message: Vec<u8>) {
        self.local_message
            .dispatch(io, LocalMessageTask { message });
    }

    fn on_message(&self, io: &dyn NetworkContext, peer: &NodeId, raw: &[u8]) {
        let (msg_id, rlp) = match decode_msg(raw) {
            Some(msg) => msg,
            None => {
                return self.handle_error(
                    io,
                    peer,
                    msgid::INVALID,
                    ErrorKind::InvalidMessageFormat.into(),
                )
            }
        };

        debug!("on_message: peer={}, msgid={:?}", peer, msg_id);

        self.dispatch_message(io, peer, msg_id.into(), rlp)
            .unwrap_or_else(|e| self.handle_error(io, peer, msg_id.into(), e));

        // TODO: Only call when the message is a Response. But maybe not worth
        // doing since the check for available request_id is cheap.
        self.request_manager.send_pending_requests(io, peer);
    }

    fn on_work_dispatch(
        &self, io: &dyn NetworkContext, work_type: HandlerWorkType,
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

    fn on_peer_connected(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        peer_protocol_version: ProtocolVersion,
    )
    {
        info!(
            "Peer connected: peer={:?}, version={}",
            peer, peer_protocol_version
        );
        if let Err(e) = self.send_status(io, peer, peer_protocol_version) {
            debug!("Error sending status message: {:?}", e);
            io.disconnect_peer(
                peer,
                Some(UpdateNodeOperation::Failure),
                "send status failed", /* reason */
            );
        } else {
            self.syn
                .handshaking_peers
                .write()
                .insert(*peer, (peer_protocol_version, Instant::now()));
        }
    }

    fn on_peer_disconnected(&self, io: &dyn NetworkContext, peer: &NodeId) {
        info!("Peer disconnected: peer={}", peer);
        self.syn.peers.write().remove(peer);
        self.syn.handshaking_peers.write().remove(peer);
        self.request_manager.on_peer_disconnected(io, peer);
        self.state_sync.on_peer_disconnected(&peer);
    }

    fn on_timeout(&self, io: &dyn NetworkContext, timer: TimerToken) {
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
            HEARTBEAT_TIMER => {
                self.send_heartbeat(io);
            }
            BLOCK_CACHE_GC_TIMER => {
                self.cache_gc();
                self.graph.try_remove_old_era_blocks_from_disk();
            }
            CHECK_CATCH_UP_MODE_TIMER => {
                self.update_sync_phase(io);
            }
            LOG_STATISTIC_TIMER => {
                self.log_statistics();
            }
            TOTAL_WEIGHT_IN_PAST_TIMER => {
                self.update_total_weight_delta_heartbeat();
            }
            CHECK_PEER_HEARTBEAT_TIMER => {
                let timeout_peers = self.syn.get_heartbeat_timeout_peers(
                    self.protocol_config.heartbeat_timeout,
                );
                for peer in timeout_peers {
                    io.disconnect_peer(
                        &peer,
                        Some(UpdateNodeOperation::Failure),
                        "sync heartbeat timeout", /* reason */
                    );
                }
            }
            EXPIRE_BLOCK_GC_TIMER => {
                // remove expire blocks every `expire_block_gc_period`
                // TODO Parameterize this timeout.
                // Set to twice expire period to ensure that stale blocks will
                // exist in the frontier across two consecutive GC.
                self.expire_block_gc(
                    io,
                    self.protocol_config.sync_expire_block_timeout.as_secs(),
                )
                .ok();
            }
            _ => warn!("Unknown timer {} triggered.", timer),
        }
    }
}
