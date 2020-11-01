// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod sync;

use crate::{
    block_data_manager::BlockDataManager,
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{validate_chain_id, FullPeerState, Peers},
        error::*,
        handle_error,
        message::{
            msgid, BlockHashes as GetBlockHashesResponse,
            BlockHeaders as GetBlockHeadersResponse,
            BlockTxs as GetBlockTxsResponse, Blooms as GetBloomsResponse,
            NewBlockHashes, NodeType, Receipts as GetReceiptsResponse,
            SendRawTx, StateEntries as GetStateEntriesResponse,
            StateRoots as GetStateRootsResponse, StatusPingDeprecatedV1,
            StatusPingV2, StatusPongDeprecatedV1, StatusPongV2,
            StorageRoots as GetStorageRootsResponse,
            TxInfos as GetTxInfosResponse, Txs as GetTxsResponse,
            WitnessInfo as GetWitnessInfoResponse,
        },
        LightNodeConfiguration, LIGHT_PROTOCOL_OLD_VERSIONS_TO_SUPPORT,
        LIGHT_PROTOCOL_VERSION, LIGHT_PROTO_V1,
    },
    message::{decode_msg, decode_rlp_and_check_deprecation, Message, MsgId},
    sync::{message::Throttled, SynchronizationGraph},
    Notifications, UniqueId,
};
use cfx_parameters::light::{
    CATCH_UP_EPOCH_LAG_THRESHOLD, CLEANUP_PERIOD, HEARTBEAT_PERIOD, SYNC_PERIOD,
};
use cfx_types::H256;
use io::TimerToken;
use network::{
    node_table::NodeId, service::ProtocolVersion, NetworkContext,
    NetworkProtocolHandler,
};
use parking_lot::RwLock;
use rlp::Rlp;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use sync::{
    BlockTxs, Blooms, Epochs, HashSource, Headers, Receipts, StateEntries,
    StateRoots, StorageRoots, TxInfos, Txs, Witnesses,
};
use throttling::token_bucket::TokenBucketManager;

const SYNC_TIMER: TimerToken = 0;
const REQUEST_CLEANUP_TIMER: TimerToken = 1;
const LOG_STATISTICS_TIMER: TimerToken = 2;
const HEARTBEAT_TIMER: TimerToken = 3;
const TOTAL_WEIGHT_IN_PAST_TIMER: TimerToken = 4;

/// Handler is responsible for maintaining peer meta-information and
/// dispatching messages to the query and sync sub-handlers.
pub struct Handler {
    pub protocol_version: ProtocolVersion,

    // block tx sync manager
    pub block_txs: Arc<BlockTxs>,

    // bloom sync manager
    pub blooms: Blooms,

    // shared consensus graph
    consensus: SharedConsensusGraph,

    // epoch sync manager
    epochs: Epochs,

    // header sync manager
    headers: Arc<Headers>,

    // join handle for witness worker thread
    join_handle: Option<thread::JoinHandle<()>>,

    // collection of all peers available
    pub peers: Arc<Peers<FullPeerState>>,

    // receipt sync manager
    pub receipts: Arc<Receipts>,

    // state entry sync manager
    pub state_entries: StateEntries,

    // state root sync manager
    pub state_roots: Arc<StateRoots>,

    // whether the witness worker thread should be stopped
    stopped: Arc<AtomicBool>,

    // storage root sync manager
    pub storage_roots: StorageRoots,

    // tx sync manager
    pub txs: Arc<Txs>,

    // tx info sync manager
    pub tx_infos: TxInfos,

    // path to unexpected messages config file
    throttling_config_file: Option<String>,

    // witness sync manager
    pub witnesses: Arc<Witnesses>,
}

impl Handler {
    pub fn new(
        consensus: SharedConsensusGraph, graph: Arc<SynchronizationGraph>,
        throttling_config_file: Option<String>,
        notifications: Arc<Notifications>, config: LightNodeConfiguration,
    ) -> Self
    {
        let peers = Arc::new(Peers::new());
        let request_id_allocator = Arc::new(UniqueId::new());

        let headers = Arc::new(Headers::new(
            graph.clone(),
            peers.clone(),
            request_id_allocator.clone(),
            config.clone(),
        ));

        let epochs = Epochs::new(
            consensus.clone(),
            headers.clone(),
            peers.clone(),
            request_id_allocator.clone(),
            config,
        );

        let witnesses = Arc::new(Witnesses::new(
            consensus.clone(),
            peers.clone(),
            request_id_allocator.clone(),
        ));

        let blooms = Blooms::new(
            peers.clone(),
            request_id_allocator.clone(),
            witnesses.clone(),
        );

        let receipts = Arc::new(Receipts::new(
            peers.clone(),
            request_id_allocator.clone(),
            witnesses.clone(),
        ));

        let snapshot_epoch_count =
            consensus.get_data_manager().get_snapshot_epoch_count() as u64;

        let state_roots = Arc::new(StateRoots::new(
            peers.clone(),
            request_id_allocator.clone(),
            snapshot_epoch_count,
            witnesses.clone(),
        ));

        let state_entries = StateEntries::new(
            peers.clone(),
            state_roots.clone(),
            request_id_allocator.clone(),
        );

        let storage_roots = StorageRoots::new(
            peers.clone(),
            state_roots.clone(),
            request_id_allocator.clone(),
        );

        let txs =
            Arc::new(Txs::new(peers.clone(), request_id_allocator.clone()));

        let block_txs = Arc::new(BlockTxs::new(
            consensus.clone(),
            peers.clone(),
            request_id_allocator.clone(),
            txs.clone(),
        ));

        let tx_infos = TxInfos::new(
            consensus.clone(),
            peers.clone(),
            request_id_allocator.clone(),
            witnesses.clone(),
        );

        let stopped = Arc::new(AtomicBool::new(false));

        let join_handle = Some(Self::start_witness_worker(
            notifications,
            witnesses.clone(),
            stopped.clone(),
            consensus.get_data_manager().clone(),
        ));

        graph.recover_graph_from_db(true /* header_only */);

        Handler {
            block_txs,
            blooms,
            consensus,
            epochs,
            headers,
            join_handle,
            peers,
            protocol_version: LIGHT_PROTOCOL_VERSION,
            receipts,
            state_entries,
            state_roots,
            stopped,
            storage_roots,
            throttling_config_file,
            tx_infos,
            txs,
            witnesses,
        }
    }

    // start a standalone thread for requesting witnesses.
    // this thread will be joined when `Handler` is dropped.
    fn start_witness_worker(
        notifications: Arc<Notifications>, witnesses: Arc<Witnesses>,
        stopped: Arc<AtomicBool>, data_man: Arc<BlockDataManager>,
    ) -> thread::JoinHandle<()>
    {
        thread::Builder::new()
            .name("Witness Worker".into())
            .spawn(move || {
                let mut receiver =
                    notifications.blame_verification_results.subscribe();

                loop {
                    // `stopped` is set during Drop
                    if stopped.load(Ordering::SeqCst) {
                        break;
                    }

                    // receive next item from channel
                    let wait_for = Duration::from_secs(1);

                    let (height, maybe_witness) =
                        match receiver.recv_with_timeout(wait_for) {
                            Err(_) => continue, // channel empty, try again
                            Ok(None) => return, // sender dropped, terminate
                            Ok(Some(val)) => val,
                        };

                    trace!(
                        "Witness worker received: height = {:?}, maybe_witness = {:?}",
                        height, maybe_witness
                    );

                    // avoid serving stale roots from db
                    //
                    //                 blame
                    //              ............
                    //              v          |
                    //             ---        ---
                    //         .- | B | <--- | C | <--- ...
                    //  ---    |   ---        ---
                    // | A | <-*
                    //  ---    |   ---
                    //         .- | D | <--- ...
                    //             ---
                    //              ^
                    //          height = X
                    //
                    // we receive A, B, C, ..., A, D (chain reorg),
                    // we stored the verified roots of B on disk,
                    // after chain reorg, height X is not blamed anymore
                    // --> need to make sure to serve correct roots directly from
                    //     header D instead of the stale roots retrieved for B
                    data_man.remove_blamed_header_verified_roots(height);

                    // handle witness
                    match maybe_witness {
                        // request witness for blamed headers
                        Some(w) => {
                            // this request covers all blamed headers:
                            // [w - w.blame, w - w.blame + 1, ..., w]
                            debug!("Requesting witness at height {}", w);
                            witnesses.request(w);
                        }

                        // for non-blamed headers, we will serve roots from disk
                        None => {
                            // `height` might have been blamed before a chain reorg
                            witnesses.in_flight.write().remove(&height);
                        }
                    }

                    *witnesses.height_of_latest_verified_header.write() = height;
                }
            })
            .expect("Starting the Witness Worker should succeed")
    }

    #[inline]
    fn get_existing_peer_state(
        &self, peer: &NodeId,
    ) -> Result<Arc<RwLock<FullPeerState>>> {
        match self.peers.get(&peer) {
            Some(state) => Ok(state),
            None => {
                // NOTE: this should not happen as we register
                // all peers in `on_peer_connected`
                bail!(ErrorKind::InternalError(format!(
                    "Received message from unknown peer={:?}",
                    peer
                )));
            }
        }
    }

    #[allow(unused)]
    #[inline]
    fn peer_version(&self, peer: &NodeId) -> Result<ProtocolVersion> {
        Ok(self.get_existing_peer_state(peer)?.read().protocol_version)
    }

    #[inline]
    fn validate_peer_state(&self, peer: &NodeId, msg_id: MsgId) -> Result<()> {
        let state = self.get_existing_peer_state(&peer)?;

        if msg_id != msgid::STATUS_PONG_DEPRECATED
            && msg_id != msgid::STATUS_PONG_V2
            && !state.read().handshake_completed
        {
            warn!("Received msg={:?} from handshaking peer={:?}", msg_id, peer);
            bail!(ErrorKind::UnexpectedMessage {
                expected: vec![
                    msgid::STATUS_PONG_DEPRECATED,
                    msgid::STATUS_PONG_V2
                ],
                received: msg_id,
            });
        }

        Ok(())
    }

    #[inline]
    fn validate_peer_type(&self, node_type: NodeType) -> Result<()> {
        match node_type {
            NodeType::Archive => Ok(()),
            NodeType::Full => Ok(()),
            _ => bail!(ErrorKind::UnexpectedPeerType { node_type }),
        }
    }

    #[inline]
    fn validate_genesis_hash(&self, genesis: H256) -> Result<()> {
        let ours = self.consensus.get_data_manager().true_genesis.hash();
        let theirs = genesis;

        if ours != theirs {
            bail!(ErrorKind::GenesisMismatch { ours, theirs });
        }

        Ok(())
    }

    #[rustfmt::skip]
    fn dispatch_message(
        &self, io: &dyn NetworkContext, peer: &NodeId, msg_id: MsgId, rlp: Rlp,
    ) -> Result<()> {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);
        self.validate_peer_state(peer, msg_id)?;
        let min_supported_ver = self.minimum_supported_version();
        let protocol = io.get_protocol();

        match msg_id {
            // general messages
            msgid::STATUS_PONG_DEPRECATED => self.on_status_deprecated(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),
            msgid::STATUS_PONG_V2 => self.on_status_v2(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),

            // sync messages
            msgid::BLOCK_HASHES => self.on_block_hashes(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),
            msgid::BLOCK_HEADERS => self.on_block_headers(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),
            msgid::BLOCK_TXS => self.on_block_txs(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),
            msgid::BLOOMS => self.on_blooms(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),
            msgid::NEW_BLOCK_HASHES => self.on_new_block_hashes(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),
            msgid::RECEIPTS => self.on_receipts(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),
            msgid::STATE_ENTRIES => self.on_state_entries(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),
            msgid::STATE_ROOTS => self.on_state_roots(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),
            msgid::STORAGE_ROOTS => self.on_storage_roots(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),
            msgid::TXS => self.on_txs(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),
            msgid::TX_INFOS => self.on_tx_infos(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),
            msgid::WITNESS_INFO => self.on_witness_info(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),

            // request was throttled by service provider
            msgid::THROTTLED => self.on_throttled(io, peer, decode_rlp_and_check_deprecation(&rlp, min_supported_ver, protocol)?),

            _ => bail!(ErrorKind::UnknownMessage{id: msg_id}),
        }
    }

    #[inline]
    pub fn median_peer_epoch(&self) -> Option<u64> {
        let mut best_epochs = self.peers.fold(vec![], |mut res, state| {
            res.push(state.read().best_epoch);
            res
        });

        best_epochs.sort();

        match best_epochs.len() {
            0 => None,
            n => Some(best_epochs[n / 2]),
        }
    }

    #[inline]
    fn catch_up_mode(&self) -> bool {
        match self.median_peer_epoch() {
            None => true,
            Some(epoch) => {
                let my_epoch = self.consensus.best_epoch_number();
                my_epoch + CATCH_UP_EPOCH_LAG_THRESHOLD < epoch
            }
        }
    }

    #[inline]
    fn print_stats(&self) {
        match self.catch_up_mode() {
            true => {
                let latest_epoch = self.consensus.best_epoch_number();
                let best_peer_epoch = self.epochs.best_peer_epoch();

                let progress = if best_peer_epoch == 0 {
                    0.0
                } else {
                    100.0 * (latest_epoch as f64) / (best_peer_epoch as f64)
                };

                info!(
                    "Catch-up mode: true, latest epoch: {} / {} ({:.2}%), latest verified: {}, inserted header count: {}",
                    latest_epoch,
                    best_peer_epoch,
                    progress,
                    self.witnesses.latest_verified(),
                    self.headers.inserted_count.load(Ordering::Relaxed),
                )
            }
            false => info!(
                "Catch-up mode: false, latest epoch: {}, latest verified: {}",
                self.consensus.best_epoch_number(),
                self.witnesses.latest_verified(),
            ),
        }
    }

    #[inline]
    fn collect_terminals(&self) {
        let terminals = self.peers.fold(vec![], |mut res, state| {
            let mut state = state.write();
            res.extend(state.terminals.iter());
            state.terminals.clear();
            res
        });

        let terminals = terminals.into_iter();
        self.headers.request(terminals, HashSource::NewHash);
    }

    #[inline]
    fn send_status(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        peer_protocol_version: ProtocolVersion,
    ) -> Result<()>
    {
        let msg: Box<dyn Message>;

        if peer_protocol_version == LIGHT_PROTO_V1 {
            msg = Box::new(StatusPingDeprecatedV1 {
                protocol_version: self.protocol_version.0,
                genesis_hash: self
                    .consensus
                    .get_data_manager()
                    .true_genesis
                    .hash(),
                node_type: NodeType::Light,
            });
        } else {
            msg = Box::new(StatusPingV2 {
                chain_id: self.consensus.get_config().chain_id.clone(),
                genesis_hash: self
                    .consensus
                    .get_data_manager()
                    .true_genesis
                    .hash(),
                node_type: NodeType::Light,
            });
        }

        msg.send(io, peer)?;
        Ok(())
    }

    #[inline]
    pub fn send_heartbeat(&self, io: &dyn NetworkContext) {
        let peer_ids = self.peers.all_peers_satisfying(|_| true);

        for peer in peer_ids {
            let protocol_version = match self.get_existing_peer_state(&peer) {
                Ok(state) => state.read().protocol_version,
                Err(_) => {
                    warn!("Peer not found for heartbeat: {:?}", peer);
                    continue;
                }
            };

            debug!("send_heartbeat peer={:?}", peer);

            if let Err(e) = self.send_status(io, &peer, protocol_version) {
                warn!(
                    "Error while sending heartbeat to peer {:?}: {:?}",
                    peer, e
                );
            }
        }
    }

    #[inline]
    pub fn send_raw_tx(
        &self, io: &dyn NetworkContext, peer: &NodeId, raw: Vec<u8>,
    ) -> Result<()> {
        let msg: Box<dyn Message> = Box::new(SendRawTx { raw });
        msg.send(io, peer)?;
        Ok(())
    }

    fn on_status_v2(
        &self, io: &dyn NetworkContext, peer: &NodeId, status: StatusPongV2,
    ) -> Result<()> {
        debug!("on_status (v2) peer={:?} status={:?}", peer, status);

        self.validate_peer_type(status.node_type)?;
        self.validate_genesis_hash(status.genesis_hash)?;
        validate_chain_id(
            &self.consensus.get_config().chain_id,
            &status.chain_id,
        )?;

        {
            let state = self.get_existing_peer_state(peer)?;
            let mut state = state.write();
            state.best_epoch = status.best_epoch;
            state.handshake_completed = true;
            state.terminals = status.terminals.into_iter().collect();
        }

        // NOTE: `start_sync` acquires read locks on peer states so
        // we need to make sure to release locks before calling it
        self.start_sync(io);
        Ok(())
    }

    fn on_status_deprecated(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        status: StatusPongDeprecatedV1,
    ) -> Result<()>
    {
        debug!("on_status (v1) peer={:?} status={:?}", peer, status);

        self.on_status_v2(
            io,
            peer,
            StatusPongV2 {
                chain_id: self.consensus.get_config().chain_id.clone(),
                node_type: status.node_type,
                genesis_hash: status.genesis_hash,
                best_epoch: status.best_epoch,
                terminals: status.terminals,
            },
        )
    }

    fn on_block_hashes(
        &self, io: &dyn NetworkContext, _peer: &NodeId,
        resp: GetBlockHashesResponse,
    ) -> Result<()>
    {
        debug!(
            "received {} block hashes (request id = {})",
            resp.hashes.len(),
            resp.request_id
        );
        trace!("on_block_hashes resp={:?}", resp);

        self.epochs.receive(&resp.request_id);

        // TODO(thegaram): do not request hashes that we did not ask for
        let hashes = resp.hashes.into_iter();
        self.headers.request(hashes, HashSource::Epoch);

        self.start_sync(io);
        Ok(())
    }

    fn on_block_headers(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        resp: GetBlockHeadersResponse,
    ) -> Result<()>
    {
        debug!(
            "received {} block headers (request id = {})",
            resp.headers.len(),
            resp.request_id
        );
        trace!("on_block_headers resp={:?}", resp);

        self.headers.receive(
            peer,
            resp.request_id,
            resp.headers.into_iter(),
        )?;

        self.start_sync(io);
        Ok(())
    }

    fn on_block_txs(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        resp: GetBlockTxsResponse,
    ) -> Result<()>
    {
        debug!(
            "received {} block txs (request id = {})",
            resp.block_txs.len(),
            resp.request_id
        );
        trace!("on_block_txs resp={:?}", resp);

        self.block_txs.receive(
            peer,
            resp.request_id,
            resp.block_txs.into_iter(),
        )?;

        self.block_txs.sync(io);
        Ok(())
    }

    fn on_blooms(
        &self, io: &dyn NetworkContext, peer: &NodeId, resp: GetBloomsResponse,
    ) -> Result<()> {
        debug!(
            "received {} blooms (request id = {})",
            resp.blooms.len(),
            resp.request_id
        );
        trace!("on_blooms resp={:?}", resp);

        self.blooms
            .receive(peer, resp.request_id, resp.blooms.into_iter())?;

        self.blooms.sync(io);
        Ok(())
    }

    fn on_new_block_hashes(
        &self, io: &dyn NetworkContext, peer: &NodeId, msg: NewBlockHashes,
    ) -> Result<()> {
        debug!("received {} new block hashes", msg.hashes.len());
        trace!("on_new_block_hashes msg={:?}", msg);

        if self.catch_up_mode() {
            if let Some(state) = self.peers.get(peer) {
                let mut state = state.write();
                state.terminals.extend(msg.hashes);
            }
            return Ok(());
        }

        self.headers.request_now_from_peer(
            io,
            peer,
            msg.hashes.into_iter(),
            HashSource::NewHash,
        );

        self.start_sync(io);
        Ok(())
    }

    fn on_receipts(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        resp: GetReceiptsResponse,
    ) -> Result<()>
    {
        debug!(
            "received {} receipts (request id = {})",
            resp.receipts.len(),
            resp.request_id
        );
        trace!("on_receipts resp={:?}", resp);

        self.receipts.receive(
            peer,
            resp.request_id,
            resp.receipts.into_iter(),
        )?;

        self.receipts.sync(io);
        Ok(())
    }

    fn on_state_entries(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        resp: GetStateEntriesResponse,
    ) -> Result<()>
    {
        debug!(
            "received {} state entries (request id = {})",
            resp.entries.len(),
            resp.request_id
        );
        trace!("on_state_entries resp={:?}", resp);

        self.state_entries.receive(
            peer,
            resp.request_id,
            resp.entries.into_iter(),
        )?;

        self.state_entries.sync(io);
        Ok(())
    }

    fn on_state_roots(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        resp: GetStateRootsResponse,
    ) -> Result<()>
    {
        debug!(
            "received {} state roots (request id = {})",
            resp.state_roots.len(),
            resp.request_id
        );
        trace!("on_state_roots resp={:?}", resp);

        self.state_roots.receive(
            peer,
            resp.request_id,
            resp.state_roots.into_iter(),
        )?;

        self.state_roots.sync(io);
        Ok(())
    }

    fn on_storage_roots(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        resp: GetStorageRootsResponse,
    ) -> Result<()>
    {
        debug!(
            "received {} storage roots (request id = {})",
            resp.roots.len(),
            resp.request_id
        );
        trace!("on_storage_roots resp={:?}", resp);

        self.storage_roots.receive(
            peer,
            resp.request_id,
            resp.roots.into_iter(),
        )?;

        self.storage_roots.sync(io);
        Ok(())
    }

    fn on_txs(
        &self, io: &dyn NetworkContext, peer: &NodeId, resp: GetTxsResponse,
    ) -> Result<()> {
        debug!(
            "received {} txs (request id = {})",
            resp.txs.len(),
            resp.request_id
        );
        trace!("on_txs resp={:?}", resp);

        self.txs
            .receive(peer, resp.request_id, resp.txs.into_iter())?;

        self.txs.sync(io);
        Ok(())
    }

    fn on_tx_infos(
        &self, io: &dyn NetworkContext, peer: &NodeId, resp: GetTxInfosResponse,
    ) -> Result<()> {
        debug!(
            "received {} tx infos (request id = {})",
            resp.infos.len(),
            resp.request_id
        );
        trace!("on_tx_infos resp={:?}", resp);

        self.tx_infos
            .receive(peer, resp.request_id, resp.infos.into_iter())?;

        self.tx_infos.sync(io);
        Ok(())
    }

    fn on_witness_info(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        resp: GetWitnessInfoResponse,
    ) -> Result<()>
    {
        debug!(
            "received {} witnesses (request id = {})",
            resp.infos.len(),
            resp.request_id
        );
        trace!("on_witness_info resp={:?}", resp);

        self.witnesses.receive(
            peer,
            resp.request_id,
            resp.infos.into_iter(),
        )?;

        self.witnesses.sync(io);
        Ok(())
    }

    fn start_sync(&self, io: &dyn NetworkContext) {
        match self.catch_up_mode() {
            true => {
                self.headers.sync(io);
                self.epochs.sync(io);
            }
            false => {
                self.collect_terminals();
                self.headers.sync(io);
            }
        };

        self.witnesses.sync(io);
        self.blooms.sync(io);
        self.receipts.sync(io);
        self.block_txs.sync(io);
        self.state_entries.sync(io);
        self.state_roots.sync(io);
        self.storage_roots.sync(io);
        self.txs.sync(io);
        self.tx_infos.sync(io);
    }

    fn clean_up_requests(&self) {
        self.block_txs.clean_up();
        self.blooms.clean_up();
        self.epochs.clean_up();
        self.headers.clean_up();
        self.receipts.clean_up();
        self.state_entries.clean_up();
        self.state_roots.clean_up();
        self.storage_roots.clean_up();
        self.tx_infos.clean_up();
        self.txs.clean_up();
        self.witnesses.clean_up();
    }

    fn on_throttled(
        &self, _io: &dyn NetworkContext, peer: &NodeId, resp: Throttled,
    ) -> Result<()> {
        debug!("on_throttled resp={:?}", resp);

        let peer = self.get_existing_peer_state(peer)?;
        peer.write().throttled_msgs.set_throttled(
            resp.msg_id,
            Instant::now() + Duration::from_nanos(resp.wait_time_nanos),
        );

        // TODO(boqiu): update when throttled
        // In case of throttled for a RPC call:
        // 1. Just return error to client;
        // 2. Select another peer to try again (e.g. 3 times at most).
        //
        // In addition, if no peer available, return error to client
        // immediately. So, when any error occur (e.g. proof validation failed,
        // throttled), light node should return error instead of waiting for
        // timeout.

        Ok(())
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        // signal stop to worker thread
        self.stopped.store(true, Ordering::SeqCst);

        if let Some(thread) = self.join_handle.take() {
            // joining a thread from itself is not a good idea; this should not
            // happen in this case as the thread has no references to `Handler`
            assert!(
                thread.thread().id() != thread::current().id(),
                "Attempting to join Witness Worker thread from itself (id = {:?})", thread::current().id(),
            );

            // `stopped` is set and `recv` in the worker will timeout,
            // so the thread should stop eventually.
            thread.join().expect("Witness Worker should not panic");

            // for more info about these issues,
            // see https://stackoverflow.com/a/42791007

            // for a discussion about why we want to join the thread,
            // see https://github.com/rust-lang/rust/issues/48820#issue-303146976
        }
    }
}

impl NetworkProtocolHandler for Handler {
    fn minimum_supported_version(&self) -> ProtocolVersion {
        let my_version = self.protocol_version.0;
        if my_version > LIGHT_PROTOCOL_OLD_VERSIONS_TO_SUPPORT {
            ProtocolVersion(my_version - LIGHT_PROTOCOL_OLD_VERSIONS_TO_SUPPORT)
        } else {
            LIGHT_PROTO_V1
        }
    }

    fn initialize(&self, io: &dyn NetworkContext) {
        io.register_timer(SYNC_TIMER, *SYNC_PERIOD)
            .expect("Error registering sync timer");

        io.register_timer(REQUEST_CLEANUP_TIMER, *CLEANUP_PERIOD)
            .expect("Error registering request cleanup timer");

        io.register_timer(LOG_STATISTICS_TIMER, Duration::from_secs(1))
            .expect("Error registering log statistics timer");

        io.register_timer(HEARTBEAT_TIMER, *HEARTBEAT_PERIOD)
            .expect("Error registering heartbeat timer");

        io.register_timer(TOTAL_WEIGHT_IN_PAST_TIMER, Duration::from_secs(20))
            .expect("Error registering total weight in past timer");
    }

    fn on_message(&self, io: &dyn NetworkContext, peer: &NodeId, raw: &[u8]) {
        trace!("on_message: peer={:?}, raw={:?}", peer, raw);

        let (msg_id, rlp) = match decode_msg(raw) {
            Some(msg) => msg,
            None => {
                return handle_error(
                    io,
                    peer,
                    msgid::INVALID,
                    &ErrorKind::InvalidMessageFormat.into(),
                )
            }
        };

        trace!("on_message: peer={:?}, msgid={:?}", peer, msg_id);

        if let Err(e) = self.dispatch_message(io, peer, msg_id.into(), rlp) {
            handle_error(io, peer, msg_id.into(), &e);
        }
    }

    fn on_peer_connected(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        peer_protocol_version: ProtocolVersion,
    )
    {
        debug!("on_peer_connected: peer={:?}", peer);

        match self.send_status(io, peer, peer_protocol_version) {
            Ok(_) => {
                // insert handshaking peer
                self.peers.insert(*peer);
                self.peers.get(peer).unwrap().write().protocol_version =
                    peer_protocol_version;

                if let Some(ref file) = self.throttling_config_file {
                    let peer = self.peers.get(peer).expect("peer not found");
                    peer.write().unexpected_msgs = TokenBucketManager::load(
                        file,
                        Some("light_protocol::unexpected_msgs"),
                    )
                    .expect("invalid throttling configuration file");
                }
            }
            Err(e) => {
                warn!("Error while sending status: {}", e);
                handle_error(
                    io,
                    peer,
                    msgid::INVALID,
                    &ErrorKind::SendStatusFailed { peer: *peer }.into(),
                );
            }
        }
    }

    fn on_peer_disconnected(&self, _io: &dyn NetworkContext, peer: &NodeId) {
        debug!("on_peer_disconnected: peer={}", peer);
        self.peers.remove(peer);
    }

    fn on_timeout(&self, io: &dyn NetworkContext, timer: TimerToken) {
        trace!("Timeout: timer={:?}", timer);
        match timer {
            SYNC_TIMER => self.start_sync(io),
            REQUEST_CLEANUP_TIMER => self.clean_up_requests(),
            LOG_STATISTICS_TIMER => {
                self.print_stats();
                self.block_txs.print_stats();
                self.blooms.print_stats();
                self.epochs.print_stats();
                self.headers.print_stats();
                self.receipts.print_stats();
                self.state_entries.print_stats();
                self.state_roots.print_stats();
                self.storage_roots.print_stats();
                self.tx_infos.print_stats();
                self.txs.print_stats();
                self.witnesses.print_stats();
            }
            HEARTBEAT_TIMER => {
                self.send_heartbeat(io);
            }
            TOTAL_WEIGHT_IN_PAST_TIMER => {
                self.consensus.update_total_weight_delta_heartbeat();
            }
            // TODO(thegaram): add other timers (e.g. data_man gc)
            _ => warn!("Unknown timer {} triggered.", timer),
        }
    }

    fn send_local_message(&self, _io: &dyn NetworkContext, _message: Vec<u8>) {
        unreachable!("Light node handler does not have send_local_message.")
    }

    fn on_work_dispatch(&self, _io: &dyn NetworkContext, _work_type: u8) {
        unreachable!("Light node handler does not have on_work_dispatch.")
    }
}
