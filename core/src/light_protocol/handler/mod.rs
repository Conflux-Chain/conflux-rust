// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod sync;

use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{validate_chain_id, FullPeerState, Peers},
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
        Error, ErrorKind, LIGHT_PROTOCOL_OLD_VERSIONS_TO_SUPPORT,
        LIGHT_PROTOCOL_VERSION, LIGHT_PROTO_V1,
    },
    message::{decode_msg, decode_rlp_and_check_deprecation, Message, MsgId},
    network::{NetworkContext, NetworkProtocolHandler},
    parameters::light::{
        CATCH_UP_EPOCH_LAG_THRESHOLD, CLEANUP_PERIOD, SYNC_PERIOD,
    },
    sync::{message::Throttled, SynchronizationGraph},
    UniqueId,
};
use cfx_types::H256;
use io::TimerToken;
use network::{node_table::NodeId, service::ProtocolVersion};
use parking_lot::RwLock;
use rlp::Rlp;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use sync::{
    BlockTxs, Blooms, Epochs, HashSource, Headers, Receipts, StateEntries,
    StateRoots, StorageRoots, TxInfos, Txs, Witnesses,
};
use throttling::token_bucket::TokenBucketManager;

const SYNC_TIMER: TimerToken = 0;
const REQUEST_CLEANUP_TIMER: TimerToken = 1;

#[derive(Debug)]
struct Statistics {
    catch_up_mode: bool,
    latest_epoch: u64,
    latest_verified: u64,
}

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

    // collection of all peers available
    pub peers: Arc<Peers<FullPeerState>>,

    // receipt sync manager
    pub receipts: Arc<Receipts>,

    // state entry sync manager
    pub state_entries: StateEntries,

    // state root sync manager
    pub state_roots: Arc<StateRoots>,

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
    ) -> Self
    {
        let peers = Arc::new(Peers::new());
        let request_id_allocator = Arc::new(UniqueId::new());

        // TODO(thegaram): At this point the light node does not persist
        // anything. Need to make sure we persist the checkpoint hashes,
        // along with a Merkle-root for headers in each era.
        graph.recover_graph_from_db(true /* header_only */);

        let headers = Arc::new(Headers::new(
            graph.clone(),
            peers.clone(),
            request_id_allocator.clone(),
        ));

        let epochs = Epochs::new(
            consensus.clone(),
            headers.clone(),
            peers.clone(),
            request_id_allocator.clone(),
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

        let state_roots = Arc::new(StateRoots::new(
            peers.clone(),
            request_id_allocator.clone(),
            witnesses.clone(),
        ));

        let state_entries = StateEntries::new(
            peers.clone(),
            state_roots.clone(),
            request_id_allocator.clone(),
        );

        let snapshot_epoch_count =
            consensus.get_data_manager().get_snapshot_epoch_count() as u64;

        let storage_roots = StorageRoots::new(
            peers.clone(),
            snapshot_epoch_count,
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

        Handler {
            protocol_version: LIGHT_PROTOCOL_VERSION,
            block_txs,
            blooms,
            consensus,
            epochs,
            headers,
            peers,
            receipts,
            state_entries,
            state_roots,
            storage_roots,
            txs,
            tx_infos,
            throttling_config_file,
            witnesses,
        }
    }

    #[inline]
    fn get_existing_peer_state(
        &self, peer: &NodeId,
    ) -> Result<Arc<RwLock<FullPeerState>>, Error> {
        match self.peers.get(&peer) {
            Some(state) => Ok(state),
            None => {
                // NOTE: this should not happen as we register
                // all peers in `on_peer_connected`
                error!("Received message from unknown peer={:?}", peer);
                Err(ErrorKind::InternalError.into())
            }
        }
    }

    #[allow(unused)]
    #[inline]
    fn peer_version(&self, peer: &NodeId) -> Result<ProtocolVersion, Error> {
        Ok(self.get_existing_peer_state(peer)?.read().protocol_version)
    }

    #[inline]
    fn validate_peer_state(
        &self, peer: &NodeId, msg_id: MsgId,
    ) -> Result<(), Error> {
        let state = self.get_existing_peer_state(&peer)?;

        if msg_id != msgid::STATUS_PONG_DEPRECATED
            && msg_id != msgid::STATUS_PONG_V2
            && !state.read().handshake_completed
        {
            warn!("Received msg={:?} from handshaking peer={:?}", msg_id, peer);
            return Err(ErrorKind::UnexpectedMessage.into());
        }

        Ok(())
    }

    #[inline]
    fn validate_peer_type(&self, node_type: &NodeType) -> Result<(), Error> {
        match node_type {
            NodeType::Archive => Ok(()),
            NodeType::Full => Ok(()),
            _ => Err(ErrorKind::UnexpectedPeerType.into()),
        }
    }

    #[inline]
    fn validate_genesis_hash(&self, genesis: H256) -> Result<(), Error> {
        match self.consensus.get_data_manager().true_genesis.hash() {
            h if h == genesis => Ok(()),
            h => {
                debug!(
                    "Genesis mismatch (ours: {:?}, theirs: {:?})",
                    h, genesis
                );
                Err(ErrorKind::GenesisMismatch.into())
            }
        }
    }

    #[rustfmt::skip]
    fn dispatch_message(
        &self, io: &dyn NetworkContext, peer: &NodeId, msg_id: MsgId, rlp: Rlp,
    ) -> Result<(), Error> {
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

            _ => Err(ErrorKind::UnknownMessage.into()),
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
    fn get_statistics(&self) -> Statistics {
        Statistics {
            catch_up_mode: self.catch_up_mode(),
            latest_epoch: self.consensus.best_epoch_number(),
            latest_verified: self.witnesses.latest_verified(),
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
    ) -> Result<(), Error>
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
    pub fn send_raw_tx(
        &self, io: &dyn NetworkContext, peer: &NodeId, raw: Vec<u8>,
    ) -> Result<(), Error> {
        let msg: Box<dyn Message> = Box::new(SendRawTx { raw });
        msg.send(io, peer)?;
        Ok(())
    }

    fn on_status_v2(
        &self, io: &dyn NetworkContext, peer: &NodeId, status: StatusPongV2,
    ) -> Result<(), Error> {
        info!("on_status peer={:?} status={:?}", peer, status);

        self.validate_peer_type(&status.node_type)?;
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
    ) -> Result<(), Error>
    {
        info!("on_status peer={:?} status={:?}", peer, status);

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
    ) -> Result<(), Error>
    {
        debug!("on_block_hashes resp={:?}", resp);

        self.epochs.receive(&resp.request_id);

        let hashes = resp.hashes.into_iter();
        self.headers.request(hashes, HashSource::Epoch);

        self.start_sync(io);
        Ok(())
    }

    fn on_block_headers(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        resp: GetBlockHeadersResponse,
    ) -> Result<(), Error>
    {
        debug!("on_block_headers resp={:?}", resp);

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
    ) -> Result<(), Error>
    {
        debug!("on_block_txs resp={:?}", resp);

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
    ) -> Result<(), Error> {
        debug!("on_blooms resp={:?}", resp);

        self.blooms
            .receive(peer, resp.request_id, resp.blooms.into_iter())?;

        self.blooms.sync(io);
        Ok(())
    }

    fn on_new_block_hashes(
        &self, io: &dyn NetworkContext, peer: &NodeId, msg: NewBlockHashes,
    ) -> Result<(), Error> {
        debug!("on_new_block_hashes msg={:?}", msg);

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
    ) -> Result<(), Error>
    {
        debug!("on_receipts resp={:?}", resp);

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
    ) -> Result<(), Error>
    {
        debug!("on_state_entries resp={:?}", resp);

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
    ) -> Result<(), Error>
    {
        debug!("on_state_roots resp={:?}", resp);

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
    ) -> Result<(), Error>
    {
        debug!("on_storage_roots resp={:?}", resp);

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
    ) -> Result<(), Error> {
        debug!("on_txs resp={:?}", resp);

        self.txs
            .receive(peer, resp.request_id, resp.txs.into_iter())?;

        self.txs.sync(io);
        Ok(())
    }

    fn on_tx_infos(
        &self, io: &dyn NetworkContext, peer: &NodeId, resp: GetTxInfosResponse,
    ) -> Result<(), Error> {
        debug!("on_tx_infos resp={:?}", resp);

        self.tx_infos
            .receive(peer, resp.request_id, resp.infos.into_iter())?;

        self.tx_infos.sync(io);
        Ok(())
    }

    fn on_witness_info(
        &self, io: &dyn NetworkContext, peer: &NodeId,
        resp: GetWitnessInfoResponse,
    ) -> Result<(), Error>
    {
        debug!("on_witness_info resp={:?}", resp);

        self.witnesses.receive(
            peer,
            resp.request_id,
            resp.infos.into_iter(),
        )?;

        self.witnesses.sync(io);
        Ok(())
    }

    fn start_sync(&self, io: &dyn NetworkContext) {
        info!("general sync statistics: {:?}", self.get_statistics());

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
        trace!("clean_up_requests");
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
    ) -> Result<(), Error> {
        debug!("on_throttled resp={:?}", resp);

        let peer = self.get_existing_peer_state(peer)?;
        peer.write().throttled_msgs.set_throttled(
            resp.msg_id,
            Instant::now() + Duration::from_nanos(resp.wait_time_nanos),
        );

        // todo (boqiu): update when throttled
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
                    ErrorKind::InvalidMessageFormat.into(),
                )
            }
        };

        debug!("on_message: peer={:?}, msgid={:?}", peer, msg_id);

        if let Err(e) = self.dispatch_message(io, peer, msg_id.into(), rlp) {
            handle_error(io, peer, msg_id.into(), e);
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
                    ErrorKind::SendStatusFailed.into(),
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
