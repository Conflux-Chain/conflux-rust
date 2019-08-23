// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use io::TimerToken;
use parking_lot::RwLock;
use rand::Rng;
use rlp::Rlp;
use std::sync::{Arc, Weak};

use cfx_types::H256;
use primitives::{SignedTransaction, TransactionWithSignature};

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        common::{LedgerInfo, Peers, Validate},
        handle_error,
        message::{
            msgid, BlockHashes as GetBlockHashesResponse,
            BlockHeaders as GetBlockHeadersResponse, GetBlockHashesByEpoch,
            GetBlockHeaders, GetReceipts, GetStateEntry, GetStateRoot, GetTxs,
            NewBlockHashes, NodeType, Receipts as GetReceiptsResponse,
            SendRawTx, StateEntry as GetStateEntryResponse,
            StateRoot as GetStateRootResponse, StatusPing, StatusPong,
            Txs as GetTxsResponse,
        },
        Error, ErrorKind, LIGHT_PROTOCOL_ID, LIGHT_PROTOCOL_VERSION,
    },
    message::{Message, MsgId},
    network::{
        throttling::THROTTLING_SERVICE, NetworkContext, NetworkProtocolHandler,
        NetworkService, PeerId,
    },
    parameters::light::{
        MAX_EPOCHS_TO_SEND, MAX_HEADERS_TO_SEND, MAX_TXS_TO_SEND,
    },
    sync::SynchronizationGraph,
    TransactionPool,
};

#[derive(Default)]
pub struct LightPeerState {
    pub handshake_completed: bool,
    pub protocol_version: u8,
}

pub struct Provider {
    // shared consensus graph
    consensus: Arc<ConsensusGraph>,

    // shared synchronization graph
    graph: Arc<SynchronizationGraph>,

    // helper API for retrieving ledger information
    ledger: LedgerInfo,

    // shared network service
    // NOTE: use weak pointer in order to avoid circular references
    network: Weak<NetworkService>,

    // collection of all peers available
    peers: Peers<LightPeerState>,

    // shared transaction pool
    tx_pool: Arc<TransactionPool>,

    // helper API for validating ledger and state information
    validate: Validate,
}

impl Provider {
    pub fn new(
        consensus: Arc<ConsensusGraph>, graph: Arc<SynchronizationGraph>,
        network: Weak<NetworkService>, tx_pool: Arc<TransactionPool>,
    ) -> Self
    {
        let ledger = LedgerInfo::new(consensus.clone());
        let peers = Peers::new();
        let validate = Validate::new(consensus.clone());

        Provider {
            consensus,
            graph,
            ledger,
            network,
            peers,
            tx_pool,
            validate,
        }
    }

    pub fn register(
        self: Arc<Self>, network: Arc<NetworkService>,
    ) -> Result<(), String> {
        network
            .register_protocol(
                self,
                LIGHT_PROTOCOL_ID,
                &[LIGHT_PROTOCOL_VERSION],
            )
            .map_err(|e| {
                format!("failed to register protocol Provider: {:?}", e)
            })
    }

    #[inline]
    fn get_existing_peer_state(
        &self, peer: &PeerId,
    ) -> Result<Arc<RwLock<LightPeerState>>, Error> {
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

    #[inline]
    fn validate_peer_state(
        &self, peer: PeerId, msg_id: MsgId,
    ) -> Result<(), Error> {
        let state = self.get_existing_peer_state(&peer)?;

        if msg_id != msgid::STATUS_PING && !state.read().handshake_completed {
            warn!("Received msg={:?} from handshaking peer={:?}", msg_id, peer);
            return Err(ErrorKind::UnexpectedMessage.into());
        }

        Ok(())
    }

    #[rustfmt::skip]
    fn dispatch_message(
        &self, io: &dyn NetworkContext, peer: PeerId, msg_id: MsgId, rlp: Rlp,
    ) -> Result<(), Error> {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);
        self.validate_peer_state(peer, msg_id)?;

        match msg_id {
            msgid::STATUS_PING => self.on_status(io, peer, &rlp),
            msgid::GET_STATE_ROOT => self.on_get_state_root(io, peer, &rlp),
            msgid::GET_STATE_ENTRY => self.on_get_state_entry(io, peer, &rlp),
            msgid::GET_BLOCK_HASHES_BY_EPOCH => self.on_get_block_hashes_by_epoch(io, peer, &rlp),
            msgid::GET_BLOCK_HEADERS => self.on_get_block_headers(io, peer, &rlp),
            msgid::SEND_RAW_TX => self.on_send_raw_tx(io, peer, &rlp),
            msgid::GET_RECEIPTS => self.on_get_receipts(io, peer, &rlp),
            msgid::GET_TXS => self.on_get_txs(io, peer, &rlp),
            _ => Err(ErrorKind::UnknownMessage.into()),
        }
    }

    #[inline]
    fn all_light_peers(&self) -> Vec<PeerId> {
        // peers completing the handshake are guaranteed to be light peers
        self.peers.all_peers_satisfying(|s| s.handshake_completed)
    }

    #[inline]
    fn tx_by_hash(&self, hash: H256) -> Option<SignedTransaction> {
        if let Some(info) = self.consensus.get_transaction_info_by_hash(&hash) {
            return Some(info.0);
        };

        if let Some(tx) = self.tx_pool.get_transaction(&hash) {
            return Some((*tx).clone());
        };

        None
    }

    fn send_status(
        &self, io: &dyn NetworkContext, peer: PeerId,
    ) -> Result<(), Error> {
        let best_info = self.consensus.get_best_info();
        let genesis_hash = self.consensus.data_man.true_genesis_block.hash();

        let terminals = match &best_info.terminal_block_hashes {
            Some(x) => x.clone(),
            None => best_info.bounded_terminal_block_hashes.clone(),
        };

        let msg: Box<dyn Message> = Box::new(StatusPong {
            best_epoch: best_info.best_epoch_number,
            genesis_hash,
            network_id: 0x0,
            node_type: NodeType::Full,
            protocol_version: LIGHT_PROTOCOL_VERSION,
            terminals,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    #[inline]
    fn validate_peer_type(&self, node_type: &NodeType) -> Result<(), Error> {
        match node_type {
            NodeType::Light => Ok(()),
            _ => Err(ErrorKind::UnexpectedPeerType.into()),
        }
    }

    fn on_status(
        &self, io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let status: StatusPing = rlp.as_val()?;
        info!("on_status peer={:?} status={:?}", peer, status);

        self.validate_peer_type(&status.node_type)?;
        self.validate.genesis_hash(status.genesis_hash)?;

        if let Err(e) = self.send_status(io, peer) {
            warn!("Failed to send status to peer={:?}: {:?}", peer, e);
            return Err(ErrorKind::SendStatusFailed.into());
        };

        let state = self.get_existing_peer_state(&peer)?;
        let mut state = state.write();
        state.handshake_completed = true;
        state.protocol_version = status.protocol_version;
        Ok(())
    }

    fn on_get_state_root(
        &self, io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetStateRoot = rlp.as_val()?;
        info!("on_get_state_root req={:?}", req);
        let request_id = req.request_id;

        let pivot_hash = self.ledger.pivot_hash_of(req.epoch)?;
        let state_root = self.ledger.state_root_with_proof_of(req.epoch)?;

        let msg: Box<dyn Message> = Box::new(GetStateRootResponse {
            request_id,
            pivot_hash,
            state_root,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_get_state_entry(
        &self, io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetStateEntry = rlp.as_val()?;
        info!("on_get_state_entry req={:?}", req);
        let request_id = req.request_id;

        let pivot_hash = self.ledger.pivot_hash_of(req.epoch)?;
        let state_root = self.ledger.state_root_with_proof_of(req.epoch)?;
        let (entry, proof) = self.ledger.state_entry_at(req.epoch, &req.key)?;
        let entry = entry.map(|x| x.to_vec());

        let msg: Box<dyn Message> = Box::new(GetStateEntryResponse {
            request_id,
            pivot_hash,
            state_root,
            entry,
            proof,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_get_block_hashes_by_epoch(
        &self, io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetBlockHashesByEpoch = rlp.as_val()?;
        info!("on_get_block_hashes_by_epoch req={:?}", req);
        let request_id = req.request_id;

        let hashes = req
            .epochs
            .iter()
            .take(MAX_EPOCHS_TO_SEND)
            .filter_map(|&e| self.graph.get_block_hashes_by_epoch(e).ok())
            .fold(vec![], |mut res, sub| {
                res.extend(sub);
                res
            });

        let msg: Box<dyn Message> =
            Box::new(GetBlockHashesResponse { request_id, hashes });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_get_block_headers(
        &self, io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetBlockHeaders = rlp.as_val()?;
        info!("on_get_block_headers req={:?}", req);
        let request_id = req.request_id;

        let headers = req
            .hashes
            .iter()
            .take(MAX_HEADERS_TO_SEND)
            .filter_map(|h| self.graph.block_header_by_hash(&h))
            .collect();

        let msg: Box<dyn Message> = Box::new(GetBlockHeadersResponse {
            request_id,
            headers,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_send_raw_tx(
        &self, _io: &dyn NetworkContext, _peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: SendRawTx = rlp.as_val()?;
        info!("on_send_raw_tx req={:?}", req);
        let tx: TransactionWithSignature = rlp::decode(&req.raw)?;

        let (passed, failed) = self.tx_pool.insert_new_transactions(&vec![tx]);

        match (passed.len(), failed.len()) {
            (0, 0) => {
                info!("Tx already inserted, ignoring");
                Ok(())
            }
            (0, 1) => {
                let err = failed.values().next().expect("Not empty");
                warn!("Failed to insert tx: {}", err);
                Ok(())
            }
            (1, 0) => {
                info!("Tx inserted successfully");
                // TODO(thegaram): consider relaying to peers
                Ok(())
            }
            _ => {
                // NOTE: this should not happen
                error!(
                    "insert_new_transactions failed: {:?}, {:?}",
                    passed, failed
                );
                Err(ErrorKind::InternalError.into())
            }
        }
    }

    fn on_get_receipts(
        &self, io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetReceipts = rlp.as_val()?;
        info!("on_get_receipts req={:?}", req);
        let request_id = req.request_id;

        let pivot_hash = self.ledger.pivot_hash_of(req.epoch)?;
        let receipts = self.ledger.receipts_with_proof_of(req.epoch)?;

        let msg: Box<dyn Message> = Box::new(GetReceiptsResponse {
            request_id,
            pivot_hash,
            receipts,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_get_txs(
        &self, io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetTxs = rlp.as_val()?;
        info!("on_get_txs req={:?}", req);
        let request_id = req.request_id;

        let txs = req
            .hashes
            .into_iter()
            .take(MAX_TXS_TO_SEND)
            .filter_map(|h| self.tx_by_hash(h))
            .collect();

        let msg: Box<dyn Message> =
            Box::new(GetTxsResponse { request_id, txs });

        msg.send(io, peer)?;
        Ok(())
    }

    fn broadcast(
        &self, io: &dyn NetworkContext, mut peers: Vec<PeerId>,
        msg: &dyn Message,
    ) -> Result<(), Error>
    {
        info!("broadcast peers={:?}", peers);

        let throttle_ratio = THROTTLING_SERVICE.read().get_throttling_ratio();
        let total = peers.len();
        let allowed = (total as f64 * throttle_ratio) as usize;

        if total > allowed {
            debug!(
                "Apply throttling for broadcast, total: {}, allowed: {}",
                total, allowed
            );
            rand::thread_rng().shuffle(&mut peers);
            peers.truncate(allowed);
        }

        for id in peers {
            msg.send(io, id)?;
        }

        Ok(())
    }

    pub fn relay_hashes(&self, hashes: Vec<H256>) -> Result<(), Error> {
        info!("relay_hashes hashes={:?}", hashes);

        if hashes.is_empty() {
            return Ok(());
        }

        // check network availability
        let network = match self.network.upgrade() {
            Some(network) => network,
            None => {
                error!("Network unavailable, not relaying hashes");
                return Err(ErrorKind::InternalError.into());
            }
        };

        // broadcast message
        let res = network.with_context(LIGHT_PROTOCOL_ID, |io| {
            let msg: Box<dyn Message> = Box::new(NewBlockHashes { hashes });
            self.broadcast(io, self.all_light_peers(), msg.as_ref())
        });

        if let Err(e) = res {
            warn!("Error broadcasting blocks: {:?}", e);
        };

        Ok(())
    }
}

impl NetworkProtocolHandler for Provider {
    fn initialize(&self, _io: &dyn NetworkContext) {}

    fn on_message(&self, io: &dyn NetworkContext, peer: PeerId, raw: &[u8]) {
        trace!("on_message: peer={:?}, raw={:?}", peer, raw);

        if raw.len() < 2 {
            return handle_error(
                io,
                peer,
                msgid::INVALID,
                ErrorKind::InvalidMessageFormat.into(),
            );
        }

        let msg_id = raw[0];
        let rlp = Rlp::new(&raw[1..]);
        debug!("on_message: peer={:?}, msgid={:?}", peer, msg_id);

        if let Err(e) = self.dispatch_message(io, peer, msg_id.into(), rlp) {
            handle_error(io, peer, msg_id.into(), e);
        }
    }

    fn on_peer_connected(&self, _io: &dyn NetworkContext, peer: PeerId) {
        info!("on_peer_connected: peer={:?}", peer);

        // insert handshaking peer, wait for StatusPing
        self.peers.insert(peer);
    }

    fn on_peer_disconnected(&self, _io: &dyn NetworkContext, peer: PeerId) {
        info!("on_peer_disconnected: peer={:?}", peer);
        self.peers.remove(&peer);
    }

    fn on_timeout(&self, _io: &dyn NetworkContext, _timer: TimerToken) {
        // EMPTY
    }
}
