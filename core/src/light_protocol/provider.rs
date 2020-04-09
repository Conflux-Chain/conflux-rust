// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use io::TimerToken;
use parking_lot::RwLock;
use rlp::Rlp;
use std::sync::{Arc, Weak};

use cfx_types::H256;
use primitives::{SignedTransaction, TransactionWithSignature};

use crate::{
    consensus::SharedConsensusGraph,
    light_protocol::{
        common::{LedgerInfo, LightPeerState, Peers},
        handle_error,
        message::{
            msgid, BlockHashes as GetBlockHashesResponse,
            BlockHeaders as GetBlockHeadersResponse,
            BlockTxs as GetBlockTxsResponse, BlockTxsWithHash, BloomWithEpoch,
            Blooms as GetBloomsResponse, GetBlockHashesByEpoch,
            GetBlockHeaders, GetBlockTxs, GetBlooms, GetReceipts,
            GetStateEntries, GetStateRoots, GetTxInfos, GetTxs, GetWitnessInfo,
            NewBlockHashes, NodeType, Receipts as GetReceiptsResponse,
            ReceiptsWithEpoch, SendRawTx,
            StateEntries as GetStateEntriesResponse, StateEntryWithKey,
            StateRootWithEpoch, StateRoots as GetStateRootsResponse,
            StatusPing, StatusPong, TxInfo, TxInfos as GetTxInfosResponse,
            Txs as GetTxsResponse, WitnessInfo as GetWitnessInfoResponse,
            WitnessInfoWithHeight,
        },
        Error, ErrorKind, LIGHT_PROTOCOL_ID, LIGHT_PROTOCOL_VERSION,
    },
    message::{decode_msg, Message, MsgId},
    network::{
        throttling::THROTTLING_SERVICE, NetworkContext, NetworkProtocolHandler,
        NetworkService,
    },
    parameters::light::{
        MAX_EPOCHS_TO_SEND, MAX_HEADERS_TO_SEND, MAX_TXS_TO_SEND,
    },
    sync::{message::Throttled, SynchronizationGraph},
    TransactionPool,
};
use network::node_table::NodeId;
use rand::prelude::SliceRandom;
use throttling::token_bucket::{ThrottleResult, TokenBucketManager};

pub struct Provider {
    // shared consensus graph
    consensus: SharedConsensusGraph,

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

    throttling_config_file: Option<String>,
}

impl Provider {
    pub fn new(
        consensus: SharedConsensusGraph, graph: Arc<SynchronizationGraph>,
        network: Weak<NetworkService>, tx_pool: Arc<TransactionPool>,
        throttling_config_file: Option<String>,
    ) -> Self
    {
        let ledger = LedgerInfo::new(consensus.clone());
        let peers = Peers::new();

        Provider {
            consensus,
            graph,
            ledger,
            network,
            peers,
            tx_pool,
            throttling_config_file,
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
        &self, peer: &NodeId,
    ) -> Result<Arc<RwLock<LightPeerState>>, Error> {
        match self.peers.get(peer) {
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
        &self, peer: &NodeId, msg_id: MsgId,
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
        &self, io: &dyn NetworkContext, peer: &NodeId, msg_id: MsgId, rlp: Rlp,
    ) -> Result<(), Error> {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);
        self.validate_peer_state(peer, msg_id)?;

        match msg_id {
            msgid::STATUS_PING => self.on_status(io, peer, &rlp),
            msgid::GET_STATE_ENTRIES => self.on_get_state_entries(io, peer, &rlp),
            msgid::GET_STATE_ROOTS => self.on_get_state_roots(io, peer, &rlp),
            msgid::GET_BLOCK_HASHES_BY_EPOCH => self.on_get_block_hashes_by_epoch(io, peer, &rlp),
            msgid::GET_BLOCK_HEADERS => self.on_get_block_headers(io, peer, &rlp),
            msgid::SEND_RAW_TX => self.on_send_raw_tx(io, peer, &rlp),
            msgid::GET_RECEIPTS => self.on_get_receipts(io, peer, &rlp),
            msgid::GET_TXS => self.on_get_txs(io, peer, &rlp),
            msgid::GET_WITNESS_INFO => self.on_get_witness_info(io, peer, &rlp),
            msgid::GET_BLOOMS => self.on_get_blooms(io, peer, &rlp),
            msgid::GET_BLOCK_TXS => self.on_get_block_txs(io, peer, &rlp),
            msgid::GET_TX_INFOS => self.on_get_tx_infos(io, peer, &rlp),
            _ => Err(ErrorKind::UnknownMessage.into()),
        }
    }

    #[inline]
    fn all_light_peers(&self) -> Vec<NodeId> {
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

    #[inline]
    fn tx_info_by_hash(&self, hash: H256) -> Option<TxInfo> {
        let addr = match self.consensus.get_transaction_info_by_hash(&hash) {
            Some(info) => info.2,
            None => {
                warn!("Unable to get tx info for {:?}", hash);
                return None;
            }
        };

        let block_hash = addr.block_hash;
        let index = addr.index;

        let epoch = match self.consensus.get_block_epoch_number(&block_hash) {
            Some(epoch) => epoch,
            None => {
                warn!("Unable to get epoch number for block {:?}", block_hash);
                return None;
            }
        };

        let epoch_receipts = match self.ledger.receipts_of(epoch) {
            Ok(rs) => rs,
            Err(e) => {
                warn!("Unable to retrieve receipts for {}: {}", epoch, e);
                return None;
            }
        };

        let block = match self.ledger.block(block_hash) {
            Ok(b) => b,
            Err(e) => {
                warn!("Unable to retrieve block {:?}: {}", block_hash, e);
                return None;
            }
        };

        let block_txs = block
            .transactions
            .clone()
            .into_iter()
            .map(|arc_tx| (*arc_tx).clone())
            .collect();

        Some(TxInfo {
            tx_hash: hash,
            epoch,
            block_hash,
            index,
            epoch_receipts,
            block_txs,
        })
    }

    fn send_status(
        &self, io: &dyn NetworkContext, peer: &NodeId,
    ) -> Result<(), Error> {
        let best_info = self.consensus.best_info();
        let genesis_hash = self.graph.data_man.true_genesis.hash();

        let terminals = best_info.bounded_terminal_block_hashes.clone();

        let msg: Box<dyn Message> = Box::new(StatusPong {
            best_epoch: best_info.best_epoch_number,
            genesis_hash,
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

    #[inline]
    fn validate_genesis_hash(&self, genesis: H256) -> Result<(), Error> {
        match self.graph.data_man.true_genesis.hash() {
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

    fn on_status(
        &self, io: &dyn NetworkContext, peer: &NodeId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let status: StatusPing = rlp.as_val()?;
        info!("on_status peer={:?} status={:?}", peer, status);
        self.throttle(peer, &status)?;

        self.validate_peer_type(&status.node_type)?;
        self.validate_genesis_hash(status.genesis_hash)?;

        if let Err(e) = self.send_status(io, peer) {
            warn!("Failed to send status to peer={:?}: {:?}", peer, e);
            return Err(ErrorKind::SendStatusFailed.into());
        };

        let state = self.get_existing_peer_state(peer)?;
        let mut state = state.write();
        state.handshake_completed = true;
        state.protocol_version = status.protocol_version;
        Ok(())
    }

    fn on_get_state_roots(
        &self, io: &dyn NetworkContext, peer: &NodeId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetStateRoots = rlp.as_val()?;
        info!("on_get_state_roots req={:?}", req);
        self.throttle(peer, &req)?;
        let request_id = req.request_id;

        let state_roots = req
            .epochs
            .into_iter()
            .map(|e| self.ledger.state_root_of(e).map(|root| (e, root)))
            .filter_map(Result::ok)
            .map(|(epoch, state_root)| StateRootWithEpoch { epoch, state_root })
            .collect();

        let msg: Box<dyn Message> = Box::new(GetStateRootsResponse {
            request_id,
            state_roots,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_get_state_entries(
        &self, io: &dyn NetworkContext, peer: &NodeId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetStateEntries = rlp.as_val()?;
        info!("on_get_state_entries req={:?}", req);
        self.throttle(peer, &req)?;
        let request_id = req.request_id;

        let entries = req
            .keys
            .into_iter()
            .map(|key| {
                self.ledger
                    .state_entry_at(key.epoch, &key.key)
                    .map(|(entry, proof)| (key, entry, proof))
            })
            .filter_map(Result::ok)
            .map(|(key, entry, proof)| StateEntryWithKey { key, entry, proof })
            .collect();

        let msg: Box<dyn Message> = Box::new(GetStateEntriesResponse {
            request_id,
            entries,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_get_block_hashes_by_epoch(
        &self, io: &dyn NetworkContext, peer: &NodeId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetBlockHashesByEpoch = rlp.as_val()?;
        info!("on_get_block_hashes_by_epoch req={:?}", req);
        self.throttle(peer, &req)?;
        let request_id = req.request_id;

        let hashes = req
            .epochs
            .iter()
            .take(MAX_EPOCHS_TO_SEND)
            .filter_map(|&e| self.graph.get_all_block_hashes_by_epoch(e).ok())
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
        &self, io: &dyn NetworkContext, peer: &NodeId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetBlockHeaders = rlp.as_val()?;
        info!("on_get_block_headers req={:?}", req);
        self.throttle(peer, &req)?;
        let request_id = req.request_id;

        let headers = req
            .hashes
            .iter()
            .take(MAX_HEADERS_TO_SEND)
            .filter_map(|h| {
                self.graph
                    .data_man
                    .block_header_by_hash(&h)
                    .map(|header_arc| header_arc.as_ref().clone())
            })
            .collect();

        let msg: Box<dyn Message> = Box::new(GetBlockHeadersResponse {
            request_id,
            headers,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_send_raw_tx(
        &self, _io: &dyn NetworkContext, peer: &NodeId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: SendRawTx = rlp.as_val()?;
        info!("on_send_raw_tx req={:?}", req);
        self.throttle(peer, &req)?;
        let tx: TransactionWithSignature = rlp::decode(&req.raw)?;

        let (passed, failed) = self.tx_pool.insert_new_transactions(vec![tx]);

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
        &self, io: &dyn NetworkContext, peer: &NodeId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetReceipts = rlp.as_val()?;
        info!("on_get_receipts req={:?}", req);
        self.throttle(peer, &req)?;
        let request_id = req.request_id;

        let receipts = req
            .epochs
            .into_iter()
            .map(|e| self.ledger.receipts_of(e).map(|receipts| (e, receipts)))
            .filter_map(Result::ok)
            .map(|(epoch, epoch_receipts)| ReceiptsWithEpoch {
                epoch,
                epoch_receipts,
            })
            .collect();

        let msg: Box<dyn Message> = Box::new(GetReceiptsResponse {
            request_id,
            receipts,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_get_txs(
        &self, io: &dyn NetworkContext, peer: &NodeId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetTxs = rlp.as_val()?;
        info!("on_get_txs req={:?}", req);
        self.throttle(peer, &req)?;
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

    fn on_get_witness_info(
        &self, io: &dyn NetworkContext, peer: &NodeId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetWitnessInfo = rlp.as_val()?;
        info!("on_get_witness_info req={:?}", req);
        self.throttle(peer, &req)?;
        let request_id = req.request_id;

        let infos = req
            .witnesses
            .into_iter()
            .map(|w| self.ledger.witness_info(w))
            .collect::<Result<Vec<WitnessInfoWithHeight>, Error>>()?;

        let msg: Box<dyn Message> =
            Box::new(GetWitnessInfoResponse { request_id, infos });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_get_blooms(
        &self, io: &dyn NetworkContext, peer: &NodeId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetBlooms = rlp.as_val()?;
        info!("on_get_blooms req={:?}", req);
        self.throttle(peer, &req)?;
        let request_id = req.request_id;

        let blooms = req
            .epochs
            .into_iter()
            .map(|e| self.ledger.bloom_of(e).map(|bloom| (e, bloom)))
            .filter_map(Result::ok)
            .map(|(epoch, bloom)| BloomWithEpoch { epoch, bloom })
            .collect();

        let msg: Box<dyn Message> =
            Box::new(GetBloomsResponse { request_id, blooms });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_get_block_txs(
        &self, io: &dyn NetworkContext, peer: &NodeId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetBlockTxs = rlp.as_val()?;
        info!("on_get_block_txs req={:?}", req);
        self.throttle(peer, &req)?;
        let request_id = req.request_id;

        let block_txs = req
            .hashes
            .into_iter()
            .map(|h| self.ledger.block(h))
            .filter_map(Result::ok)
            .map(|block| {
                let block_txs = block
                    .transactions
                    .clone()
                    .into_iter()
                    .map(|arc_tx| (*arc_tx).clone())
                    .collect();
                BlockTxsWithHash {
                    hash: block.hash(),
                    block_txs,
                }
            })
            .collect();

        let msg: Box<dyn Message> = Box::new(GetBlockTxsResponse {
            request_id,
            block_txs,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_get_tx_infos(
        &self, io: &dyn NetworkContext, peer: &NodeId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetTxInfos = rlp.as_val()?;
        info!("on_get_tx_infos req={:?}", req);
        self.throttle(peer, &req)?;
        let request_id = req.request_id;

        // TODO(thegaram): consider merging overlapping tx infos
        let infos = req
            .hashes
            .into_iter()
            .filter_map(|h| self.tx_info_by_hash(h))
            .collect();

        let msg: Box<dyn Message> =
            Box::new(GetTxInfosResponse { request_id, infos });

        msg.send(io, peer)?;
        Ok(())
    }

    fn broadcast(
        &self, io: &dyn NetworkContext, mut peers: Vec<NodeId>,
        msg: &dyn Message,
    ) -> Result<(), Error>
    {
        debug!("broadcast peers={:?}", peers);

        let throttle_ratio = THROTTLING_SERVICE.read().get_throttling_ratio();
        let total = peers.len();
        let allowed = (total as f64 * throttle_ratio) as usize;

        if total > allowed {
            debug!(
                "Apply throttling for broadcast, total: {}, allowed: {}",
                total, allowed
            );
            peers.shuffle(&mut rand::thread_rng());
            peers.truncate(allowed);
        }

        for id in peers {
            msg.send(io, &id)?;
        }

        Ok(())
    }

    pub fn relay_hashes(&self, hashes: Vec<H256>) -> Result<(), Error> {
        debug!("relay_hashes hashes={:?}", hashes);

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

    fn throttle<T: Message>(
        &self, peer: &NodeId, msg: &T,
    ) -> Result<(), Error> {
        let peer = self.get_existing_peer_state(peer)?;

        let bucket_name = msg.msg_name().to_string();
        let bucket = match peer.read().throttling.get(&bucket_name) {
            Some(bucket) => bucket,
            None => return Ok(()),
        };

        let result = bucket.lock().throttle();

        match result {
            ThrottleResult::Success => Ok(()),
            ThrottleResult::Throttled(wait_time) => {
                let throttled = Throttled {
                    msg_id: msg.msg_id(),
                    wait_time_nanos: wait_time.as_nanos() as u64,
                    request_id: msg.get_request_id(),
                };

                Err(ErrorKind::Throttled(msg.msg_name(), throttled).into())
            }
            ThrottleResult::AlreadyThrottled => {
                Err(ErrorKind::AlreadyThrottled(msg.msg_name()).into())
            }
        }
    }
}

impl NetworkProtocolHandler for Provider {
    fn initialize(&self, _io: &dyn NetworkContext) {}

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

    fn on_peer_connected(&self, _io: &dyn NetworkContext, peer: &NodeId) {
        info!("on_peer_connected: peer={:?}", peer);

        // insert handshaking peer, wait for StatusPing
        self.peers.insert(*peer);

        if let Some(ref file) = self.throttling_config_file {
            let peer = self.peers.get(peer).expect("peer not found");
            peer.write().throttling =
                TokenBucketManager::load(file, Some("light_protocol"))
                    .expect("invalid throttling configuration file");
        }
    }

    fn on_peer_disconnected(&self, _io: &dyn NetworkContext, peer: &NodeId) {
        info!("on_peer_disconnected: peer={:?}", peer);
        self.peers.remove(peer);
    }

    fn on_timeout(&self, _io: &dyn NetworkContext, _timer: TimerToken) {
        // EMPTY
    }
}
