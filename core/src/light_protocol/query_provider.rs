// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use io::TimerToken;
use rand::Rng;
use rlp::Rlp;
use std::sync::Arc;

use cfx_types::H256;
use primitives::{BlockHeader, EpochNumber, StateRoot};

use crate::{
    consensus::ConsensusGraph,
    message::{Message, MsgId},
    network::{
        throttling::THROTTLING_SERVICE, NetworkContext, NetworkProtocolHandler,
        NetworkService, PeerId,
    },
    statedb::StateDb,
    storage::{
        state_manager::StateManagerTrait, SnapshotAndEpochIdRef, StateProof,
    },
    sync::SynchronizationGraph,
};

use super::{
    handle_error,
    message::{
        msgid, BlockHashes as GetBlockHashesResponse,
        BlockHeaders as GetBlockHeadersResponse, GetBlockHashesByEpoch,
        GetBlockHeaders, GetStateEntry, GetStateRoot, NewBlockHashes, NodeType,
        StateEntry as GetStateEntryResponse, StateRoot as GetStateRootResponse,
        Status,
    },
    peers::Peers,
    Error, ErrorKind, LIGHT_PROTOCOL_ID, LIGHT_PROTOCOL_VERSION,
};
use crate::parameters::consensus::DEFERRED_STATE_EPOCH_COUNT;

pub const MAX_EPOCHS_TO_SEND: usize = 128;
pub const MAX_HEADERS_TO_SEND: usize = 512;

pub struct QueryProvider {
    consensus: Arc<ConsensusGraph>,
    graph: Arc<SynchronizationGraph>,
    peers: Peers,
}

impl QueryProvider {
    pub fn new(
        consensus: Arc<ConsensusGraph>, graph: Arc<SynchronizationGraph>,
    ) -> Self {
        let peers = Peers::new();

        QueryProvider {
            consensus,
            graph,
            peers,
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
                format!("failed to register protocol QueryProvider: {:?}", e)
            })
    }

    #[rustfmt::skip]
    fn dispatch_message(
        &self, io: &NetworkContext, peer: PeerId, msg_id: MsgId, rlp: Rlp,
    ) -> Result<(), Error> {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);

        // TODO(thegaram): check if peer is known

        match msg_id {
            msgid::STATUS => self.on_status(io, peer, &rlp),
            msgid::GET_STATE_ROOT => self.on_get_state_root(io, peer, &rlp),
            msgid::GET_STATE_ENTRY => self.on_get_state_entry(io, peer, &rlp),
            msgid::GET_BLOCK_HASHES_BY_EPOCH => self.on_get_block_hashes_by_epoch(io, peer, &rlp),
            msgid::GET_BLOCK_HEADERS => self.on_get_block_headers(io, peer, &rlp),
            _ => Err(ErrorKind::UnknownMessage.into()),
        }
    }

    #[inline]
    fn get_local_pivot_hash(&self, epoch: u64) -> Result<H256, Error> {
        let epoch = EpochNumber::Number(epoch);
        let pivot_hash = self.consensus.get_hash_from_epoch_number(epoch)?;
        Ok(pivot_hash)
    }

    #[inline]
    fn get_local_header(&self, epoch: u64) -> Result<Arc<BlockHeader>, Error> {
        let epoch = EpochNumber::Number(epoch);
        let hash = self.consensus.get_hash_from_epoch_number(epoch)?;
        let header = self.consensus.data_man.block_header_by_hash(&hash);
        header.ok_or(ErrorKind::InternalError.into())
    }

    #[inline]
    fn get_local_state_root(&self, epoch: u64) -> Result<StateRoot, Error> {
        let h = self.get_local_header(epoch + DEFERRED_STATE_EPOCH_COUNT)?;
        Ok(h.state_root_with_aux_info.state_root.clone())
    }

    #[inline]
    fn get_local_state_entry(
        &self, hash: H256, key: &Vec<u8>,
    ) -> Result<(Option<Vec<u8>>, StateProof), Error> {
        let maybe_state = self
            .consensus
            .data_man
            .storage_manager
            .get_state_no_commit(SnapshotAndEpochIdRef::new(&hash, None))
            .map_err(|e| format!("Failed to get state, err={:?}", e))?;

        match maybe_state {
            None => Err(ErrorKind::InternalError.into()),
            Some(state) => {
                let (value, proof) = StateDb::new(state)
                    .get_raw_with_proof(key)
                    .or(Err(ErrorKind::InternalError))?;

                let value = value.map(|x| x.to_vec());
                Ok((value, proof))
            }
        }
    }

    fn send_status(
        &self, io: &NetworkContext, peer: PeerId,
    ) -> Result<(), Error> {
        let best_info = self.consensus.get_best_info();
        let genesis_hash = self.consensus.data_man.true_genesis_block.hash();

        let terminals = match &best_info.terminal_block_hashes {
            Some(x) => x.clone(),
            None => best_info.bounded_terminal_block_hashes.clone(),
        };

        let msg: Box<dyn Message> = Box::new(Status {
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
    fn validate_genesis_hash(&self, genesis: H256) -> Result<(), Error> {
        match self.consensus.data_man.true_genesis_block.hash() {
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
        &self, _io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let status: Status = rlp.as_val()?;
        info!("on_status peer={:?} status={:?}", peer, status);

        self.validate_genesis_hash(status.genesis_hash)?;
        // TODO(thegaram): check protocol version

        let peer_state = self.peers.insert(peer);
        let mut state = peer_state.write();

        state.best_epoch = status.best_epoch;
        state.genesis_hash = status.genesis_hash;
        state.node_type = status.node_type;
        state.protocol_version = status.protocol_version;
        state.terminals = status.terminals.into_iter().collect();

        Ok(())
    }

    fn on_get_state_root(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetStateRoot = rlp.as_val()?;
        info!("on_get_state_root req={:?}", req);
        let request_id = req.request_id;

        let pivot_hash = self.get_local_pivot_hash(req.epoch)?;
        let state_root = self.get_local_state_root(req.epoch)?;

        let msg: Box<dyn Message> = Box::new(GetStateRootResponse {
            request_id,
            pivot_hash,
            state_root,
        });

        msg.send(io, peer)?;
        Ok(())
    }

    fn on_get_state_entry(
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let req: GetStateEntry = rlp.as_val()?;
        info!("on_get_state_entry req={:?}", req);
        let request_id = req.request_id;

        let pivot_hash = self.get_local_pivot_hash(req.epoch)?;
        let state_root = self.get_local_state_root(req.epoch)?;
        let (entry, proof) =
            self.get_local_state_entry(pivot_hash, &req.key)?;
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
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
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
        &self, io: &NetworkContext, peer: PeerId, rlp: &Rlp,
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

    fn broadcast(
        &self, io: &NetworkContext, mut peers: Vec<PeerId>, msg: &Message,
    ) -> Result<(), Error> {
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

    pub fn relay_hashes(
        &self, io: &NetworkContext, hashes: Vec<H256>,
    ) -> Result<(), Error> {
        if hashes.is_empty() {
            return Ok(());
        }

        let peers = self
            .peers
            .all_peers_satisfying(|state| state.node_type == NodeType::Light);

        let msg: Box<dyn Message> = Box::new(NewBlockHashes { hashes });

        if let Err(e) = self.broadcast(io, peers, msg.as_ref()) {
            warn!("Error broadcasting blocks: {:?}", e);
        };

        Ok(())
    }
}

impl NetworkProtocolHandler for QueryProvider {
    fn initialize(&self, _io: &NetworkContext) {}

    fn on_message(&self, io: &NetworkContext, peer: PeerId, raw: &[u8]) {
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

    fn on_peer_connected(&self, io: &NetworkContext, peer: PeerId) {
        info!("on_peer_connected: peer={:?}", peer);

        match self.send_status(io, peer) {
            Ok(_) => {
                self.peers.insert(peer);
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

    fn on_peer_disconnected(&self, _io: &NetworkContext, peer: PeerId) {
        info!("on_peer_disconnected: peer={:?}", peer);
        self.peers.remove(&peer);
    }

    fn on_timeout(&self, _io: &NetworkContext, _timer: TimerToken) {
        // EMPTY
    }
}
