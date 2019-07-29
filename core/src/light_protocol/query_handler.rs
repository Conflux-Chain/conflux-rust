// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    collections::{BTreeMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

extern crate futures;
use futures::{
    sync::oneshot::{self, Sender},
    Async, Future,
};

use io::TimerToken;
use parking_lot::RwLock;
use rand::Rng;
use rlp::Rlp;

use cfx_types::H256;
use primitives::{BlockHeader, EpochNumber, StateRoot};

use crate::{
    consensus::{ConsensusGraph, DEFERRED_STATE_EPOCH_COUNT},
    network::{NetworkContext, NetworkProtocolHandler, PeerId},
    statedb::StateDb,
    storage::{
        state_manager::StateManagerTrait, SnapshotAndEpochIdRef, StateProof,
    },
};

use super::{
    message::{
        msgid, GetStateEntry, GetStateRoot,
        StateEntry as GetStateEntryResponse, StateRoot as GetStateRootResponse,
    },
    Error, ErrorKind,
};

use crate::message::{HasRequestId, Message, MsgId, RequestId};

const POLL_PERIOD_MS: u64 = 100;
const MAX_POLL_TIME_MS: u64 = 1000;

#[derive(Debug)]
pub(super) enum QueryResult {
    StateEntry(Option<Vec<u8>>),
    StateRoot(StateRoot),
}

struct PendingRequest {
    msg: Box<dyn Message>,
    sender: Sender<QueryResult>,
}

pub(super) struct QueryHandler {
    consensus: Arc<ConsensusGraph>,
    next_request_id: AtomicU64,
    peers: RwLock<HashSet<PeerId>>,
    pending: RwLock<BTreeMap<(PeerId, RequestId), PendingRequest>>,
}

impl QueryHandler {
    pub fn new(consensus: Arc<ConsensusGraph>) -> Self {
        QueryHandler {
            consensus,
            next_request_id: AtomicU64::new(0),
            peers: RwLock::new(HashSet::new()),
            pending: RwLock::new(BTreeMap::new()),
        }
    }

    fn dispatch_message(
        &self, io: &NetworkContext, peer: PeerId, msg_id: MsgId, rlp: Rlp,
    ) -> Result<(), Error> {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);

        match msg_id {
            msgid::GET_STATE_ROOT => self.on_get_state_root(io, peer, &rlp),
            msgid::STATE_ROOT => self.on_state_root(io, peer, &rlp),
            msgid::GET_STATE_ENTRY => self.on_get_state_entry(io, peer, &rlp),
            msgid::STATE_ENTRY => self.on_state_entry(io, peer, &rlp),
            _ => {
                warn!("Unknown message: peer={:?} msgid={:?}", peer, msg_id);
                // io.disconnect_peer(peer, Some(UpdateNodeOperation::Remove));
                Ok(())
            }
        }
    }

    fn handle_error(
        &self, io: &NetworkContext, peer: PeerId, msg_id: MsgId, e: Error,
    ) {
        warn!(
            "Error while handling message, peer={}, msg_id={:?}, error={:?}",
            peer, msg_id, e
        );

        // TODO(thegaram): remove wildcard so that
        // the compiler can help us cover all cases
        let disconnect = match e.0 {
            ErrorKind::InvalidStateRoot => true,
            ErrorKind::InvalidProof => true,
            ErrorKind::InvalidRequestId => true,
            ErrorKind::PivotHashMismatch => false,
            ErrorKind::InternalError => false,
            _ => false,
        };

        if disconnect {
            io.disconnect_peer(peer, None);
        }
    }

    fn get_local_pivot_hash(&self, epoch: u64) -> Result<H256, Error> {
        let epoch = EpochNumber::Number(epoch);
        let pivot_hash = self.consensus.get_hash_from_epoch_number(epoch)?;
        Ok(pivot_hash)
    }

    fn get_local_header(&self, epoch: u64) -> Result<Arc<BlockHeader>, Error> {
        let epoch = EpochNumber::Number(epoch);
        let hash = self.consensus.get_hash_from_epoch_number(epoch)?;
        let header = self.consensus.data_man.block_header_by_hash(&hash);
        header.ok_or(ErrorKind::InternalError.into())
    }

    fn get_local_state_root(&self, epoch: u64) -> Result<StateRoot, Error> {
        let h = self.get_local_header(epoch + DEFERRED_STATE_EPOCH_COUNT)?;
        Ok(h.state_root_with_aux_info.state_root.clone())
    }

    fn get_local_state_root_hash(&self, epoch: u64) -> Result<H256, Error> {
        let h = self.get_local_header(epoch + DEFERRED_STATE_EPOCH_COUNT)?;
        Ok(h.deferred_state_root().clone())
    }

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

    fn validate_pivot_hash(&self, epoch: u64, hash: H256) -> Result<(), Error> {
        match self.get_local_pivot_hash(epoch)? {
            h if h == hash => Ok(()),
            h => {
                // NOTE: this can happen in normal scenarios
                // where the pivot chain has not converged
                debug!("Pivot hash mismatch: local={}, response={}", h, hash);
                Err(ErrorKind::PivotHashMismatch.into())
            }
        }
    }

    fn validate_state_root(
        &self, epoch: u64, state_root: &StateRoot,
    ) -> Result<(), Error> {
        let hash = state_root.compute_state_root_hash();

        match self.get_local_state_root_hash(epoch)? {
            h if h == hash => Ok(()),
            h => {
                info!("State root mismatch: local={}, response={}", h, hash);
                return Err(ErrorKind::InvalidStateRoot.into());
            }
        }
    }

    fn match_request<T>(
        &self, peer: PeerId, id: RequestId,
    ) -> Result<(T, Sender<QueryResult>), Error>
    where T: Message + Clone + 'static {
        let (msg, sender) = match self.pending.write().remove(&(peer, id)) {
            Some(PendingRequest { msg, sender }) => (msg, sender),
            None => {
                warn!("Unexpected request id: {:?}", id);
                return Err(ErrorKind::UnexpectedResponse.into());
            }
        };

        match msg.as_any().downcast_ref::<T>() {
            Some(req) => Ok(((*req).clone(), sender)),
            None => {
                warn!("Unexpected response type from peer={}", peer);
                Err(ErrorKind::UnexpectedResponse.into())
            }
        }
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

        msg.send(io, peer, None)?;
        Ok(())
    }

    fn on_state_root(
        &self, _io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetStateRootResponse = rlp.as_val()?;
        info!("on_state_root resp={:?}", resp);

        let id = resp.request_id;
        let (req, sender) = self.match_request::<GetStateRoot>(peer, id)?;

        self.validate_pivot_hash(req.epoch, resp.pivot_hash)?;
        self.validate_state_root(req.epoch, &resp.state_root)?;

        sender.complete(QueryResult::StateRoot(resp.state_root));
        // note: in case of early return, `sender` will be cancelled

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

        msg.send(io, peer, None)?;
        Ok(())
    }

    fn on_state_entry(
        &self, _io: &NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let resp: GetStateEntryResponse = rlp.as_val()?;
        info!("on_state_entry resp={:?}", resp);

        let id = resp.request_id;
        let (req, sender) = self.match_request::<GetStateEntry>(peer, id)?;

        self.validate_pivot_hash(req.epoch, resp.pivot_hash)?;
        self.validate_state_root(req.epoch, &resp.state_root)?;

        // validate proof
        if !resp.proof.is_valid(
            &req.key,
            &resp.entry,
            resp.state_root.delta_root,
            resp.state_root.intermediate_delta_root,
            resp.state_root.snapshot_root,
        ) {
            info!("Invalid proof from peer={}", peer);
            return Err(ErrorKind::InvalidProof.into());
        }

        sender.complete(QueryResult::StateEntry(resp.entry));
        // note: in case of early return, `sender` will be cancelled

        Ok(())
    }

    fn next_request_id(&self) -> RequestId {
        self.next_request_id.fetch_add(1, Ordering::Relaxed).into()
    }

    /// Send `req` to `peer` and wait for result.
    pub fn execute_request<T>(
        &self, io: &NetworkContext, peer: PeerId, mut req: T,
    ) -> Result<QueryResult, Error>
    where T: Message + HasRequestId + Clone + 'static {
        // set request id
        let id = self.next_request_id();
        req.set_request_id(id);

        // set up channel and store request
        let mut receiver = {
            let msg: Box<dyn Message> = Box::new(req.clone());
            let (sender, receiver) = oneshot::channel();
            let pending = PendingRequest { msg, sender };
            self.pending.write().insert((peer, id), pending);
            receiver
        };

        // send request
        let msg: Box<dyn Message> = Box::new(req);
        msg.send(io, peer, None)?;

        // poll result
        // TODO(thegaram): come up with something better
        // we can consider returning a future if it is
        // compatible with our current event loop
        let max_poll_num = MAX_POLL_TIME_MS / POLL_PERIOD_MS;

        for _ in 0..max_poll_num {
            match receiver.poll() {
                Ok(Async::Ready(resp)) => return Ok(resp),
                Ok(Async::NotReady) => (),
                Err(_) => return Err(ErrorKind::ValidationFailed.into()),
            }

            let d = std::time::Duration::from_millis(POLL_PERIOD_MS);
            std::thread::sleep(d);
        }

        Err(ErrorKind::NoResponse.into())
    }

    /// Get all peers in random order.
    pub fn get_peers_shuffled(&self) -> Vec<PeerId> {
        let mut rand = rand::thread_rng();
        let mut peers: Vec<_> = self.peers.read().iter().cloned().collect();
        rand.shuffle(&mut peers[..]);
        peers
    }
}

impl NetworkProtocolHandler for QueryHandler {
    fn initialize(&self, _io: &NetworkContext) {}

    fn on_message(&self, io: &NetworkContext, peer: PeerId, raw: &[u8]) {
        let msg_id = raw[0];
        let rlp = Rlp::new(&raw[1..]);
        debug!("on_message: peer={:?}, msgid={:?}", peer, msg_id);

        if let Err(e) = self.dispatch_message(io, peer, msg_id.into(), rlp) {
            self.handle_error(io, peer, msg_id.into(), e);
        }
    }

    fn on_peer_connected(&self, _io: &NetworkContext, peer: PeerId) {
        info!("on_peer_connected: peer={:?}", peer);
        self.peers.write().insert(peer);
    }

    fn on_peer_disconnected(&self, _io: &NetworkContext, peer: PeerId) {
        info!("on_peer_disconnected: peer={:?}", peer);
        self.peers.write().remove(&peer);
    }

    fn on_timeout(&self, _io: &NetworkContext, _timer: TimerToken) {
        // EMPTY
    }
}
