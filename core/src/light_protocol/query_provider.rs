// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use io::TimerToken;
use rlp::Rlp;
use std::sync::Arc;

use cfx_types::H256;
use primitives::{BlockHeader, EpochNumber, StateRoot};

use crate::{
    consensus::{ConsensusGraph, DEFERRED_STATE_EPOCH_COUNT},
    message::{Message, MsgId},
    network::{NetworkContext, NetworkProtocolHandler, NetworkService, PeerId},
    statedb::StateDb,
    storage::{
        state_manager::StateManagerTrait, SnapshotAndEpochIdRef, StateProof,
    },
};

use super::{
    handle_error,
    message::{
        msgid, GetStateEntry, GetStateRoot,
        StateEntry as GetStateEntryResponse, StateRoot as GetStateRootResponse,
    },
    Error, ErrorKind, LIGHT_PROTOCOL_ID, LIGHT_PROTOCOL_VERSION,
};

pub struct QueryProvider {
    consensus: Arc<ConsensusGraph>,
}

impl QueryProvider {
    pub fn new(consensus: Arc<ConsensusGraph>) -> Self {
        QueryProvider { consensus }
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

    fn dispatch_message(
        &self, io: &NetworkContext, peer: PeerId, msg_id: MsgId, rlp: Rlp,
    ) -> Result<(), Error> {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);

        match msg_id {
            msgid::GET_STATE_ROOT => self.on_get_state_root(io, peer, &rlp),
            msgid::GET_STATE_ENTRY => self.on_get_state_entry(io, peer, &rlp),
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

    fn on_peer_connected(&self, _io: &NetworkContext, peer: PeerId) {
        info!("on_peer_connected: peer={:?}", peer);
    }

    fn on_peer_disconnected(&self, _io: &NetworkContext, peer: PeerId) {
        info!("on_peer_disconnected: peer={:?}", peer);
    }

    fn on_timeout(&self, _io: &NetworkContext, _timer: TimerToken) {
        // EMPTY
    }
}
