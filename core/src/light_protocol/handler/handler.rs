// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use io::TimerToken;
use rlp::Rlp;
use std::sync::{atomic::AtomicU64, Arc};

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        handle_error,
        message::{msgid, NodeType, Status},
        peers::Peers,
        Error, ErrorKind, LIGHT_PROTOCOL_VERSION,
    },
    message::{Message, MsgId},
    network::{NetworkContext, NetworkProtocolHandler, PeerId},
};

use cfx_types::H256;

use super::{query::QueryHandler, sync::SyncHandler};

/// Handler is responsible for maintaining peer meta-information and
/// dispatching messages to the query and sync sub-handlers.
pub struct Handler {
    consensus: Arc<ConsensusGraph>,
    pub peers: Arc<Peers>,
    pub query: QueryHandler,
    pub sync: SyncHandler,
}

impl Handler {
    pub fn new(consensus: Arc<ConsensusGraph>) -> Self {
        let next_request_id = Arc::new(AtomicU64::new(0));

        Handler {
            consensus: consensus.clone(),
            peers: Arc::new(Peers::new()),
            query: QueryHandler::new(consensus, next_request_id.clone()),
            sync: SyncHandler::new(next_request_id),
        }
    }

    fn dispatch_message(
        &self, io: &NetworkContext, peer: PeerId, msg_id: MsgId, rlp: Rlp,
    ) -> Result<(), Error> {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);

        // TODO(thegaram): check if peer is known

        match msg_id {
            msgid::STATUS => self.on_status(io, peer, &rlp),
            msgid::STATE_ROOT => self.query.on_state_root(io, peer, &rlp),
            msgid::STATE_ENTRY => self.query.on_state_entry(io, peer, &rlp),
            _ => Err(ErrorKind::UnknownMessage.into()),
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
            node_type: NodeType::Light,
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
}

impl NetworkProtocolHandler for Handler {
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
