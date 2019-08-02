// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    collections::HashSet,
    sync::{atomic::AtomicU64, Arc},
};

use io::TimerToken;
use parking_lot::RwLock;
use rand::Rng;
use rlp::Rlp;

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{handle_error, message::msgid, Error, ErrorKind},
    message::MsgId,
    network::{NetworkContext, NetworkProtocolHandler, PeerId},
};

use super::{query::QueryHandler, sync::SyncHandler};

/// Handler is responsible for maintaining peer meta-information and
/// dispatching messages to the query and sync sub-handlers.
pub struct Handler {
    peers: RwLock<HashSet<PeerId>>,
    pub query: QueryHandler,
    pub sync: SyncHandler,
}

impl Handler {
    pub fn new(consensus: Arc<ConsensusGraph>) -> Self {
        let next_request_id = Arc::new(AtomicU64::new(0));

        Handler {
            peers: RwLock::new(HashSet::new()),
            query: QueryHandler::new(consensus, next_request_id.clone()),
            sync: SyncHandler::new(next_request_id),
        }
    }

    fn dispatch_message(
        &self, io: &NetworkContext, peer: PeerId, msg_id: MsgId, rlp: Rlp,
    ) -> Result<(), Error> {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);

        match msg_id {
            msgid::STATE_ROOT => self.query.on_state_root(io, peer, &rlp),
            msgid::STATE_ENTRY => self.query.on_state_entry(io, peer, &rlp),
            _ => Err(ErrorKind::UnknownMessage.into()),
        }
    }

    /// Get all peers in random order.
    pub fn get_peers_shuffled(&self) -> Vec<PeerId> {
        let mut rand = rand::thread_rng();
        let mut peers: Vec<_> = self.peers.read().iter().cloned().collect();
        rand.shuffle(&mut peers[..]);
        peers
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
