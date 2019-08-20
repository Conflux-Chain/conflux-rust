// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use io::TimerToken;
use parking_lot::RwLock;
use rlp::Rlp;
use std::{
    collections::HashSet,
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

use crate::{
    consensus::ConsensusGraph,
    light_protocol::{
        handle_error,
        message::{msgid, NodeType, SendRawTx, StatusPing, StatusPong},
        peers::Peers,
        Error, ErrorKind, LIGHT_PROTOCOL_VERSION,
    },
    message::{Message, MsgId},
    network::{NetworkContext, NetworkProtocolHandler, PeerId},
    parameters::light::{CLEANUP_PERIOD_MS, SYNC_PERIOD_MS},
    sync::SynchronizationGraph,
};

use cfx_types::H256;

use super::{query::QueryHandler, sync::SyncHandler};

const SYNC_TIMER: TimerToken = 0;
const REQUEST_CLEANUP_TIMER: TimerToken = 1;

#[derive(Default)]
pub struct FullPeerState {
    pub best_epoch: u64,
    pub handshake_completed: bool,
    pub protocol_version: u8,
    pub terminals: HashSet<H256>,
}

/// Handler is responsible for maintaining peer meta-information and
/// dispatching messages to the query and sync sub-handlers.
pub struct Handler {
    // shared consensus graph
    consensus: Arc<ConsensusGraph>,

    // collection of all peers available
    pub peers: Arc<Peers<FullPeerState>>,

    // sub-handler serving light queries (e.g. state entries, transactions)
    pub query: QueryHandler,

    // sub-handler serving epoch and headers for syncing
    sync: SyncHandler,
}

impl Handler {
    pub fn new(
        consensus: Arc<ConsensusGraph>, graph: Arc<SynchronizationGraph>,
    ) -> Self {
        let peers = Arc::new(Peers::new());
        let next_request_id = Arc::new(AtomicU64::new(0));

        let query =
            QueryHandler::new(consensus.clone(), next_request_id.clone());

        let sync = SyncHandler::new(
            consensus.clone(),
            graph,
            next_request_id,
            peers.clone(),
        );

        Handler {
            consensus,
            peers,
            query,
            sync,
        }
    }

    #[inline]
    fn get_existing_peer_state(
        &self, peer: &PeerId,
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

    #[inline]
    fn validate_peer_state(
        &self, peer: PeerId, msg_id: MsgId,
    ) -> Result<(), Error> {
        let state = self.get_existing_peer_state(&peer)?;

        if msg_id != msgid::STATUS_PONG && !state.read().handshake_completed {
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
            msgid::STATUS_PONG => self.on_status(io, peer, &rlp),
            msgid::STATE_ROOT => self.query.on_state_root(io, peer, &rlp),
            msgid::STATE_ENTRY => self.query.on_state_entry(io, peer, &rlp),
            msgid::RECEIPTS => self.query.on_receipts(io, peer, &rlp),
            msgid::BLOCK_HASHES => self.sync.on_block_hashes(io, peer, &rlp),
            msgid::BLOCK_HEADERS => self.sync.on_block_headers(io, peer, &rlp),
            msgid::NEW_BLOCK_HASHES => self.sync.on_new_block_hashes(io, peer, &rlp),
            _ => Err(ErrorKind::UnknownMessage.into()),
        }
    }

    fn send_status(
        &self, io: &dyn NetworkContext, peer: PeerId,
    ) -> Result<(), Error> {
        let msg: Box<dyn Message> = Box::new(StatusPing {
            genesis_hash: self.consensus.data_man.true_genesis_block.hash(),
            network_id: 0x0,
            node_type: NodeType::Light,
            protocol_version: LIGHT_PROTOCOL_VERSION,
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

    #[inline]
    fn validate_peer_type(&self, node_type: &NodeType) -> Result<(), Error> {
        match node_type {
            NodeType::Full => Ok(()),
            _ => Err(ErrorKind::UnexpectedPeerType.into()),
        }
    }

    fn on_status(
        &self, io: &dyn NetworkContext, peer: PeerId, rlp: &Rlp,
    ) -> Result<(), Error> {
        let status: StatusPong = rlp.as_val()?;
        info!("on_status peer={:?} status={:?}", peer, status);

        self.validate_peer_type(&status.node_type)?;
        self.validate_genesis_hash(status.genesis_hash)?;

        {
            let state = self.get_existing_peer_state(&peer)?;
            let mut state = state.write();
            state.best_epoch = status.best_epoch;
            state.handshake_completed = true;
            state.protocol_version = status.protocol_version;
            state.terminals = status.terminals.into_iter().collect();
        }

        // NOTE: `start_sync` acquires read locks on peer states so
        // we need to make sure to release locks before calling it
        self.sync.start_sync(io);
        Ok(())
    }

    pub fn send_raw_tx(
        &self, io: &dyn NetworkContext, peer: PeerId, raw: Vec<u8>,
    ) -> Result<(), Error> {
        let msg: Box<dyn Message> = Box::new(SendRawTx { raw });
        msg.send(io, peer)?;
        Ok(())
    }
}

impl NetworkProtocolHandler for Handler {
    fn initialize(&self, io: &dyn NetworkContext) {
        let period = Duration::from_millis(SYNC_PERIOD_MS);
        io.register_timer(SYNC_TIMER, period)
            .expect("Error registering sync timer");

        let period = Duration::from_millis(CLEANUP_PERIOD_MS);
        io.register_timer(REQUEST_CLEANUP_TIMER, period)
            .expect("Error registering request cleanup timer");
    }

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

    fn on_peer_connected(&self, io: &dyn NetworkContext, peer: PeerId) {
        info!("on_peer_connected: peer={:?}", peer);

        match self.send_status(io, peer) {
            Ok(_) => self.peers.insert(peer), // insert handshaking peer
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

    fn on_peer_disconnected(&self, _io: &dyn NetworkContext, peer: PeerId) {
        info!("on_peer_disconnected: peer={:?}", peer);
        self.peers.remove(&peer);
    }

    fn on_timeout(&self, io: &dyn NetworkContext, timer: TimerToken) {
        trace!("Timeout: timer={:?}", timer);
        match timer {
            SYNC_TIMER => self.sync.start_sync(io),
            REQUEST_CLEANUP_TIMER => self.sync.clean_up_requests(),
            // TODO(thegaram): add other timers (e.g. data_man gc)
            _ => warn!("Unknown timer {} triggered.", timer),
        }
    }
}
