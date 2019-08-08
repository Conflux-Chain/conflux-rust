// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use io::TimerToken;
use rlp::Rlp;
use std::{
    sync::{atomic::AtomicU64, Arc},
    time::Duration,
};

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
    sync::SynchronizationGraph,
};

use cfx_types::H256;

use super::{query::QueryHandler, sync::SyncHandler};

const SYNC_TIMER: TimerToken = 0;
const REQUEST_CLEANUP_TIMER: TimerToken = 1;

const SYNC_PERIOD_MS: u64 = 5000;
const CLEANUP_PERIOD_MS: u64 = 1000;

/// Handler is responsible for maintaining peer meta-information and
/// dispatching messages to the query and sync sub-handlers.
pub struct Handler {
    // shared consensus graph
    consensus: Arc<ConsensusGraph>,

    // collection of all peers available
    pub peers: Arc<Peers>,

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

    #[rustfmt::skip]
    fn dispatch_message(
        &self, io: &NetworkContext, peer: PeerId, msg_id: MsgId, rlp: Rlp,
    ) -> Result<(), Error> {
        trace!("Dispatching message: peer={:?}, msg_id={:?}", peer, msg_id);

        // TODO(thegaram): check if peer is known

        match msg_id {
            msgid::STATUS => self.on_status(io, peer, &rlp),
            msgid::STATE_ROOT => self.query.on_state_root(io, peer, &rlp),
            msgid::STATE_ENTRY => self.query.on_state_entry(io, peer, &rlp),
            msgid::BLOCK_HASHES => self.sync.on_block_hashes(io, peer, &rlp),
            msgid::BLOCK_HEADERS => self.sync.on_block_headers(io, peer, &rlp),
            msgid::NEW_BLOCK_HASHES => self.sync.on_new_block_hashes(io, peer, &rlp),
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
    fn initialize(&self, io: &NetworkContext) {
        let period = Duration::from_millis(SYNC_PERIOD_MS);
        io.register_timer(SYNC_TIMER, period)
            .expect("Error registering sync timer");

        let period = Duration::from_millis(CLEANUP_PERIOD_MS);
        io.register_timer(REQUEST_CLEANUP_TIMER, period)
            .expect("Error registering request cleanup timer");
    }

    fn on_message(&self, io: &NetworkContext, peer: PeerId, raw: &[u8]) {
        debug!("on_message: peer={:?}, raw={:?}", peer, raw);

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

    fn on_timeout(&self, io: &NetworkContext, timer: TimerToken) {
        trace!("Timeout: timer={:?}", timer);
        match timer {
            SYNC_TIMER => {
                if let Err(e) = self.sync.start_sync(io) {
                    warn!("Failed to trigger sync: {:?}", e);
                }
            }
            REQUEST_CLEANUP_TIMER => {
                self.sync.clean_up_requests();
            }
            // TODO(thegaram): add other timers (e.g. data_man gc)
            _ => warn!("Unknown timer {} triggered.", timer),
        }
    }
}
