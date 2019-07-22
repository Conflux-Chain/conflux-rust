// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use network::PeerId;
//use slab::Slab;
use crate::sync::{random, Error, ErrorKind};
use message::MsgId;
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

pub struct SynchronizationPeerState {
    pub id: PeerId,
    pub protocol_version: u8,
    pub genesis_hash: H256,
    pub best_epoch: u64,
    pub latest_block_hashes: HashSet<H256>,

    /// The following fields are used to control how to handle
    /// transaction propagation for nodes in catch-up mode.
    pub received_transaction_count: usize,
    pub need_prop_trans: bool,
    pub notified_mode: Option<bool>,

    // heartbeat is used to disconnect inactive nodes periodically,
    // and updated when new message received.
    pub heartbeat: Instant,
}

pub type SynchronizationPeers =
    HashMap<PeerId, Arc<RwLock<SynchronizationPeerState>>>;

pub struct SynchronizationState {
    is_full_node: bool,
    pub sync_phase: Mutex<SyncPhase>,
    pub peers: RwLock<SynchronizationPeers>,
    pub handshaking_peers: RwLock<HashMap<PeerId, Instant>>,
    pub last_sent_transaction_hashes: RwLock<HashSet<H256>>,
}

impl SynchronizationState {
    pub fn new(is_full_node: bool, genesis_hash: H256) -> Self {
        SynchronizationState {
            is_full_node,
            sync_phase: Mutex::new(
                if is_full_node {
                    SyncPhase::SyncHeaders(genesis_hash)
                } else {
                    SyncPhase::SyncBlocks(genesis_hash)
                },
            ),
            peers: Default::default(),
            handshaking_peers: Default::default(),
            last_sent_transaction_hashes: Default::default(),
        }
    }

    pub fn on_status(&self, peer: PeerId) -> bool {
        let peers = self.peers.read();
        let mut handshaking_peers = self.handshaking_peers.write();
        handshaking_peers.remove(&peer).is_some() && !peers.contains_key(&peer)
    }

    pub fn peer_connected(
        &self, peer: PeerId, state: SynchronizationPeerState,
    ) {
        self.peers
            .write()
            .insert(peer, Arc::new(RwLock::new(state)));
    }

    pub fn contains_peer(&self, peer: &PeerId) -> bool {
        self.peers.read().contains_key(peer)
    }

    pub fn get_peer_info(
        &self, id: &PeerId,
    ) -> Result<Arc<RwLock<SynchronizationPeerState>>, Error> {
        Ok(self
            .peers
            .read()
            .get(&id)
            .ok_or(ErrorKind::UnknownPeer)?
            .clone())
    }

    /// Choose one random peer excluding the given `exclude` set.
    /// Return None if there is no peer to choose from
    pub fn get_random_peer(&self, exclude: &HashSet<PeerId>) -> Option<PeerId> {
        let peer_set: HashSet<PeerId> =
            self.peers.read().keys().cloned().collect();
        let choose_from: Vec<&PeerId> = peer_set.difference(exclude).collect();
        let mut rand = random::new();
        rand.choose(&choose_from).cloned().cloned()
    }

    /// Choose one random peer that satisfies `predicate`.
    /// Return None if there is no peer to choose from
    pub fn get_random_peer_satisfying<F>(
        &self, predicate: F,
    ) -> Option<PeerId>
    where F: Fn(&&PeerId) -> bool {
        let peer_set: HashSet<PeerId> =
            self.peers.read().keys().cloned().collect();
        let choose_from: Vec<&PeerId> =
            peer_set.iter().filter(predicate).collect();
        let mut rand = random::new();
        rand.choose(&choose_from).cloned().cloned()
    }

    /// Choose a random peer set given set size
    /// Return all peers if there are not enough peers
    pub fn get_random_peer_vec<F>(
        &self, size: usize, filter: F,
    ) -> Vec<PeerId>
    where F: Fn(&PeerId) -> bool {
        let mut peer_vec: Vec<PeerId> =
            self.peers.read().keys().cloned().filter(filter).collect();
        let mut rand = random::new();
        rand.shuffle(&mut peer_vec);
        peer_vec.truncate(size);
        peer_vec
    }

    /// Updates the heartbeat for the specified peer. It takes no effect if the
    /// peer is in handshaking status or not found.
    pub fn update_heartbeat(&self, peer: &PeerId) {
        if let Some(state) = self.peers.read().get(peer) {
            state.write().heartbeat = Instant::now();
        }
    }

    /// Retrieves the heartbeat timeout peers, including handshaking timeout
    /// peers and inactive peers after handshake.
    pub fn get_heartbeat_timeout_peers(
        &self, timeout: Duration,
    ) -> Vec<PeerId> {
        let mut timeout_peers = Vec::new();

        for (peer, handshake_time) in self.handshaking_peers.read().iter() {
            if handshake_time.elapsed() > timeout {
                timeout_peers.push(peer.clone());
            }
        }

        for (peer, state) in self.peers.read().iter() {
            if state.read().heartbeat.elapsed() > timeout {
                timeout_peers.push(peer.clone());
            }
        }

        timeout_peers
    }

    pub fn is_full_node(&self) -> bool { self.is_full_node }

    pub fn get_middle_epoch(&self) -> Option<u64> {
        let mut peer_best_epoches = {
            let peers = self.peers.read();
            peers
                .iter()
                .map(|(_, state)| state.read().best_epoch)
                .collect::<Vec<_>>()
        };

        if peer_best_epoches.is_empty() {
            return None;
        }

        peer_best_epoches.sort();
        Some(peer_best_epoches[peer_best_epoches.len() / 2])
    }

    pub fn validate_msg_id(&self, msg_id: &MsgId) -> bool {
        let sync_phase = &*self.sync_phase.lock();
        if sync_phase.validate_msg_id(msg_id) {
            true
        } else {
            debug!("MsgId:{:?} is ignored in phase {:?}", msg_id, sync_phase);
            false
        }
    }
}

/// The phases are used to control the catch-up logic.
/// Archive nodes do not have phases `SyncHeaders` and `SyncCheckpoints`.
#[derive(Debug)]
pub enum SyncPhase {
    /// The first phase to sync all headers after the latest known checkpoint
    /// and handle these headers in Consensus without handling any
    /// state-related work. After enough headers are received, we can find
    /// a new checkpoint and enter `SyncCheckPoints`. The hash inside is the
    /// checkpoint from which we need to start syncing to the latest
    /// headers.
    SyncHeaders(H256),

    /// The second phase to sync the states of the new checkpoint. The hash
    /// inside is the hash of the checkpoint block. After the
    /// state is retrieved, we'll be able to execute and verify blocks
    /// after it, so we can enter `SyncBlocks`.
    SyncCheckpoints(H256),

    /// The third phase to sync all blocks since the latest checkpoint. The
    /// hash inside is the checkpoint from which we need to start syncing
    /// to the latest blocks.
    SyncBlocks(H256),

    /// We have catch up with most peers, so we can follow normal logic.
    Latest,
}

impl SyncPhase {
    /// Check if the msg_id should be processed in current phase.
    fn validate_msg_id(&self, msg_id: &MsgId) -> bool {
        match self {
            SyncPhase::SyncHeaders(_) => match *msg_id {
                MsgId::STATUS
                | MsgId::TRANSACTION_PROPAGATION_CONTROL
                | MsgId::GET_BLOCK_HASHES_RESPONSE
                | MsgId::GET_BLOCK_HEADERS_RESPONSE => true,
                _ => false,
            },
            SyncPhase::SyncCheckpoints(_) => match *msg_id {
                MsgId::STATUS
                | MsgId::TRANSACTION_PROPAGATION_CONTROL
                | MsgId::GET_SNAPSHOT_MANIFEST_RESPONSE
                | MsgId::GET_SNAPSHOT_CHUNK_RESPONSE => true,
                _ => false,
            },
            SyncPhase::SyncBlocks(_) => match *msg_id {
                MsgId::STATUS
                | MsgId::TRANSACTION_PROPAGATION_CONTROL
                | MsgId::GET_BLOCK_HASHES_RESPONSE
                | MsgId::GET_BLOCKS_RESPONSE
                | MsgId::GET_BLOCKS_WITH_PUBLIC_RESPONSE => true,
                _ => false,
            },
            SyncPhase::Latest => true,
        }
    }

    pub fn catch_up_mode(&self) -> bool {
        match self {
            SyncPhase::Latest => false,
            _ => true,
        }
    }

    pub fn need_requesting_blocks(&self) -> bool {
        match self {
            SyncPhase::SyncBlocks(_) | SyncPhase::Latest => true,
            _ => false,
        }
    }

    pub fn get_sync_checkpoint(&self) -> Option<H256> {
        match self {
            SyncPhase::SyncCheckpoints(checkpoint) => Some(checkpoint.clone()),
            _ => None,
        }
    }
}
