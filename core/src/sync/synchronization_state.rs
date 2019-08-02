// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use network::PeerId;
//use slab::Slab;
use crate::sync::{
    message::{DynamicCapability, DynamicCapabilitySet},
    random, Error, ErrorKind,
};
use parking_lot::RwLock;
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

    // heartbeat is used to disconnect inactive nodes periodically,
    // and updated when new message received.
    pub heartbeat: Instant,

    // latest received capabilities from the remote peer.
    pub capabilities: DynamicCapabilitySet,
    // latest notified capabilities of mine to the remote peer.
    pub notified_capabilities: DynamicCapabilitySet,
}

pub type SynchronizationPeers =
    HashMap<PeerId, Arc<RwLock<SynchronizationPeerState>>>;

pub struct SynchronizationState {
    is_full_node: bool,
    pub peers: RwLock<SynchronizationPeers>,
    pub handshaking_peers: RwLock<HashMap<PeerId, Instant>>,
    pub last_sent_transaction_hashes: RwLock<HashSet<H256>>,
}

impl SynchronizationState {
    pub fn new(is_full_node: bool) -> Self {
        SynchronizationState {
            is_full_node,
            peers: Default::default(),
            handshaking_peers: Default::default(),
            last_sent_transaction_hashes: Default::default(),
        }
    }

    pub fn on_status_in_handshaking(&self, peer: PeerId) -> bool {
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
    where F: Fn(&SynchronizationPeerState) -> bool {
        let choose_from: Vec<PeerId> = self
            .peers
            .read()
            .iter()
            .filter_map(|(id, state)| {
                if predicate(&*state.read()) {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        let mut rand = random::new();
        rand.choose(&choose_from).cloned()
    }

    pub fn get_random_peer_with_cap(
        &self, cap: Option<DynamicCapability>,
    ) -> Option<PeerId> {
        match cap {
            Some(cap) => self.get_random_peer_satisfying(|peer| {
                peer.capabilities.contains(cap)
            }),
            None => {
                let peers: Vec<PeerId> =
                    self.peers.read().keys().cloned().collect();
                let mut rand = random::new();
                rand.choose(&peers).cloned()
            }
        }
    }

    pub fn get_random_peers(&self, size: usize) -> Vec<PeerId> {
        let mut peers: Vec<PeerId> =
            self.peers.read().keys().cloned().collect();
        let mut rand = random::new();
        rand.shuffle(&mut peers);
        peers.truncate(size);
        peers
    }

    /// Choose a random peer set given set size
    /// Return all peers if there are not enough peers
    pub fn get_random_peers_satisfying<F>(
        &self, size: usize, filter: F,
    ) -> Vec<PeerId>
    where F: Fn(&SynchronizationPeerState) -> bool {
        let mut peers: Vec<PeerId> = self
            .peers
            .read()
            .iter()
            .filter_map(|(id, state)| {
                if filter(&*state.read()) {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        let mut rand = random::new();
        rand.shuffle(&mut peers);
        peers.truncate(size);
        peers
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
}
