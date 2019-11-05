// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use network::PeerId;
//use slab::Slab;
use crate::{
    message::MsgId,
    sync::{
        message::{DynamicCapability, DynamicCapabilitySet},
        random, Error, ErrorKind,
    },
};
use parking_lot::RwLock;
use rand::prelude::SliceRandom;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use throttling::token_bucket::TokenBucketManager;

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

    // Used to throttle the P2P messages from remote peer, so as to avoid DoS
    // attack. E.g. send large number of P2P messages to query blocks.
    pub throttling: TokenBucketManager,
    // Used to track the throttled P2P messages to remote peer.
    // The `Instant` value in `HashMap` is the time to allow send P2P message
    // again. Otherwise, the remote peer will disconnect the TCP connection.
    pub throttled_msgs: HashMap<MsgId, Instant>,
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

    pub fn best_peer_epoch(&self) -> Option<u64> {
        self.peers
            .read()
            .iter()
            .map(|(_, state)| state.read().best_epoch)
            .fold(None, |max, x| match max {
                None => Some(x),
                Some(max) => Some(if x > max { x } else { max }),
            })
    }
}

#[derive(Default)]
pub struct PeerFilter {
    throttle_msg_ids: Option<HashSet<MsgId>>,
    excludes: Option<HashSet<PeerId>>,
    cap: Option<DynamicCapability>,
    min_best_epoch: Option<u64>,
}

impl PeerFilter {
    pub fn new(msg_id: MsgId) -> Self { PeerFilter::default().throttle(msg_id) }

    pub fn throttle(mut self, msg_id: MsgId) -> Self {
        self.throttle_msg_ids
            .get_or_insert_with(|| HashSet::new())
            .insert(msg_id);
        self
    }

    pub fn exclude(mut self, peer: PeerId) -> Self {
        self.excludes
            .get_or_insert_with(|| HashSet::new())
            .insert(peer);
        self
    }

    pub fn with_cap(mut self, cap: DynamicCapability) -> Self {
        self.cap.replace(cap);
        self
    }

    pub fn with_min_best_epoch(mut self, min_best_epoch: u64) -> Self {
        self.min_best_epoch.replace(min_best_epoch);
        self
    }

    pub fn select_all(self, syn: &SynchronizationState) -> Vec<PeerId> {
        let mut peers = Vec::new();

        let check_state = self.throttle_msg_ids.is_some()
            || self.cap.is_some()
            || self.min_best_epoch.is_some();

        for (id, peer) in syn.peers.read().iter() {
            if let Some(ref excludes) = self.excludes {
                if excludes.contains(id) {
                    continue;
                }
            }

            if check_state {
                let peer = peer.read();

                if let Some(ref ids) = self.throttle_msg_ids {
                    if ids.iter().any(|id| peer.throttled_msgs.contains_key(id))
                    {
                        continue;
                    }
                }

                if let Some(cap) = self.cap {
                    if !peer.capabilities.contains(cap) {
                        continue;
                    }
                }

                if let Some(min) = self.min_best_epoch {
                    if peer.best_epoch < min {
                        continue;
                    }
                }
            }

            peers.push(*id);
        }

        peers
    }

    pub fn select(self, syn: &SynchronizationState) -> Option<PeerId> {
        self.select_all(syn).choose(&mut random::new()).cloned()
    }

    pub fn select_n(self, n: usize, syn: &SynchronizationState) -> Vec<PeerId> {
        let mut peers = self.select_all(syn);
        peers.shuffle(&mut random::new());
        peers.truncate(n);
        peers
    }
}
