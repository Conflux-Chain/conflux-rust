// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
//use slab::Slab;
use crate::{
    message::MsgId,
    sync::{
        message::{DynamicCapability, DynamicCapabilitySet},
        random, Error, ErrorKind,
    },
};
use network::{
    node_table::NodeId, service::ProtocolVersion, Error as NetworkError,
    ErrorKind as NetworkErrorKind,
};
use parking_lot::RwLock;
use rand::prelude::SliceRandom;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use throttling::token_bucket::{ThrottledManager, TokenBucketManager};

pub struct SynchronizationPeerState {
    pub node_id: NodeId,
    // This field is only used for consortium setup.
    // Whether this node is a validator.
    pub is_validator: bool,
    pub protocol_version: ProtocolVersion,
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
    // Used to track the throttled P2P messages to remote peer. When throttled,
    // should not send requests to the remote peer. Otherwise, the remote peer
    // may disconnect the TCP connection.
    pub throttled_msgs: ThrottledManager<MsgId>,
}

pub type SynchronizationPeers =
    HashMap<NodeId, Arc<RwLock<SynchronizationPeerState>>>;

pub struct SynchronizationState {
    is_consortium: bool,
    is_full_node: bool,
    is_dev_or_test_mode: bool,
    pub peers: RwLock<SynchronizationPeers>,
    pub handshaking_peers: RwLock<HashMap<NodeId, (ProtocolVersion, Instant)>>,
    pub last_sent_transaction_hashes: RwLock<HashSet<H256>>,
}

impl SynchronizationState {
    pub fn new(
        is_consortium: bool, is_full_node: bool, is_dev_or_test_mode: bool,
    ) -> Self {
        SynchronizationState {
            is_consortium,
            is_full_node,
            is_dev_or_test_mode,
            peers: Default::default(),
            handshaking_peers: Default::default(),
            last_sent_transaction_hashes: Default::default(),
        }
    }

    pub fn is_consortium(&self) -> bool { self.is_consortium }

    pub fn on_status_in_handshaking(
        &self, node_id: &NodeId,
    ) -> Option<ProtocolVersion> {
        let peers = self.peers.read();
        let mut handshaking_peers = self.handshaking_peers.write();
        if !peers.contains_key(node_id) {
            handshaking_peers.remove(node_id).map(|(v, _)| v)
        } else {
            None
        }
    }

    pub fn peer_connected(
        &self, node_id: NodeId, state: SynchronizationPeerState,
    ) {
        let mut peers = self.peers.write();
        if self.is_consortium() {
            unimplemented!();
        } else {
            peers.insert(node_id, Arc::new(RwLock::new(state)));
        }
    }

    pub fn contains_peer(&self, node_id: &NodeId) -> bool {
        self.peers.read().contains_key(node_id)
    }

    pub fn get_peer_info(
        &self, node_id: &NodeId,
    ) -> Result<Arc<RwLock<SynchronizationPeerState>>, Error> {
        Ok(self
            .peers
            .read()
            .get(node_id)
            .ok_or(ErrorKind::UnknownPeer)?
            .clone())
    }

    pub fn get_peer_version(
        &self, peer: &NodeId,
    ) -> Result<ProtocolVersion, NetworkError> {
        match self.get_peer_info(peer) {
            Err(_) => bail!(NetworkErrorKind::InvalidNodeId),
            Ok(info) => Ok(info.read().protocol_version),
        }
    }

    /// Updates the heartbeat for the specified peer. It takes no effect if the
    /// peer is in handshaking status or not found.
    pub fn update_heartbeat(&self, node_id: &NodeId) {
        if let Some(state) = self.peers.read().get(node_id) {
            state.write().heartbeat = Instant::now();
        }
    }

    /// Retrieves the heartbeat timeout peers, including handshaking timeout
    /// peers and inactive peers after handshake.
    pub fn get_heartbeat_timeout_peers(
        &self, timeout: Duration,
    ) -> Vec<NodeId> {
        let mut timeout_peers = Vec::new();

        for (peer, (_, handshake_time)) in self.handshaking_peers.read().iter()
        {
            if handshake_time.elapsed() > timeout {
                timeout_peers.push(*peer);
            }
        }

        for (peer, state) in self.peers.read().iter() {
            if state.read().heartbeat.elapsed() > timeout {
                timeout_peers.push(*peer);
            }
        }

        timeout_peers
    }

    pub fn is_full_node(&self) -> bool { self.is_full_node }

    pub fn is_dev_or_test_mode(&self) -> bool { self.is_dev_or_test_mode }

    // FIXME: median_chain_height_from_peers.
    // FIXME: it lead to more questions but these are questions on the
    // FIXME: algorithm side.
    pub fn median_epoch_from_normal_peers(&self) -> Option<u64> {
        // This flag is set to true if all peers are just starting from a clean
        // state, so we can just enter the normal phase because there's
        // nothing to catch up.
        let mut fresh_start = true;
        let mut peer_best_epoches = Vec::new();
        {
            for (_, state_lock) in &*self.peers.read() {
                let state = state_lock.read();
                if state
                    .capabilities
                    .contains(DynamicCapability::NormalPhase(true))
                {
                    peer_best_epoches.push(state.best_epoch);
                } else if state.best_epoch != 0 {
                    // Note `best_epoch` is initialized according to Status,
                    // so if it's 0, the peer is just newly started
                    fresh_start = false;
                }
            }
        };

        if peer_best_epoches.is_empty() {
            return if fresh_start { Some(0) } else { None };
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
/// Filter peers that match ``all'' the provided conditions.
pub struct PeerFilter<'a> {
    throttle_msg_ids: Option<HashSet<MsgId>>,
    excludes: Option<HashSet<NodeId>>,
    choose_from: Option<&'a HashSet<NodeId>>,
    cap: Option<DynamicCapability>,
    min_best_epoch: Option<u64>,
}

impl<'a> PeerFilter<'a> {
    pub fn new(msg_id: MsgId) -> Self { PeerFilter::default().throttle(msg_id) }

    pub fn throttle(mut self, msg_id: MsgId) -> Self {
        self.throttle_msg_ids
            .get_or_insert_with(|| HashSet::new())
            .insert(msg_id);
        self
    }

    pub fn exclude(mut self, node_id: NodeId) -> Self {
        self.excludes
            .get_or_insert_with(|| HashSet::new())
            .insert(node_id);
        self
    }

    /// Exclude the peers not in the `peer_set`
    pub fn choose_from(mut self, peer_set: &'a HashSet<NodeId>) -> Self {
        self.choose_from = Some(peer_set);
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

    pub fn select_all(self, syn: &SynchronizationState) -> Vec<NodeId> {
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

            if let Some(ref choose_from) = self.choose_from {
                if !choose_from.contains(id) {
                    continue;
                }
            }

            if check_state {
                let mut peer = peer.write();

                if syn.is_consortium() {
                    if !peer.is_validator {
                        continue;
                    }
                }

                if let Some(ref ids) = self.throttle_msg_ids {
                    if ids
                        .iter()
                        .any(|id| peer.throttled_msgs.check_throttled(id))
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

    pub fn select(self, syn: &SynchronizationState) -> Option<NodeId> {
        self.select_all(syn).choose(&mut random::new()).cloned()
    }

    pub fn select_n(self, n: usize, syn: &SynchronizationState) -> Vec<NodeId> {
        let mut peers = self.select_all(syn);
        peers.shuffle(&mut random::new());
        peers.truncate(n);
        peers
    }
}
