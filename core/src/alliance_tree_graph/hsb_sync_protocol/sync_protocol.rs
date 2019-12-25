// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{HSB_PROTOCOL_ID, HSB_PROTOCOL_VERSION};
use crate::{
    network::{
        NetworkContext, NetworkProtocolHandler, NetworkService, PeerId,
        UpdateNodeOperation,
    },
    sync::request_manager::RequestManager,
};
use cfx_types::H256;
use io::TimerToken;
use keccak_hash::keccak;
use parking_lot::RwLock;
use std::{cmp::Eq, collections::HashMap, hash::Hash, sync::Arc};

#[derive(Default)]
pub struct PeerState {
    id: PeerId,
    peer_hash: H256,
}

#[derive(Default)]
pub struct Peers<T: Default, K: Eq + Hash + Default + Copy>(
    RwLock<HashMap<K, Arc<RwLock<T>>>>,
);

impl<T, K> Peers<T, K>
where
    T: Default,
    K: Eq + Hash + Default + Copy,
{
    pub fn new() -> Peers<T, K> { Self::default() }

    pub fn get(&self, peer: &K) -> Option<Arc<RwLock<T>>> {
        self.0.read().get(peer).cloned()
    }

    pub fn insert(&self, peer: K) {
        self.0
            .write()
            .entry(peer)
            .or_insert(Arc::new(RwLock::new(T::default())));
    }

    pub fn is_empty(&self) -> bool { self.0.read().is_empty() }

    pub fn contains(&self, peer: &K) -> bool {
        self.0.read().contains_key(peer)
    }

    pub fn remove(&self, peer: &K) -> Option<Arc<RwLock<T>>> {
        self.0.write().remove(peer)
    }

    pub fn all_peers_satisfying<F>(&self, mut predicate: F) -> Vec<K>
    where F: FnMut(&mut T) -> bool {
        self.0
            .read()
            .iter()
            .filter_map(|(id, state)| {
                if predicate(&mut *state.write()) {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn fold<B, F>(&self, init: B, f: F) -> B
    where F: FnMut(B, &Arc<RwLock<T>>) -> B {
        self.0.write().values().fold(init, f)
    }
}

pub struct HotStuffSynchronizationProtocol {
    pub own_node_hash: H256,
    pub peers: Arc<Peers<PeerState, H256>>,
    pub request_manager: Arc<RequestManager>,
}

impl HotStuffSynchronizationProtocol {
    pub fn new(
        own_node_hash: H256, request_manager: Arc<RequestManager>,
    ) -> Self {
        HotStuffSynchronizationProtocol {
            own_node_hash,
            peers: Arc::new(Peers::new()),
            request_manager,
        }
    }

    pub fn register(
        self: Arc<Self>, network: Arc<NetworkService>,
    ) -> Result<(), String> {
        network
            .register_protocol(self, HSB_PROTOCOL_ID, &[HSB_PROTOCOL_VERSION])
            .map_err(|e| {
                format!(
                    "failed to register HotStuffSynchronizationProtocol: {:?}",
                    e
                )
            })
    }

    /// In the event two peers simultaneously dial each other we need to be able
    /// to do tie-breaking to determine which connection to keep and which
    /// to drop in a deterministic way. One simple way is to compare our
    /// local PeerId with that of the remote's PeerId and
    /// keep the connection where the peer with the greater PeerId is the
    /// dialer.
    ///
    /// Returns `true` if the existing connection should be dropped and `false`
    /// if the new connection should be dropped.
    fn simultaneous_dial_tie_breaking(
        own_peer_id: H256, remote_peer_id: H256, existing_origin: bool,
        new_origin: bool,
    ) -> bool
    {
        match (existing_origin, new_origin) {
            // If the remote dials while an existing connection is open, the
            // older connection is dropped.
            (false /* in-bound */, false /* in-bound */) => true,
            (false /* in-bound */, true /* out-bound */) => {
                remote_peer_id < own_peer_id
            }
            (true /* out-bound */, false /* in-bound */) => {
                own_peer_id < remote_peer_id
            }
            // We should never dial the same peer twice, but if we do drop the
            // new connection
            (true /* out-bound */, true /* out-bound */) => false,
        }
    }
}

impl NetworkProtocolHandler for HotStuffSynchronizationProtocol {
    fn initialize(&self, _io: &dyn NetworkContext) {}

    fn on_message(&self, _io: &dyn NetworkContext, _peer: PeerId, _raw: &[u8]) {
    }

    fn on_peer_connected(&self, io: &dyn NetworkContext, peer: PeerId) {
        let new_originated = io.get_peer_connection_origin(peer);
        if new_originated.is_none() {
            debug!("Peer does not exist when just connected");
            return;
        }
        let new_originated = new_originated.unwrap();
        let node_id = io.get_peer_node_id(peer);
        let peer_hash = keccak(&node_id);

        let add_new_peer = if let Some(old_peer) = self.peers.remove(&peer_hash)
        {
            let old_peer_id = old_peer.read().id;
            let old_originated = io.get_peer_connection_origin(old_peer_id);
            if old_originated.is_none() {
                debug!("Old session does not exist.");
                true
            } else {
                let old_originated = old_originated.unwrap();
                if Self::simultaneous_dial_tie_breaking(
                    self.own_node_hash.clone(),
                    peer_hash.clone(),
                    old_originated,
                    new_originated,
                ) {
                    // Drop the existing connection and replace it with the new
                    // connection.
                    io.disconnect_peer(
                        old_peer_id,
                        Some(UpdateNodeOperation::Failure),
                        "remove old peer connection",
                    );
                    true
                } else {
                    // Drop the new connection.
                    false
                }
            }
        } else {
            true
        };

        if add_new_peer {
            self.peers.insert(peer_hash.clone());
            let peer_state =
                self.peers.get(&peer_hash).expect("peer not found");
            let mut peer_state = peer_state.write();
            peer_state.id = peer;
            peer_state.peer_hash = peer_hash;
        } else {
            io.disconnect_peer(
                peer,
                Some(UpdateNodeOperation::Failure),
                "remove new peer connection",
            );
        }
    }

    fn on_peer_disconnected(&self, io: &dyn NetworkContext, peer: PeerId) {
        let node_id = io.get_peer_node_id(peer);
        let peer_hash = keccak(&node_id);
        info!("on_peer_disconnected: peer={:?}", peer_hash);
        self.peers.remove(&peer_hash);
    }

    fn on_timeout(&self, _io: &dyn NetworkContext, _timer: TimerToken) {}
}
