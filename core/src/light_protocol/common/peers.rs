// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use parking_lot::RwLock;
use rand::Rng;

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::network::PeerId;

#[derive(Default)]
pub struct FullPeerState {
    pub best_epoch: u64,
    pub handshake_completed: bool,
    pub protocol_version: u8,
    pub terminals: HashSet<H256>,
}

#[derive(Default)]
pub struct LightPeerState {
    pub handshake_completed: bool,
    pub protocol_version: u8,
}

#[derive(Default)]
pub struct Peers<T: Default>(RwLock<HashMap<PeerId, Arc<RwLock<T>>>>);

impl<T> Peers<T>
where T: Default
{
    pub fn new() -> Peers<T> { Self::default() }

    pub fn get(&self, peer: &PeerId) -> Option<Arc<RwLock<T>>> {
        self.0.read().get(&peer).cloned()
    }

    pub fn insert(&self, peer: PeerId) {
        self.0
            .write()
            .entry(peer)
            .or_insert(Arc::new(RwLock::new(T::default())));
    }

    pub fn is_empty(&self) -> bool { self.0.read().is_empty() }

    pub fn contains(&self, peer: &PeerId) -> bool {
        self.0.read().contains_key(&peer)
    }

    pub fn remove(&self, peer: &PeerId) { self.0.write().remove(&peer); }

    pub fn all_peers_satisfying<F>(&self, predicate: F) -> Vec<PeerId>
    where F: Fn(&T) -> bool {
        self.0
            .read()
            .iter()
            .filter_map(|(id, state)| {
                if predicate(&*state.read()) {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn random_peer_satisfying<F>(&self, predicate: F) -> Option<PeerId>
    where F: Fn(&T) -> bool {
        let options = self.all_peers_satisfying(predicate);
        rand::thread_rng().choose(&options).cloned()
    }

    pub fn all_peers_shuffled(&self) -> Vec<PeerId> {
        let mut peers: Vec<_> = self.0.read().keys().cloned().collect();
        rand::thread_rng().shuffle(&mut peers);
        peers
    }

    pub fn random_peer(&self) -> Option<PeerId> {
        let peers: Vec<_> = self.0.read().keys().cloned().collect();
        rand::thread_rng().choose(&peers).cloned()
    }

    pub fn fold<B, F>(&self, init: B, f: F) -> B
    where F: FnMut(B, &Arc<RwLock<T>>) -> B {
        self.0.write().values().fold(init, f)
    }
}
