// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use parking_lot::RwLock;
use rand::Rng;

use cfx_types::H256;

use crate::network::PeerId;

#[derive(Default)]
pub(super) struct PeerState {
    pub protocol_version: u8,
    pub genesis_hash: H256,
    pub best_epoch: u64,
    pub terminals: HashSet<H256>,
}

#[derive(Default)]
pub struct Peers(RwLock<HashMap<PeerId, Arc<RwLock<PeerState>>>>);

impl Peers {
    pub(super) fn insert(&self, peer: PeerId) -> Arc<RwLock<PeerState>> {
        self.0
            .write()
            .entry(peer)
            .or_insert(Arc::new(RwLock::new(PeerState::default())))
            .clone()
    }

    pub(super) fn remove(&self, peer: &PeerId) { self.0.write().remove(&peer); }

    pub fn all_peers_shuffled(&self) -> Vec<PeerId> {
        let mut rand = rand::thread_rng();
        let mut peers: Vec<_> = self.0.read().keys().cloned().collect();
        rand.shuffle(&mut peers[..]);
        peers
    }
}
