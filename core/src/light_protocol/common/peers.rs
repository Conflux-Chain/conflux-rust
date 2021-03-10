// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use parking_lot::RwLock;

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::message::MsgId;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use network::{node_table::NodeId, service::ProtocolVersion};
use rand::prelude::SliceRandom;
use throttling::token_bucket::{ThrottledManager, TokenBucketManager};

#[derive(Default)]
pub struct FullPeerState {
    pub best_epoch: u64,
    pub handshake_completed: bool,
    pub protocol_version: ProtocolVersion,
    pub terminals: HashSet<H256>,
    pub throttled_msgs: ThrottledManager<MsgId>,
    pub unexpected_msgs: TokenBucketManager,
}

#[derive(Default, DeriveMallocSizeOf)]
pub struct LightPeerState {
    pub handshake_completed: bool,
    pub protocol_version: ProtocolVersion,
    pub throttling: TokenBucketManager,
}

#[derive(Default)]
pub struct Peers<T: Default>(RwLock<HashMap<NodeId, Arc<RwLock<T>>>>);

impl<T: Default + MallocSizeOf> MallocSizeOf for Peers<T> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.0.size_of(ops)
    }
}

impl<T> Peers<T>
where
    T: Default,
{
    pub fn new() -> Peers<T> {
        Self::default()
    }

    pub fn get(&self, peer: &NodeId) -> Option<Arc<RwLock<T>>> {
        self.0.read().get(&peer).cloned()
    }

    pub fn insert(&self, peer: NodeId) {
        self.0
            .write()
            .entry(peer)
            .or_insert(Arc::new(RwLock::new(T::default())));
    }

    pub fn is_empty(&self) -> bool {
        self.0.read().is_empty()
    }

    pub fn contains(&self, peer: &NodeId) -> bool {
        self.0.read().contains_key(&peer)
    }

    pub fn remove(&self, peer: &NodeId) {
        self.0.write().remove(&peer);
    }

    pub fn all_peers_satisfying<F>(&self, mut predicate: F) -> Vec<NodeId>
    where
        F: FnMut(&mut T) -> bool,
    {
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
    where
        F: FnMut(B, &Arc<RwLock<T>>) -> B,
    {
        self.0.write().values().fold(init, f)
    }
}

pub struct FullPeerFilter {
    msg_id: MsgId,
    min_best_epoch: Option<u64>,
}

impl FullPeerFilter {
    pub fn new(msg_id: MsgId) -> Self {
        FullPeerFilter {
            msg_id,
            min_best_epoch: None,
        }
    }

    pub fn with_min_best_epoch(mut self, min_best_epoch: u64) -> Self {
        self.min_best_epoch.replace(min_best_epoch);
        self
    }

    pub fn select(self, peers: Arc<Peers<FullPeerState>>) -> Option<NodeId> {
        self.select_all(peers)
            .choose(&mut rand::thread_rng())
            .cloned()
    }

    pub fn select_all(self, peers: Arc<Peers<FullPeerState>>) -> Vec<NodeId> {
        peers.all_peers_satisfying(|peer| {
            if peer.throttled_msgs.check_throttled(&self.msg_id) {
                return false;
            }

            let min_best_epoch = self.min_best_epoch.unwrap_or_default();
            peer.best_epoch >= min_best_epoch
        })
    }
}
