// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use message::{
    GetBlockHeaders, GetBlockTxn, GetBlocks, GetCompactBlocks,
    GetTerminalBlockHashes, GetTransactions, Message, TransIndex,
};
use network::{PeerId, NetworkContext};
//use slab::Slab;
use crate::sync::{
    random,  Error,
    ErrorKind,
};
use parking_lot::{RwLock, Mutex};
use primitives::{SignedTransaction, TxPropagateId};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    mem,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use priority_send_queue::SendQueuePriority;
use std::collections::binary_heap::BinaryHeap;
use super::synchronization_protocol_handler::ProtocolConfiguration;
use super::request_manager::RequestManager;
use std::sync::atomic::AtomicBool;


pub struct SynchronizationPeerState {
    pub id: PeerId,
    pub protocol_version: u8,
    pub genesis_hash: H256,
    pub best_epoch: u64,

    /// The following fields are used to control how to handle
    /// transaction propagation for nodes in catch-up mode.
    pub received_transaction_count: usize,
    pub need_prop_trans: bool,
    pub notified_mode: Option<bool>,
}

pub type SynchronizationPeers =
    HashMap<PeerId, Arc<RwLock<SynchronizationPeerState>>>;

pub struct SynchronizationState {
    pub catch_up_mode: AtomicBool,
    pub peers: RwLock<SynchronizationPeers>,
    pub handshaking_peers: RwLock<HashMap<PeerId, Instant>>,
    pub last_sent_transaction_hashes: RwLock<HashSet<H256>>,
}

impl SynchronizationState {
    pub fn new(
        catch_up_mode: bool, protocol_config: &ProtocolConfiguration
    ) -> Self
    {
        SynchronizationState {
            catch_up_mode: AtomicBool::new(catch_up_mode),
            peers: Default::default(),
            handshaking_peers: Default::default(),
            last_sent_transaction_hashes: Default::default(),
        }
    }

    pub fn on_status(&self, peer: PeerId) {
        let peers = self.peers.read();
        let mut handshaking_peers = self.handshaking_peers.write();
        if handshaking_peers.remove(&peer).is_none()
            || peers.contains_key(&peer)
        {
            debug!("Unexpected status message: peer={:?}", peer);
        }
    }

    pub fn peer_connected(&self, peer: PeerId, state: SynchronizationPeerState) {
        self.peers.write().insert(peer, Arc::new(RwLock::new(state)));
    }

    pub fn contains_peer(&self, peer: &PeerId) -> bool {
        self.peers.read().contains_key(peer)
    }

    pub fn get_peer_info(
        &self, id: &PeerId,
    ) -> Result<Arc<RwLock<SynchronizationPeerState>>, Error> {
        Ok(self.peers.read().get(&id).ok_or(ErrorKind::UnknownPeer)?.clone())
    }

    /// Choose one random peer excluding the given `exclude` set.
    /// Return None if there is no peer to choose from
    pub fn get_random_peer(&self, exclude: &HashSet<PeerId>) -> Option<PeerId> {
        let peer_set: HashSet<PeerId> = self.peers.read().keys().cloned().collect();
        let choose_from: Vec<&PeerId> = peer_set.difference(exclude).collect();
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
}
