// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use message::{
    GetBlockHeaders, GetBlockTxn, GetBlocks, GetCompactBlocks,
    GetTerminalBlockHashes, Message,
};
use network::PeerId;
//use slab::Slab;
use crate::sync::{
    random, synchronization_protocol_handler::TimedSyncRequests,
};
use rand::Rng;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    mem,
    sync::Arc,
    time::Instant,
};

#[derive(Debug)]
pub enum RequestMessage {
    Headers(GetBlockHeaders),
    Blocks(GetBlocks),
    Compact(GetCompactBlocks),
    BlockTxn(GetBlockTxn),
    Terminals(GetTerminalBlockHashes),
}

impl RequestMessage {
    pub fn set_request_id(&mut self, request_id: u64) {
        match self {
            RequestMessage::Headers(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::Blocks(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::Compact(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::BlockTxn(ref mut msg) => {
                msg.set_request_id(request_id)
            }
            RequestMessage::Terminals(ref mut msg) => {
                msg.set_request_id(request_id)
            }
        }
    }

    pub fn get_msg(&self) -> &Message {
        match self {
            RequestMessage::Headers(ref msg) => msg,
            RequestMessage::Blocks(ref msg) => msg,
            RequestMessage::Compact(ref msg) => msg,
            RequestMessage::BlockTxn(ref msg) => msg,
            RequestMessage::Terminals(ref msg) => msg,
        }
    }
}

#[derive(Debug)]
pub struct SynchronizationPeerRequest {
    pub message: Box<RequestMessage>,
    pub timed_req: Arc<TimedSyncRequests>,
}

pub struct SynchronizationPeerState {
    pub id: PeerId,
    pub protocol_version: u8,
    pub genesis_hash: H256,
    pub inflight_requests: Vec<Option<SynchronizationPeerRequest>>,
    /// lowest = next if there is no inflight requests
    pub lowest_request_id: u64,
    pub next_request_id: u64,
    pub best_epoch: u64,

    pub max_inflight_request_count: u64,
    pub pending_requests: VecDeque<Box<RequestMessage>>,
    /// Holds a set of transactions recently sent to this peer to avoid
    /// spamming.
    pub last_sent_transactions: HashSet<H256>,
    pub received_transaction_count: usize,
    pub need_prop_trans: bool,
    pub notified_mode: Option<bool>,
}

impl SynchronizationPeerState {
    /// If new request will be allowed to send, advance the request id now,
    /// otherwise, actual new request id will be given to this request
    /// when it is moved from pending to inflight queue.
    pub fn get_next_request_id(&mut self) -> Option<u64> {
        if self.next_request_id
            < self.lowest_request_id + self.max_inflight_request_count
        {
            let id = self.next_request_id;
            self.next_request_id += 1;
            Some(id)
        } else {
            None
        }
    }

    pub fn append_inflight_request(
        &mut self, request_id: u64, message: Box<RequestMessage>,
        timed_req: Arc<TimedSyncRequests>,
    )
    {
        self.inflight_requests
            [(request_id % self.max_inflight_request_count) as usize] =
            Some(SynchronizationPeerRequest { message, timed_req });
    }

    pub fn append_pending_request(&mut self, msg: Box<RequestMessage>) {
        self.pending_requests.push_back(msg);
    }

    #[allow(unused)]
    pub fn is_inflight_request(&self, request_id: u64) -> bool {
        request_id < self.next_request_id
            && request_id >= self.lowest_request_id
            && self.inflight_requests
                [(request_id % self.max_inflight_request_count) as usize]
                .is_some()
    }

    pub fn has_pending_requests(&self) -> bool {
        !self.pending_requests.is_empty()
    }

    pub fn pop_pending_request(&mut self) -> Option<Box<RequestMessage>> {
        self.pending_requests.pop_front()
    }

    pub fn remove_inflight_request(
        &mut self, request_id: u64,
    ) -> Option<SynchronizationPeerRequest> {
        if request_id < self.next_request_id
            && request_id >= self.lowest_request_id
        {
            let save_req = mem::replace(
                &mut self.inflight_requests
                    [(request_id % self.max_inflight_request_count) as usize],
                None,
            );
            // Advance lowest_request_id to the next in-flight request
            if request_id == self.lowest_request_id {
                while self.inflight_requests[(self.lowest_request_id
                    % self.max_inflight_request_count)
                    as usize]
                    .is_none()
                    && self.lowest_request_id < self.next_request_id
                {
                    self.lowest_request_id += 1;
                }
            }
            save_req
        } else {
            warn!("Remove out of bound request peer={} request_id={} low={} next={}", self.id, request_id, self.lowest_request_id, self.next_request_id);
            None
        }
    }
}

pub type SynchronizationPeers = HashMap<PeerId, SynchronizationPeerState>;

pub struct SynchronizationState {
    pub catch_up_mode: bool,
    pub peers: SynchronizationPeers,
    pub handshaking_peers: HashMap<PeerId, Instant>,
}

impl SynchronizationState {
    pub fn new(catch_up_mode: bool) -> Self {
        SynchronizationState {
            catch_up_mode,
            peers: HashMap::new(),
            handshaking_peers: HashMap::new(),
        }
    }

    /// Choose one random peer excluding the given `exclude` set.
    /// Return None if there is no peer to choose from
    pub fn get_random_peer(&self, exclude: &HashSet<PeerId>) -> Option<PeerId> {
        let peer_set: HashSet<PeerId> = self.peers.keys().cloned().collect();
        let choose_from: Vec<&PeerId> = peer_set.difference(exclude).collect();
        let mut rand = random::new();
        rand.choose(&choose_from).cloned().cloned()
    }
}
