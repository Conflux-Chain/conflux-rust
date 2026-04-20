// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::pos::mempool::{
    counters,
    logging::{LogEntry, LogEvent, LogSchema},
    network::MempoolSyncMsg,
    shared_mempool::{
        tasks,
        types::{notify_subscribers, SharedMempool, SharedMempoolNotification},
    },
};
use diem_infallible::Mutex;
use diem_logger::prelude::*;
use diem_types::transaction::SignedTransaction;
//use netcore::transport::ConnectionOrigin;
//use network::transport::ConnectionMetadata;
use network::node_table::NodeId;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ops::Add,
    time::{Duration, SystemTime},
};
//use vm_validator::vm_validator::TransactionValidation;

const PRIMARY_NETWORK_PREFERENCE: usize = 0;

/// Peers that receive txns from this node.
pub(crate) type PeerSyncStates = HashMap<NodeId, PeerSyncState>;

/// State of last sync with peer:
/// `timeline_id` is position in log of ready transactions
/// `is_alive` - is connection healthy
#[derive(Clone)]
pub(crate) struct PeerSyncState {
    pub timeline_id: u64,
    pub is_alive: bool,
    pub broadcast_info: BroadcastInfo,
    //pub metadata: ConnectionMetadata,
}

impl PeerSyncState {
    pub fn new(/*metadata: ConnectionMetadata*/) -> Self {
        PeerSyncState {
            timeline_id: 0,
            is_alive: true,
            broadcast_info: BroadcastInfo::new(),
            //metadata,
        }
    }
}

pub(crate) struct PeerManager {
    peer_states: Mutex<PeerSyncStates>,
}
/// Identifier for a broadcasted batch of txns.
/// For BatchId(`start_id`, `end_id`), (`start_id`, `end_id`) is the range of
/// timeline IDs read from the core mempool timeline index that produced the
/// txns in this batch.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct BatchId(pub u64, pub u64);

impl PartialOrd for BatchId {
    fn partial_cmp(&self, other: &BatchId) -> Option<std::cmp::Ordering> {
        Some((other.0, other.1).cmp(&(self.0, self.1)))
    }
}

impl Ord for BatchId {
    fn cmp(&self, other: &BatchId) -> std::cmp::Ordering {
        (other.0, other.1).cmp(&(self.0, self.1))
    }
}

/// Txn broadcast-related info for a given remote peer.
#[derive(Clone)]
pub struct BroadcastInfo {
    // Sent broadcasts that have not yet received an ack.
    pub sent_batches: BTreeMap<BatchId, SystemTime>,
    // Broadcasts that have received a retry ack and are pending a resend.
    pub retry_batches: BTreeSet<BatchId>,
    // Whether broadcasting to this peer is in backoff mode, e.g. broadcasting
    // at longer intervals.
    pub backoff_mode: bool,
}

impl BroadcastInfo {
    fn new() -> Self {
        Self {
            sent_batches: BTreeMap::new(),
            retry_batches: BTreeSet::new(),
            backoff_mode: false,
        }
    }
}

impl PeerManager {
    pub fn new() -> Self {
        // Primary network is always chosen at initialization.
        counters::upstream_network(PRIMARY_NETWORK_PREFERENCE);
        diem_info!(LogSchema::new(LogEntry::UpstreamNetwork)
            .network_level(PRIMARY_NETWORK_PREFERENCE));
        Self {
            peer_states: Mutex::new(PeerSyncStates::new()),
        }
    }

    // Returns true if `peer` is discovered for the first time, else false.
    pub fn add_peer(
        &self,
        peer: NodeId, //metadata: ConnectionMetadata,
    ) -> bool {
        diem_debug!("PeerManager::add_peer [{:?}]", peer);
        let mut peer_states = self.peer_states.lock();
        let is_new_peer = !peer_states.contains_key(&peer);
        //if self.is_upstream_peer(&peer, Some(&metadata)) {
        // If we have a new peer, let's insert new data, otherwise, let's
        // just update the current state
        if is_new_peer {
            //counters::active_upstream_peers(&peer.raw_network_id()).inc();
            peer_states.insert(peer, PeerSyncState::new(/*metadata*/));
        } else if let Some(peer_state) = peer_states.get_mut(&peer) {
            if !peer_state.is_alive {
                //counters::active_upstream_peers(&peer.raw_network_id())
                //    .inc();
            }
            peer_state.is_alive = true;
            //peer_state.metadata = metadata;
        }
        //}
        drop(peer_states);
        is_new_peer
    }

    /// Disables a peer if it can be restarted, otherwise removes it
    pub fn disable_peer(&self, peer: NodeId) {
        diem_debug!("PeerManager::disable_peer [{:?}]", peer);
        self.peer_states.lock().remove(&peer);
    }

    pub fn is_backoff_mode(&self, peer: &NodeId) -> bool {
        if let Some(state) = self.peer_states.lock().get(peer) {
            state.broadcast_info.backoff_mode
        } else {
            // If we don't have sync state, we shouldn't backoff
            false
        }
    }

    pub fn contains_peer(&self, peer: &NodeId) -> bool {
        return self.peer_states.lock().contains_key(peer);
    }

    pub fn execute_broadcast(
        &self, peer: NodeId, scheduled_backoff: bool, smp: &mut SharedMempool,
    ) {
        diem_trace!("start execute_broadcast for peer {:?}", peer);
        let mut peer_states = self.peer_states.lock();
        let state = if let Some(state) = peer_states.get_mut(&peer) {
            state
        } else {
            diem_trace!("no state of peer {:?}", peer);
            // If we don't have any info about the node, we shouldn't broadcast
            // to it
            return;
        };

        // Only broadcast to peers that are alive.
        if !state.is_alive {
            return;
        }

        // If backoff mode is on for this peer, only execute broadcasts that
        // were scheduled as a backoff broadcast. This is to ensure the
        // backoff mode is actually honored (there is a chance a broadcast was
        // scheduled in non-backoff mode before backoff mode was turned
        // on - ignore such scheduled broadcasts).
        if state.broadcast_info.backoff_mode && !scheduled_backoff {
            return;
        }

        let batch_id: BatchId;
        let transactions: Vec<SignedTransaction>;
        {
            let mut mempool = smp.mempool.lock();

            // Sync peer's pending broadcasts with latest mempool state.
            // A pending broadcast might become empty if the corresponding txns
            // were committed through another peer, so don't track
            // broadcasts for committed txns.
            state.broadcast_info.sent_batches = state
                .broadcast_info
                .sent_batches
                .clone()
                .into_iter()
                .filter(|(id, _batch)| {
                    !mempool.timeline_range(id.0, id.1).is_empty()
                })
                .collect::<BTreeMap<BatchId, SystemTime>>();

            // Check for batch to rebroadcast:
            // 1. Batch that did not receive ACK in configured window of time
            // 2. Batch that an earlier ACK marked as retriable
            let mut pending_broadcasts = 0;
            let mut expired = None;

            // Find earliest batch in timeline index that expired.
            // Note that state.broadcast_info.sent_batches is ordered in
            // decreasing order in the timeline index
            for (batch, sent_time) in state.broadcast_info.sent_batches.iter() {
                let deadline = sent_time.add(Duration::from_millis(
                    smp.config.shared_mempool_ack_timeout_ms,
                ));
                if SystemTime::now().duration_since(deadline).is_ok() {
                    expired = Some(batch);
                } else {
                    pending_broadcasts += 1;
                }

                // The maximum number of broadcasts sent to a single peer that
                // are pending a response ACK at any point.
                // If the number of un-ACK'ed un-expired broadcasts reaches this
                // threshold, we do not broadcast anymore
                // and wait until an ACK is received or a sent broadcast
                // expires. This helps rate-limit egress network
                // bandwidth and not overload a remote peer or this
                // node's Diem network sender.
                if pending_broadcasts >= smp.config.max_broadcasts_per_peer {
                    diem_debug!(
                        "pending_broadcasts too much for peer {:?}",
                        peer
                    );
                    return;
                }
            }
            let retry = state.broadcast_info.retry_batches.iter().rev().next();

            let (new_batch_id, new_transactions) =
                match std::cmp::max(expired, retry) {
                    Some(id) => {
                        let txns = mempool.timeline_range(id.0, id.1);
                        (*id, txns)
                    }
                    None => {
                        // Fresh broadcast
                        let (txns, new_timeline_id) = mempool.read_timeline(
                            state.timeline_id,
                            smp.config.shared_mempool_batch_size,
                        );
                        (BatchId(state.timeline_id, new_timeline_id), txns)
                    }
                };

            batch_id = new_batch_id;
            transactions = new_transactions;
        }

        if transactions.is_empty() {
            diem_trace!("transactions empty");
            return;
        }

        if let Err(e) = smp.network_sender.send_message_with_peer_id(
            &peer,
            &MempoolSyncMsg::BroadcastTransactionsRequest {
                request_id: bcs::to_bytes(&batch_id)
                    .expect("failed BCS serialization of batch ID"),
                transactions,
            },
        ) {
            counters::network_send_fail_inc(counters::BROADCAST_TXNS);
            diem_info!(LogSchema::event_log(
                LogEntry::BroadcastTransaction,
                LogEvent::NetworkSendFail
            )
            //.peer(&peer)
            .error(&e.into()));
            // Actively enter backoff mode if error happens.
            state.broadcast_info.backoff_mode = true;
            return;
        }
        // Update peer sync state with info from above broadcast.
        state.timeline_id = std::cmp::max(state.timeline_id, batch_id.1);
        // Turn off backoff mode after every broadcast.
        state.broadcast_info.backoff_mode = false;
        state
            .broadcast_info
            .sent_batches
            .insert(batch_id, SystemTime::now());
        state.broadcast_info.retry_batches.remove(&batch_id);
        notify_subscribers(
            SharedMempoolNotification::Broadcast,
            &smp.subscribers,
        );

        diem_trace!(LogSchema::event_log(
            LogEntry::BroadcastTransaction,
            LogEvent::Success
        )
        //.peer(&peer)
        .batch_id(&batch_id)
        .backpressure(scheduled_backoff));
    }

    pub fn process_broadcast_ack(
        &self, peer: NodeId, request_id_bytes: Vec<u8>, retry: bool,
        backoff: bool, timestamp: SystemTime,
    ) {
        let batch_id = if let Ok(id) =
            bcs::from_bytes::<BatchId>(&request_id_bytes)
        {
            id
        } else {
            //counters::invalid_ack_inc(&peer, counters::INVALID_REQUEST_ID);
            return;
        };

        let mut peer_states = self.peer_states.lock();

        let sync_state = if let Some(state) = peer_states.get_mut(&peer) {
            state
        } else {
            //counters::invalid_ack_inc(&peer, counters::UNKNOWN_PEER);
            return;
        };

        if let Some(sent_timestamp) =
            sync_state.broadcast_info.sent_batches.remove(&batch_id)
        {
            let _rtt = timestamp
                .duration_since(sent_timestamp)
                .expect("failed to calculate mempool broadcast RTT");

        /*let network_id = peer.raw_network_id();
        let peer_id = peer.peer_id().short_str();
        counters::SHARED_MEMPOOL_BROADCAST_RTT
            .with_label_values(&[network_id.as_str(), peer_id.as_str()])
            .observe(rtt.as_secs_f64());

        counters::shared_mempool_pending_broadcasts(&peer).dec();*/
        } else {
            diem_trace!(
                LogSchema::new(LogEntry::ReceiveACK)
                    //.peer(&peer)
                    .batch_id(&batch_id),
                "batch ID does not exist or expired"
            );
            return;
        }

        diem_trace!(
            LogSchema::new(LogEntry::ReceiveACK)
                //.peer(&peer)
                .batch_id(&batch_id)
                .backpressure(backoff),
            retry = retry,
        );
        tasks::update_ack_counter(
            &peer,
            counters::RECEIVED_LABEL,
            retry,
            backoff,
        );

        if retry {
            sync_state.broadcast_info.retry_batches.insert(batch_id);
        }

        // Backoff mode can only be turned off by executing a broadcast that was
        // scheduled as a backoff broadcast.
        // This ensures backpressure request from remote peer is honored at
        // least once.
        if backoff {
            sync_state.broadcast_info.backoff_mode = true;
        }
    }

    /*// If the origin is provided, checks whether this peer is an upstream peer
    // based on configured preferences and connection origin.
    // If the origin is not provided, checks whether this peer is an upstream
    // peer that was seen before.
    pub fn is_upstream_peer(
        &self, peer: &PeerNetworkId, metadata: Option<&ConnectionMetadata>,
    ) -> bool {
        // Validator network is always upstream
        if peer.raw_network_id().is_validator_network() {
            return true;
        }

        // Outbound connections are upstream on non-P2P networks
        if let Some(metadata) = metadata {
            metadata.origin == ConnectionOrigin::Outbound
        } else {
            // If we already know about the peer, it's upstream
            // TODO: If this is actually used it seems kinda pointless?
            self.peer_states.lock().contains_key(peer)
        }
    }*/
}
