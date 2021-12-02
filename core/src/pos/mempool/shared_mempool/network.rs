// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Interface between Mempool and Network layers.

use crate::pos::protocol::network_event::NetworkEvent;
use channel::{diem_channel, message_queues::QueueStyle};
use diem_types::transaction::SignedTransaction;
use network::node_table::NodeId;
use serde::{Deserialize, Serialize};
use std::{fmt::Formatter, mem::Discriminant};

/// Container for exchanging transactions with other Mempools.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum MempoolSyncMsg {
    /// Broadcast request issued by the sender.
    BroadcastTransactionsRequest {
        /// Unique id of sync request. Can be used by sender for rebroadcast
        /// analysis
        request_id: Vec<u8>,
        transactions: Vec<SignedTransaction>,
    },
    /// Broadcast ack issued by the receiver.
    BroadcastTransactionsResponse {
        request_id: Vec<u8>,
        /// Retry signal from recipient if there are txns in corresponding
        /// broadcast that were rejected from mempool but may succeed
        /// on resend.
        retry: bool,
        /// A backpressure signal from the recipient when it is overwhelmed
        /// (e.g., mempool is full).
        backoff: bool,
    },
}

impl std::fmt::Display for MempoolSyncMsg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::BroadcastTransactionsRequest { .. } => {
                write!(f, "BroadcastTransactionsRequest")
            }
            Self::BroadcastTransactionsResponse { .. } => {
                write!(f, "BroadcastTransactionsResponse")
            }
        }
    }
}

/// Just a convenience struct to keep all the network proxy receiving queues in
/// one place. Will be returned by the NetworkTask upon startup.
pub struct NetworkReceivers {
    /// Provide a LIFO buffer for each (Author, MessageType) key
    pub mempool_sync_message: diem_channel::Receiver<
        (NodeId, Discriminant<MempoolSyncMsg>),
        (NodeId, MempoolSyncMsg),
    >,
    pub network_events: diem_channel::Receiver<
        (NodeId, Discriminant<NetworkEvent>),
        (NodeId, NetworkEvent),
    >,
}

pub struct NetworkTask {
    pub mempool_sync_message_tx: diem_channel::Sender<
        (NodeId, Discriminant<MempoolSyncMsg>),
        (NodeId, MempoolSyncMsg),
    >,
    pub network_events_tx: diem_channel::Sender<
        (NodeId, Discriminant<NetworkEvent>),
        (NodeId, NetworkEvent),
    >,
}

impl NetworkTask {
    /// Establishes the initial connections with the peers and returns the
    /// receivers.
    pub fn new() -> (NetworkTask, NetworkReceivers) {
        let (mempool_sync_message_tx, mempool_sync_message) = diem_channel::new(
            QueueStyle::LIFO,
            1,
            None, //Some(&counters::CONSENSUS_CHANNEL_MSGS),
        );
        let (network_events_tx, network_events) = diem_channel::new(
            QueueStyle::LIFO,
            1,
            None, //Some(&counters::CONSENSUS_CHANNEL_MSGS),
        );
        (
            NetworkTask {
                mempool_sync_message_tx,
                network_events_tx,
            },
            NetworkReceivers {
                mempool_sync_message,
                network_events,
            },
        )
    }
}
