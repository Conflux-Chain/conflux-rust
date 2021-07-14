// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! Interface between Mempool and Network layers.

use crate::pos::{
    mempool::counters,
    protocol::{
        network_sender::NetworkSender,
        sync_protocol::HotStuffSynchronizationProtocol,
    },
};
use channel::{diem_channel, message_queues::QueueStyle};
use consensus_types::common::Author;
use diem_metrics::IntCounterVec;
use diem_types::transaction::SignedTransaction;
use fail::fail_point;
use network::node_table::NodeId;
use serde::{Deserialize, Serialize};
use std::mem::Discriminant;

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

/// Just a convenience struct to keep all the network proxy receiving queues in
/// one place. Will be returned by the NetworkTask upon startup.
pub struct NetworkReceivers {
    /// Provide a LIFO buffer for each (Author, MessageType) key
    pub mempool_sync_message: diem_channel::Receiver<
        (NodeId, Discriminant<MempoolSyncMsg>),
        (NodeId, MempoolSyncMsg),
    >,
}

pub struct NetworkTask {
    pub mempool_sync_message_tx: diem_channel::Sender<
        (NodeId, Discriminant<MempoolSyncMsg>),
        (NodeId, MempoolSyncMsg),
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
        (
            NetworkTask {
                mempool_sync_message_tx,
            },
            NetworkReceivers {
                mempool_sync_message,
            },
        )
    }
}
