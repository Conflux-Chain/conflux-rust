// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Objects used by/related to shared mempool

use crate::pos::{
    mempool::{
        core_mempool::CoreMempool,
        shared_mempool::{
            peer_manager::PeerManager,
            transaction_validator::TransactionValidator,
        },
    },
    protocol::network_sender::NetworkSender,
};
use anyhow::Result;
use cached_pos_ledger_db::CachedPosLedgerDB;
use diem_config::config::MempoolConfig;
use diem_crypto::HashValue;
use diem_types::{
    account_address::AccountAddress, mempool_status::MempoolStatus,
    term_state::PosState, transaction::SignedTransaction,
    validator_verifier::ValidatorVerifier, vm_status::DiscardedVMStatus,
};
use futures::{
    channel::{
        mpsc::{self, UnboundedSender},
        oneshot,
    },
    future::Future,
    task::{Context, Poll},
};
use network::node_table::NodeId;
use parking_lot::{Mutex, RwLock};
use std::{fmt, pin::Pin, sync::Arc, task::Waker, time::Instant};
use tokio::runtime::Handle;

/// Struct that owns all dependencies required by shared mempool routines.
#[derive(Clone)]
pub(crate) struct SharedMempool {
    pub mempool: Arc<Mutex<CoreMempool>>,
    pub config: MempoolConfig,
    pub network_sender: NetworkSender,
    pub db_with_cache: Arc<CachedPosLedgerDB>,
    pub validator: Arc<RwLock<TransactionValidator>>,
    pub peer_manager: Arc<PeerManager>,
    pub subscribers: Vec<UnboundedSender<SharedMempoolNotification>>,
    pub commited_pos_state: Arc<PosState>,
}

impl SharedMempool {
    pub(crate) fn update_pos_state(&mut self) {
        self.commited_pos_state =
            self.db_with_cache.db.reader.get_latest_pos_state();
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SharedMempoolNotification {
    NewTransactions,
    ACK,
    Broadcast,
}

pub(crate) fn notify_subscribers(
    event: SharedMempoolNotification,
    subscribers: &[UnboundedSender<SharedMempoolNotification>],
) {
    for subscriber in subscribers {
        let _ = subscriber.unbounded_send(event);
    }
}

/// A future that represents a scheduled mempool txn broadcast
pub(crate) struct ScheduledBroadcast {
    /// Time of scheduled broadcast
    deadline: Instant,
    peer: NodeId,
    backoff: bool,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl ScheduledBroadcast {
    pub fn new(
        deadline: Instant, peer: NodeId, backoff: bool, executor: Handle,
    ) -> Self {
        let waker: Arc<Mutex<Option<Waker>>> = Arc::new(Mutex::new(None));
        let waker_clone = waker.clone();

        if deadline > Instant::now() {
            let tokio_instant = tokio::time::Instant::from_std(deadline);
            executor.spawn(async move {
                tokio::time::sleep_until(tokio_instant).await;
                let mut waker = waker_clone.lock();
                if let Some(waker) = waker.take() {
                    waker.wake()
                }
            });
        }

        Self {
            deadline,
            peer,
            backoff,
            waker,
        }
    }
}

impl Future for ScheduledBroadcast {
    type Output = (NodeId, bool);

    // (peer, whether this broadcast was scheduled as a backoff broadcast)

    fn poll(self: Pin<&mut Self>, context: &mut Context) -> Poll<Self::Output> {
        if Instant::now() < self.deadline {
            let waker_clone = context.waker().clone();
            let mut waker = self.waker.lock();
            *waker = Some(waker_clone);

            Poll::Pending
        } else {
            Poll::Ready((self.peer.clone(), self.backoff))
        }
    }
}

/// Consensus asking mempool to pull a block to submit to consensus.
pub struct ConsensusRequest {
    pub max_block_size: u64,
    pub exclude_txns: Vec<TransactionExclusion>,
    pub parent_block_id: HashValue,
    pub validators: ValidatorVerifier,
    pub callback: oneshot::Sender<Result<ConsensusResponse>>,
}

impl fmt::Display for ConsensusRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut txns_str = "".to_string();
        for tx in self.exclude_txns.iter() {
            txns_str += &format!("{} ", tx);
        }
        write!(
            f,
            "GetBlockRequest [block_size: {}, excluded_txns: {}, parent_block_id: {}]",
            self.max_block_size, txns_str, self.parent_block_id
        )
    }
}

/// Block of transactions returned from mempool to consensus.
pub struct ConsensusResponse {
    pub txns: Vec<SignedTransaction>,
}

/// Notification from consensus to mempool of commit event.
/// This notifies mempool to remove committed txns.
pub struct CommitNotification {
    pub transactions: Vec<CommittedTransaction>,
    pub callback: oneshot::Sender<Result<CommitResponse>>,
}

impl fmt::Display for CommitNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut txns = "".to_string();
        for txn in self.transactions.iter() {
            txns += &format!("{} ", txn);
        }
        write!(f, "CommitNotification [txns: {}]", txns)
    }
}

#[derive(Debug)]
pub struct CommitResponse {
    pub success: bool,
    /// The error message if `success` is false.
    pub error_message: Option<String>,
}

impl CommitResponse {
    // Returns a new CommitResponse without an error.
    pub fn success() -> Self {
        CommitResponse {
            success: true,
            error_message: None,
        }
    }

    // Returns a new CommitResponse holding the given error message.
    pub fn error(error_message: String) -> Self {
        CommitResponse {
            success: false,
            error_message: Some(error_message),
        }
    }
}

/// Successfully executed and committed txn
pub struct CommittedTransaction {
    pub sender: AccountAddress,
    pub hash: HashValue,
}

impl fmt::Display for CommittedTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.sender, self.hash,)
    }
}

#[derive(Clone)]
pub struct TransactionExclusion {
    pub sender: AccountAddress,
    pub hash: HashValue,
}

impl fmt::Display for TransactionExclusion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.sender, self.hash,)
    }
}

pub type SubmissionStatus = (MempoolStatus, Option<DiscardedVMStatus>);

pub type SubmissionStatusBundle = (SignedTransaction, SubmissionStatus);

pub type MempoolClientSender = mpsc::Sender<(
    SignedTransaction,
    oneshot::Sender<Result<SubmissionStatus>>,
)>;
