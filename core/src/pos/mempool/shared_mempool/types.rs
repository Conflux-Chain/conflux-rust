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
use channel::diem_channel::Receiver;
use diem_config::config::MempoolConfig;
use diem_crypto::HashValue;
use diem_infallible::{Mutex, RwLock};
use diem_types::{
    account_address::AccountAddress,
    mempool_status::MempoolStatus,
    on_chain_config::{
        ConfigID, DiemVersion, OnChainConfig, OnChainConfigPayload, VMConfig,
    },
    term_state::PosState,
    transaction::SignedTransaction,
    validator_verifier::ValidatorVerifier,
    vm_status::DiscardedVMStatus,
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
use std::{fmt, pin::Pin, sync::Arc, task::Waker, time::Instant};
use subscription_service::ReconfigSubscription;
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

/// Message sent from consensus to mempool.
pub enum ConsensusRequest {
    /// Request to pull block to submit to consensus.
    GetBlockRequest(
        // max block size
        u64,
        // transactions to exclude from requested block
        Vec<TransactionExclusion>,
        // parent block id
        HashValue,
        // current validators
        ValidatorVerifier,
        oneshot::Sender<Result<ConsensusResponse>>,
    ),
    /// Notifications about *rejected* committed txns.
    RejectNotification(
        Vec<CommittedTransaction>,
        oneshot::Sender<Result<ConsensusResponse>>,
    ),
}

impl fmt::Display for ConsensusRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let payload = match self {
            ConsensusRequest::GetBlockRequest(
                block_size,
                excluded_txns,
                parent_block_id,
                _,
                _,
            ) => {
                let mut txns_str = "".to_string();
                for tx in excluded_txns.iter() {
                    txns_str += &format!("{} ", tx);
                }
                format!(
                    "GetBlockRequest [block_size: {}, excluded_txns: {}, parent_block_id: {}]",
                    block_size, txns_str, parent_block_id
                )
            }
            ConsensusRequest::RejectNotification(rejected_txns, _) => {
                let mut txns_str = "".to_string();
                for tx in rejected_txns.iter() {
                    txns_str += &format!("{} ", tx);
                }
                format!("RejectNotification [rejected_txns: {}]", txns_str)
            }
        };
        write!(f, "{}", payload)
    }
}

/// Response sent from mempool to consensus.
pub enum ConsensusResponse {
    /// Block to submit to consensus
    GetBlockResponse(Vec<SignedTransaction>),
    CommitResponse(),
}

/// Notification from state sync to mempool of commit event.
/// This notifies mempool to remove committed txns.
pub struct CommitNotification {
    pub transactions: Vec<CommittedTransaction>,
    /// Timestamp of committed block.
    pub block_timestamp_usecs: u64,
    pub callback: oneshot::Sender<Result<CommitResponse>>,
}

impl fmt::Display for CommitNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut txns = "".to_string();
        for txn in self.transactions.iter() {
            txns += &format!("{} ", txn);
        }
        write!(
            f,
            "CommitNotification [block_timestamp_usecs: {}, txns: {}]",
            self.block_timestamp_usecs, txns
        )
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

const MEMPOOL_SUBSCRIBED_CONFIGS: &[ConfigID] =
    &[DiemVersion::CONFIG_ID, VMConfig::CONFIG_ID];

pub fn gen_mempool_reconfig_subscription(
) -> (ReconfigSubscription, Receiver<(), OnChainConfigPayload>) {
    ReconfigSubscription::subscribe_all(
        "mempool",
        MEMPOOL_SUBSCRIBED_CONFIGS.to_vec(),
        vec![],
    )
}
