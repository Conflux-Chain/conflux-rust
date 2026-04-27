// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Tasks that are executed by coordinators (short-lived compared to
//! coordinators)

use crate::pos::mempool::{
    core_mempool::{CoreMempool, TimelineState, TxnPointer},
    logging::{LogEntry, LogEvent, LogSchema},
    network::MempoolSyncMsg,
    shared_mempool::types::{
        notify_subscribers, ScheduledBroadcast, SharedMempool,
        SharedMempoolNotification, SubmissionStatusBundle,
    },
    CommitNotification, CommitResponse, CommittedTransaction, ConsensusRequest,
    ConsensusResponse, SubmissionStatus,
};
use anyhow::Result;
use cached_pos_ledger_db::CachedPosLedgerDB;
use diem_logger::prelude::*;
use diem_types::{
    mempool_status::{MempoolStatus, MempoolStatusCode},
    transaction::SignedTransaction,
};
use futures::{channel::oneshot, stream::FuturesUnordered};
use network::node_table::NodeId;
use parking_lot::Mutex;
use rayon::prelude::*;
use std::{
    cmp,
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::runtime::Handle;

// ============================== //
//  broadcast_coordinator tasks  //
// ============================== //

/// Attempts broadcast to `peer` and schedules the next broadcast.
pub(crate) fn execute_broadcast(
    peer: NodeId, backoff: bool, smp: &mut SharedMempool,
    scheduled_broadcasts: &mut FuturesUnordered<ScheduledBroadcast>,
    broadcasting_peers: &mut HashSet<NodeId>, executor: Handle,
) {
    diem_trace!("execute_broadcast starts: peer={}", peer);
    let peer_manager = &smp.peer_manager.clone();
    peer_manager.execute_broadcast(peer.clone(), backoff, smp);
    let schedule_backoff = peer_manager.is_backoff_mode(&peer);

    let interval_ms = if schedule_backoff {
        smp.config.shared_mempool_backoff_interval_ms
    } else {
        smp.config.shared_mempool_tick_interval_ms
    };

    if peer_manager.contains_peer(&peer) {
        // Make sure we only has one broadcast task for one peer id.
        broadcasting_peers.insert(peer);
        scheduled_broadcasts.push(ScheduledBroadcast::new(
            Instant::now() + Duration::from_millis(interval_ms),
            peer,
            schedule_backoff,
            executor,
        ));
    } else {
        // The peer has been disconnected,
        // so it can be added again after reconnection.
        broadcasting_peers.remove(&peer);
    }
    diem_trace!("execute_broadcast end: peer={}", peer);
}

// =============================== //
// Tasks processing txn submission //
// =============================== //

/// Processes transactions directly submitted by client.
pub(crate) async fn process_client_transaction_submission(
    smp: SharedMempool, transaction: SignedTransaction,
    callback: oneshot::Sender<Result<SubmissionStatus>>,
) {
    let statuses = process_incoming_transactions(
        &smp,
        vec![transaction],
        TimelineState::NotReady,
    )
    .await;
    log_txn_process_results(&statuses, None);

    if let Some(status) = statuses.get(0) {
        if callback.send(Ok(status.1.clone())).is_err() {
            diem_error!(LogSchema::event_log(
                LogEntry::JsonRpc,
                LogEvent::CallbackFail
            ));
        }
    }
}

/// Processes transactions from other nodes.
pub(crate) async fn process_transaction_broadcast(
    smp: SharedMempool, transactions: Vec<SignedTransaction>,
    request_id: Vec<u8>, timeline_state: TimelineState, peer: NodeId,
) {
    diem_trace!("process_transaction_broadcast starts: peer={}", peer);
    let results = process_incoming_transactions(
        &smp,
        transactions.clone(),
        timeline_state,
    )
    .await;
    log_txn_process_results(&results, Some(peer.clone()));

    let ack_response = gen_ack_response(request_id, results, &peer);
    if let Err(e) = smp
        .network_sender
        .send_message_with_peer_id(&peer, &ack_response)
    {
        diem_error!(LogSchema::event_log(
            LogEntry::BroadcastACK,
            LogEvent::NetworkSendFail
        )
        .error(&e.into()));
        return;
    }
    notify_subscribers(SharedMempoolNotification::ACK, &smp.subscribers);
    diem_trace!("process_transaction_broadcast ends: peer={}", peer);
}

fn gen_ack_response(
    request_id: Vec<u8>, results: Vec<SubmissionStatusBundle>, peer: &NodeId,
) -> MempoolSyncMsg {
    let mut backoff = false;
    let mut retry = false;
    for r in results.into_iter() {
        let submission_status = r.1;
        if submission_status.0.code == MempoolStatusCode::MempoolIsFull {
            backoff = true;
        }
        if is_txn_retryable(submission_status) {
            retry = true;
        }

        if backoff && retry {
            break;
        }
    }

    diem_trace!(
        "request[{:?}] from peer[{:?}] retry[{:?}]",
        request_id,
        peer,
        retry
    );

    MempoolSyncMsg::BroadcastTransactionsResponse {
        request_id,
        retry,
        backoff,
    }
}

fn is_txn_retryable(result: SubmissionStatus) -> bool {
    result.0.code == MempoolStatusCode::MempoolIsFull
}

/// Submits a list of SignedTransaction to the local mempool
/// and returns a vector containing AdmissionControlStatus.
pub(crate) async fn process_incoming_transactions(
    smp: &SharedMempool, transactions: Vec<SignedTransaction>,
    timeline_state: TimelineState,
) -> Vec<SubmissionStatusBundle> {
    let mut statuses = vec![];

    // Filter out already received transactions, so we do not need to process
    // them.
    let transactions: Vec<SignedTransaction> = {
        let mempool = smp.mempool.lock();
        transactions
            .into_iter()
            .filter(|tx| mempool.transactions.get(&tx.hash()).is_none())
            .collect()
    };
    let validation_results = transactions
        .par_iter()
        .map(|t| {
            smp.validator
                .read()
                .validate_transaction(&t, smp.commited_pos_state.clone())
        })
        .collect::<Vec<_>>();

    {
        let mut mempool = smp.mempool.lock();
        for (idx, transaction) in transactions.into_iter().enumerate() {
            match validation_results[idx] {
                None => {
                    let mempool_status =
                        mempool.add_txn(transaction.clone(), timeline_state);
                    statuses.push((transaction, (mempool_status, None)));
                }
                Some(validation_status) => {
                    statuses.push((
                        transaction,
                        (
                            MempoolStatus::new(MempoolStatusCode::VmError),
                            Some(validation_status),
                        ),
                    ));
                }
            }
        }
    }
    notify_subscribers(
        SharedMempoolNotification::NewTransactions,
        &smp.subscribers,
    );
    statuses
}

fn log_txn_process_results(
    results: &[SubmissionStatusBundle], sender: Option<NodeId>,
) {
    let sender = match sender {
        Some(peer) => peer,
        None => {
            return;
        }
    };
    for (txn, (_mempool_status, maybe_vm_status)) in results.iter() {
        if let Some(vm_status) = maybe_vm_status {
            diem_trace!(
                SecurityEvent::InvalidTransactionMempool,
                failed_transaction = txn,
                vm_status = vm_status,
                sender = sender,
            );
        }
    }
}

// ================================= //
// intra-node communication handlers //
// ================================= //

pub(crate) async fn process_committed_transactions(
    mempool: Arc<Mutex<CoreMempool>>, req: CommitNotification,
) {
    diem_debug!(LogSchema::event_log(
        LogEntry::StateSyncCommit,
        LogEvent::Received
    )
    .state_sync_msg(&req));
    commit_txns(&mempool, req.transactions, req.block_timestamp_usecs).await;
    if req.callback.send(Ok(CommitResponse::success())).is_err() {
        diem_error!(LogSchema::event_log(
            LogEntry::StateSyncCommit,
            LogEvent::CallbackFail
        ));
    }
}

pub(crate) async fn process_consensus_request(
    db: Arc<CachedPosLedgerDB>, mempool: &Mutex<CoreMempool>,
    req: ConsensusRequest,
) {
    diem_debug!(
        LogSchema::event_log(LogEntry::Consensus, LogEvent::Received)
            .consensus_msg(&req)
    );

    let ConsensusRequest {
        max_block_size,
        exclude_txns,
        parent_block_id,
        validators,
        callback,
    } = req;
    let exclude_transactions: HashSet<TxnPointer> = exclude_txns
        .iter()
        .map(|txn| (txn.sender, txn.hash))
        .collect();
    let mut txns;
    {
        let mut mempool = mempool.lock();
        // gc before pulling block as extra protection against txns that
        // may expire in consensus Note: this gc
        // operation relies on the fact that consensus uses the system
        // time to determine block timestamp
        let curr_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time is before UNIX_EPOCH");
        mempool.gc_by_expiration_time(curr_time);
        let block_size = cmp::max(max_block_size, 1);
        let pos_state = db
            .get_pos_state(&parent_block_id)
            .expect("pos_state should exist");
        txns = mempool.get_block(
            block_size,
            exclude_transactions,
            &pos_state,
            validators,
        );
    }
    let pulled_block = txns.drain(..).map(SignedTransaction::into).collect();
    let resp = ConsensusResponse { txns: pulled_block };
    if callback.send(Ok(resp)).is_err() {
        diem_error!(LogSchema::event_log(
            LogEntry::Consensus,
            LogEvent::CallbackFail
        ));
    }
}

async fn commit_txns(
    mempool: &Mutex<CoreMempool>, transactions: Vec<CommittedTransaction>,
    block_timestamp_usecs: u64,
) {
    let mut pool = mempool.lock();

    for transaction in transactions {
        pool.remove_transaction(transaction.hash);
    }

    if block_timestamp_usecs > 0 {
        pool.gc_by_expiration_time(Duration::from_micros(
            block_timestamp_usecs,
        ));
    }
}
