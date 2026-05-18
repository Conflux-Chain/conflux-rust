// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Processes that are directly spawned by shared mempool runtime initialization

use crate::pos::{
    mempool::{
        core_mempool::{CoreMempool, TimelineState},
        logging::{LogEntry, LogEvent, LogSchema},
        network::{MempoolSyncMsg, NetworkReceivers},
        shared_mempool::{tasks, types::SharedMempool},
        CommitNotification, ConsensusRequest, SubmissionStatus,
    },
    protocol::network_event::NetworkEvent,
};
use anyhow::Result;
use bounded_executor::BoundedExecutor;
use diem_logger::prelude::*;
use diem_types::{
    mempool_status::MempoolStatus, transaction::SignedTransaction,
    vm_status::DiscardedVMStatus,
};
use futures::{
    channel::{mpsc, oneshot},
    stream::FuturesUnordered,
    StreamExt,
};
use network::node_table::NodeId;
use parking_lot::Mutex;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::{runtime::Handle, time::interval};
use tokio_stream::wrappers::IntervalStream;

/// Coordinator that handles inbound network events and outbound txn broadcasts.
pub(crate) async fn coordinator(
    mut smp: SharedMempool, executor: Handle,
    mut network_receivers: NetworkReceivers,
    mut client_events: mpsc::Receiver<(
        SignedTransaction,
        oneshot::Sender<Result<SubmissionStatus>>,
    )>,
    mut consensus_requests: mpsc::Receiver<ConsensusRequest>,
    mut commit_notifications: mpsc::Receiver<CommitNotification>,
) {
    diem_info!(LogSchema::event_log(
        LogEntry::CoordinatorRuntime,
        LogEvent::Start
    ));
    let mut scheduled_broadcasts = FuturesUnordered::new();
    let mut broadcasting_peers = HashSet::new();

    // Use a BoundedExecutor to restrict only `workers_available` concurrent
    // worker tasks that can process incoming transactions.
    let workers_available =
        smp.config.shared_mempool_max_concurrent_inbound_syncs;
    let bounded_executor =
        BoundedExecutor::new(workers_available, executor.clone());

    loop {
        ::futures::select! {
            (msg, callback) = client_events.select_next_some() => {
                handle_client_event(&mut smp, &bounded_executor, msg, callback).await;
            },
            msg = consensus_requests.select_next_some() => {
                tasks::process_consensus_request(smp.db_with_cache.clone(), &smp.mempool, msg).await;
            }
            msg = commit_notifications.select_next_some() => {
                handle_commit_notification(&mut smp, msg);
            }
            (peer, backoff) = scheduled_broadcasts.select_next_some() => {
                // diem_debug!("scheduled_broadcasts");
                tasks::execute_broadcast(peer, backoff, &mut smp, &mut scheduled_broadcasts, &mut broadcasting_peers, executor.clone());
            },
            (peer, event) = network_receivers.network_events.select_next_some() => {
                diem_debug!("network_events to scheduled_broadcasts");
                match event {
                        NetworkEvent::PeerConnected => {
                        if smp.peer_manager.add_peer(peer) && !broadcasting_peers.contains(&peer) {
                            // Only spawn tx broadcast for new peers.
                            tasks::execute_broadcast(peer, true, &mut smp, &mut scheduled_broadcasts,&mut broadcasting_peers, executor.clone());
                        }
                    }
                    NetworkEvent::PeerDisconnected => {
                        smp.peer_manager.disable_peer(peer);
                    }
                }
            },
            (peer, msg) = network_receivers.mempool_sync_message.select_next_some() => {
                diem_debug!("receive mempool_sync_message");
                handle_mempool_sync_msg(&bounded_executor, &mut smp, peer, msg).await;
            }
            complete => break,
        }
    }
    diem_error!(LogSchema::event_log(
        LogEntry::CoordinatorRuntime,
        LogEvent::Terminated
    ));
}

async fn handle_client_event(
    smp: &mut SharedMempool, bounded_executor: &BoundedExecutor,
    msg: SignedTransaction,
    callback: oneshot::Sender<
        anyhow::Result<(MempoolStatus, Option<DiscardedVMStatus>)>,
    >,
) {
    diem_debug!("handle_client_event");
    bounded_executor
        .spawn(tasks::process_client_transaction_submission(
            smp.clone(),
            msg,
            callback,
        ))
        .await;
}

fn handle_commit_notification(
    smp: &mut SharedMempool, msg: CommitNotification,
) {
    smp.update_pos_state();
    tokio::spawn(tasks::process_committed_transactions(
        smp.mempool.clone(),
        msg,
    ));
}

async fn handle_mempool_sync_msg(
    bounded_executor: &BoundedExecutor, smp: &mut SharedMempool, peer: NodeId,
    msg: MempoolSyncMsg,
) {
    match msg {
        MempoolSyncMsg::BroadcastTransactionsRequest {
            request_id,
            transactions,
        } => {
            let smp_clone = smp.clone();
            let timeline_state = TimelineState::NonQualified;
            bounded_executor
                .spawn(tasks::process_transaction_broadcast(
                    smp_clone,
                    transactions,
                    request_id,
                    timeline_state,
                    peer,
                ))
                .await;
        }
        MempoolSyncMsg::BroadcastTransactionsResponse {
            request_id,
            retry,
            backoff,
        } => {
            smp.peer_manager
                .process_broadcast_ack(peer, request_id, retry, backoff);
        }
    }
}

/// Garbage collect all expired transactions by SystemTTL.
pub(crate) async fn gc_coordinator(
    mempool: Arc<Mutex<CoreMempool>>, gc_interval_ms: u64,
) {
    diem_info!(LogSchema::event_log(LogEntry::GCRuntime, LogEvent::Start));
    let mut interval =
        IntervalStream::new(interval(Duration::from_millis(gc_interval_ms)));
    while let Some(_interval) = interval.next().await {
        diem_sample!(
            SampleRate::Duration(Duration::from_secs(60)),
            diem_info!(LogSchema::event_log(
                LogEntry::GCRuntime,
                LogEvent::Live
            ))
        );
        mempool.lock().gc();
    }

    diem_error!(LogSchema::event_log(
        LogEntry::GCRuntime,
        LogEvent::Terminated
    ));
}
