// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Processes that are directly spawned by shared mempool runtime initialization

use crate::pos::{
    mempool::{
        core_mempool::{CoreMempool, TimelineState},
        counters,
        logging::{LogEntry, LogEvent, LogSchema},
        network::{MempoolSyncMsg, NetworkReceivers},
        shared_mempool::{tasks, types::SharedMempool},
        CommitNotification, ConsensusRequest, SubmissionStatus,
    },
    protocol::network_event::NetworkEvent,
};
use anyhow::Result;
use bounded_executor::BoundedExecutor;
use channel::diem_channel;
use diem_infallible::Mutex;
use diem_logger::prelude::*;
use diem_types::{
    mempool_status::MempoolStatus, on_chain_config::OnChainConfigPayload,
    transaction::SignedTransaction, vm_status::DiscardedVMStatus,
};
use futures::{
    channel::{mpsc, oneshot},
    stream::FuturesUnordered,
    StreamExt,
};
use network::node_table::NodeId;
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, SystemTime},
};
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
    mut state_sync_requests: mpsc::Receiver<CommitNotification>,
    mut mempool_reconfig_events: diem_channel::Receiver<
        (),
        OnChainConfigPayload,
    >,
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
        let _timer = counters::MAIN_LOOP.start_timer();
        ::futures::select! {
            (msg, callback) = client_events.select_next_some() => {
                handle_client_event(&mut smp, &bounded_executor, msg, callback).await;
            },
            msg = consensus_requests.select_next_some() => {
                tasks::process_consensus_request(smp.db_with_cache.clone(), &smp.mempool, msg).await;
            }
            msg = state_sync_requests.select_next_some() => {
                handle_state_sync_request(&mut smp, msg);
            }
            config_update = mempool_reconfig_events.select_next_some() => {
                handle_mempool_reconfig_event(&mut smp, &bounded_executor, config_update).await;
            },
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
    // This timer measures how long it took for the bounded executor to
    // *schedule* the task.
    let _timer = counters::task_spawn_latency_timer(
        counters::CLIENT_EVENT_LABEL,
        counters::SPAWN_LABEL,
    );
    // This timer measures how long it took for the task to go from scheduled to
    // started.
    let task_start_timer = counters::task_spawn_latency_timer(
        counters::CLIENT_EVENT_LABEL,
        counters::START_LABEL,
    );
    bounded_executor
        .spawn(tasks::process_client_transaction_submission(
            smp.clone(),
            msg,
            callback,
            task_start_timer,
        ))
        .await;
}

fn handle_state_sync_request(smp: &mut SharedMempool, msg: CommitNotification) {
    let _timer = counters::task_spawn_latency_timer(
        counters::STATE_SYNC_EVENT_LABEL,
        counters::SPAWN_LABEL,
    );
    smp.update_pos_state();
    tokio::spawn(tasks::process_state_sync_request(smp.mempool.clone(), msg));
}

async fn handle_mempool_reconfig_event(
    smp: &mut SharedMempool, bounded_executor: &BoundedExecutor,
    config_update: OnChainConfigPayload,
) {
    diem_info!(LogSchema::event_log(
        LogEntry::ReconfigUpdate,
        LogEvent::Received
    ));
    let _timer = counters::task_spawn_latency_timer(
        counters::RECONFIG_EVENT_LABEL,
        counters::SPAWN_LABEL,
    );

    bounded_executor
        .spawn(tasks::process_config_update(
            config_update,
            smp.validator.clone(),
        ))
        .await;
}

async fn handle_mempool_sync_msg(
    bounded_executor: &BoundedExecutor, smp: &mut SharedMempool, peer: NodeId,
    msg: MempoolSyncMsg,
) {
    counters::shared_mempool_event_inc("message");
    match msg {
        MempoolSyncMsg::BroadcastTransactionsRequest {
            request_id,
            transactions,
        } => {
            let smp_clone = smp.clone();
            let timeline_state = TimelineState::NonQualified;
            /*
            match smp.peer_manager.is_upstream_peer(&peer, None) {
                true => TimelineState::NonQualified,
                false => TimelineState::NotReady,
            };*/
            // This timer measures how long it took for the bounded
            // executor to *schedule* the task.
            let _timer = counters::task_spawn_latency_timer(
                counters::PEER_BROADCAST_EVENT_LABEL,
                counters::SPAWN_LABEL,
            );
            // This timer measures how long it took for the task to go
            // from scheduled to started.
            let task_start_timer = counters::task_spawn_latency_timer(
                counters::PEER_BROADCAST_EVENT_LABEL,
                counters::START_LABEL,
            );
            bounded_executor
                .spawn(tasks::process_transaction_broadcast(
                    smp_clone,
                    transactions,
                    request_id,
                    timeline_state,
                    peer,
                    task_start_timer,
                ))
                .await;
        }
        MempoolSyncMsg::BroadcastTransactionsResponse {
            request_id,
            retry,
            backoff,
        } => {
            let ack_timestamp = SystemTime::now();
            smp.peer_manager.process_broadcast_ack(
                peer,
                request_id,
                retry,
                backoff,
                ack_timestamp,
            );
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
