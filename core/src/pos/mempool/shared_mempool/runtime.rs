// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::pos::{
    mempool::{
        core_mempool::CoreMempool,
        network::NetworkReceivers,
        shared_mempool::{
            coordinator::{coordinator, gc_coordinator},
            peer_manager::PeerManager,
            transaction_validator::TransactionValidator,
            types::{SharedMempool, SharedMempoolNotification},
        },
        CommitNotification, ConsensusRequest, SubmissionStatus,
    },
    protocol::network_sender::NetworkSender,
};
use anyhow::Result;
use cached_pos_ledger_db::CachedPosLedgerDB;
use channel::diem_channel;
use diem_config::config::NodeConfig;
use diem_infallible::{Mutex, RwLock};
use diem_types::{
    on_chain_config::OnChainConfigPayload, transaction::SignedTransaction,
};
use futures::channel::{
    mpsc::{self, Receiver, UnboundedSender},
    oneshot,
};
use std::sync::Arc;
use tokio::runtime::{Builder, Handle, Runtime};

/// Bootstrap of SharedMempool.
/// Creates a separate Tokio Runtime that runs the following routines:
///   - outbound_sync_task (task that periodically broadcasts transactions to
///     peers).
///   - inbound_network_task (task that handles inbound mempool messages and
///     network events).
///   - gc_task (task that performs GC of all expired transactions by
///     SystemTTL).
pub(crate) fn start_shared_mempool(
    executor: &Handle, config: &NodeConfig, mempool: Arc<Mutex<CoreMempool>>,
    network_sender: NetworkSender, network_receivers: NetworkReceivers,
    client_events: mpsc::Receiver<(
        SignedTransaction,
        oneshot::Sender<Result<SubmissionStatus>>,
    )>,
    consensus_requests: mpsc::Receiver<ConsensusRequest>,
    state_sync_requests: mpsc::Receiver<CommitNotification>,
    mempool_reconfig_events: diem_channel::Receiver<(), OnChainConfigPayload>,
    db_with_cache: Arc<CachedPosLedgerDB>,
    validator: Arc<RwLock<TransactionValidator>>,
    subscribers: Vec<UnboundedSender<SharedMempoolNotification>>,
) {
    let peer_manager =
        Arc::new(PeerManager::new(config.base.role, config.mempool.clone()));

    let smp = SharedMempool {
        mempool: mempool.clone(),
        config: config.mempool.clone(),
        network_sender,
        db_with_cache: db_with_cache.clone(),
        validator,
        peer_manager,
        subscribers,
        commited_pos_state: db_with_cache.db.reader.get_latest_pos_state(),
    };

    executor.spawn(coordinator(
        smp,
        executor.clone(),
        network_receivers,
        client_events,
        consensus_requests,
        state_sync_requests,
        mempool_reconfig_events,
    ));

    executor.spawn(gc_coordinator(
        mempool.clone(),
        config.mempool.system_transaction_gc_interval_ms,
    ));
}

pub fn bootstrap(
    config: &NodeConfig, db_with_cache: Arc<CachedPosLedgerDB>,
    network_sender: NetworkSender, network_receivers: NetworkReceivers,
    client_events: Receiver<(
        SignedTransaction,
        oneshot::Sender<Result<SubmissionStatus>>,
    )>,
    consensus_requests: Receiver<ConsensusRequest>,
    state_sync_requests: Receiver<CommitNotification>,
    mempool_reconfig_events: diem_channel::Receiver<(), OnChainConfigPayload>,
) -> Runtime {
    let runtime = Builder::new_multi_thread()
        .thread_name("shared-mem")
        .enable_all()
        .build()
        .expect("[shared mempool] failed to create runtime");
    let mempool = Arc::new(Mutex::new(CoreMempool::new(&config)));
    let validator = Arc::new(RwLock::new(TransactionValidator::new()));
    start_shared_mempool(
        runtime.handle(),
        config,
        mempool,
        network_sender,
        network_receivers,
        client_events,
        consensus_requests,
        state_sync_requests,
        mempool_reconfig_events,
        db_with_cache,
        validator,
        vec![],
    );
    runtime
}
