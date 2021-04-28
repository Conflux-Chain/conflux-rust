// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    counters,
    epoch_manager::EpochManager,
    network::NetworkTask,
    network_interface::{ConsensusNetworkSender},
    persistent_liveness_storage::StorageWriteProxy,
    state_computer::ExecutionProxy,
    txn_manager::MempoolProxy,
    util::time_service::ClockTimeService,
};
use channel::diem_channel;
use diem_config::config::NodeConfig;
use diem_logger::prelude::*;
//use diem_mempool::ConsensusRequest;
use diem_types::on_chain_config::OnChainConfigPayload;
//use execution_correctness::ExecutionCorrectnessManager;
use futures::channel::mpsc;
//use state_sync::client::StateSyncClient;
use std::sync::Arc;
use storage_interface::DbReader;
use tokio::runtime::{self, Runtime};
use crate::pos::consensus::executor::Executor;

/// Helper function to start consensus based on configuration and return the
/// runtime
pub fn start_consensus(
    node_config: &NodeConfig, network_sender: ConsensusNetworkSender,
    //network_events: ConsensusNetworkEvents,
    //state_sync_client: StateSyncClient,
    //consensus_to_mempool_sender: mpsc::Sender<ConsensusRequest>,
    diem_db: Arc<dyn DbReader>,
    executor: Arc<Executor>,
    reconfig_events: diem_channel::Receiver<(), OnChainConfigPayload>,
) -> Runtime
{
    let runtime = runtime::Builder::new()
        .thread_name("consensus")
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime!");
    let storage = Arc::new(StorageWriteProxy::new(node_config, diem_db));
    let txn_manager = Arc::new(MempoolProxy::new(
        //consensus_to_mempool_sender,
        node_config.consensus.mempool_poll_count,
        node_config.consensus.mempool_txn_pull_timeout_ms,
        node_config.consensus.mempool_executed_txn_timeout_ms,
    ));
    //let execution_correctness_manager =
    //    ExecutionCorrectnessManager::new(node_config);
    let state_computer = Arc::new(ExecutionProxy::new(
        executor
        //execution_correctness_manager.client(),
        //state_sync_client,
    ));
    let time_service =
        Arc::new(ClockTimeService::new(runtime.handle().clone()));

    let (timeout_sender, timeout_receiver) =
        channel::new(1_024, &counters::PENDING_ROUND_TIMEOUTS);
    //let (self_sender, self_receiver) =
    //    channel::new(1_024, &counters::PENDING_SELF_MESSAGES);

    let epoch_mgr = EpochManager::new(
        node_config,
        time_service,
        //self_sender,
        network_sender,
        timeout_sender,
        txn_manager,
        state_computer,
        storage,
        reconfig_events,
    );

    let (network_task, network_receiver) =
        NetworkTask::new(
            //network_events,
            //self_receiver
        );

    runtime.spawn(network_task.start());
    runtime.spawn(epoch_mgr.start(timeout_receiver, network_receiver));

    diem_debug!("Consensus started.");
    runtime
}
