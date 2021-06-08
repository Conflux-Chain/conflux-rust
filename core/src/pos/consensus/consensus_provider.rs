// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    counters, epoch_manager::EpochManager, network::NetworkTask,
    network_interface::ConsensusNetworkSender,
    persistent_liveness_storage::StorageWriteProxy,
    state_computer::ExecutionProxy, txn_manager::MempoolProxy,
    util::time_service::ClockTimeService,
};
use crate::{
    pos::{
        pow_handler::PowHandler,
        protocol::sync_protocol::HotStuffSynchronizationProtocol,
    },
    sync::ProtocolConfiguration,
};
use cfx_types::H256;
use channel::diem_channel;
use diem_config::config::NodeConfig;
use diem_logger::prelude::*;
use diem_types::{
    account_address::AccountAddress, on_chain_config::OnChainConfigPayload,
};
use executor::{vm::FakeVM, Executor};
use executor_types::BlockExecutor;
use network::NetworkService;
use state_sync::client::StateSyncClient;
use std::sync::Arc;
use storage_interface::{DbReader, DbReaderWriter};
use tokio::runtime::{self, Runtime};

/// Helper function to start consensus based on configuration and return the
/// runtime
pub fn start_consensus(
    node_config: &NodeConfig, network: Arc<NetworkService>,
    own_node_hash: H256, protocol_config: ProtocolConfiguration,
    state_sync_client: StateSyncClient, diem_db: Arc<dyn DbReader>,
    db_rw: DbReaderWriter,
    reconfig_events: diem_channel::Receiver<(), OnChainConfigPayload>,
    author: AccountAddress,
) -> (Runtime, Arc<PowHandler>)
{
    let runtime = runtime::Builder::new()
        .basic_scheduler()
        .thread_name("consensus")
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime!");
    let storage = Arc::new(StorageWriteProxy::new(node_config, diem_db));
    let txn_manager = Arc::new(MempoolProxy::new(
        node_config.consensus.mempool_poll_count,
        node_config.consensus.mempool_txn_pull_timeout_ms,
        node_config.consensus.mempool_executed_txn_timeout_ms,
    ));
    let executor = Box::new(Executor::<FakeVM>::new(db_rw));
    let state_computer =
        Arc::new(ExecutionProxy::new(executor, state_sync_client));
    let time_service =
        Arc::new(ClockTimeService::new(runtime.handle().clone()));

    let (network_task, network_receiver) = NetworkTask::new();
    let protocol_handler = Arc::new(HotStuffSynchronizationProtocol::new(
        own_node_hash,
        network_task,
        protocol_config,
    ));
    protocol_handler.clone().register(network.clone()).unwrap();
    network.start_network_poll().unwrap();
    let network_sender = ConsensusNetworkSender {
        network,
        protocol_handler,
    };

    let (timeout_sender, timeout_receiver) =
        channel::new(1_024, &counters::PENDING_ROUND_TIMEOUTS);
    let pow_handler = Arc::new(PowHandler::new(runtime.handle().clone()));

    let epoch_mgr = EpochManager::new(
        node_config,
        time_service,
        network_sender,
        timeout_sender,
        txn_manager,
        state_computer,
        storage,
        reconfig_events,
        pow_handler.clone(),
        author,
    );

    runtime.spawn(epoch_mgr.start(timeout_receiver, network_receiver));

    diem_debug!("Consensus started.");
    (runtime, pow_handler)
}
