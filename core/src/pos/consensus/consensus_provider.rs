// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    counters, epoch_manager::EpochManager, network::NetworkReceivers,
    persistent_liveness_storage::StorageWriteProxy,
    state_computer::ExecutionProxy, txn_manager::MempoolProxy,
    util::time_service::ClockTimeService,
};
use crate::pos::{
    consensus::consensusdb::ConsensusDB,
    mempool::{ConsensusRequest, SubmissionStatus},
    pow_handler::PowHandler,
    protocol::network_sender::NetworkSender,
    state_sync::client::StateSyncClient,
};
use channel::diem_channel;
use diem_config::config::NodeConfig;
use diem_logger::prelude::*;
use diem_types::{
    account_address::AccountAddress, on_chain_config::OnChainConfigPayload,
    transaction::SignedTransaction,
};
use executor::{vm::FakeVM, Executor};
use futures::channel::{mpsc, oneshot};
use std::sync::{atomic::AtomicBool, Arc};
use storage_interface::{DbReader, DbReaderWriter};
use tokio::runtime::{self, Runtime};

/// Helper function to start consensus based on configuration and return the
/// runtime
pub fn start_consensus(
    node_config: &NodeConfig, network_sender: NetworkSender,
    network_receiver: NetworkReceivers,
    consensus_to_mempool_sender: mpsc::Sender<ConsensusRequest>,
    state_sync_client: StateSyncClient, diem_db: Arc<dyn DbReader>,
    db_rw: DbReaderWriter,
    reconfig_events: diem_channel::Receiver<(), OnChainConfigPayload>,
    author: AccountAddress,
    tx_sender: mpsc::Sender<(
        SignedTransaction,
        oneshot::Sender<anyhow::Result<SubmissionStatus>>,
    )>,
) -> (Runtime, Arc<PowHandler>, Arc<AtomicBool>, Arc<ConsensusDB>)
{
    let stopped = Arc::new(AtomicBool::new(false));
    let runtime = runtime::Builder::new_multi_thread()
        .thread_name("consensus")
        .enable_all()
        // TODO(lpl): This is for debugging.
        .worker_threads(4)
        .build()
        .expect("Failed to create Tokio runtime!");
    let storage = Arc::new(StorageWriteProxy::new(node_config, diem_db));
    let consensus_db = storage.consensus_db();
    let txn_manager = Arc::new(MempoolProxy::new(
        consensus_to_mempool_sender,
        node_config.consensus.mempool_poll_count,
        node_config.consensus.mempool_txn_pull_timeout_ms,
        node_config.consensus.mempool_executed_txn_timeout_ms,
    ));
    let pow_handler = Arc::new(PowHandler::new(runtime.handle().clone()));
    let executor =
        Box::new(Executor::<FakeVM>::new(db_rw, pow_handler.clone()));
    let state_computer =
        Arc::new(ExecutionProxy::new(executor, state_sync_client));
    let time_service =
        Arc::new(ClockTimeService::new(runtime.handle().clone()));

    let (timeout_sender, timeout_receiver) =
        channel::new(1_024, &counters::PENDING_ROUND_TIMEOUTS);
    let (proposal_timeout_sender, proposal_timeout_receiver) =
        channel::new(1_024, &counters::PENDING_PROPOSAL_TIMEOUTS);

    let epoch_mgr = EpochManager::new(
        node_config,
        time_service,
        network_sender,
        timeout_sender,
        proposal_timeout_sender,
        txn_manager,
        state_computer,
        storage,
        reconfig_events,
        pow_handler.clone(),
        author,
        tx_sender,
    );

    runtime.spawn(epoch_mgr.start(
        timeout_receiver,
        proposal_timeout_receiver,
        network_receiver,
        stopped.clone(),
    ));

    diem_debug!("Consensus started.");
    (runtime, pow_handler, stopped, consensus_db)
}
