// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::sync::{atomic::AtomicBool, Arc};

use futures::channel::{mpsc, oneshot};
use tokio::runtime::{self, Runtime};

use cached_pos_ledger_db::CachedPosLedgerDB;
use channel::diem_channel;
use consensus_types::db::LedgerBlockRW;
use diem_config::config::NodeConfig;
use diem_logger::prelude::*;
use diem_types::{
    account_address::AccountAddress, on_chain_config::OnChainConfigPayload,
    transaction::SignedTransaction,
};
use executor::{vm::PosVM, Executor};
use storage_interface::DbReader;

use crate::pos::{
    mempool::{ConsensusRequest, SubmissionStatus},
    pow_handler::PowHandler,
    protocol::network_sender::NetworkSender,
    state_sync::client::StateSyncClient,
};

use super::{
    counters, epoch_manager::EpochManager, network::NetworkReceivers,
    persistent_liveness_storage::StorageWriteProxy,
    state_computer::ExecutionProxy, txn_manager::MempoolProxy,
    util::time_service::ClockTimeService,
};
use crate::pos::consensus::{ConsensusDB, TestCommand};

/// Helper function to start consensus based on configuration and return the
/// runtime
pub fn start_consensus(
    node_config: &NodeConfig, network_sender: NetworkSender,
    network_receiver: NetworkReceivers,
    consensus_to_mempool_sender: mpsc::Sender<ConsensusRequest>,
    state_sync_client: StateSyncClient, pos_ledger_db: Arc<dyn DbReader>,
    db_with_cache: Arc<CachedPosLedgerDB>,
    reconfig_events: diem_channel::Receiver<(), OnChainConfigPayload>,
    author: AccountAddress,
    tx_sender: mpsc::Sender<(
        SignedTransaction,
        oneshot::Sender<anyhow::Result<SubmissionStatus>>,
    )>,
    test_command_receiver: channel::Receiver<TestCommand>,
    started_as_voter: bool,
) -> (Runtime, Arc<PowHandler>, Arc<AtomicBool>, Arc<ConsensusDB>) {
    let stopped = Arc::new(AtomicBool::new(false));
    let runtime = runtime::Builder::new_multi_thread()
        .thread_name("consensus")
        .enable_all()
        // TODO(lpl): This is for debugging.
        .worker_threads(4)
        .build()
        .expect("Failed to create Tokio runtime!");
    let storage = Arc::new(StorageWriteProxy::new(node_config, pos_ledger_db));
    let consensus_db = storage.consensus_db();
    let txn_manager = Arc::new(MempoolProxy::new(
        consensus_to_mempool_sender,
        node_config.consensus.mempool_poll_count,
        node_config.consensus.mempool_txn_pull_timeout_ms,
        node_config.consensus.mempool_executed_txn_timeout_ms,
    ));
    let pow_handler = Arc::new(PowHandler::new(
        runtime.handle().clone(),
        consensus_db.clone(),
    ));
    let executor = Box::new(Executor::<PosVM>::new(
        db_with_cache,
        pow_handler.clone(),
        consensus_db.clone() as Arc<dyn LedgerBlockRW>,
    ));
    let state_computer =
        Arc::new(ExecutionProxy::new(executor, state_sync_client));
    let time_service =
        Arc::new(ClockTimeService::new(runtime.handle().clone()));

    let (timeout_sender, timeout_receiver) =
        channel::new(1_024, &counters::PENDING_ROUND_TIMEOUTS);
    let (proposal_timeout_sender, proposal_timeout_receiver) =
        channel::new(1_024, &counters::PENDING_PROPOSAL_TIMEOUTS);
    let (new_round_timeout_sender, new_round_timeout_receiver) =
        channel::new(1_024, &counters::PENDING_NEW_ROUND_TIMEOUTS);

    let epoch_mgr = EpochManager::new(
        node_config,
        time_service,
        network_sender,
        timeout_sender,
        proposal_timeout_sender,
        new_round_timeout_sender,
        txn_manager,
        state_computer,
        storage,
        reconfig_events,
        pow_handler.clone(),
        author,
        tx_sender,
        started_as_voter,
    );

    runtime.spawn(epoch_mgr.start(
        timeout_receiver,
        proposal_timeout_receiver,
        new_round_timeout_receiver,
        network_receiver,
        test_command_receiver,
        stopped.clone(),
    ));

    diem_debug!("Consensus started.");
    (runtime, pow_handler, stopped, consensus_db)
}
