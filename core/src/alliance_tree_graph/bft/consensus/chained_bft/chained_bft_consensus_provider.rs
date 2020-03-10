// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    chained_bft::{
        chained_bft_smr::{ChainedBftSMR, ChainedBftSMRConfig},
        persistent_storage::{PersistentStorage, StorageWriteProxy},
    },
    consensus_provider::ConsensusProvider,
    state_replication::StateMachineReplication,
};
use anyhow::Result;
//use executor::Executor;
use libra_config::config::NodeConfig;
//use libra_logger::prelude::*;
//use libra_mempool::proto::mempool_client::MempoolClientWrapper;
use libra_types::transaction::SignedTransaction;
//use network::validator_network::{ConsensusNetworkEvents,
// ConsensusNetworkSender};
use super::super::safety_rules::SafetyRulesManagerConfig;
//use state_synchronizer::StateSyncClient;
use super::super::super::executor::Executor;
use crate::{
    alliance_tree_graph::bft::consensus::{
        state_computer::ExecutionProxy,
        state_replication::{StateComputer, TxnTransformerProxy},
    },
    sync::{ProtocolConfiguration, SharedSynchronizationService},
};
use cfx_types::H256;
use network::NetworkService;
use parking_lot::RwLock;
use std::sync::Arc;
use tokio::runtime;
//use vm_runtime::LibraVM;

///  The state necessary to begin state machine replication including
/// ValidatorSet, networking etc.
pub struct InitialSetup {
    //pub network_sender: ConsensusNetworkSender,
    //pub network_events: ConsensusNetworkEvents,
    pub safety_rules_manager_config: Option<SafetyRulesManagerConfig>,
}

/// Supports the implementation of ConsensusProvider using LibraBFT.
pub struct ChainedBftProvider {
    smr: ChainedBftSMR<Vec<SignedTransaction>>,
    txn_transformer: TxnTransformerProxy,
    // The manager for administrator transaction (for epoch change).
    admin_transaction: Arc<RwLock<Option<SignedTransaction>>>,
    state_computer: Arc<dyn StateComputer<Payload = Vec<SignedTransaction>>>,
    tg_sync: SharedSynchronizationService,
}

impl ChainedBftProvider {
    pub fn new(
        node_config: &mut NodeConfig, executor: Arc<Executor>,
        /* synchronizer_client: Arc<StateSyncClient>, */
        tg_sync: SharedSynchronizationService,
    ) -> Self
    {
        let runtime = runtime::Builder::new()
            .thread_name("consensus-")
            .threaded_scheduler()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime!");

        let initial_setup = Self::initialize_setup(node_config);
        let config = ChainedBftSMRConfig::from_node_config(&node_config);
        debug!("[Consensus] My peer: {:?}", config.author);

        let libra_db = executor.get_libra_db();

        let storage =
            Arc::new(StorageWriteProxy::new(node_config, libra_db.clone()));
        let initial_data = storage.start();

        let txn_transformer = TxnTransformerProxy::default();
        let admin_transaction = Arc::new(RwLock::new(None));

        let state_computer = Arc::new(ExecutionProxy::new(
            executor, /* , synchronizer_client.clone()) */
            tg_sync.clone(),
        ));
        let smr = ChainedBftSMR::new(
            initial_setup,
            runtime,
            config,
            storage,
            initial_data,
        );
        Self {
            smr,
            txn_transformer,
            admin_transaction,
            state_computer,
            tg_sync,
        }
    }

    /// Retrieve the initial "state" for consensus. This function is synchronous
    /// and returns after reading the local persistent store and retrieving
    /// the initial state from the executor.
    fn initialize_setup(
        //network_sender: ConsensusNetworkSender,
        //network_events: ConsensusNetworkEvents,
        node_config: &mut NodeConfig,
    ) -> InitialSetup
    {
        InitialSetup {
            //network_sender,
            //network_events,
            safety_rules_manager_config: Some(SafetyRulesManagerConfig::new(
                node_config,
            )),
        }
    }
}

impl ConsensusProvider for ChainedBftProvider {
    fn start(
        &mut self, network: Arc<NetworkService>, own_node_hash: H256,
        protocol_config: ProtocolConfiguration,
    ) -> Result<()>
    {
        debug!("Starting consensus provider.");
        self.smr.start(
            self.txn_transformer.clone(),
            self.state_computer.clone(),
            network,
            own_node_hash,
            protocol_config,
            self.tg_sync.clone(),
            self.admin_transaction.clone(),
        )
    }

    fn stop(&mut self) {
        self.smr.stop();
        debug!("Consensus provider stopped.");
    }

    fn get_executor(&self) -> Arc<Executor> {
        self.state_computer.get_executor()
    }

    fn get_admin_transaction(&self) -> Arc<RwLock<Option<SignedTransaction>>> {
        self.admin_transaction.clone()
    }
}
