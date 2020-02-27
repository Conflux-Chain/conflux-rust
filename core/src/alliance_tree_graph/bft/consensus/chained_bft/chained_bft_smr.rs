// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    chained_bft::{
        block_storage::BlockStore,
        chained_bft_consensus_provider::InitialSetup,
        epoch_manager::EpochManager,
        event_processor::EventProcessor,
        network::{NetworkReceivers, NetworkTask},
        persistent_storage::{PersistentStorage, RecoveryData},
    },
    consensus_types::common::{Author, Payload, Round},
    counters,
    state_replication::StateMachineReplication,
    util::time_service::ClockTimeService,
};
use crate::alliance_tree_graph::hsb_sync_protocol::sync_protocol::HotStuffSynchronizationProtocol;
use anyhow::Result;
use channel;
use futures::{select, stream::StreamExt};
use libra_config::config::{ConsensusProposerType, NodeConfig};
//use libra_logger::prelude::*;
use super::super::safety_rules::SafetyRulesManager;
use crate::{
    alliance_tree_graph::bft::consensus::{
        chained_bft::network::NetworkSender,
        state_replication::{StateComputer, TxnTransformer},
    },
    sync::{ProtocolConfiguration, SharedSynchronizationService},
};
use cfx_types::H256;
use libra_types::crypto_proxies::EpochInfo;
use network::NetworkService;
use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::runtime::{Handle, Runtime};

/// Consensus configuration derived from ConsensusConfig
pub struct ChainedBftSMRConfig {
    /// Keep up to this number of committed blocks before cleaning them up from
    /// the block store.
    pub max_pruned_blocks_in_mem: usize,
    /// Initial timeout for pacemaker
    pub pacemaker_initial_timeout: Duration,
    /// Consensus proposer type
    pub proposer_type: ConsensusProposerType,
    /// Contiguous rounds for proposer
    pub contiguous_rounds: u32,
    /// Max block size (number of transactions) that consensus pulls from
    /// mempool
    pub max_block_size: u64,
    /// Validator's PeerId / Account Address
    pub author: Author,
    /// Whether to expose inner state.
    pub enable_state_expose: bool,
}

impl ChainedBftSMRConfig {
    pub fn from_node_config(node_cfg: &NodeConfig) -> ChainedBftSMRConfig {
        let cfg = &node_cfg.consensus;
        let pacemaker_initial_timeout_ms =
            cfg.pacemaker_initial_timeout_ms.unwrap_or(1000);
        ChainedBftSMRConfig {
            max_pruned_blocks_in_mem: cfg
                .max_pruned_blocks_in_mem
                .unwrap_or(10000)
                as usize,
            pacemaker_initial_timeout: Duration::from_millis(
                pacemaker_initial_timeout_ms,
            ),
            proposer_type: cfg.proposer_type,
            contiguous_rounds: cfg.contiguous_rounds,
            max_block_size: cfg.max_block_size,
            author: node_cfg.validator_network.as_ref().unwrap().peer_id,
            enable_state_expose: node_cfg.enable_state_expose,
        }
    }
}

/// ChainedBFTSMR is the one to generate the components (BlockStore, Proposer,
/// etc.) and start the driver. ChainedBftSMR implements the
/// StateMachineReplication, it is going to be used by ConsensusProvider for the
/// e2e flow.
pub struct ChainedBftSMR<T> {
    initial_setup: Option<InitialSetup>,
    runtime: Option<Runtime>,
    block_store: Option<Arc<BlockStore<T>>>,
    config: Option<ChainedBftSMRConfig>,
    storage: Arc<dyn PersistentStorage<T>>,
    initial_data: Option<RecoveryData<T>>,
}

impl<T: Payload> ChainedBftSMR<T> {
    pub fn new(
        initial_setup: InitialSetup, runtime: Runtime,
        config: ChainedBftSMRConfig, storage: Arc<dyn PersistentStorage<T>>,
        initial_data: RecoveryData<T>,
    ) -> Self
    {
        Self {
            initial_setup: Some(initial_setup),
            runtime: Some(runtime),
            block_store: None,
            config: Some(config),
            storage,
            initial_data: Some(initial_data),
        }
    }

    fn start_event_processing<TT: TxnTransformer<Payload = T>>(
        executor: Handle, mut epoch_manager: EpochManager<TT, T>,
        mut event_processor: EventProcessor<TT, T>,
        mut pacemaker_timeout_sender_rx: channel::Receiver<Round>,
        mut network_receivers: NetworkReceivers<T>,
    )
    {
        let fut = async move {
            event_processor.start().await;
            loop {
                let pre_select_instant = Instant::now();
                let idle_duration;
                select! {
                    proposal_msg = network_receivers.proposals.select_next_some() => {
                        idle_duration = pre_select_instant.elapsed();
                        event_processor.process_proposal_msg(proposal_msg).await;
                    }
                    block_retrieval = network_receivers.block_retrieval.select_next_some() => {
                        idle_duration = pre_select_instant.elapsed();
                        event_processor.process_block_retrieval(block_retrieval).await;
                    }
                    vote_msg = network_receivers.votes.select_next_some() => {
                        idle_duration = pre_select_instant.elapsed();
                        event_processor.process_vote(vote_msg).await;
                    }
                    local_timeout_round = pacemaker_timeout_sender_rx.select_next_some() => {
                        idle_duration = pre_select_instant.elapsed();
                        event_processor.process_local_timeout(local_timeout_round).await;
                    }
                    sync_info_msg = network_receivers.sync_info_msgs.select_next_some() => {
                        idle_duration = pre_select_instant.elapsed();
                        event_processor.process_sync_info_msg(sync_info_msg.0, sync_info_msg.1).await;
                    }
                    ledger_info = network_receivers.epoch_change.select_next_some() => {
                        idle_duration = pre_select_instant.elapsed();
                        event_processor = epoch_manager.start_new_epoch(ledger_info, event_processor.get_network());
                        // clean up all the previous messages from the old epochs
                        network_receivers.clear_prev_epoch_msgs();
                        event_processor.start().await;
                    }
                    different_epoch_and_peer = network_receivers.different_epoch.select_next_some() => {
                        idle_duration = pre_select_instant.elapsed();
                        epoch_manager.process_different_epoch(different_epoch_and_peer.0, different_epoch_and_peer.1).await
                    }
                    epoch_retrieval_and_peer = network_receivers.epoch_retrieval.select_next_some() => {
                        idle_duration = pre_select_instant.elapsed();
                        epoch_manager.process_epoch_retrieval(epoch_retrieval_and_peer.0, epoch_retrieval_and_peer.1).await
                    }
                }
                counters::EVENT_PROCESSING_LOOP_BUSY_DURATION_S
                    .observe_duration(
                        pre_select_instant.elapsed() - idle_duration,
                    );
                counters::EVENT_PROCESSING_LOOP_IDLE_DURATION_S
                    .observe_duration(idle_duration);
            }
        };
        executor.spawn(fut);
    }
}

impl<T: Payload> StateMachineReplication for ChainedBftSMR<T> {
    type Payload = T;

    /// We're following the steps to start
    /// 1. Construct the EpochManager from the latest libradb state
    /// 2. Construct per-epoch component with the fixed Validators provided by
    /// EpochManager including ProposerElection, Pacemaker, SafetyRules,
    /// Network(Populate with known validators), EventProcessor
    fn start<TT: TxnTransformer<Payload = Self::Payload>>(
        &mut self, txn_transformer: TT,
        state_computer: Arc<dyn StateComputer<Payload = Self::Payload>>,
        network: Arc<NetworkService>, own_node_hash: H256,
        protocol_config: ProtocolConfiguration,
        tg_sync: SharedSynchronizationService,
    ) -> Result<()>
    {
        let mut initial_setup = self
            .initial_setup
            .take()
            .expect("already started, initial setup is None");
        let initial_data = self
            .initial_data
            .take()
            .expect("already started, initial data is None");
        let executor = self
            .runtime
            .as_mut()
            .expect("Consensus start: No valid runtime found!")
            .handle();
        let time_service = Arc::new(ClockTimeService::new(executor.clone()));

        let (timeout_sender, timeout_receiver) =
            channel::new(1_024, &counters::PENDING_PACEMAKER_TIMEOUTS);
        //let (self_sender, self_receiver) = channel::new(1_024,
        // &counters::PENDING_SELF_MESSAGES);
        let epoch_info = Arc::new(RwLock::new(EpochInfo {
            epoch: initial_data.epoch(),
            verifier: initial_data.validators(),
        }));

        let (network_task, network_receiver) =
            NetworkTask::new(epoch_info.clone());

        let protocol_handler =
            Arc::new(HotStuffSynchronizationProtocol::with_peers(
                protocol_config,
                own_node_hash,
                network_task,
                state_computer.get_peers(),
            ));
        protocol_handler.clone().register(network.clone()).unwrap();
        network.start_network_poll().unwrap();

        let safety_rules_manager_config = initial_setup
            .safety_rules_manager_config
            .take()
            .expect("already started, safety_rules_manager is None");
        let safety_rules_manager =
            SafetyRulesManager::new(safety_rules_manager_config);

        let network_sender = Arc::new(NetworkSender::new(
            network.clone(),
            protocol_handler.clone(),
        ));

        let mut epoch_mgr = EpochManager::new(
            epoch_info.clone(),
            self.config.take().expect("already started, config is None"),
            time_service,
            //self_sender,
            //initial_setup.network_sender,
            network_sender.clone(),
            timeout_sender,
            txn_transformer,
            state_computer,
            self.storage.clone(),
            safety_rules_manager,
            tg_sync,
        );

        // Step 2
        let event_processor =
            epoch_mgr.start_epoch(initial_data, network_sender.clone());

        // TODO: this is test only, we should remove this
        self.block_store = Some(event_processor.block_store());

        Self::start_event_processing(
            executor.clone(),
            epoch_mgr,
            event_processor,
            timeout_receiver,
            network_receiver,
        );

        debug!("Chained BFT SMR started.");
        Ok(())
    }

    /// Stop is synchronous: waits for all the worker threads to terminate.
    fn stop(&mut self) {
        if let Some(_rt) = self.runtime.take() {
            debug!("Chained BFT SMR stopped.")
        }
    }
}
