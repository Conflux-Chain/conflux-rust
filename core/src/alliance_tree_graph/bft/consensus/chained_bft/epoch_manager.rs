// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::{
    chained_bft::{
        block_storage::{BlockReader, BlockStore},
        chained_bft_smr::ChainedBftSMRConfig,
        event_processor::EventProcessor,
        liveness::{
            multi_proposer_election::MultiProposer,
            pacemaker::{ExponentialTimeInterval, Pacemaker},
            proposal_generator::ProposalGenerator,
            proposer_election::ProposerElection,
            rotating_proposer_election::{choose_leader, RotatingProposer},
        },
        persistent_storage::{PersistentStorage, RecoveryData},
    },
    counters,
};
//use crate::state_replication::{StateComputer, TxnManager};
use super::super::{
    consensus_types::{
        common::{Payload, Round},
        epoch_retrieval::EpochRetrievalRequest,
    },
    util::time_service::{ClockTimeService, TimeService},
};
//use futures::executor::block_on;
use libra_config::config::ConsensusProposerType;
//use libra_logger::prelude::*;
use libra_types::{
    account_address::AccountAddress,
    crypto_proxies::{EpochInfo, LedgerInfoWithSignatures, ValidatorVerifier},
};
//use network::proto::ConsensusMsg;
//use network::proto::ConsensusMsg_oneof;
//use network::validator_network::{ConsensusNetworkSender, Event};
use super::super::safety_rules::SafetyRulesManager;
use crate::{
    alliance_tree_graph::bft::consensus::{
        chained_bft::network::NetworkSender,
        state_replication::{StateComputer, TxnTransformer},
    },
    sync::SharedSynchronizationService,
};
use futures::executor::block_on;
use libra_types::transaction::SignedTransaction;
use parking_lot::RwLock;
use std::{cmp::Ordering, sync::Arc};

// Manager the components that shared across epoch and spawn per-epoch
// EventProcessor with epoch-specific input.
pub struct EpochManager<TT, T> {
    epoch_info: Arc<RwLock<EpochInfo>>,
    config: ChainedBftSMRConfig,
    time_service: Arc<ClockTimeService>,
    //self_sender: channel::Sender<anyhow::Result<Event<ConsensusMsg>>>,
    network_sender: Arc<NetworkSender<T>>,
    timeout_sender: channel::Sender<Round>,
    txn_transformer: TT,
    // The manager for administrator transaction (for epoch change).
    admin_transaction: Arc<RwLock<Option<SignedTransaction>>>,
    state_computer: Arc<dyn StateComputer<Payload = T>>,
    storage: Arc<dyn PersistentStorage<T>>,
    safety_rules_manager: SafetyRulesManager<T>,
    tg_sync: SharedSynchronizationService,
}

impl<TT, T> EpochManager<TT, T>
where
    TT: TxnTransformer<Payload = T>,
    T: Payload,
{
    pub fn new(
        epoch_info: Arc<RwLock<EpochInfo>>,
        config: ChainedBftSMRConfig,
        time_service: Arc<ClockTimeService>,
        //self_sender: channel::Sender<anyhow::Result<Event<ConsensusMsg>>>,
        network_sender: Arc<NetworkSender<T>>,
        timeout_sender: channel::Sender<Round>,
        txn_transformer: TT,
        state_computer: Arc<dyn StateComputer<Payload = T>>,
        storage: Arc<dyn PersistentStorage<T>>,
        safety_rules_manager: SafetyRulesManager<T>,
        tg_sync: SharedSynchronizationService,
        admin_transaction: Arc<RwLock<Option<SignedTransaction>>>,
    ) -> Self
    {
        Self {
            epoch_info,
            config,
            time_service,
            //self_sender,
            network_sender,
            timeout_sender,
            txn_transformer,
            admin_transaction,
            state_computer,
            storage,
            safety_rules_manager,
            tg_sync,
        }
    }

    fn epoch(&self) -> u64 { self.epoch_info.read().epoch }

    fn create_pacemaker(
        &self, time_service: Arc<dyn TimeService>,
        timeout_sender: channel::Sender<Round>,
    ) -> Pacemaker
    {
        // 1.5^6 ~= 11
        // Timeout goes from initial_timeout to initial_timeout*11 in 6 steps
        let time_interval = Box::new(ExponentialTimeInterval::new(
            self.config.pacemaker_initial_timeout,
            1.5,
            6,
        ));
        Pacemaker::new(time_interval, time_service, timeout_sender)
    }

    /// Create a proposer election handler based on proposers
    fn create_proposer_election(
        &self, epoch: u64, validators: &ValidatorVerifier,
    ) -> Box<dyn ProposerElection<T> + Send + Sync> {
        let proposers = validators
            .get_ordered_account_addresses_iter()
            .collect::<Vec<_>>();
        match self.config.proposer_type {
            ConsensusProposerType::MultipleOrderedProposers => {
                Box::new(MultiProposer::new(epoch, proposers, 2))
            }
            ConsensusProposerType::RotatingProposer => Box::new(
                RotatingProposer::new(proposers, self.config.contiguous_rounds),
            ),
            // We don't really have a fixed proposer!
            ConsensusProposerType::FixedProposer => {
                let proposer = choose_leader(proposers);
                Box::new(RotatingProposer::new(
                    vec![proposer],
                    self.config.contiguous_rounds,
                ))
            }
        }
    }

    pub async fn process_epoch_retrieval(
        &mut self, request: EpochRetrievalRequest, peer_id: AccountAddress,
    ) {
        let proof = match self
            .state_computer
            .get_epoch_proof(request.start_epoch, request.end_epoch)
            .await
        {
            Ok(proof) => proof,
            Err(e) => {
                warn!("Failed to get epoch proof from storage: {:?}", e);
                return;
            }
        };
        self.network_sender.send_message(vec![peer_id], &proof);
    }

    pub async fn process_different_epoch(
        &mut self, different_epoch: u64, peer_id: AccountAddress,
    ) {
        match different_epoch.cmp(&self.epoch()) {
            // We try to help nodes that have lower epoch than us
            Ordering::Less => {
                self.process_epoch_retrieval(
                    EpochRetrievalRequest {
                        start_epoch: different_epoch,
                        end_epoch: self.epoch(),
                    },
                    peer_id,
                )
                .await
            }
            // We request proof to join higher epoch
            Ordering::Greater => {
                let request = EpochRetrievalRequest {
                    start_epoch: self.epoch(),
                    end_epoch: different_epoch,
                };

                self.network_sender.send_message(vec![peer_id], &request)
            }
            Ordering::Equal => {
                warn!("Same epoch should not come to process_different_epoch");
            }
        }
    }

    pub fn start_new_epoch(
        &mut self, ledger_info: LedgerInfoWithSignatures,
        network: Arc<NetworkSender<T>>,
    ) -> EventProcessor<TT, T>
    {
        // make sure storage is on this ledger_info too, it should be no-op if
        // it's already committed
        if let Err(e) =
            block_on(self.state_computer.sync_to(ledger_info.clone()))
        {
            error!("State sync to new epoch {} failed with {:?}, we'll try to start from current libradb", ledger_info, e);
        }
        let initial_data = self.storage.start();
        *self.epoch_info.write() = EpochInfo {
            epoch: initial_data.epoch(),
            verifier: initial_data.validators(),
        };
        self.start_epoch(initial_data, network)
    }

    pub fn start_epoch(
        &mut self, initial_data: RecoveryData<T>,
        network_sender: Arc<NetworkSender<T>>,
    ) -> EventProcessor<TT, T>
    {
        let validators = initial_data.validators();
        self.tg_sync.update_validator_info(validators.as_ref());
        let epoch = self.epoch();
        counters::EPOCH.set(epoch as i64);
        counters::CURRENT_EPOCH_VALIDATORS.set(validators.len() as i64);
        counters::CURRENT_EPOCH_QUORUM_SIZE
            .set(validators.quorum_voting_power() as i64);
        info!(
            "Start EventProcessor with epoch {} with genesis {}, validators {}",
            epoch,
            initial_data.root_block(),
            validators,
        );
        /*
        block_on(
            self.network_sender
                .update_eligible_nodes(initial_data.validator_keys()),
        )
        .expect("Unable to update network's eligible peers");
        */
        let last_vote = initial_data.last_vote();

        let block_store = Arc::new(BlockStore::new(
            Arc::clone(&self.storage),
            initial_data,
            Arc::clone(&self.state_computer),
            self.config.max_pruned_blocks_in_mem,
        ));

        let mut safety_rules = self.safety_rules_manager.client();
        safety_rules
            .start_new_epoch(block_store.highest_quorum_cert().as_ref())
            .expect("Unable to transition SafetyRules to the new epoch");

        // txn manager is required both by proposal generator (to pull the
        // proposers) and by event processor (to update their status).
        let proposal_generator = ProposalGenerator::new(
            self.config.author,
            block_store.clone(),
            self.txn_transformer.clone(),
            self.time_service.clone(),
            self.config.max_block_size,
            self.tg_sync.clone(),
            network_sender
                .network
                .net_key_pair()
                .expect("Network service not started yet!"),
            self.admin_transaction.clone(),
        );

        let pacemaker = self.create_pacemaker(
            self.time_service.clone(),
            self.timeout_sender.clone(),
        );

        let proposer_election =
            self.create_proposer_election(epoch, &validators);

        EventProcessor::new(
            block_store,
            last_vote,
            pacemaker,
            proposer_election,
            proposal_generator,
            safety_rules,
            self.txn_transformer.clone(),
            network_sender,
            self.storage.clone(),
            self.time_service.clone(),
            validators,
            self.config.enable_state_expose,
        )
    }
}
