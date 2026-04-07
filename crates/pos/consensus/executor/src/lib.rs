// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use anyhow::{anyhow, bail, ensure, format_err, Result};
use fail::fail_point;

use cached_pos_ledger_db::CachedPosLedgerDB;
use cfx_types::H256;
use consensus_types::db::LedgerBlockRW;
use diem_crypto::{
    hash::{CryptoHash, EventAccumulatorHasher, PRE_GENESIS_BLOCK_ID},
    HashValue,
};
use diem_logger::prelude::*;
use diem_state_view::StateViewId;
use diem_types::{
    block_info::PivotBlockDecision,
    committed_block::CommittedBlock,
    contract_event::ContractEvent,
    epoch_state::EpochState,
    ledger_info::LedgerInfoWithSignatures,
    on_chain_config::{self, ValidatorSet},
    proof::accumulator::InMemoryAccumulator,
    reward_distribution_event::{RewardDistributionEventV2, VoteCount},
    term_state::{
        ElectionEvent, RegisterEvent, RetireEvent, UpdateVotingPowerEvent,
    },
    transaction::{
        Transaction, TransactionInfo, TransactionOutput, TransactionStatus,
        TransactionToCommit, Version,
    },
};
use executor_types::{
    BlockExecutor, Error, ExecutedTrees, ProcessedVMOutput, StateComputeResult,
    TransactionData,
};
use pow_types::PowInterface;
use storage_interface::state_view::VerifiedStateView;

use crate::{
    logging::{LogEntry, LogSchema},
    metrics::{
        DIEM_EXECUTOR_COMMIT_BLOCKS_SECONDS, DIEM_EXECUTOR_ERRORS,
        DIEM_EXECUTOR_EXECUTE_BLOCK_SECONDS,
        DIEM_EXECUTOR_SAVE_TRANSACTIONS_SECONDS,
        DIEM_EXECUTOR_TRANSACTIONS_SAVED,
        DIEM_EXECUTOR_VM_EXECUTE_BLOCK_SECONDS,
    },
    vm::PosVM,
};
use diem_types::term_state::{
    pos_state_config::{PosStateConfigTrait, POS_STATE_CONFIG},
    DisputeEvent,
};

pub mod db_bootstrapper;
mod logging;
mod metrics;
pub mod vm;

/// `Executor` implements all functionalities the execution module needs to
/// provide.
pub struct Executor {
    db_with_cache: Arc<CachedPosLedgerDB>,
    consensus_db: Arc<dyn LedgerBlockRW>,
    pow_handler: Arc<dyn PowInterface>,
}

impl Executor {
    pub fn committed_block_id(&self) -> HashValue {
        self.db_with_cache.committed_block_id()
    }

    /// Constructs an `Executor`.
    pub fn new(
        db_with_cache: Arc<CachedPosLedgerDB>,
        pow_handler: Arc<dyn PowInterface>,
        consensus_db: Arc<dyn LedgerBlockRW>,
    ) -> Self {
        Self {
            db_with_cache,
            consensus_db,
            pow_handler,
        }
    }

    /// Post-processing of what the VM outputs. Returns the entire block's
    /// output.
    fn process_vm_outputs(
        &self, transactions: &[Transaction],
        vm_outputs: Vec<TransactionOutput>, parent_trees: &ExecutedTrees,
        parent_block_id: &HashValue, catch_up_mode: bool,
    ) -> Result<ProcessedVMOutput> {
        // The data of each individual transaction. For convenience purpose,
        // even for the transactions that will be discarded, we will
        // compute its in-memory Sparse Merkle Tree (it will be
        // identical to the previous one).
        let mut txn_data = vec![];
        // The hash of each individual TransactionInfo object. This will not
        // include the transactions that will be discarded, since they
        // do not go into the transaction accumulator.
        let mut txn_info_hashes = vec![];

        let pivot_select_event_key =
            PivotBlockDecision::pivot_select_event_key();
        let election_event_key = ElectionEvent::event_key();
        let retire_event_key = RetireEvent::event_key();
        let register_event_key = RegisterEvent::event_key();
        let update_voting_power_event_key = UpdateVotingPowerEvent::event_key();
        let dispute_event_key = DisputeEvent::event_key();

        // Find the next pivot block.
        let mut pivot_decision = None;
        let mut new_pos_state = parent_trees.pos_state().clone();
        let parent_pivot_decision = new_pos_state.pivot_decision().clone();
        for vm_output in vm_outputs.clone().into_iter() {
            for event in vm_output.events() {
                // check for pivot block selection.
                if *event.key() == pivot_select_event_key {
                    if pivot_decision.is_some() {
                        bail!("Multiple pivot decisions in one block!");
                    }
                    pivot_decision = Some(PivotBlockDecision::from_bytes(
                        event.event_data(),
                    )?);
                } else if *event.key() == election_event_key {
                    let election_event =
                        ElectionEvent::from_bytes(event.event_data())?;
                    new_pos_state.new_node_elected(&election_event)?;
                } else if *event.key() == dispute_event_key {
                    let dispute_event =
                        DisputeEvent::from_bytes(event.event_data())?;
                    new_pos_state.forfeit_node(&dispute_event.node_id)?;
                }
            }
        }

        if *parent_block_id != *PRE_GENESIS_BLOCK_ID {
            if let Some(pivot_decision) = &pivot_decision {
                diem_debug!(
                    "process_vm_outputs: parent={:?} parent_pivot={:?}",
                    parent_block_id,
                    parent_pivot_decision
                );

                // The check and event processing below will be skipped during
                // PoS catching up, because pow has not processed these pivot
                // decisions.
                if !catch_up_mode {
                    if !self.pow_handler.validate_proposal_pivot_decision(
                        parent_pivot_decision.block_hash,
                        pivot_decision.block_hash,
                    ) {
                        bail!("Invalid pivot decision for block");
                    }

                    // Verify if the proposer has packed all staking events as
                    // expected.
                    diem_debug!(
                        "check staking events: parent={:?} me={:?}",
                        parent_pivot_decision,
                        pivot_decision
                    );
                    let staking_events = self.pow_handler.get_staking_events(
                        parent_pivot_decision.height,
                        pivot_decision.height,
                        parent_pivot_decision.block_hash,
                        pivot_decision.block_hash,
                    )?;
                    let mut staking_events_iter = staking_events.iter();
                    for vm_output in vm_outputs.clone().into_iter() {
                        for event in vm_output.events() {
                            // check for pivot block selection.
                            if *event.key() == register_event_key {
                                let register_event = RegisterEvent::from_bytes(
                                    event.event_data(),
                                )?;
                                match register_event.matches_staking_event(staking_events_iter.next().ok_or(anyhow!("More staking transactions packed than actual pow events"))?) {
                                    Ok(true) => {}
                                    Ok(false) => bail!("Packed staking transactions unmatch PoW events)"),
                                    Err(e) => diem_error!("error decoding pow events: err={:?}", e),
                                }
                                new_pos_state
                                    .register_node(register_event.node_id)?;
                            } else if *event.key()
                                == update_voting_power_event_key
                            {
                                let update_voting_power_event =
                                    UpdateVotingPowerEvent::from_bytes(
                                        event.event_data(),
                                    )?;
                                match update_voting_power_event.matches_staking_event(staking_events_iter.next().ok_or(anyhow!("More staking transactions packed than actual pow events"))?) {
                                    Ok(true) => {}
                                    Ok(false) => bail!("Packed staking transactions unmatch PoW events)"),
                                    Err(e) => diem_error!("error decoding pow events: err={:?}", e),
                                }
                                new_pos_state.update_voting_power(
                                    &update_voting_power_event.node_address,
                                    update_voting_power_event.voting_power,
                                )?;
                            } else if *event.key() == retire_event_key {
                                let retire_event = RetireEvent::from_bytes(
                                    event.event_data(),
                                )?;
                                match retire_event.matches_staking_event(staking_events_iter.next().ok_or(anyhow!("More staking transactions packed than actual pow events"))?) {
                                    Ok(true) => {}
                                    Ok(false) => bail!("Packed staking transactions unmatch PoW events)"),
                                    Err(e) => diem_error!("error decoding pow events: err={:?}", e),
                                }
                                new_pos_state.retire_node(
                                    &retire_event.node_id,
                                    retire_event.votes,
                                )?;
                            }
                        }
                    }
                    ensure!(
                        staking_events_iter.next().is_none(),
                        "Not all PoW staking events are packed"
                    );
                } else {
                    for vm_output in vm_outputs.clone().into_iter() {
                        for event in vm_output.events() {
                            // check for pivot block selection.
                            if *event.key() == register_event_key {
                                let register_event = RegisterEvent::from_bytes(
                                    event.event_data(),
                                )?;
                                new_pos_state
                                    .register_node(register_event.node_id)?;
                            } else if *event.key()
                                == update_voting_power_event_key
                            {
                                let update_voting_power_event =
                                    UpdateVotingPowerEvent::from_bytes(
                                        event.event_data(),
                                    )?;
                                new_pos_state.update_voting_power(
                                    &update_voting_power_event.node_address,
                                    update_voting_power_event.voting_power,
                                )?;
                            } else if *event.key() == retire_event_key {
                                let retire_event = RetireEvent::from_bytes(
                                    event.event_data(),
                                )?;
                                new_pos_state.retire_node(
                                    &retire_event.node_id,
                                    retire_event.votes,
                                )?;
                            }
                        }
                    }
                }
            } else {
                // No new pivot decision, so there should be no staking-related
                // transactions.
                if vm_outputs.iter().any(|output| {
                    output.events().iter().any(|event| {
                        *event.key() == retire_event_key
                            || *event.key() == update_voting_power_event_key
                    })
                }) {
                    bail!("Should not pack staking related transactions");
                }
                pivot_decision = Some(parent_pivot_decision);
            }
        }
        // TODO(lpl): This is only for pos-tool
        if let Some(pivot_decision) = &pivot_decision {
            new_pos_state.set_pivot_decision(pivot_decision.clone());
        }
        let mut next_epoch_state = new_pos_state.next_view()?;

        let is_genesis =
            next_epoch_state.as_ref().map_or(false, |es| es.epoch == 1);

        for (vm_output, txn) in
            itertools::zip_eq(vm_outputs.into_iter(), transactions.iter())
        {
            let event_tree = {
                let event_hashes: Vec<_> =
                    vm_output.events().iter().map(CryptoHash::hash).collect();
                InMemoryAccumulator::<EventAccumulatorHasher>::from_leaves(
                    &event_hashes,
                )
            };

            let mut txn_info_hash = None;
            match vm_output.status() {
                TransactionStatus::Keep(status) => {
                    // ensure!(
                    //     !vm_output.write_set().is_empty(),
                    //     "Transaction with empty write set should be
                    // discarded.", );
                    // Compute hash for the TransactionInfo object. We need the
                    // hash of the transaction itself, the
                    // state root hash as well as the event root hash.
                    let txn_info = TransactionInfo::new(
                        txn.hash(),
                        Default::default(),
                        event_tree.root_hash(),
                        vm_output.gas_used(),
                        status.clone(),
                    );

                    let real_txn_info_hash = txn_info.hash();
                    txn_info_hashes.push(real_txn_info_hash);
                    txn_info_hash = Some(real_txn_info_hash);
                }
                TransactionStatus::Discard(status) => {
                    if !vm_output.events().is_empty() {
                        diem_error!(
                            "Discarded transaction has non-empty write set or events. \
                             Transaction: {:?}. Status: {:?}.",
                            txn, status,
                        );
                        DIEM_EXECUTOR_ERRORS.inc();
                    }
                }
                TransactionStatus::Retry => (),
            }

            txn_data.push(TransactionData::new(
                vm_output.events().to_vec(),
                vm_output.status().clone(),
                Arc::new(event_tree),
                vm_output.gas_used(),
                txn_info_hash,
            ));
        }

        // For genesis, extract ValidatorSet directly from the epoch
        // change event instead of going through the WriteSet →
        // AccountState roundtrip.
        if is_genesis {
            let new_epoch_event_key = on_chain_config::new_epoch_event_key();
            let validator_set = txn_data
                .iter()
                .flat_map(|td| td.events())
                .find(|event| *event.key() == new_epoch_event_key)
                .ok_or_else(|| format_err!("Genesis epoch event not found"))
                .and_then(|event| {
                    bcs::from_bytes::<ValidatorSet>(event.event_data()).map_err(
                        |e| {
                            format_err!(
                                "Failed to deserialize ValidatorSet: {}",
                                e
                            )
                        },
                    )
                })?;
            next_epoch_state = Some(EpochState::new(
                1,
                (&validator_set).into(),
                pivot_decision
                    .as_ref()
                    .map(|p| p.block_hash.as_bytes().to_vec())
                    .unwrap_or(vec![]),
            ))
        }

        let current_transaction_accumulator =
            parent_trees.txn_accumulator().append(&txn_info_hashes);

        Ok(ProcessedVMOutput::new(
            txn_data,
            ExecutedTrees::new_copy(
                Arc::new(current_transaction_accumulator),
                new_pos_state,
            ),
            next_epoch_state,
            // TODO(lpl): Check if we need to assert it's Some.
            pivot_decision,
        ))
    }

    fn extract_reconfig_events(
        events: Vec<ContractEvent>,
    ) -> Vec<ContractEvent> {
        let new_epoch_event_key = on_chain_config::new_epoch_event_key();
        events
            .into_iter()
            .filter(|event| *event.key() == new_epoch_event_key)
            .collect()
    }

    fn get_executed_trees(
        &self, block_id: HashValue,
    ) -> Result<ExecutedTrees, Error> {
        let executed_trees = if block_id
            == self.db_with_cache.cache.lock().committed_block_id()
        {
            self.db_with_cache.cache.lock().committed_trees().clone()
        } else {
            self.db_with_cache
                .get_block(&block_id)?
                .lock()
                .output()
                .executed_trees()
                .clone()
        };

        Ok(executed_trees)
    }

    fn get_executed_state_view(
        &self, id: StateViewId, executed_trees: &ExecutedTrees,
    ) -> VerifiedStateView {
        VerifiedStateView::new(id, executed_trees.pos_state().clone())
    }
}

impl BlockExecutor for Executor {
    fn committed_block_id(&self) -> Result<HashValue, Error> {
        Ok(self.committed_block_id())
    }

    fn execute_block(
        &self, block: (HashValue, Vec<Transaction>),
        parent_block_id: HashValue, catch_up_mode: bool,
    ) -> Result<StateComputeResult, Error> {
        let (block_id, mut transactions) = block;

        // Reconfiguration rule - if a block is a child of pending
        // reconfiguration, it needs to be empty So we roll over the
        // executed state until it's committed and we start new epoch.
        let (output, state_compute_result) = if parent_block_id
            != self.committed_block_id()
            && self
                .db_with_cache
                .get_block(&parent_block_id)?
                .lock()
                .output()
                .has_reconfiguration()
        {
            let parent = self.db_with_cache.get_block(&parent_block_id)?;
            let parent_block = parent.lock();
            let parent_output = parent_block.output();

            diem_info!(
                LogSchema::new(LogEntry::BlockExecutor).block_id(block_id),
                "reconfig_descendant_block_received"
            );

            let mut output = ProcessedVMOutput::new(
                vec![],
                parent_output.executed_trees().clone(),
                parent_output.epoch_state().clone(),
                // The block has no pivot decision transaction, so it's the
                // same as the parent.
                parent_output.pivot_block().clone(),
            );
            output.set_pos_state_skipped();

            let parent_accu = parent_output.executed_trees().txn_accumulator();
            let state_compute_result = output.compute_result(
                parent_accu.frozen_subtree_roots().clone(),
                parent_accu.num_leaves(),
            );

            // Reset the reconfiguration suffix transactions to empty list.
            transactions = vec![];

            (output, state_compute_result)
        } else {
            diem_info!(
                LogSchema::new(LogEntry::BlockExecutor).block_id(block_id),
                "execute_block"
            );

            let _timer = DIEM_EXECUTOR_EXECUTE_BLOCK_SECONDS.start_timer();

            let parent_block_executed_trees =
                self.get_executed_trees(parent_block_id)?;

            let state_view = self.get_executed_state_view(
                StateViewId::BlockExecution { block_id },
                &parent_block_executed_trees,
            );

            // FIXME(lpl): Check the error processing in `execute_block`,
            // `process_vm_outputs`, and transaction packing. We
            // need to ensure that there is no packing behavior that
            // makes all new proposals invalid during execution.
            let vm_outputs = {
                // trace_code_block!("executor::execute_block", {"block",
                // block_id});
                let _timer =
                    DIEM_EXECUTOR_VM_EXECUTE_BLOCK_SECONDS.start_timer();
                fail_point!("executor::vm_execute_block", |_| {
                    Err(Error::from(anyhow::anyhow!(
                        "Injected error in vm_execute_block"
                    )))
                });
                PosVM::execute_block(
                    transactions.clone(),
                    &state_view,
                    catch_up_mode,
                )
                .map_err(anyhow::Error::from)?
            };

            // trace_code_block!("executor::process_vm_outputs", {"block",
            // block_id});
            let status: Vec<_> = vm_outputs
                .iter()
                .map(TransactionOutput::status)
                .cloned()
                .collect();
            if !status.is_empty() {
                diem_trace!("Execution status: {:?}", status);
            }

            let output = self
                .process_vm_outputs(
                    &transactions,
                    vm_outputs,
                    &parent_block_executed_trees,
                    &parent_block_id,
                    catch_up_mode,
                )
                .map_err(|err| {
                    format_err!("Failed to execute block: {}", err)
                })?;

            let parent_accu = parent_block_executed_trees.txn_accumulator();

            diem_debug!("parent leaves: {}", parent_accu.num_leaves());
            let state_compute_result = output.compute_result(
                parent_accu.frozen_subtree_roots().clone(),
                parent_accu.num_leaves(),
            );
            (output, state_compute_result)
        };

        // Add the output to the speculation_output_tree
        self.db_with_cache
            .add_block(parent_block_id, (block_id, transactions, output))?;

        Ok(state_compute_result)
    }

    fn commit_blocks(
        &self, block_ids: Vec<HashValue>,
        ledger_info_with_sigs: LedgerInfoWithSignatures,
    ) -> Result<(Vec<Transaction>, Vec<ContractEvent>), Error> {
        let _timer = DIEM_EXECUTOR_COMMIT_BLOCKS_SECONDS.start_timer();
        let mut pos_state_to_commit = self
            .get_executed_trees(
                ledger_info_with_sigs.ledger_info().consensus_block_id(),
            )?
            .pos_state()
            .clone();

        // TODO(lpl): Implement force_retire better?
        // Process pos_state to apply force_retire.
        if ledger_info_with_sigs.ledger_info().ends_epoch()
            && ledger_info_with_sigs.ledger_info().epoch() != 0
        {
            let ending_block =
                ledger_info_with_sigs.ledger_info().consensus_block_id();
            let mut elected = BTreeMap::new();
            let mut voted_block_id = ending_block;
            // `self.cache.committed_trees` should be within this epoch and
            // before ending_block.
            let verifier = self
                .db_with_cache
                .cache
                .lock()
                .committed_trees()
                .pos_state()
                .epoch_state()
                .verifier()
                // Clone to avoid possible deadlock.
                .clone();
            for committee_member in verifier.address_to_validator_info().keys()
            {
                elected.insert(*committee_member, VoteCount::default());
            }
            loop {
                let block = self
                    .consensus_db
                    .get_ledger_block(&voted_block_id)?
                    .unwrap();
                diem_trace!("count vote for block {:?}", block);
                if block.quorum_cert().ledger_info().signatures().len() == 0 {
                    // parent is round-0 virtual block and has not voters, so we
                    // just add `leader_count` and break the loop.
                    if let Some(author) = block.author() {
                        let leader_status =
                            elected.get_mut(&author).expect("in epoch state");
                        leader_status.leader_count += 1;
                    }
                    break;
                }
                if let Some(author) = block.author() {
                    let leader_status =
                        elected.get_mut(&author).expect("in epoch state");
                    leader_status.leader_count += 1;
                    leader_status.included_vote_count += verifier
                        .extra_vote_count(
                            block
                                .quorum_cert()
                                .ledger_info()
                                .signatures()
                                .keys(),
                        )
                        .unwrap();
                }
                for voter in
                    block.quorum_cert().ledger_info().signatures().keys()
                {
                    elected
                        .get_mut(&voter)
                        .expect("in epoch state")
                        .vote_count +=
                        verifier.get_voting_power(voter).unwrap();
                }
                voted_block_id = block.parent_id();
            }
            let mut force_retired = HashSet::new();

            // Force retire the nodes that have not voted in this term.
            for (node, vote_count) in elected.iter_mut() {
                if vote_count.vote_count == 0 {
                    force_retired.insert(node);
                } else {
                    vote_count.total_votes =
                        verifier.get_voting_power(node).unwrap_or(0);
                    if vote_count.total_votes == 0 {
                        diem_warn!("Node {:?} has voted for epoch {} without voting power.",
                            node,
                            pos_state_to_commit.epoch_state().epoch);
                    }
                }
            }

            if !force_retired.is_empty() {
                // `end_epoch` has been checked above and is excluded below.
                let end_epoch = ledger_info_with_sigs.ledger_info().epoch();
                let start_epoch = end_epoch.saturating_sub(
                    POS_STATE_CONFIG.force_retire_check_epoch_count(
                        pos_state_to_commit.current_view(),
                    ),
                ) + 1;
                // Check more past epochs to see if the nodes in `force_retired`
                // have voted.
                for end_ledger_info in self
                    .db_with_cache
                    .db
                    .reader
                    .get_epoch_ending_ledger_infos(start_epoch, end_epoch)?
                    .get_all_ledger_infos()
                {
                    let mut voted_block_id =
                        end_ledger_info.ledger_info().consensus_block_id();
                    loop {
                        let block = self
                            .consensus_db
                            .get_ledger_block(&voted_block_id)?
                            .unwrap();
                        if block.quorum_cert().ledger_info().signatures().len()
                            == 0
                        {
                            break;
                        }
                        for voter in block
                            .quorum_cert()
                            .ledger_info()
                            .signatures()
                            .keys()
                        {
                            // Find a vote, so the node will not be force
                            // retired.
                            force_retired.remove(voter);
                        }
                        voted_block_id = block.parent_id();
                    }
                }
                for node in force_retired {
                    pos_state_to_commit.force_retire_node(&node)?;
                }
            }

            let reward_event = RewardDistributionEventV2 {
                candidates: pos_state_to_commit.next_evicted_term(),
                elected: elected
                    .into_iter()
                    .map(|(k, v)| (H256::from_slice(k.as_ref()), v))
                    .collect(),
                view: pos_state_to_commit.current_view(),
            };
            self.db_with_cache.db.writer.save_reward_event(
                ledger_info_with_sigs.ledger_info().epoch(),
                &reward_event,
            )?;
            self.db_with_cache
                .get_block(&ending_block)
                .expect("latest committed block not pruned")
                .lock()
                .replace_pos_state(pos_state_to_commit.clone());
        }

        diem_info!(
            LogSchema::new(LogEntry::BlockExecutor).block_id(
                ledger_info_with_sigs.ledger_info().consensus_block_id()
            ),
            "commit_block"
        );

        let version = ledger_info_with_sigs.ledger_info().version();

        let num_txns_in_li = version
            .checked_add(1)
            .ok_or_else(|| format_err!("version + 1 overflows"))?;
        let num_persistent_txns = self
            .db_with_cache
            .cache
            .lock()
            .synced_trees()
            .txn_accumulator()
            .num_leaves();

        if num_txns_in_li < num_persistent_txns {
            return Err(Error::InternalError {
                error: format!(
                    "Try to commit stale transactions with the last version as {}",
                    version
                ),
            });
        }

        // All transactions that need to go to storage. In the above example,
        // this means all the transactions in A, B and C whose status ==
        // TransactionStatus::Keep. This must be done before calculate
        // potential skipping of transactions in idempotent commit.
        let mut txns_to_keep = vec![];
        let arc_blocks = block_ids
            .iter()
            .map(|id| self.db_with_cache.get_block(id))
            .collect::<Result<Vec<_>, Error>>()?;
        let blocks = arc_blocks.iter().map(|b| b.lock()).collect::<Vec<_>>();
        let mut committed_blocks = Vec::new();
        let mut signatures_vec = Vec::new();
        if ledger_info_with_sigs.ledger_info().epoch() != 0 {
            for (i, b) in blocks.iter().enumerate() {
                let ledger_block = self
                    .consensus_db
                    .get_ledger_block(&b.id())
                    .unwrap()
                    .unwrap();
                let view =
                    b.output().executed_trees().pos_state().current_view();
                committed_blocks.push(CommittedBlock {
                    hash: b.id(),
                    epoch: ledger_block.epoch(),
                    miner: ledger_block.author(),
                    parent_hash: ledger_block.parent_id(),
                    round: ledger_block.round(),
                    pivot_decision: b.output().pivot_block().clone().unwrap(),
                    version: b.output().version().unwrap(),
                    timestamp: ledger_block.timestamp_usecs(),
                    view,
                    is_skipped: b
                        .output()
                        .executed_trees()
                        .pos_state()
                        .skipped(),
                });
                // The signatures of each block is in the qc of the next block.
                if i != 0 {
                    signatures_vec.push((
                        ledger_block.quorum_cert().certified_block().id(),
                        ledger_block.quorum_cert().ledger_info().clone(),
                    ));
                }
            }
            let last_block = blocks.last().expect("not empty").id();
            if let Some(qc) = self.consensus_db.get_qc_for_block(&last_block)? {
                signatures_vec.push((last_block, qc.ledger_info().clone()));
            } else {
                // If we are catching up, all QCs come from retrieved blocks, so
                // we cannot get the QC that votes for the last
                // block in an epoch as the QC is within another
                // unknown child block.
                assert!(ledger_info_with_sigs.ledger_info().ends_epoch());
            }
        } else {
            committed_blocks.push(CommittedBlock {
                hash: ledger_info_with_sigs.ledger_info().consensus_block_id(),
                epoch: 0,
                round: 0,
                miner: None,
                parent_hash: HashValue::default(),
                pivot_decision: ledger_info_with_sigs
                    .ledger_info()
                    .pivot_decision()
                    .unwrap()
                    .clone(),
                version: ledger_info_with_sigs.ledger_info().version(),
                timestamp: ledger_info_with_sigs
                    .ledger_info()
                    .timestamp_usecs(),
                view: 1,
                is_skipped: false,
            });
        }
        for (txn, txn_data) in blocks.iter().flat_map(|block| {
            itertools::zip_eq(
                block.transactions(),
                block.output().transaction_data(),
            )
        }) {
            if let TransactionStatus::Keep(recorded_status) = txn_data.status()
            {
                txns_to_keep.push(TransactionToCommit::new(
                    txn.clone(),
                    txn_data.events().to_vec(),
                    txn_data.gas_used(),
                    recorded_status.clone(),
                ));
            }
        }

        let last_block = blocks
            .last()
            .ok_or_else(|| format_err!("CommittableBlockBatch is empty"))?;

        // Check that the version in ledger info (computed by consensus) matches
        // the version computed by us.
        let num_txns_in_speculative_accumulator = last_block
            .output()
            .executed_trees()
            .txn_accumulator()
            .num_leaves();
        assert_eq!(
            num_txns_in_li, num_txns_in_speculative_accumulator as Version,
            "Number of transactions in ledger info ({}) does not match number of transactions \
             in accumulator ({}).",
            num_txns_in_li, num_txns_in_speculative_accumulator,
        );

        let num_txns_to_keep = txns_to_keep.len() as u64;

        // Skip txns that are already committed to allow failures in state sync
        // process.
        let first_version_to_keep = num_txns_in_li - num_txns_to_keep;
        assert!(
            first_version_to_keep <= num_persistent_txns,
            "first_version {} in the blocks to commit cannot exceed # of committed txns: {}.",
            first_version_to_keep,
            num_persistent_txns
        );

        let num_txns_to_skip = num_persistent_txns - first_version_to_keep;
        let first_version_to_commit = first_version_to_keep + num_txns_to_skip;

        if num_txns_to_skip != 0 {
            diem_debug!(
                LogSchema::new(LogEntry::BlockExecutor)
                    .latest_synced_version(num_persistent_txns - 1)
                    .first_version_to_keep(first_version_to_keep)
                    .num_txns_to_keep(num_txns_to_keep)
                    .first_version_to_commit(first_version_to_commit),
                "skip_transactions_when_committing"
            );
        }

        // Skip duplicate txns that are already persistent.
        let txns_to_commit = &txns_to_keep[num_txns_to_skip as usize..];

        let num_txns_to_commit = txns_to_commit.len() as u64;
        {
            let _timer = DIEM_EXECUTOR_SAVE_TRANSACTIONS_SECONDS.start_timer();
            DIEM_EXECUTOR_TRANSACTIONS_SAVED.observe(num_txns_to_commit as f64);

            assert_eq!(
                first_version_to_commit,
                num_txns_in_li - num_txns_to_commit
            );
            fail_point!("executor::commit_blocks", |_| {
                Err(Error::from(anyhow::anyhow!(
                    "Injected error in commit_blocks"
                )))
            });
            self.db_with_cache.db.writer.save_transactions(
                txns_to_commit,
                first_version_to_commit,
                Some(&ledger_info_with_sigs),
                Some(pos_state_to_commit),
                committed_blocks,
                signatures_vec,
            )?;
        }

        // Calculate committed transactions and reconfig events now that commit
        // has succeeded
        let mut committed_txns = vec![];
        let mut reconfig_events = vec![];
        for txn in txns_to_commit.iter() {
            committed_txns.push(txn.transaction().clone());
            reconfig_events.append(&mut Self::extract_reconfig_events(
                txn.events().to_vec(),
            ));
        }

        // Drop block locks before prune() which needs to re-lock them.
        drop(blocks);
        drop(arc_blocks);

        let old_committed_block = self.db_with_cache.prune(
            ledger_info_with_sigs.ledger_info(),
            committed_txns.clone(),
            reconfig_events.clone(),
        )?;
        self.db_with_cache
            .db
            .writer
            .delete_pos_state_by_block(&old_committed_block)?;

        // Now that the blocks are persisted successfully, we can reply to
        // consensus
        Ok((committed_txns, reconfig_events))
    }
}
