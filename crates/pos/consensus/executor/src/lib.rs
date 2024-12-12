// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

use std::{
    collections::{hash_map, BTreeMap, HashMap, HashSet},
    convert::TryFrom,
    marker::PhantomData,
    sync::Arc,
};

use anyhow::{anyhow, bail, ensure, format_err, Result};
use fail::fail_point;

use cached_pos_ledger_db::CachedPosLedgerDB;
use cfx_types::H256;
use consensus_types::db::LedgerBlockRW;
use diem_crypto::{
    hash::{
        CryptoHash, EventAccumulatorHasher, TransactionAccumulatorHasher,
        PRE_GENESIS_BLOCK_ID,
    },
    HashValue,
};
use diem_logger::prelude::*;
use diem_state_view::StateViewId;
use diem_types::{
    account_address::{AccountAddress, HashAccountAddress},
    account_state::AccountState,
    account_state_blob::AccountStateBlob,
    block_info::PivotBlockDecision,
    committed_block::CommittedBlock,
    contract_event::ContractEvent,
    epoch_state::EpochState,
    ledger_info::LedgerInfoWithSignatures,
    on_chain_config,
    proof::accumulator::InMemoryAccumulator,
    reward_distribution_event::{RewardDistributionEventV2, VoteCount},
    term_state::{
        ElectionEvent, PosState, RegisterEvent, RetireEvent,
        UpdateVotingPowerEvent,
    },
    transaction::{
        Transaction, TransactionInfo, TransactionListWithProof,
        TransactionOutput, TransactionPayload, TransactionStatus,
        TransactionToCommit, Version,
    },
    write_set::{WriteOp, WriteSet},
};
use executor_types::{
    BlockExecutor, ChunkExecutor, Error, ExecutedTrees, ProcessedVMOutput,
    ProofReader, StateComputeResult, TransactionData, TransactionReplayer,
};
use pow_types::PowInterface;
use storage_interface::state_view::VerifiedStateView;

use crate::{
    logging::{LogEntry, LogSchema},
    metrics::{
        DIEM_EXECUTOR_COMMIT_BLOCKS_SECONDS, DIEM_EXECUTOR_ERRORS,
        DIEM_EXECUTOR_EXECUTE_AND_COMMIT_CHUNK_SECONDS,
        DIEM_EXECUTOR_EXECUTE_BLOCK_SECONDS,
        DIEM_EXECUTOR_SAVE_TRANSACTIONS_SECONDS,
        DIEM_EXECUTOR_TRANSACTIONS_SAVED,
        DIEM_EXECUTOR_VM_EXECUTE_BLOCK_SECONDS,
    },
    vm::VMExecutor,
};
use diem_types::term_state::{
    pos_state_config::{PosStateConfigTrait, POS_STATE_CONFIG},
    DisputeEvent,
};

pub mod db_bootstrapper;
mod logging;
mod metrics;
pub mod vm;

type SparseMerkleProof = diem_types::proof::SparseMerkleProof<AccountStateBlob>;

/// `Executor` implements all functionalities the execution module needs to
/// provide.
pub struct Executor<V> {
    db_with_cache: Arc<CachedPosLedgerDB>,
    consensus_db: Arc<dyn LedgerBlockRW>,
    phantom: PhantomData<V>,
    pow_handler: Arc<dyn PowInterface>,
}

impl<V> Executor<V>
where V: VMExecutor
{
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
            phantom: PhantomData,
            pow_handler,
        }
    }

    /// In case there is a new LI to be added to a LedgerStore, verify and
    /// return it.
    fn find_chunk_li(
        verified_target_li: LedgerInfoWithSignatures,
        epoch_change_li: Option<LedgerInfoWithSignatures>,
        new_output: &ProcessedVMOutput,
    ) -> Result<Option<LedgerInfoWithSignatures>> {
        // If the chunk corresponds to the target LI, the target LI can be added
        // to storage.
        if verified_target_li.ledger_info().version()
            == new_output.version().unwrap_or(0)
        {
            ensure!(
                verified_target_li
                    .ledger_info()
                    .transaction_accumulator_hash()
                    == new_output.accu_root(),
                "Root hash in target ledger info does not match local computation."
            );
            return Ok(Some(verified_target_li));
        }
        // If the epoch change LI is present, it must match the version of the
        // chunk: verify the version and the root hash.
        if let Some(epoch_change_li) = epoch_change_li {
            // Verify that the given ledger info corresponds to the new
            // accumulator.
            ensure!(
                epoch_change_li.ledger_info().transaction_accumulator_hash()
                    == new_output.accu_root(),
                "Root hash of a given epoch LI does not match local computation."
            );
            ensure!(
                epoch_change_li.ledger_info().version()
                    == new_output.version().unwrap_or(0),
                "Version of a given epoch LI does not match local computation."
            );
            ensure!(
                epoch_change_li.ledger_info().ends_epoch(),
                "Epoch change LI does not carry validator set"
            );
            ensure!(
                epoch_change_li.ledger_info().next_epoch_state()
                    == new_output.epoch_state().as_ref(),
                "New validator set of a given epoch LI does not match local computation"
            );
            return Ok(Some(epoch_change_li));
        }
        ensure!(
            new_output.epoch_state().is_none(),
            "End of epoch chunk based on local computation but no EoE LedgerInfo provided."
        );
        Ok(None)
    }

    /// Verify input chunk and return transactions to be applied, skipping those
    /// already persisted. Specifically:
    ///  1. Verify that input transactions belongs to the ledger represented by
    /// the ledger info.  2. Verify that transactions to skip match what's
    /// already persisted (no fork).  3. Return Transactions to be applied.
    fn verify_chunk(
        &self, txn_list_with_proof: TransactionListWithProof,
        verified_target_li: &LedgerInfoWithSignatures,
    ) -> Result<(Vec<Transaction>, Vec<TransactionInfo>)> {
        // 1. Verify that input transactions belongs to the ledger represented
        // by the ledger info.
        txn_list_with_proof.verify(
            verified_target_li.ledger_info(),
            txn_list_with_proof.first_transaction_version,
        )?;

        // Return empty if there's no work to do.
        if txn_list_with_proof.transactions.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let first_txn_version =
            match txn_list_with_proof.first_transaction_version {
                Some(tx) => tx as Version,
                None => {
                    bail!(
                        "first_transaction_version doesn't exist in {:?}",
                        txn_list_with_proof
                    );
                }
            };

        let num_committed_txns = self
            .db_with_cache
            .cache
            .lock()
            .synced_trees()
            .txn_accumulator()
            .num_leaves();
        ensure!(
            first_txn_version <= num_committed_txns,
            "Transaction list too new. Expected version: {}. First transaction version: {}.",
            num_committed_txns,
            first_txn_version
        );
        let versions_between_first_and_committed =
            num_committed_txns - first_txn_version;
        if txn_list_with_proof.transactions.len()
            <= versions_between_first_and_committed as usize
        {
            // All already in DB, nothing to do.
            return Ok((Vec::new(), Vec::new()));
        }

        // 2. Verify that skipped transactions match what's already persisted
        // (no fork):
        let num_txns_to_skip = num_committed_txns - first_txn_version;

        diem_debug!(
            LogSchema::new(LogEntry::ChunkExecutor).num(num_txns_to_skip),
            "skipping_chunk_txns"
        );

        // If the proof is verified, then the length of txn_infos and txns must
        // be the same.
        let skipped_transaction_infos = &txn_list_with_proof
            .proof
            .transaction_infos()[..num_txns_to_skip as usize];

        // Left side of the proof happens to be the frozen subtree roots of the
        // accumulator right before the list of txns are applied.
        let frozen_subtree_roots_from_proof = txn_list_with_proof
            .proof
            .left_siblings()
            .iter()
            .rev()
            .cloned()
            .collect::<Vec<_>>();
        let accu_from_proof =
            InMemoryAccumulator::<TransactionAccumulatorHasher>::new(
                frozen_subtree_roots_from_proof,
                first_txn_version,
            )?
            .append(
                &skipped_transaction_infos
                    .iter()
                    .map(CryptoHash::hash)
                    .collect::<Vec<_>>()[..],
            );
        // The two accumulator root hashes should be identical.
        ensure!(
            self.db_with_cache.cache.lock().synced_trees().state_id() == accu_from_proof.root_hash(),
            "Fork happens because the current synced_trees doesn't match the txn list provided."
        );

        // 3. Return verified transactions to be applied.
        let mut txns: Vec<_> = txn_list_with_proof.transactions;
        txns.drain(0..num_txns_to_skip as usize);
        let (_, mut txn_infos) = txn_list_with_proof.proof.unpack();
        txn_infos.drain(0..num_txns_to_skip as usize);

        Ok((txns, txn_infos))
    }

    /// Post-processing of what the VM outputs. Returns the entire block's
    /// output.
    fn process_vm_outputs(
        &self, mut account_to_state: HashMap<AccountAddress, AccountState>,
        account_to_proof: HashMap<HashValue, SparseMerkleProof>,
        transactions: &[Transaction], vm_outputs: Vec<TransactionOutput>,
        parent_trees: &ExecutedTrees, parent_block_id: &HashValue,
        catch_up_mode: bool,
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

        let proof_reader = ProofReader::new(account_to_proof);
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

        let txn_blobs =
            itertools::zip_eq(vm_outputs.iter(), transactions.iter())
                .map(|(vm_output, txn)| {
                    process_write_set(
                        txn,
                        &mut account_to_state,
                        vm_output.write_set().clone(),
                    )
                })
                .collect::<Result<Vec<_>>>()?;

        let (txn_state_roots, current_state_tree) = parent_trees
            .state_tree()
            .batch_update(
                txn_blobs
                    .iter()
                    .map(|m| {
                        m.iter()
                            .map(|(account, value)| (account.hash(), value))
                            .collect::<Vec<_>>()
                    })
                    .collect(),
                &proof_reader,
            )
            .expect("Failed to update state tree.");

        for ((vm_output, txn), (mut state_tree_hash, blobs)) in
            itertools::zip_eq(
                itertools::zip_eq(vm_outputs.into_iter(), transactions.iter()),
                itertools::zip_eq(txn_state_roots, txn_blobs),
            )
        {
            // Not genesis transactions.
            diem_debug!(
                "process_vm_outputs: {} {:?}",
                parent_trees.txn_accumulator().version(),
                state_tree_hash
            );
            if parent_trees.txn_accumulator().version() != 0 {
                // TODO(lpl): Remove state tree.
                state_tree_hash = Default::default();
            }
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
                        state_tree_hash,
                        event_tree.root_hash(),
                        vm_output.gas_used(),
                        status.clone(),
                    );

                    let real_txn_info_hash = txn_info.hash();
                    txn_info_hashes.push(real_txn_info_hash);
                    txn_info_hash = Some(real_txn_info_hash);
                }
                TransactionStatus::Discard(status) => {
                    if !vm_output.write_set().is_empty()
                        || !vm_output.events().is_empty()
                    {
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
                blobs,
                vm_output.events().to_vec(),
                vm_output.status().clone(),
                state_tree_hash,
                Arc::new(event_tree),
                vm_output.gas_used(),
                txn_info_hash,
            ));
        }

        // TODO(lpl): For genesis.
        if next_epoch_state.is_some()
            && next_epoch_state.as_ref().unwrap().epoch == 1
        {
            // Pad the rest of transactions
            txn_data.resize(
                transactions.len(),
                TransactionData::new(
                    HashMap::new(),
                    vec![],
                    TransactionStatus::Retry,
                    current_state_tree.root_hash(),
                    Arc::new(
                        InMemoryAccumulator::<EventAccumulatorHasher>::default(
                        ),
                    ),
                    0,
                    None,
                ),
            );

            let validator_set = account_to_state
                .get(&on_chain_config::config_address())
                .map(|state| {
                    state.get_validator_set()?.ok_or_else(|| {
                        format_err!("ValidatorSet does not exist")
                    })
                })
                .ok_or_else(|| {
                    format_err!("ValidatorSet account does not exist")
                })??;
            /*let configuration = account_to_state
            .get(&on_chain_config::config_address())
            .map(|state| {
                state.get_configuration_resource()?.ok_or_else(|| {
                    format_err!("Configuration does not exist")
                })
            })
            .ok_or_else(|| {
                format_err!("Association account does not exist")
            })??;*/
            next_epoch_state = Some(EpochState::new(
                // TODO(lpl): This is only used for genesis, and after
                // executing the genesis block, the epoch
                // number should be increased from 0 to 1.
                1,
                (&validator_set).into(),
                pivot_decision
                    .as_ref()
                    .map(|p| p.block_hash.as_bytes().to_vec())
                    .unwrap_or(vec![]),
            ))
        };

        let current_transaction_accumulator =
            parent_trees.txn_accumulator().append(&txn_info_hashes);

        Ok(ProcessedVMOutput::new(
            txn_data,
            ExecutedTrees::new_copy(
                Arc::new(current_state_tree),
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

    fn get_executed_state_view<'a>(
        &self, id: StateViewId, executed_trees: &'a ExecutedTrees,
    ) -> VerifiedStateView<'a> {
        let cache = self.db_with_cache.cache.lock();
        VerifiedStateView::new(
            id,
            Arc::clone(&self.db_with_cache.db.reader),
            cache.committed_trees().version(),
            cache.committed_trees().state_root(),
            executed_trees.state_tree(),
            executed_trees.pos_state().clone(),
        )
    }

    fn replay_transactions_impl(
        &self, first_version: u64, transactions: Vec<Transaction>,
        transaction_infos: Vec<TransactionInfo>,
    ) -> Result<(
        ProcessedVMOutput,
        Vec<TransactionToCommit>,
        Vec<ContractEvent>,
        Vec<Transaction>,
        Vec<TransactionInfo>,
    )> {
        // Construct a StateView and pass the transactions to VM.
        let cache = self.db_with_cache.cache.lock();
        let state_view = VerifiedStateView::new(
            StateViewId::ChunkExecution { first_version },
            Arc::clone(&self.db_with_cache.db.reader),
            cache.synced_trees().version(),
            cache.synced_trees().state_root(),
            cache.synced_trees().state_tree(),
            // TODO(lpl): State sync not used yet.
            PosState::new_empty(),
        );

        fail_point!("executor::vm_execute_chunk", |_| {
            Err(anyhow::anyhow!("Injected error in execute_chunk"))
        });
        let vm_outputs =
            V::execute_block(transactions.clone(), &state_view, true)?;

        // Since other validators have committed these transactions, their
        // status should all be TransactionStatus::Keep.
        for output in &vm_outputs {
            if let TransactionStatus::Discard(_) = output.status() {
                bail!("Syncing transactions that should be discarded.");
            }
        }

        let (account_to_state, account_to_proof) = state_view.into();

        let output = self.process_vm_outputs(
            account_to_state,
            account_to_proof,
            &transactions,
            vm_outputs,
            cache.synced_trees(),
            // TODO(lpl): This function is not used.
            &HashValue::zero(),
            true,
        )?;

        // Since we have verified the proofs, we just need to verify that each
        // TransactionInfo object matches what we have computed locally.
        let mut txns_to_commit = vec![];
        let mut reconfig_events = vec![];
        let mut seen_retry = false;
        let mut txns_to_retry = vec![];
        let mut txn_infos_to_retry = vec![];
        for ((txn, txn_data), (i, txn_info)) in itertools::zip_eq(
            itertools::zip_eq(transactions, output.transaction_data()),
            transaction_infos.into_iter().enumerate(),
        ) {
            let recorded_status = match txn_data.status() {
                TransactionStatus::Keep(recorded_status) => recorded_status.clone(),
                status @ TransactionStatus::Discard(_) => bail!(
                    "The transaction at version {}, got the status of 'Discard': {:?}",
                    first_version
                        .checked_add(i as u64)
                        .ok_or_else(|| format_err!("version + i overflows"))?,
                    status
                ),
                TransactionStatus::Retry => {
                    seen_retry = true;
                    txns_to_retry.push(txn);
                    txn_infos_to_retry.push(txn_info);
                    continue;
                }
            };
            assert!(!seen_retry);
            let generated_txn_info = TransactionInfo::new(
                txn.hash(),
                txn_data.state_root_hash(),
                txn_data.event_root_hash(),
                txn_data.gas_used(),
                recorded_status.clone(),
            );
            ensure!(
                txn_info == generated_txn_info,
                "txn_info do not match for {}-th transaction in chunk.\nChunk txn_info: {}\nProof txn_info: {}",
                i, generated_txn_info, txn_info
            );
            txns_to_commit.push(TransactionToCommit::new(
                txn,
                txn_data.account_blobs().clone(),
                txn_data.events().to_vec(),
                txn_data.gas_used(),
                recorded_status,
            ));
            reconfig_events.append(&mut Self::extract_reconfig_events(
                txn_data.events().to_vec(),
            ));
        }

        Ok((
            output,
            txns_to_commit,
            reconfig_events,
            txns_to_retry,
            txn_infos_to_retry,
        ))
    }

    fn execute_chunk(
        &self, first_version: u64, transactions: Vec<Transaction>,
        transaction_infos: Vec<TransactionInfo>,
    ) -> Result<(
        ProcessedVMOutput,
        Vec<TransactionToCommit>,
        Vec<ContractEvent>,
    )> {
        let num_txns = transactions.len();

        let (
            processed_vm_output,
            txns_to_commit,
            events,
            txns_to_retry,
            _txn_infos_to_retry,
        ) = self.replay_transactions_impl(
            first_version,
            transactions,
            transaction_infos,
        )?;

        ensure!(
            txns_to_retry.is_empty(),
            "The transaction at version {} got the status of 'Retry'",
            num_txns
                .checked_sub(txns_to_retry.len())
                .ok_or_else(|| format_err!("integer overflow occurred"))?
                .checked_add(first_version as usize)
                .ok_or_else(|| format_err!("integer overflow occurred"))?,
        );

        Ok((processed_vm_output, txns_to_commit, events))
    }
}

impl<V: VMExecutor> ChunkExecutor for Executor<V> {
    fn execute_and_commit_chunk(
        &self,
        txn_list_with_proof: TransactionListWithProof,
        // Target LI that has been verified independently: the proofs are
        // relative to this version.
        verified_target_li: LedgerInfoWithSignatures,
        // An optional end of epoch LedgerInfo. We do not allow chunks that end
        // epoch without carrying any epoch change LI.
        epoch_change_li: Option<LedgerInfoWithSignatures>,
    ) -> Result<Vec<ContractEvent>> {
        let _timer =
            DIEM_EXECUTOR_EXECUTE_AND_COMMIT_CHUNK_SECONDS.start_timer();
        // 1. Update the cache in executor to be consistent with latest synced
        // state.
        // self.reset_cache()?;

        diem_info!(
            LogSchema::new(LogEntry::ChunkExecutor)
                .local_synced_version(
                    self.db_with_cache
                        .cache
                        .lock()
                        .synced_trees()
                        .txn_accumulator()
                        .num_leaves()
                        - 1
                )
                .first_version_in_request(
                    txn_list_with_proof.first_transaction_version
                )
                .num_txns_in_request(txn_list_with_proof.transactions.len()),
            "sync_request_received",
        );

        // 2. Verify input transaction list.
        let (transactions, transaction_infos) =
            self.verify_chunk(txn_list_with_proof, &verified_target_li)?;

        // 3. Execute transactions.
        let first_version = self
            .db_with_cache
            .cache
            .lock()
            .synced_trees()
            .txn_accumulator()
            .num_leaves();
        let (output, txns_to_commit, reconfig_events) =
            self.execute_chunk(first_version, transactions, transaction_infos)?;

        // 4. Commit to DB.
        let ledger_info_to_commit =
            Self::find_chunk_li(verified_target_li, epoch_change_li, &output)?;
        if ledger_info_to_commit.is_none() && txns_to_commit.is_empty() {
            return Ok(reconfig_events);
        }
        fail_point!("executor::commit_chunk", |_| {
            Err(anyhow::anyhow!("Injected error in commit_chunk"))
        });
        self.db_with_cache.db.writer.save_transactions(
            &txns_to_commit,
            first_version,
            ledger_info_to_commit.as_ref(),
            None,
            vec![],
            vec![],
        )?;

        // 5. Cache maintenance.
        let output_trees = output.executed_trees().clone();
        if let Some(ledger_info_with_sigs) = &ledger_info_to_commit {
            self.db_with_cache.update_block_tree_root(
                output_trees,
                ledger_info_with_sigs.ledger_info(),
                vec![],
                vec![],
            );
        } else {
            self.db_with_cache.update_synced_trees(output_trees);
        }
        self.db_with_cache.reset();

        diem_info!(
            LogSchema::new(LogEntry::ChunkExecutor)
                .synced_to_version(
                    self.db_with_cache
                        .cache
                        .lock()
                        .synced_trees()
                        .version()
                        .expect("version must exist")
                )
                .committed_with_ledger_info(ledger_info_to_commit.is_some()),
            "sync_finished",
        );

        Ok(reconfig_events)
    }
}

impl<V: VMExecutor> TransactionReplayer for Executor<V> {
    fn replay_chunk(
        &self, mut first_version: Version, mut txns: Vec<Transaction>,
        mut txn_infos: Vec<TransactionInfo>,
    ) -> Result<()> {
        ensure!(
            first_version
                == self
                    .db_with_cache
                    .cache
                    .lock()
                    .synced_trees()
                    .txn_accumulator()
                    .num_leaves(),
            "Version not expected. Expected: {}, got: {}",
            self.db_with_cache
                .cache
                .lock()
                .synced_trees()
                .txn_accumulator()
                .num_leaves(),
            first_version,
        );
        while !txns.is_empty() {
            let num_txns = txns.len();

            let (output, txns_to_commit, _, txns_to_retry, txn_infos_to_retry) =
                self.replay_transactions_impl(first_version, txns, txn_infos)?;
            assert!(txns_to_retry.len() < num_txns);

            self.db_with_cache.db.writer.save_transactions(
                &txns_to_commit,
                first_version,
                None,
                None,
                vec![],
                vec![],
            )?;

            self.db_with_cache
                .update_synced_trees(output.executed_trees().clone());

            txns = txns_to_retry;
            txn_infos = txn_infos_to_retry;
            first_version += txns_to_commit.len() as u64;
        }
        Ok(())
    }

    fn expecting_version(&self) -> Version {
        self.db_with_cache
            .cache
            .lock()
            .synced_trees()
            .version()
            .map_or(0, |v| v.checked_add(1).expect("Integer overflow occurred"))
    }
}

impl<V: VMExecutor> BlockExecutor for Executor<V> {
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
                V::execute_block(
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

            let (account_to_state, account_to_proof) = state_view.into();

            let output = self
                .process_vm_outputs(
                    account_to_state,
                    account_to_proof,
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
                let start_epoch = end_epoch
                    - POS_STATE_CONFIG.force_retire_check_epoch_count(
                        pos_state_to_commit.current_view(),
                    )
                    + 1;
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
                    txn_data.account_blobs().clone(),
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

        for block in blocks {
            block.output().executed_trees().state_tree().prune()
        }

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

/// For all accounts modified by this transaction, find the previous blob and
/// update it based on the write set. Returns the blob value of all these
/// accounts.
pub fn process_write_set(
    transaction: &Transaction,
    account_to_state: &mut HashMap<AccountAddress, AccountState>,
    write_set: WriteSet,
) -> Result<HashMap<AccountAddress, AccountStateBlob>> {
    let mut updated_blobs = HashMap::new();

    // Find all addresses this transaction touches while processing each write
    // op.
    let mut addrs = HashSet::new();
    for (access_path, write_op) in write_set.into_iter() {
        let address = access_path.address;
        let path = access_path.path;
        match account_to_state.entry(address) {
            hash_map::Entry::Occupied(mut entry) => {
                update_account_state(entry.get_mut(), path, write_op);
            }
            hash_map::Entry::Vacant(entry) => {
                // Before writing to an account, VM should always read that
                // account. So we should not reach this code
                // path. The exception is genesis transaction (and
                // maybe other writeset transactions).
                match transaction {
                    Transaction::GenesisTransaction(_) => (),
                    Transaction::BlockMetadata(_) => {
                        // bail!("BlockMetadata: Write set should be a subset of
                        // read set.")
                    }
                    Transaction::UserTransaction(txn) => match txn.payload() {
                        TransactionPayload::WriteSet(_) => (),
                        _ => bail!(
                            "Write set should be a subset of read set: {:?}.",
                            txn
                        ),
                    },
                }

                let mut account_state = Default::default();
                update_account_state(&mut account_state, path, write_op);
                entry.insert(account_state);
            }
        }
        addrs.insert(address);
    }

    for addr in addrs {
        let account_state =
            account_to_state.get(&addr).expect("Address should exist.");
        let account_blob = AccountStateBlob::try_from(account_state)?;
        updated_blobs.insert(addr, account_blob);
    }

    Ok(updated_blobs)
}

fn update_account_state(
    account_state: &mut AccountState, path: Vec<u8>, write_op: WriteOp,
) {
    match write_op {
        WriteOp::Value(new_value) => account_state.insert(path, new_value),
        WriteOp::Deletion => account_state.remove(&path),
    };
}
