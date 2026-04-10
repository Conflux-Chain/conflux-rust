// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

use std::{cmp::max, sync::Arc};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use diem_crypto::{hash::TransactionAccumulatorHasher, HashValue};
use diem_types::{
    block_info::PivotBlockDecision,
    contract_event::ContractEvent,
    epoch_state::EpochState,
    ledger_info::LedgerInfoWithSignatures,
    proof::{accumulator::InMemoryAccumulator, AccumulatorExtensionProof},
    term_state::PosState,
    transaction::{Transaction, TransactionStatus, Version},
    validator_config::ConsensusSignature,
};
pub use error::Error;
use storage_interface::TreeState;

pub use self::processed_vm_output::{ProcessedVMOutput, TransactionData};

mod error;
mod processed_vm_output;

pub trait BlockExecutor: Send {
    /// Get the latest committed block id
    fn committed_block_id(&self) -> Result<HashValue, Error>;

    /// Executes a block.
    fn execute_block(
        &self, block: (HashValue, Vec<Transaction>),
        parent_block_id: HashValue, catch_up_mode: bool,
    ) -> Result<StateComputeResult, Error>;

    /// Saves eligible blocks to persistent storage.
    /// If we have multiple blocks and not all of them have signatures, we may
    /// send them to storage in a few batches. For example, if we have
    /// ```text
    /// A <- B <- C <- D <- E
    /// ```
    /// and only `C` and `E` have signatures, we will send `A`, `B` and `C` in
    /// the first batch, then `D` and `E` later in the another batch.
    /// Commits a block and all its ancestors in a batch manner.
    ///
    /// Returns `Ok(Result<Vec<Transaction>, Vec<ContractEvents>)` if
    /// successful, where `Vec<Transaction>` is a vector of transactions that
    /// were kept from the submitted blocks, and `Vec<ContractEvents>` is a
    /// vector of reconfiguration events in the submitted blocks
    fn commit_blocks(
        &self, block_ids: Vec<HashValue>,
        ledger_info_with_sigs: LedgerInfoWithSignatures,
    ) -> Result<(Vec<Transaction>, Vec<ContractEvent>), Error>;
}

/// A structure that summarizes the result of the execution needed for consensus
/// to agree on. The execution is responsible for generating the ID of the new
/// state, which is returned in the result.
///
/// Not every transaction in the payload succeeds: the returned vector keeps the
/// boolean status of success / failure of the transactions.
/// Note that the specific details of compute_status are opaque to
/// StateMachineReplication, which is going to simply pass the results between
/// StateComputer and TxnManager.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct StateComputeResult {
    /// transaction accumulator root hash is identified as `state_id` in
    /// Consensus.
    root_hash: HashValue,
    /// Represents the roots of all the full subtrees from left to right in
    /// this accumulator after the execution.
    frozen_subtree_roots: Vec<HashValue>,

    /// The frozen subtrees roots of the parent block,
    parent_frozen_subtree_roots: Vec<HashValue>,

    /// The number of leaves of the transaction accumulator after executing a
    /// proposed block. This state must be persisted to ensure that on
    /// restart that the version is calculated correctly.
    num_leaves: u64,

    /// The number of leaves after executing the parent block,
    parent_num_leaves: u64,

    /// If set, this is the new epoch info that should be changed to if this
    /// block is committed.
    epoch_state: Option<EpochState>,
    /// The compute status (success/failure) of the given payload. The specific
    /// details are opaque for StateMachineReplication, which is merely
    /// passing it between StateComputer and TxnManager.
    compute_status: Vec<TransactionStatus>,

    /// The transaction info hashes of all success txns.
    transaction_info_hashes: Vec<HashValue>,

    /// The signature of the VoteProposal corresponding to this block.
    signature: Option<ConsensusSignature>,

    /// Tracks the last pivot selection of a proposed block
    pivot_decision: Option<PivotBlockDecision>,
}

impl StateComputeResult {
    pub fn new(
        root_hash: HashValue, frozen_subtree_roots: Vec<HashValue>,
        num_leaves: u64, parent_frozen_subtree_roots: Vec<HashValue>,
        parent_num_leaves: u64, epoch_state: Option<EpochState>,
        compute_status: Vec<TransactionStatus>,
        transaction_info_hashes: Vec<HashValue>,
        pivot_decision: Option<PivotBlockDecision>,
    ) -> Self {
        Self {
            root_hash,
            frozen_subtree_roots,
            num_leaves,
            parent_frozen_subtree_roots,
            parent_num_leaves,
            epoch_state,
            compute_status,
            transaction_info_hashes,
            signature: None,
            pivot_decision,
        }
    }
}

impl StateComputeResult {
    pub fn version(&self) -> Version {
        max(self.num_leaves, 1)
            .checked_sub(1)
            .expect("Integer overflow occurred")
    }

    pub fn root_hash(&self) -> HashValue { self.root_hash }

    pub fn compute_status(&self) -> &Vec<TransactionStatus> {
        &self.compute_status
    }

    pub fn epoch_state(&self) -> &Option<EpochState> { &self.epoch_state }

    pub fn extension_proof(
        &self,
    ) -> AccumulatorExtensionProof<TransactionAccumulatorHasher> {
        AccumulatorExtensionProof::<TransactionAccumulatorHasher>::new(
            self.parent_frozen_subtree_roots.clone(),
            self.parent_num_leaves(),
            self.transaction_info_hashes().clone(),
        )
    }

    pub fn transaction_info_hashes(&self) -> &Vec<HashValue> {
        &self.transaction_info_hashes
    }

    pub fn num_leaves(&self) -> u64 { self.num_leaves }

    pub fn frozen_subtree_roots(&self) -> &Vec<HashValue> {
        &self.frozen_subtree_roots
    }

    pub fn parent_num_leaves(&self) -> u64 { self.parent_num_leaves }

    pub fn parent_frozen_subtree_roots(&self) -> &Vec<HashValue> {
        &self.parent_frozen_subtree_roots
    }

    pub fn pivot_decision(&self) -> &Option<PivotBlockDecision> {
        &self.pivot_decision
    }

    pub fn has_reconfiguration(&self) -> bool { self.epoch_state.is_some() }

    pub fn signature(&self) -> &Option<ConsensusSignature> { &self.signature }

    pub fn set_signature(&mut self, sig: ConsensusSignature) {
        self.signature = Some(sig);
    }
}

/// A wrapper of the transaction accumulator and PoS state that represent a
/// specific blockchain state collectively. Usually it is a state after
/// executing a block.
#[derive(Clone, Debug)]
pub struct ExecutedTrees {
    /// The in-memory Merkle Accumulator representing the blockchain state.
    transaction_accumulator:
        Arc<InMemoryAccumulator<TransactionAccumulatorHasher>>,

    pos_state: PosState,
}

impl From<TreeState> for ExecutedTrees {
    fn from(tree_state: TreeState) -> Self {
        ExecutedTrees::new(
            tree_state.ledger_frozen_subtree_hashes,
            tree_state.num_transactions,
            PosState::new_empty(),
        )
    }
}

impl ExecutedTrees {
    pub fn new_with_pos_state(
        tree_state: TreeState, pos_state: PosState,
    ) -> Self {
        ExecutedTrees::new(
            tree_state.ledger_frozen_subtree_hashes,
            tree_state.num_transactions,
            pos_state,
        )
    }

    pub fn new_copy(
        transaction_accumulator: Arc<
            InMemoryAccumulator<TransactionAccumulatorHasher>,
        >,
        pos_state: PosState,
    ) -> Self {
        Self {
            transaction_accumulator,
            pos_state,
        }
    }

    pub fn pos_state(&self) -> &PosState { &self.pos_state }

    pub fn txn_accumulator(
        &self,
    ) -> &Arc<InMemoryAccumulator<TransactionAccumulatorHasher>> {
        &self.transaction_accumulator
    }

    pub fn version(&self) -> Option<Version> {
        let num_elements = self.txn_accumulator().num_leaves() as u64;
        num_elements.checked_sub(1)
    }

    pub fn state_id(&self) -> HashValue { self.txn_accumulator().root_hash() }

    pub fn new(
        frozen_subtrees_in_accumulator: Vec<HashValue>,
        num_leaves_in_accumulator: u64, pos_state: PosState,
    ) -> ExecutedTrees {
        ExecutedTrees {
            transaction_accumulator: Arc::new(
                InMemoryAccumulator::new(
                    frozen_subtrees_in_accumulator,
                    num_leaves_in_accumulator,
                )
                .expect("The startup info read from storage should be valid."),
            ),
            pos_state,
        }
    }

    pub fn new_empty() -> ExecutedTrees {
        Self::new(vec![], 0, PosState::new_empty())
    }

    pub fn set_pos_state_skipped(&mut self, skipped: bool) {
        self.pos_state.set_skipped(skipped)
    }
}
