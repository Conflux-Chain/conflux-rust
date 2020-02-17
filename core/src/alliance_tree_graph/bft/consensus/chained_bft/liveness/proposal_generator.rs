// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::super::super::{
    chained_bft::block_storage::BlockReader,
    consensus_types::{
        block::Block,
        block_data::BlockData,
        common::{Author, Payload, Round},
        quorum_cert::QuorumCert,
    },
    counters,
    util::time_service::{
        wait_if_possible, TimeService, WaitingError, WaitingSuccess,
    },
};
use anyhow::{bail, ensure, format_err};
//use libra_logger::prelude::*;
use crate::{
    alliance_tree_graph::bft::consensus::state_replication::TxnTransformer,
    sync::SharedSynchronizationService,
};
use futures::channel::oneshot;
use keylib::KeyPair;
use libra_types::{
    block_info::PivotBlockDecision,
    contract_event::ContractEvent,
    language_storage::TypeTag,
    transaction::{ChangeSet, RawTransaction},
    write_set::WriteSet,
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// ProposalGenerator is responsible for generating the proposed block on
/// demand: it's typically used by a validator that believes it's a valid
/// candidate for serving as a proposer at a given round.
/// ProposalGenerator is the one choosing the branch to extend:
/// - round is given by the caller (typically determined by Pacemaker).
/// The transactions for the proposed block are delivered by TxnManager.
///
/// TxnManager should be aware of the pending transactions in the branch that it
/// is extending, such that it will filter them out to avoid transaction
/// duplication.
pub struct ProposalGenerator<TT, T> {
    // The account address of this validator
    author: Author,
    // Block store is queried both for finding the branch to extend and for
    // generating the proposed block.
    block_store: Arc<dyn BlockReader<Payload = T> + Send + Sync>,
    // Transaction manager is delivering the transactions.
    txn_transformer: TT,
    // Time service to generate block timestamps
    time_service: Arc<dyn TimeService>,
    // Max number of transactions to be added to a proposed block.
    // max_block_size: u64,
    // Last round that a proposal was generated
    last_round_generated: Mutex<Round>,
    // TreeGraph synchronization service.
    tg_sync: SharedSynchronizationService,
    key_pair: KeyPair,
}

impl<TT, T> ProposalGenerator<TT, T>
where
    TT: TxnTransformer<Payload = T>,
    T: Payload,
{
    pub fn new(
        author: Author,
        block_store: Arc<dyn BlockReader<Payload = T> + Send + Sync>,
        txn_transformer: TT, time_service: Arc<dyn TimeService>,
        _max_block_size: u64, tg_sync: SharedSynchronizationService,
        key_pair: KeyPair,
    ) -> Self
    {
        Self {
            author,
            block_store,
            txn_transformer,
            time_service,
            //max_block_size,
            last_round_generated: Mutex::new(0),
            tg_sync,
            key_pair,
        }
    }

    pub fn author(&self) -> Author { self.author }

    /// Creates a NIL block proposal extending the highest certified block from
    /// the block store.
    pub fn generate_nil_block(&self, round: Round) -> anyhow::Result<Block<T>> {
        let hqc = self.ensure_highest_quorum_cert(round)?;
        Ok(Block::new_nil(round, hqc.as_ref().clone()))
    }

    /// Reconfiguration rule - we propose empty blocks with parents' timestamp
    /// after reconfiguration until it's committed
    pub fn generate_reconfig_empty_suffix(
        &self, round: Round,
    ) -> anyhow::Result<BlockData<T>> {
        let hqc = self.ensure_highest_quorum_cert(round)?;
        Ok(BlockData::new_proposal(
            T::default(),
            self.author,
            round,
            hqc.certified_block().timestamp_usecs(),
            hqc.as_ref().clone(),
        ))
    }

    /// The function generates a new proposal block: the returned future is
    /// fulfilled when the payload is delivered by the TxnManager
    /// implementation.  At most one proposal can be generated per round (no
    /// proposal equivocation allowed). Errors returned by the TxnManager
    /// implementation are propagated to the caller. The logic for choosing
    /// the branch to extend is as follows: 1. The function gets the highest
    /// head of a one-chain from block tree. The new proposal must extend
    /// hqc to ensure optimistic responsiveness. 2. The round is provided by
    /// the caller. 3. In case a given round is not greater than the
    /// calculated parent, return an OldRound error.
    pub async fn generate_proposal(
        &mut self, round: Round, round_deadline: Instant,
    ) -> anyhow::Result<BlockData<T>> {
        {
            let mut last_round_generated =
                self.last_round_generated.lock().unwrap();
            if *last_round_generated < round {
                *last_round_generated = round;
            } else {
                bail!("Already proposed in the round {}", round);
            }
        }

        let hqc = self.ensure_highest_quorum_cert(round)?;

        if hqc.certified_block().has_reconfiguration() {
            return self.generate_reconfig_empty_suffix(round);
        }

        // One needs to hold the blocks with the references to the payloads
        // while get_block is being executed: pending blocks vector
        // keeps all the pending ancestors of the extended branch.
        let pending_blocks = self
            .block_store
            .path_from_root(hqc.certified_block().id())
            .ok_or_else(|| {
                format_err!("HQC {} already pruned", hqc.certified_block().id())
            })?;

        // Exclude all the pending transactions: these are all the ancestors of
        // parent (including) up to the root (excluding).
        /*
        let exclude_payload: Vec<&T> = pending_blocks
            .iter()
            .flat_map(|block| block.payload())
            .collect();
            */

        let block_timestamp = {
            match wait_if_possible(
                self.time_service.as_ref(),
                Duration::from_micros(hqc.certified_block().timestamp_usecs()),
                round_deadline,
            )
            .await
            {
                Ok(waiting_success) => {
                    debug!(
                        "Success with {:?} for getting a valid timestamp for the next proposal",
                        waiting_success
                    );

                    match waiting_success {
                        WaitingSuccess::WaitWasRequired {
                            current_duration_since_epoch,
                            wait_duration,
                        } => {
                            counters::PROPOSAL_SUCCESS_WAIT_S
                                .observe_duration(wait_duration);
                            counters::PROPOSALS_GENERATED_COUNT
                                .with_label_values(&["wait_was_required"])
                                .inc();
                            current_duration_since_epoch
                        }
                        WaitingSuccess::NoWaitRequired {
                            current_duration_since_epoch,
                            ..
                        } => {
                            counters::PROPOSAL_SUCCESS_WAIT_S
                                .observe_duration(Duration::new(0, 0));
                            counters::PROPOSALS_GENERATED_COUNT
                                .with_label_values(&["no_wait_required"])
                                .inc();
                            current_duration_since_epoch
                        }
                    }
                }
                Err(waiting_error) => {
                    match waiting_error {
                        WaitingError::MaxWaitExceeded => {
                            counters::PROPOSAL_FAILURE_WAIT_S
                                .observe_duration(Duration::new(0, 0));
                            counters::PROPOSALS_GENERATED_COUNT
                                .with_label_values(&["max_wait_exceeded"])
                                .inc();
                            bail!(
                                "Waiting until parent block timestamp usecs {:?} would exceed the round duration {:?}, hence will not create a proposal for this round",
                                hqc.certified_block().timestamp_usecs(),
                                round_deadline);
                        }
                        WaitingError::WaitFailed {
                            current_duration_since_epoch,
                            wait_duration,
                        } => {
                            counters::PROPOSAL_FAILURE_WAIT_S
                                .observe_duration(wait_duration);
                            counters::PROPOSALS_GENERATED_COUNT
                                .with_label_values(&["wait_failed"])
                                .inc();
                            bail!(
                                "Even after waiting for {:?}, parent block timestamp usecs {:?} >= current timestamp usecs {:?}, will not create a proposal for this round",
                                wait_duration,
                                hqc.certified_block().timestamp_usecs(),
                                current_duration_since_epoch);
                        }
                    };
                }
            }
        };

        let parent_block = if let Some(p) = pending_blocks.last() {
            p.clone()
        } else {
            self.block_store.root()
        };
        let (callback, cb_receiver) = oneshot::channel();
        let last_pivot_hash =
            if let Some(p) = parent_block.output().pivot_block() {
                Some(&p.block_hash)
            } else {
                None
            };
        self.tg_sync
            .get_next_selected_pivot_block(last_pivot_hash, callback);

        let response = cb_receiver.await?;
        let pivot_decision = match response {
            Ok(res) => res,
            _ => {
                bail!("Error getting the next selected pivot block");
            }
        };

        let event_data = lcs::to_bytes(&pivot_decision)?;
        let event = ContractEvent::new(
            PivotBlockDecision::pivot_select_event_key(),
            0, /* sequence_number */
            TypeTag::ByteArray,
            event_data,
        );

        let change_set = ChangeSet::new(WriteSet::default(), vec![event]);
        let raw_tx = RawTransaction::new_change_set(self.author, 0, change_set);
        let signed_tx = raw_tx
            .sign(self.key_pair.secret(), self.key_pair.public().clone())?
            .into_inner();

        let txns = self.txn_transformer.convert(signed_tx);

        /*
        let txns = self
            .txn_manager
            .pull_txns(self.max_block_size, exclude_payload)
            .await
            .context("Fail to retrieve txn")?;
            */

        Ok(BlockData::new_proposal(
            txns,
            self.author,
            round,
            block_timestamp.as_micros() as u64,
            hqc.as_ref().clone(),
        ))
    }

    fn ensure_highest_quorum_cert(
        &self, round: Round,
    ) -> anyhow::Result<Arc<QuorumCert>> {
        let hqc = self.block_store.highest_quorum_cert();
        ensure!(
            hqc.certified_block().round() < round,
            "Given round {} is lower than hqc round {}",
            round,
            hqc.certified_block().round()
        );
        ensure!(
            !hqc.ends_epoch(),
            "The epoch has already ended,a proposal is not allowed to generated"
        );

        Ok(hqc)
    }
}
