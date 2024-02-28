// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! Mempool is used to track transactions which have been submitted but not yet
//! agreed upon.
use crate::pos::mempool::{
    core_mempool::{
        index::TxnPointer,
        transaction::{MempoolTransaction, TimelineState},
        transaction_store::TransactionStore,
        ttl_cache::TtlCache,
    },
    counters,
    logging::{LogEntry, LogSchema, TxnsLog},
};
use diem_config::config::NodeConfig;
use diem_crypto::{hash::CryptoHash, HashValue};
use diem_logger::prelude::*;
use diem_types::{
    account_address::AccountAddress,
    mempool_status::MempoolStatus,
    term_state::PosState,
    transaction::{
        authenticator::TransactionAuthenticator, GovernanceRole,
        SignedTransaction, TransactionPayload,
    },
    validator_verifier::ValidatorVerifier,
};
use executor::vm::verify_dispute;
use std::{
    collections::HashSet,
    time::{Duration, SystemTime},
};

pub struct Mempool {
    // Stores the metadata of all transactions in mempool (of all states).
    pub transactions: TransactionStore,

    // For each transaction, an entry with a timestamp is added when the
    // transaction enters mempool. This is used to measure e2e latency of
    // transactions in the system, as well as the time it takes to pick it
    // up by consensus.
    pub(crate) metrics_cache: TtlCache<(AccountAddress, HashValue), SystemTime>,
    pub system_transaction_timeout: Duration,
}

impl Mempool {
    pub fn new(config: &NodeConfig) -> Self {
        Mempool {
            transactions: TransactionStore::new(&config.mempool),
            metrics_cache: TtlCache::new(
                config.mempool.capacity,
                Duration::from_secs(100),
            ),
            system_transaction_timeout: Duration::from_secs(
                config.mempool.system_transaction_timeout_secs,
            ),
        }
    }

    /// This function will be called once the transaction has been stored.
    pub(crate) fn remove_transaction(
        &mut self, sender: &AccountAddress, hash: HashValue, is_rejected: bool,
    ) {
        diem_trace!(
            LogSchema::new(LogEntry::RemoveTxn)
                .txns(TxnsLog::new_txn(*sender, hash)),
            is_rejected = is_rejected
        );
        let metric_label = if is_rejected {
            counters::COMMIT_REJECTED_LABEL
        } else {
            counters::COMMIT_ACCEPTED_LABEL
        };
        self.log_latency(*sender, hash, metric_label);
        self.metrics_cache.remove(&(*sender, hash));

        if is_rejected {
            self.transactions.reject_transaction(&sender, hash);
        } else {
            self.transactions.commit_transaction(&sender, hash);
        }
    }

    fn log_latency(
        &mut self, account: AccountAddress, hash: HashValue, metric: &str,
    ) {
        if let Some(&creation_time) = self.metrics_cache.get(&(account, hash)) {
            if let Ok(time_delta) =
                SystemTime::now().duration_since(creation_time)
            {
                counters::CORE_MEMPOOL_TXN_COMMIT_LATENCY
                    .with_label_values(&[metric])
                    .observe(time_delta.as_secs_f64());
            }
        }
    }

    /// Used to add a transaction to the Mempool.
    /// Performs basic validation: checks account's sequence number.
    pub(crate) fn add_txn(
        &mut self, txn: SignedTransaction, ranking_score: u64,
        timeline_state: TimelineState, governance_role: GovernanceRole,
    ) -> MempoolStatus {
        diem_trace!(LogSchema::new(LogEntry::AddTxn)
            .txns(TxnsLog::new_txn(txn.sender(), txn.hash())),);

        let expiration_time = diem_infallible::duration_since_epoch()
            + self.system_transaction_timeout;
        if timeline_state != TimelineState::NonQualified {
            self.metrics_cache
                .insert((txn.sender(), txn.hash()), SystemTime::now());
        }

        let txn_info = MempoolTransaction::new(
            txn,
            expiration_time,
            ranking_score,
            timeline_state,
            governance_role,
        );

        self.transactions.insert(txn_info)
    }

    /// Fetches next block of transactions for consensus.
    /// `batch_size` - size of requested block.
    /// `seen_txns` - transactions that were sent to Consensus but were not
    /// committed yet,  mempool should filter out such transactions.
    #[allow(clippy::explicit_counter_loop)]
    pub(crate) fn get_block(
        &mut self, _batch_size: u64, mut seen: HashSet<TxnPointer>,
        pos_state: &PosState, validators: ValidatorVerifier,
    ) -> Vec<SignedTransaction> {
        let mut block = vec![];
        let mut block_log = TxnsLog::new();
        // Helper DS. Helps to mitigate scenarios where account submits several
        // transactions with increasing gas price (e.g. user submits
        // transactions with sequence number 1, 2 and gas_price 1, 10
        // respectively) Later txn has higher gas price and will be
        // observed first in priority index iterator, but can't be
        // executed before first txn. Once observed, such txn will be saved in
        // `skipped` DS and rechecked once it's ancestor becomes available
        let seen_size = seen.len();
        let mut txn_walked = 0usize;
        // iterate all normal transaction
        for txn in self.transactions.iter() {
            txn_walked += 1;
            if seen.contains(&TxnPointer::from(txn)) {
                continue;
            }
            let validate_result = match txn.txn.payload() {
                TransactionPayload::Election(election_payload) => {
                    pos_state.validate_election(election_payload)
                }
                TransactionPayload::PivotDecision(_) => {
                    seen.insert((txn.get_sender(), txn.get_hash()));
                    continue;
                }
                TransactionPayload::Dispute(dispute_payload) => {
                    // TODO(lpl): Only dispute a node once.
                    pos_state.validate_dispute(dispute_payload).and(
                        verify_dispute(dispute_payload)
                            .then_some(())
                            .ok_or(anyhow::anyhow!("invalid dispute")),
                    )
                }
                _ => {
                    continue;
                }
            };
            if validate_result.is_ok() {
                block.push(txn.txn.clone());
                block_log.add(txn.get_sender(), txn.get_hash());
                seen.insert((txn.get_sender(), txn.get_hash()));
            }
        }
        let mut max_pivot_height = 0;
        let mut chosen_pivot_tx = None;
        // iterate all pivot decision transaction
        for pivot_decision_set in self.transactions.iter_pivot_decision() {
            let mut pivot_decision_opt = None;
            diem_debug!("get_block: 0 {:?}", pivot_decision_set.len());
            for (account, hash) in pivot_decision_set.iter() {
                if validators.get_public_key(account).is_some() {
                    if pivot_decision_opt.is_none() {
                        if let Some(txn) = self.transactions.get(hash) {
                            pivot_decision_opt = Some(txn);
                        }
                    }
                }
            }
            diem_debug!("get_block: 1 {:?}", pivot_decision_opt);
            if validators
                .check_voting_power(
                    pivot_decision_set.iter().map(|(addr, _)| addr),
                )
                .is_ok()
            {
                let pivot_decision = pivot_decision_opt.unwrap();
                let pivot_height = match pivot_decision.payload() {
                    TransactionPayload::PivotDecision(decision) => {
                        decision.height
                    }
                    _ => unreachable!(),
                };
                if pivot_height > max_pivot_height
                    && pivot_height > pos_state.pivot_decision().height
                {
                    max_pivot_height = pivot_height;
                    chosen_pivot_tx = Some(pivot_decision);
                }
            }
            diem_debug!("get_block: 2 {:?}", chosen_pivot_tx);
        }
        if let Some(tx) = chosen_pivot_tx {
            let pivot_decision_hash = match tx.payload() {
                TransactionPayload::PivotDecision(decision) => decision.hash(),
                _ => unreachable!(),
            };
            // aggregate signatures
            let txn_hashes =
                self.transactions.get_pivot_decisions(&pivot_decision_hash);
            let senders: Vec<AccountAddress> =
                validators.get_ordered_account_addresses_iter().collect();
            let mut signatures = vec![];
            for hash in &txn_hashes {
                if let Some(txn) = self.transactions.get(hash) {
                    match txn.authenticator() {
                        TransactionAuthenticator::BLS { signature, .. } => {
                            if let Ok(index) =
                                senders.binary_search(&txn.sender())
                            {
                                signatures.push((signature, index));
                            }
                        }
                        _ => unreachable!(),
                    }
                }
            }
            let new_tx =
                SignedTransaction::new_multisig(tx.raw_txn(), signatures);
            block_log.add(new_tx.sender(), new_tx.hash());
            block.push(new_tx);
        }

        diem_debug!(
            LogSchema::new(LogEntry::GetBlock).txns(block_log),
            seen_consensus = seen_size,
            walked = txn_walked,
            seen_after = seen.len(),
            result_size = block.len(),
            block_size = block.len()
        );
        for transaction in &block {
            self.log_latency(
                transaction.sender(),
                transaction.hash(),
                counters::GET_BLOCK_STAGE_LABEL,
            );
        }
        block
    }

    /// Periodic core mempool garbage collection.
    /// Removes all expired transactions and clears expired entries in metrics
    /// cache and sequence number cache.
    pub(crate) fn gc(&mut self) {
        let now = SystemTime::now();
        self.transactions.gc_by_system_ttl(&self.metrics_cache);
        self.metrics_cache.gc(now);
    }

    /// Garbage collection based on client-specified expiration time.
    pub(crate) fn gc_by_expiration_time(&mut self, block_time: Duration) {
        self.transactions
            .gc_by_expiration_time(block_time, &self.metrics_cache);
    }

    /// Read `count` transactions from timeline since `timeline_id`.
    /// Returns block of transactions and new last_timeline_id.
    pub(crate) fn read_timeline(
        &mut self, timeline_id: u64, count: usize,
    ) -> (Vec<SignedTransaction>, u64) {
        self.transactions.read_timeline(timeline_id, count)
    }

    /// Read transactions from timeline from `start_id` (exclusive) to `end_id`
    /// (inclusive).
    pub(crate) fn timeline_range(
        &mut self, start_id: u64, end_id: u64,
    ) -> Vec<SignedTransaction> {
        self.transactions.timeline_range(start_id, end_id)
    }
}
