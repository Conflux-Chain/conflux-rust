// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::pos::mempool::{
    core_mempool::{
        index::{
            AccountTransactionIter, AccountTransactions, TTLIndex,
            TimelineIndex,
        },
        transaction::{MempoolTransaction, TimelineState},
    },
    logging::{LogEntry, LogEvent, LogSchema, TxnsLog},
};
use diem_config::config::MempoolConfig;
use diem_crypto::{hash::CryptoHash, HashValue};
use diem_logger::prelude::*;
use diem_types::{
    account_address::AccountAddress,
    mempool_status::{MempoolStatus, MempoolStatusCode},
    transaction::{SignedTransaction, TransactionPayload},
};
use std::collections::{hash_map::Values, HashMap, HashSet};

/// TransactionStore is in-memory storage for all transactions in mempool.
pub struct TransactionStore {
    // normal transactions
    transactions: AccountTransactions,
    // pivot decision helper structure
    pivot_decisions: HashMap<HashValue, HashSet<(AccountAddress, HashValue)>>,

    // TTL keyed on `MempoolTransaction.expiration_time = add_time +
    // system_transaction_timeout`. Every txn is evicted after the timeout,
    // regardless of its payload — keeps old txns from clogging the mempool
    // when commit callbacks are delayed.
    system_ttl_index: TTLIndex,
    timeline_index: TimelineIndex,
}

pub type PivotDecisionIter<'a> =
    Values<'a, HashValue, HashSet<(AccountAddress, HashValue)>>;

impl TransactionStore {
    pub(crate) fn new(_config: &MempoolConfig) -> Self {
        Self {
            // main DS
            transactions: AccountTransactions::new(),
            pivot_decisions: HashMap::new(),

            // various indexes
            system_ttl_index: TTLIndex::new(Box::new(
                |t: &MempoolTransaction| t.expiration_time,
            )),
            timeline_index: TimelineIndex::new(),
        }
    }

    /// Fetch transaction by account address + hash.
    pub(crate) fn get(&self, hash: &HashValue) -> Option<SignedTransaction> {
        if let Some(txn) = self.transactions.get(hash) {
            return Some(txn.txn.clone());
        }
        None
    }

    /// Fetch pivot decisions by pivot hash.
    pub(crate) fn get_pivot_decisions(
        &self, hash: &HashValue,
    ) -> Vec<HashValue> {
        if let Some(decisions) = self.pivot_decisions.get(hash) {
            decisions
                .iter()
                .map(|(_, tx_hash)| tx_hash.clone())
                .collect::<_>()
        } else {
            vec![]
        }
    }

    /// Insert transaction into TransactionStore. Performs validation checks and
    /// updates indexes.
    pub(crate) fn insert(
        &mut self, mut txn: MempoolTransaction,
    ) -> MempoolStatus {
        let address = txn.get_sender();
        let hash = txn.get_hash();
        let has_tx = self.get(&hash).is_some();

        if has_tx {
            return MempoolStatus::new(MempoolStatusCode::Accepted);
        }

        self.timeline_index.insert(&mut txn);
        self.system_ttl_index.insert(&txn);

        let payload = txn.txn.clone().into_raw_transaction().into_payload();
        if let TransactionPayload::PivotDecision(pivot_decision) = payload {
            let pivot_decision_hash = pivot_decision.hash();
            self.pivot_decisions
                .entry(pivot_decision_hash)
                .or_insert_with(HashSet::new);
            if let Some(account_decision) =
                self.pivot_decisions.get_mut(&pivot_decision_hash)
            {
                diem_debug!("txpool::insert pivot {:?}", hash);
                account_decision.insert((address, hash));
            }
            self.transactions.insert(hash, txn, true);
        } else {
            self.transactions.insert(hash, txn, false);
        }
        diem_debug!(
            LogSchema::new(LogEntry::AddTxn)
                .txns(TxnsLog::new_txn(address, hash)),
            hash = hash,
            has_tx = has_tx
        );

        MempoolStatus::new(MempoolStatusCode::Accepted)
    }

    /// Handles transaction commit: deletes the transaction and cleans up
    /// its entries in the timeline and TTL indexes.
    pub(crate) fn commit_transaction(&mut self, hash: HashValue) {
        let mut txns_log = TxnsLog::new();
        if let Some(transaction) = self.transactions.remove(&hash) {
            txns_log.add(transaction.get_sender(), transaction.get_hash());
            self.index_remove(&transaction);
            // handle pivot decision
            let payload = transaction.txn.into_raw_transaction().into_payload();
            if let TransactionPayload::PivotDecision(pivot_decision) = payload {
                let pivot_decision_hash = pivot_decision.hash();
                if let Some(indices) =
                    self.pivot_decisions.remove(&pivot_decision_hash)
                {
                    for (_, hash) in indices {
                        if let Some(txn) = self.transactions.remove(&hash) {
                            txns_log.add(txn.get_sender(), txn.get_hash());
                            self.index_remove(&txn);
                        }
                    }
                }
            }
        }
        diem_debug!(LogSchema::new(LogEntry::CleanCommittedTxn).txns(txns_log));
    }

    /// Removes transaction from all indexes.
    fn index_remove(&mut self, txn: &MempoolTransaction) {
        self.system_ttl_index.remove(&txn);
        self.timeline_index.remove(&txn);
    }

    /// Read `count` transactions from timeline since `timeline_id`.
    /// Returns block of transactions and new last_timeline_id.
    pub(crate) fn read_timeline(
        &mut self, timeline_id: u64, count: usize,
    ) -> (Vec<SignedTransaction>, u64) {
        let mut batch = vec![];
        let mut last_timeline_id = timeline_id;
        for (_, hash) in self.timeline_index.read_timeline(timeline_id, count) {
            if let Some(txn) = self.transactions.get(&hash) {
                batch.push(txn.txn.clone());
                if let TimelineState::Ready(timeline_id) = txn.timeline_state {
                    last_timeline_id = timeline_id;
                }
            }
        }
        (batch, last_timeline_id)
    }

    pub(crate) fn timeline_range(
        &mut self, start_id: u64, end_id: u64,
    ) -> Vec<SignedTransaction> {
        self.timeline_index
            .timeline_range(start_id, end_id)
            .iter()
            .filter_map(|(_, hash)| {
                self.transactions.get(hash).map(|txn| txn.txn.clone())
            })
            .collect()
    }

    /// Garbage collect old transactions by system TTL.
    pub(crate) fn gc_by_system_ttl(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time is before UNIX_EPOCH");

        let mut gc_txns = self.system_ttl_index.gc(now);
        gc_txns.sort_by_key(|key| (key.address, key.hash));

        let mut gc_txns_log = TxnsLog::new();
        for key in gc_txns.iter() {
            if let Some(txn) = self.transactions.remove(&key.hash) {
                gc_txns_log.add(txn.get_sender(), txn.get_hash());
                self.index_remove(&txn);
                if let TransactionPayload::PivotDecision(pivot_decision) =
                    txn.txn.into_raw_transaction().into_payload()
                {
                    self.pivot_decisions.remove(&pivot_decision.hash());
                }
            }
        }

        diem_debug!(LogSchema::event_log(
            LogEntry::GCRemoveTxns,
            LogEvent::SystemTTLExpiration
        )
        .txns(gc_txns_log));
    }

    pub(crate) fn iter(&self) -> AccountTransactionIter<'_> {
        self.transactions.iter()
    }

    pub(crate) fn iter_pivot_decision(&self) -> PivotDecisionIter<'_> {
        self.pivot_decisions.values()
    }
}
