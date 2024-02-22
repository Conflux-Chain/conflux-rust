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
        ttl_cache::TtlCache,
    },
    counters,
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
use std::{
    collections::{hash_map::Values, HashMap, HashSet},
    time::{Duration, SystemTime},
};

/// TransactionStore is in-memory storage for all transactions in mempool.
pub struct TransactionStore {
    // normal transactions
    transactions: AccountTransactions,
    // pivot decision helper structure
    pivot_decisions: HashMap<HashValue, HashSet<(AccountAddress, HashValue)>>,

    // TTLIndex based on client-specified expiration time
    expiration_time_index: TTLIndex,
    // TTLIndex based on system expiration time
    // we keep it separate from `expiration_time_index` so Mempool can't be
    // clogged  by old transactions even if it hasn't received commit
    // callbacks for a while
    system_ttl_index: TTLIndex,
    timeline_index: TimelineIndex,

    // configuration
    _capacity: usize,
}

pub type PivotDecisionIter<'a> =
    Values<'a, HashValue, HashSet<(AccountAddress, HashValue)>>;

impl TransactionStore {
    pub(crate) fn new(config: &MempoolConfig) -> Self {
        Self {
            // main DS
            transactions: AccountTransactions::new(),
            pivot_decisions: HashMap::new(),

            // various indexes
            system_ttl_index: TTLIndex::new(Box::new(
                |t: &MempoolTransaction| t.expiration_time,
            )),
            expiration_time_index: TTLIndex::new(Box::new(
                |t: &MempoolTransaction| {
                    Duration::from_secs(t.txn.expiration_timestamp_secs())
                },
            )),
            timeline_index: TimelineIndex::new(),

            // configuration
            _capacity: config.capacity,
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

        // TODO(linxi): evict transaction when mempool is full

        // insert into storage and other indexes
        self.system_ttl_index.insert(&txn);
        self.expiration_time_index.insert(&txn);

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
        self.track_indices();
        diem_debug!(
            LogSchema::new(LogEntry::AddTxn)
                .txns(TxnsLog::new_txn(address, hash)),
            hash = hash,
            has_tx = has_tx
        );

        MempoolStatus::new(MempoolStatusCode::Accepted)
    }

    fn track_indices(&self) {
        counters::core_mempool_index_size(
            counters::SYSTEM_TTL_INDEX_LABEL,
            self.system_ttl_index.size(),
        );
        counters::core_mempool_index_size(
            counters::EXPIRATION_TIME_INDEX_LABEL,
            self.expiration_time_index.size(),
        );
        counters::core_mempool_index_size(
            counters::TIMELINE_INDEX_LABEL,
            self.timeline_index.size(),
        );
    }

    /// Handles transaction commit.
    /// It includes deletion of all transactions with sequence number <=
    /// `account_sequence_number` and potential promotion of sequential txns
    /// to PriorityIndex/TimelineIndex.
    pub(crate) fn commit_transaction(
        &mut self, _account: &AccountAddress, hash: HashValue,
    ) {
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

    pub(crate) fn reject_transaction(
        &mut self, account: &AccountAddress, _hash: HashValue,
    ) {
        let mut txns_log = TxnsLog::new();
        let mut hashes = Vec::new();
        for txn in self.transactions.iter() {
            if txn.get_sender() == *account {
                txns_log.add(txn.get_sender(), txn.get_hash());
                hashes.push(txn.get_hash());
            }
        }
        for txn in self.transactions.iter_pivot_decision() {
            if txn.get_sender() == *account {
                txns_log.add(txn.get_sender(), txn.get_hash());
                hashes.push(txn.get_hash());
            }
        }
        for hash in hashes {
            if let Some(txn) = self.transactions.remove(&hash) {
                self.index_remove(&txn);
            }
        }
        diem_debug!(LogSchema::new(LogEntry::CleanRejectedTxn).txns(txns_log));
    }

    /// Removes transaction from all indexes.
    fn index_remove(&mut self, txn: &MempoolTransaction) {
        counters::CORE_MEMPOOL_REMOVED_TXNS.inc();
        self.system_ttl_index.remove(&txn);
        self.expiration_time_index.remove(&txn);
        self.timeline_index.remove(&txn);
        self.track_indices();
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

    /// Garbage collect old transactions.
    pub(crate) fn gc_by_system_ttl(
        &mut self,
        metrics_cache: &TtlCache<(AccountAddress, HashValue), SystemTime>,
    ) {
        let now = diem_infallible::duration_since_epoch();

        self.gc(now, true, metrics_cache);
    }

    /// Garbage collect old transactions based on client-specified expiration
    /// time.
    pub(crate) fn gc_by_expiration_time(
        &mut self, block_time: Duration,
        metrics_cache: &TtlCache<(AccountAddress, HashValue), SystemTime>,
    ) {
        self.gc(block_time, false, metrics_cache);
    }

    fn gc(
        &mut self, now: Duration, by_system_ttl: bool,
        _metrics_cache: &TtlCache<(AccountAddress, HashValue), SystemTime>,
    ) {
        let (metric_label, index, log_event) = if by_system_ttl {
            (
                counters::GC_SYSTEM_TTL_LABEL,
                &mut self.system_ttl_index,
                LogEvent::SystemTTLExpiration,
            )
        } else {
            (
                counters::GC_CLIENT_EXP_LABEL,
                &mut self.expiration_time_index,
                LogEvent::ClientExpiration,
            )
        };
        counters::CORE_MEMPOOL_GC_EVENT_COUNT
            .with_label_values(&[metric_label])
            .inc();

        let mut gc_txns = index.gc(now);
        // sort the expired txns by order of sequence number per account
        gc_txns.sort_by_key(|key| (key.address, key.hash));
        let mut gc_iter = gc_txns.iter().peekable();

        let mut gc_txns_log = TxnsLog::new();
        while let Some(key) = gc_iter.next() {
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

        diem_debug!(LogSchema::event_log(LogEntry::GCRemoveTxns, log_event)
            .txns(gc_txns_log));
        self.track_indices();
    }

    pub(crate) fn iter(&self) -> AccountTransactionIter {
        self.transactions.iter()
    }

    pub(crate) fn iter_pivot_decision(&self) -> PivotDecisionIter {
        self.pivot_decisions.values()
    }
}
