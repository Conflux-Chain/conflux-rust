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

    // Evicts txns after `system_transaction_timeout` so stalled commit
    // callbacks cannot clog the mempool indefinitely.
    system_ttl_index: TTLIndex,
    timeline_index: TimelineIndex,

    // Caps live txns per sender to bound Byzantine-validator spam.
    per_sender_count: HashMap<AccountAddress, usize>,
    capacity_per_sender: usize,
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
            timeline_index: TimelineIndex::new(),

            per_sender_count: HashMap::new(),
            capacity_per_sender: config.capacity_per_sender,
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

        let sender_entry = self.per_sender_count.entry(address).or_insert(0);
        if *sender_entry >= self.capacity_per_sender {
            let sender_count = *sender_entry;
            diem_debug!(
                sender = %address,
                sender_count = sender_count,
                cap = self.capacity_per_sender,
                "mempool: per-sender capacity reached, rejecting txn",
            );
            return MempoolStatus::new(MempoolStatusCode::TooManyTransactions)
                .with_message(format!(
                    "sender {} already has {} transactions (cap {})",
                    address, sender_count, self.capacity_per_sender,
                ));
        }
        *sender_entry += 1;

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
        let sender = txn.get_sender();
        if let Some(count) = self.per_sender_count.get_mut(&sender) {
            *count -= 1;
            if *count == 0 {
                self.per_sender_count.remove(&sender);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use diem_crypto::{
        bls::{BLSPrivateKey, BLSPublicKey},
        PrivateKey, SigningKey, Uniform,
    };
    use diem_types::{
        chain_id::ChainId,
        transaction::{RawTransaction, RetirePayload, TransactionPayload},
    };
    use std::time::Duration;

    fn store_with_cap(cap: usize) -> TransactionStore {
        let mut cfg = MempoolConfig::default();
        cfg.capacity_per_sender = cap;
        TransactionStore::new(&cfg)
    }

    fn new_sender() -> (BLSPrivateKey, BLSPublicKey, AccountAddress) {
        let sk = BLSPrivateKey::generate_for_testing();
        let pk = sk.public_key();
        (sk, pk, AccountAddress::random())
    }

    fn mk_txn(
        sk: &BLSPrivateKey, pk: &BLSPublicKey, sender: AccountAddress,
        nonce: u64,
    ) -> MempoolTransaction {
        let payload = TransactionPayload::Retire(RetirePayload {
            node_id: sender,
            votes: nonce,
        });
        let raw =
            RawTransaction::new(sender, payload, u64::MAX, ChainId::test());
        let sig = sk.sign(&raw);
        MempoolTransaction::new(
            SignedTransaction::new(raw, pk.clone(), sig),
            Duration::from_secs(3600),
            TimelineState::NotReady,
        )
    }

    #[test]
    fn per_sender_count_insert_and_commit_lifecycle() {
        let mut store = store_with_cap(3);
        let (sk, pk, sender) = new_sender();
        assert!(!store.per_sender_count.contains_key(&sender));

        let mut hashes = Vec::new();
        for n in 0..3 {
            let txn = mk_txn(&sk, &pk, sender, n);
            hashes.push(txn.get_hash());
            assert_eq!(store.insert(txn).code, MempoolStatusCode::Accepted);
        }
        assert_eq!(store.per_sender_count[&sender], 3);

        for (i, h) in hashes.iter().enumerate() {
            store.commit_transaction(*h);
            let remaining = 3 - (i + 1);
            if remaining == 0 {
                assert!(!store.per_sender_count.contains_key(&sender));
            } else {
                assert_eq!(store.per_sender_count[&sender], remaining);
            }
        }
    }

    #[test]
    fn per_sender_count_cap_rejects_without_growth() {
        let mut store = store_with_cap(2);
        let (sk, pk, sender) = new_sender();

        for n in 0..2 {
            assert_eq!(
                store.insert(mk_txn(&sk, &pk, sender, n)).code,
                MempoolStatusCode::Accepted
            );
        }
        assert_eq!(store.per_sender_count[&sender], 2);

        for n in 2..6 {
            assert_eq!(
                store.insert(mk_txn(&sk, &pk, sender, n)).code,
                MempoolStatusCode::TooManyTransactions
            );
            assert_eq!(store.per_sender_count[&sender], 2);
        }
    }

    #[test]
    fn per_sender_count_duplicate_hash_no_double_count() {
        let mut store = store_with_cap(8);
        let (sk, pk, sender) = new_sender();
        let txn = mk_txn(&sk, &pk, sender, 0);
        let dup = MempoolTransaction::new(
            txn.txn.clone(),
            txn.expiration_time,
            txn.timeline_state,
        );

        assert_eq!(store.insert(txn).code, MempoolStatusCode::Accepted);
        assert_eq!(store.per_sender_count[&sender], 1);

        assert_eq!(store.insert(dup).code, MempoolStatusCode::Accepted);
        assert_eq!(store.per_sender_count[&sender], 1);
    }
}
