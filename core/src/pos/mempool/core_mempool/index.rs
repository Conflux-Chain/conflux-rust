// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// This module provides various indexes used by Mempool.
use crate::pos::mempool::core_mempool::transaction::{
    MempoolTransaction, TimelineState,
};
use diem_crypto::HashValue;
use diem_types::{
    account_address::AccountAddress, transaction::GovernanceRole,
};
use std::{
    cmp::Ordering,
    collections::{hash_map::Values, BTreeMap, BTreeSet, HashMap},
    ops::Bound,
    time::Duration,
};

pub struct AccountTransactions {
    normal_transaction: HashMap<HashValue, MempoolTransaction>,
    pivot_decision_transaction: HashMap<HashValue, MempoolTransaction>,
}

pub type AccountTransactionIter<'a> = Values<'a, HashValue, MempoolTransaction>;

impl AccountTransactions {
    pub(crate) fn new() -> Self {
        Self {
            normal_transaction: HashMap::new(),
            pivot_decision_transaction: HashMap::new(),
        }
    }

    pub(crate) fn get(&self, hash: &HashValue) -> Option<&MempoolTransaction> {
        if let Some(txn) = self.normal_transaction.get(hash) {
            Some(txn)
        } else {
            self.pivot_decision_transaction.get(hash)
        }
    }

    pub(crate) fn remove(
        &mut self, hash: &HashValue,
    ) -> Option<MempoolTransaction> {
        if let Some(txn) = self.normal_transaction.remove(hash) {
            Some(txn)
        } else {
            self.pivot_decision_transaction.remove(hash)
        }
    }

    pub(crate) fn insert(
        &mut self, hash: HashValue, txn: MempoolTransaction,
        is_pivot_decision: bool,
    ) {
        if is_pivot_decision {
            self.pivot_decision_transaction.insert(hash, txn);
        } else {
            self.normal_transaction.insert(hash, txn);
        }
    }

    pub(crate) fn iter(&self) -> AccountTransactionIter {
        self.normal_transaction.values()
    }

    pub(crate) fn iter_pivot_decision(&self) -> AccountTransactionIter {
        self.pivot_decision_transaction.values()
    }
}

pub type TxnPointer = (AccountAddress, HashValue);

impl From<&MempoolTransaction> for TxnPointer {
    fn from(transaction: &MempoolTransaction) -> Self {
        (transaction.get_sender(), transaction.get_hash())
    }
}

#[derive(Eq, PartialEq, Clone, Debug, Hash)]
pub struct OrderedQueueKey {
    pub gas_ranking_score: u64,
    pub expiration_time: Duration,
    pub address: AccountAddress,
    pub hash: HashValue,
    pub governance_role: GovernanceRole,
}

impl PartialOrd for OrderedQueueKey {
    fn partial_cmp(&self, other: &OrderedQueueKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedQueueKey {
    fn cmp(&self, other: &OrderedQueueKey) -> Ordering {
        match self
            .governance_role
            .priority()
            .cmp(&other.governance_role.priority())
        {
            Ordering::Equal => {}
            ordering => return ordering,
        }
        match self.gas_ranking_score.cmp(&other.gas_ranking_score) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
        match self.expiration_time.cmp(&other.expiration_time).reverse() {
            Ordering::Equal => {}
            ordering => return ordering,
        }
        match self.address.cmp(&other.address) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
        // TODO(linxi): correct compare
        self.hash.cmp(&other.hash).reverse()
    }
}

/// TTLIndex is used to perform garbage collection of old transactions in
/// Mempool. Periodically separate GC-like job queries this index to find out
/// transactions that have to be removed. Index is represented as
/// `BTreeSet<TTLOrderingKey>`, where `TTLOrderingKey` is a logical reference to
/// TxnInfo. Index is ordered by `TTLOrderingKey::expiration_time`.
pub struct TTLIndex {
    data: BTreeSet<TTLOrderingKey>,
    get_expiration_time:
        Box<dyn Fn(&MempoolTransaction) -> Duration + Send + Sync>,
}

impl TTLIndex {
    pub(crate) fn new<F>(get_expiration_time: Box<F>) -> Self
    where F: Fn(&MempoolTransaction) -> Duration + 'static + Send + Sync {
        Self {
            data: BTreeSet::new(),
            get_expiration_time,
        }
    }

    pub(crate) fn insert(&mut self, txn: &MempoolTransaction) {
        self.data.insert(self.make_key(&txn));
    }

    pub(crate) fn remove(&mut self, txn: &MempoolTransaction) {
        self.data.remove(&self.make_key(&txn));
    }

    /// Garbage collect all old transactions.
    pub(crate) fn gc(&mut self, now: Duration) -> Vec<TTLOrderingKey> {
        let ttl_key = TTLOrderingKey {
            expiration_time: now,
            address: AccountAddress::ZERO,
            hash: HashValue::zero(),
        };

        let mut active = self.data.split_off(&ttl_key);
        let ttl_transactions = self.data.iter().cloned().collect();
        self.data.clear();
        self.data.append(&mut active);
        ttl_transactions
    }

    fn make_key(&self, txn: &MempoolTransaction) -> TTLOrderingKey {
        TTLOrderingKey {
            expiration_time: (self.get_expiration_time)(txn),
            address: txn.get_sender(),
            hash: txn.get_hash(),
        }
    }

    pub(crate) fn size(&self) -> usize { self.data.len() }
}

#[allow(clippy::derive_ord_xor_partial_ord)]
#[derive(Eq, PartialEq, PartialOrd, Clone, Debug)]
pub struct TTLOrderingKey {
    pub expiration_time: Duration,
    pub address: AccountAddress,
    pub hash: HashValue,
}

/// Be very careful with this, to not break the partial ordering.
/// See:  https://rust-lang.github.io/rust-clippy/master/index.html#derive_ord_xor_partial_ord
#[allow(clippy::derive_ord_xor_partial_ord)]
impl Ord for TTLOrderingKey {
    fn cmp(&self, other: &TTLOrderingKey) -> Ordering {
        match self.expiration_time.cmp(&other.expiration_time) {
            Ordering::Equal => {
                (&self.address, self.hash).cmp(&(&other.address, other.hash))
            }
            ordering => ordering,
        }
    }
}

/// TimelineIndex is an ordered log of all transactions that are "ready" for
/// broadcast. We only add a transaction to the index if it has a chance to be
/// included in the next consensus block (which means its status is != NotReady
/// or its sequential to another "ready" transaction).
///
/// It's represented as Map <timeline_id, (Address, hash)>, where
/// timeline_id is auto increment unique id of "ready" transaction in local
/// Mempool. (Address, hash) is a logical reference to transaction
/// content in main storage.
pub struct TimelineIndex {
    timeline_id: u64,
    timeline: BTreeMap<u64, (AccountAddress, HashValue)>,
}

impl TimelineIndex {
    pub(crate) fn new() -> Self {
        Self {
            timeline_id: 1,
            timeline: BTreeMap::new(),
        }
    }

    /// Read all transactions from the timeline since <timeline_id>.
    pub(crate) fn read_timeline(
        &mut self, timeline_id: u64, count: usize,
    ) -> Vec<(AccountAddress, HashValue)> {
        let mut batch = vec![];
        for (_id, &(address, hash)) in self
            .timeline
            .range((Bound::Excluded(timeline_id), Bound::Unbounded))
        {
            batch.push((address, hash));
            if batch.len() == count {
                break;
            }
        }
        batch
    }

    /// Read transactions from the timeline from `start_id` (exclusive) to
    /// `end_id` (inclusive).
    pub(crate) fn timeline_range(
        &mut self, start_id: u64, end_id: u64,
    ) -> Vec<(AccountAddress, HashValue)> {
        self.timeline
            .range((Bound::Excluded(start_id), Bound::Included(end_id)))
            .map(|(_idx, txn)| txn)
            .cloned()
            .collect()
    }

    pub(crate) fn insert(&mut self, txn: &mut MempoolTransaction) {
        self.timeline
            .insert(self.timeline_id, (txn.get_sender(), txn.get_hash()));
        txn.timeline_state = TimelineState::Ready(self.timeline_id);
        self.timeline_id += 1;
    }

    pub(crate) fn remove(&mut self, txn: &MempoolTransaction) {
        if let TimelineState::Ready(timeline_id) = txn.timeline_state {
            self.timeline.remove(&timeline_id);
        }
    }

    pub(crate) fn size(&self) -> usize { self.timeline.len() }
}
