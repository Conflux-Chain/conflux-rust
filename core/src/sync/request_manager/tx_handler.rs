use crate::sync::message::TransIndex;
use primitives::{SignedTransaction, TxPropagateId};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const RECEIVED_TRANSACTION_CONTAINER_WINDOW_SIZE: usize = 64;

struct ReceivedTransactionTimeWindowedEntry {
    pub secs: u64,
    pub tx_ids: Vec<TxPropagateId>,
}

struct ReceivedTransactionContainerInner {
    window_size: usize,
    slot_duration_as_secs: u64,
    txid_container: HashSet<TxPropagateId>,
    time_windowed_indices: Vec<Option<ReceivedTransactionTimeWindowedEntry>>,
}

impl ReceivedTransactionContainerInner {
    pub fn new(window_size: usize, slot_duration_as_secs: u64) -> Self {
        let mut time_windowed_indices = Vec::new();
        for _ in 0..window_size {
            time_windowed_indices.push(None);
        }
        ReceivedTransactionContainerInner {
            window_size,
            slot_duration_as_secs,
            txid_container: HashSet::new(),
            time_windowed_indices,
        }
    }
}

pub struct ReceivedTransactionContainer {
    inner: ReceivedTransactionContainerInner,
}

impl ReceivedTransactionContainer {
    pub fn new(timeout: u64) -> Self {
        let slot_duration_as_secs =
            timeout / RECEIVED_TRANSACTION_CONTAINER_WINDOW_SIZE as u64;
        ReceivedTransactionContainer {
            inner: ReceivedTransactionContainerInner::new(
                RECEIVED_TRANSACTION_CONTAINER_WINDOW_SIZE,
                slot_duration_as_secs,
            ),
        }
    }

    pub fn contains_txid(&self, key: &TxPropagateId) -> bool {
        let inner = &self.inner;
        inner.txid_container.contains(key)
    }

    pub fn get_length(&self) -> usize { self.inner.txid_container.len() }

    pub fn append_transactions(
        &mut self, transactions: Vec<Arc<SignedTransaction>>,
    ) {
        let tx_ids = transactions
            .iter()
            .map(|tx| TxPropagateId::from(tx.hash()))
            .collect::<Vec<_>>();

        let inner = &mut self.inner;

        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH);
        let secs = duration.ok().unwrap().as_secs();
        let window_index =
            (secs / inner.slot_duration_as_secs) as usize % inner.window_size;

        let entry = if inner.time_windowed_indices[window_index].is_none() {
            inner.time_windowed_indices[window_index] =
                Some(ReceivedTransactionTimeWindowedEntry {
                    secs,
                    tx_ids: Vec::new(),
                });
            inner.time_windowed_indices[window_index].as_mut().unwrap()
        } else {
            let indices_with_time =
                inner.time_windowed_indices[window_index].as_mut().unwrap();
            if indices_with_time.secs + inner.slot_duration_as_secs <= secs {
                for tx_id in &indices_with_time.tx_ids {
                    inner.txid_container.remove(tx_id);
                }
                indices_with_time.secs = secs;
                indices_with_time.tx_ids = Vec::new();
            }
            indices_with_time
        };

        for tx_id in tx_ids {
            if !inner.txid_container.contains(&tx_id) {
                inner.txid_container.insert(tx_id.clone());
                entry.tx_ids.push(tx_id);
            }
        }
    }
}

struct SentTransactionContainerInner {
    window_size: usize,
    base_time_tick: usize,
    next_time_tick: usize,
    time_windowed_indices: Vec<Option<Vec<Arc<SignedTransaction>>>>,
}

impl SentTransactionContainerInner {
    pub fn new(window_size: usize) -> Self {
        let mut time_windowed_indices = Vec::new();
        for _ in 0..window_size {
            time_windowed_indices.push(None);
        }

        SentTransactionContainerInner {
            window_size,
            base_time_tick: 0,
            next_time_tick: 0,
            time_windowed_indices,
        }
    }
}

/// This struct is not implemented as thread-safe since
/// currently it is only used under protection of lock
/// on SynchronizationState. Later we may refine the
/// locking design to make it thread-safe.
pub struct SentTransactionContainer {
    inner: SentTransactionContainerInner,
}

impl SentTransactionContainer {
    pub fn new(window_size: usize) -> Self {
        SentTransactionContainer {
            inner: SentTransactionContainerInner::new(window_size),
        }
    }

    pub fn get_transaction(
        &self, index: &TransIndex,
    ) -> Option<Arc<SignedTransaction>> {
        let inner = &self.inner;
        if index.first() >= inner.base_time_tick {
            if index.first() - inner.base_time_tick >= inner.window_size {
                return None;
            }
        } else {
            if index.first() + 1 + std::usize::MAX - inner.base_time_tick
                >= inner.window_size
            {
                return None;
            }
        }

        let window_index = index.first() % inner.window_size;
        assert!(window_index < inner.time_windowed_indices.len());

        let transactions = inner.time_windowed_indices[window_index].as_ref();
        if transactions.is_none() {
            return None;
        }

        let transactions = transactions.unwrap();
        if index.second() >= transactions.len() {
            return None;
        }

        Some(transactions[index.second()].clone())
    }

    pub fn append_transactions(
        &mut self, transactions: Vec<Arc<SignedTransaction>>,
    ) -> usize {
        let inner = &mut self.inner;

        let base_window_index = inner.base_time_tick % inner.window_size;
        let next_time_tick = inner.next_time_tick;
        let next_window_index = next_time_tick % inner.window_size;
        inner.time_windowed_indices[next_window_index] = Some(transactions);
        if (next_window_index + 1) % inner.window_size == base_window_index {
            inner.base_time_tick += 1;
        }
        inner.next_time_tick += 1;
        next_time_tick
    }
}
