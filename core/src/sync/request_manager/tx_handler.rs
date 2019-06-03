use message::TransIndex;
use primitives::{SignedTransaction, TxPropagateId};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

const RECEIVED_TRANSACTION_CONTAINER_WINDOW_SIZE: usize = 64;

struct ReceivedTransactionContainerInner {
    window_size: usize,
    container: HashSet<TxPropagateId>,
    slot_duration_as_secs: u64,
    time_windowed_indices: Vec<Option<(u64, Vec<TxPropagateId>)>>,
}

impl ReceivedTransactionContainerInner {
    pub fn new(window_size: usize, slot_duration_as_secs: u64) -> Self {
        let mut time_windowed_indices = Vec::new();
        for _ in 0..window_size {
            time_windowed_indices.push(None);
        }
        ReceivedTransactionContainerInner {
            window_size,
            container: HashSet::new(),
            slot_duration_as_secs,
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

    pub fn contains(&self, key: &TxPropagateId) -> bool {
        let inner = &self.inner;
        inner.container.contains(key)
    }

    pub fn append_transaction_ids(&mut self, tx_ids: Vec<TxPropagateId>) {
        let inner = &mut self.inner;

        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH);
        let secs = duration.ok().unwrap().as_secs();
        let window_index =
            (secs / inner.slot_duration_as_secs) as usize % inner.window_size;

        let indices = if inner.time_windowed_indices[window_index].is_none() {
            let indices = Vec::new();
            inner.time_windowed_indices[window_index] = Some((secs, indices));
            &mut inner.time_windowed_indices[window_index]
                .as_mut()
                .unwrap()
                .1
        } else {
            let mut indices_with_time =
                inner.time_windowed_indices[window_index].as_mut().unwrap();
            if indices_with_time.0 + inner.slot_duration_as_secs <= secs {
                for key_to_remove in &indices_with_time.1 {
                    inner.container.remove(key_to_remove);
                }
                let indices = Vec::new();
                indices_with_time.0 = secs;
                indices_with_time.1 = indices;
            }
            &mut indices_with_time.1
        };

        for tx_id in tx_ids {
            if !inner.container.contains(&tx_id) {
                inner.container.insert(tx_id.clone());
                indices.push(tx_id);
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
