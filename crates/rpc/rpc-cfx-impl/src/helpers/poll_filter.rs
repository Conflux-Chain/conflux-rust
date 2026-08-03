// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// Helper type with all filter state data.

use cfx_types::H256;
use parking_lot::Mutex;
use primitives::filter::LogFilter;
use std::{
    collections::{BTreeSet, VecDeque},
    sync::Arc,
};

pub type EpochNumber = u64;

/// Thread-safe filter state.
#[derive(Clone)]
pub struct SyncPollFilter<T>(Arc<Mutex<PollFilter<T>>>);

impl<T> SyncPollFilter<T> {
    pub fn new(f: PollFilter<T>) -> Self {
        SyncPollFilter(Arc::new(Mutex::new(f)))
    }

    pub fn modify<F, R>(&self, f: F) -> R
    where F: FnOnce(&mut PollFilter<T>) -> R {
        f(&mut self.0.lock())
    }
}

/// Filter state.
#[derive(Clone)]
pub enum PollFilter<T> {
    Block {
        last_epoch_number: EpochNumber,
        recent_reported_epochs: VecDeque<(EpochNumber, Vec<H256>)>,
    },
    PendingTransaction(BTreeSet<H256>),
    Logs {
        last_epoch_number: EpochNumber,
        recent_reported_epochs: VecDeque<(EpochNumber, Vec<H256>)>,
        previous_logs: VecDeque<Vec<T>>,
        filter: LogFilter,
        include_pending: bool,
    },
}

pub const MAX_BLOCK_HISTORY_SIZE: usize = 200;

/// Returns only last `n` logs
pub fn limit_logs<T>(mut logs: Vec<T>, limit: Option<usize>) -> Vec<T> {
    let len = logs.len();
    match limit {
        Some(limit) if len >= limit => logs.split_off(len - limit),
        _ => logs,
    }
}
