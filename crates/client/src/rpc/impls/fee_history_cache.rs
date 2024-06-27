use crate::rpc::types::{FeeHistoryEntry, MAX_FEE_HISTORY_CACHE_BLOCK_COUNT};

use parking_lot::RwLock;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering::SeqCst},
        Arc,
    },
};

#[derive(Debug, Clone)]
pub struct FeeHistoryCache {
    inner: Arc<FeeHistoryCacheInner>,
}

impl FeeHistoryCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(FeeHistoryCacheInner::new()),
        }
    }

    pub fn max_blocks(&self) -> u64 { self.inner.max_blocks }

    pub fn lower_bound(&self) -> u64 { self.inner.lower_bound.load(SeqCst) }

    pub fn upper_bound(&self) -> u64 { self.inner.upper_bound.load(SeqCst) }

    pub fn is_empty(&self) -> bool {
        self.lower_bound() == self.upper_bound() && self.lower_bound() == 0
    }

    pub fn get_history(
        &self, start_block: u64, end_block: u64,
    ) -> Option<Vec<FeeHistoryEntry>> {
        let lower_bound = self.lower_bound();
        let upper_bound = self.upper_bound();
        if start_block >= lower_bound && end_block <= upper_bound {
            let entries = self.inner.entries.read();
            let result = entries
                .range(start_block..=end_block)
                .map(|(_, fee_entry)| fee_entry.clone())
                .collect::<Vec<_>>();

            if result.is_empty() {
                return None;
            }

            Some(result)
        } else {
            None
        }
    }

    pub fn get_history_with_missing_info(
        &self, start_block: u64, end_block: u64,
    ) -> Vec<Option<FeeHistoryEntry>> {
        let entries = self.inner.entries.read();
        (start_block..=end_block)
            .map(|block_number| entries.get(&block_number).cloned())
            .collect()
    }

    #[allow(dead_code)]
    fn missing_consecutive_blocks(&self) -> VecDeque<u64> {
        let entries = self.inner.entries.read();
        (self.lower_bound()..self.upper_bound())
            .rev()
            .filter(|&block_number| !entries.contains_key(&block_number))
            .collect()
    }

    // if the cached history is outdated, clear the cache
    pub fn check_and_clear_cache(&self, latest_block: u64) {
        if self.upper_bound() + self.max_blocks() <= latest_block {
            self.clear_cache();
        }
    }

    pub fn push_back(
        &self, block_number: u64, entry: FeeHistoryEntry,
    ) -> Result<(), String> {
        if !self.is_empty() && block_number - self.upper_bound() != 1 {
            return Err("block number is not consecutive".to_string());
        }

        let mut entries = self.inner.entries.write();

        entries.insert(block_number, entry);

        if self.lower_bound() == 0 {
            self.inner.lower_bound.store(block_number, SeqCst);
        }
        self.inner.upper_bound.store(block_number, SeqCst);

        if entries.len() > self.max_blocks() as usize {
            entries.pop_first();
            self.inner.lower_bound.fetch_add(1, SeqCst);
        }

        Ok(())
    }

    fn clear_cache(&self) {
        if self.is_empty() {
            return;
        }

        let mut entries = self.inner.entries.write();
        entries.clear();

        self.inner.lower_bound.store(0, SeqCst);
        self.inner.upper_bound.store(0, SeqCst);
    }
}

#[derive(Debug)]
pub struct FeeHistoryCacheInner {
    /// Stores the lower bound of the cache
    lower_bound: AtomicU64,
    /// Stores the upper bound of the cache
    upper_bound: AtomicU64,
    /// maximum number of blocks to store in the cache
    max_blocks: u64,
    /// Stores the entries of the cache
    entries: RwLock<BTreeMap<u64, FeeHistoryEntry>>,
}

impl FeeHistoryCacheInner {
    pub fn new() -> Self {
        Self {
            lower_bound: AtomicU64::new(0),
            upper_bound: AtomicU64::new(0),
            max_blocks: MAX_FEE_HISTORY_CACHE_BLOCK_COUNT,
            entries: RwLock::new(BTreeMap::new()),
        }
    }
}
