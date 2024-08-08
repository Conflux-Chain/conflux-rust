use crate::rpc::types::{FeeHistoryEntry, MAX_FEE_HISTORY_CACHE_BLOCK_COUNT};
use parking_lot::RwLock;
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

#[derive(Debug, Clone)]
pub struct FeeHistoryCache {
    inner: Arc<RwLock<FeeHistoryCacheInner>>,
}

impl FeeHistoryCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(FeeHistoryCacheInner::new())),
        }
    }

    pub fn max_blocks(&self) -> u64 { self.inner.read().max_blocks }

    pub fn lower_bound(&self) -> u64 { self.inner.read().lower_bound }

    pub fn upper_bound(&self) -> u64 { self.inner.read().upper_bound }

    pub fn is_empty(&self) -> bool {
        let inner = self.inner.read();
        inner.lower_bound == inner.upper_bound && inner.lower_bound == 0
    }

    pub fn get_history(
        &self, start_block: u64, end_block: u64,
    ) -> Option<Vec<FeeHistoryEntry>> {
        let inner = self.inner.read();
        let lower_bound = inner.lower_bound;
        let upper_bound = inner.upper_bound;
        if start_block >= lower_bound && end_block <= upper_bound {
            let result = inner
                .entries
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

    pub fn get(&self, index: u64) -> Option<FeeHistoryEntry> {
        if index < self.lower_bound() || index > self.upper_bound() {
            return None;
        }
        self.inner
            .read()
            .entries
            .get(&index)
            .map(|item| item.clone())
    }

    pub fn update(&self, block_number: u64, entry: FeeHistoryEntry) {
        let mut inner = self.inner.write();
        if block_number < inner.lower_bound || block_number > inner.upper_bound
        {
            return;
        }
        inner.entries.insert(block_number, entry);
    }

    pub fn get_history_with_missing_info(
        &self, start_block: u64, end_block: u64,
    ) -> Vec<Option<FeeHistoryEntry>> {
        let inner = self.inner.read();
        (start_block..=end_block)
            .map(|block_number| inner.entries.get(&block_number).cloned())
            .collect()
    }

    #[allow(dead_code)]
    fn missing_consecutive_blocks(&self) -> VecDeque<u64> {
        let inner = self.inner.read();
        (inner.lower_bound..inner.upper_bound)
            .rev()
            .filter(|&block_number| !inner.entries.contains_key(&block_number))
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

        let mut inner = self.inner.write();

        inner.entries.insert(block_number, entry);

        if inner.lower_bound == 0 {
            inner.lower_bound = block_number;
        }
        inner.upper_bound = block_number;

        if inner.entries.len() > inner.max_blocks as usize {
            inner.entries.pop_first();
            inner.lower_bound += 1;
        }

        Ok(())
    }

    fn clear_cache(&self) {
        if self.is_empty() {
            return;
        }

        let mut inner = self.inner.write();

        inner.entries.clear();
        inner.lower_bound = 0;
        inner.upper_bound = 0;
    }
}

#[derive(Debug)]
pub struct FeeHistoryCacheInner {
    /// Stores the lower bound of the cache
    lower_bound: u64,
    /// Stores the upper bound of the cache
    upper_bound: u64,
    /// maximum number of blocks to store in the cache
    max_blocks: u64,
    /// Stores the entries of the cache
    entries: BTreeMap<u64, FeeHistoryEntry>,
}

impl FeeHistoryCacheInner {
    pub fn new() -> Self {
        Self {
            lower_bound: 0,
            upper_bound: 0,
            max_blocks: MAX_FEE_HISTORY_CACHE_BLOCK_COUNT,
            entries: BTreeMap::new(),
        }
    }
}
