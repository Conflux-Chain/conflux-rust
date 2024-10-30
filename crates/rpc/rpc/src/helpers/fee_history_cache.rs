#![allow(dead_code)]
use cfx_rpc_cfx_types::{FeeHistoryCacheEntry, PhantomBlock};
use cfx_types::{Space, H256};
use parking_lot::RwLock;
use std::{collections::VecDeque, sync::Arc};

pub const MAX_FEE_HISTORY_CACHE_BLOCK_COUNT: u64 = 1024;

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

    /*
        This cache is used to store the FeeHistoryEntry data for the latest 1024 blocks, enabling quick queries.

        Update Logic:
        If the cached block data is outdated, clear the cache first.
        If the cache is empty, fetch the FeeHistoryEntry data for the latest q blocks directly from the DB and cache them (q is the number of blocks to be queried this time).
        If the cache is not empty, get the upper bound of the cache and update from that block number to the latest block.
        If the number of blocks in the cache exceeds 1024, delete the oldest block data until the number of blocks in the cache is 1024.
    */
    pub fn update_to_latest_block<F>(
        &self, latest_block: u64, latest_hash: H256, query_len: u64,
        fetch_block_by_hash: F,
    ) -> Result<(), String>
    where
        F: Fn(H256) -> Result<PhantomBlock, String>,
    {
        let mut inner = self.inner.write();

        // if the cached block data is outdated, clear the cache first
        inner.check_and_clear_cache(latest_block);

        let start_block = if inner.is_empty() {
            if latest_block <= query_len {
                0
            } else {
                latest_block - query_len + 1
            }
        } else {
            inner.upper_bound() + 1
        };

        let mut curr_hash = latest_hash;
        let mut container = VecDeque::new();
        for i in (start_block..=latest_block).rev() {
            let block = fetch_block_by_hash(curr_hash)?;
            container.push_front((
                i,
                FeeHistoryCacheEntry::from_block(
                    Space::Ethereum,
                    &block.pivot_header,
                    block.transactions.iter().map(|x| &**x),
                ),
            ));
            curr_hash = block.pivot_header.parent_hash().clone();
        }

        for (block_number, entry) in container {
            inner.push_back(block_number, entry)?;
        }

        // update cache if block changes due to reorg
        if inner.lower_bound < start_block {
            let need_check = start_block - inner.lower_bound;
            for item in inner.entries.iter_mut().take(need_check as usize).rev()
            {
                if item.header_hash == curr_hash {
                    break;
                }
                let block = fetch_block_by_hash(curr_hash)?;
                *item = FeeHistoryCacheEntry::from_block(
                    Space::Ethereum,
                    &block.pivot_header,
                    block.transactions.iter().map(|x| &**x),
                );
                curr_hash = block.pivot_header.parent_hash().clone();
            }
        }

        Ok(())
    }

    pub fn max_blocks(&self) -> u64 { self.inner.read().max_blocks }

    pub fn lower_bound(&self) -> u64 { self.inner.read().lower_bound }

    pub fn upper_bound(&self) -> u64 { self.inner.read().upper_bound() }

    pub fn get_history(
        &self, start_block: u64, end_block: u64,
    ) -> Option<Vec<FeeHistoryCacheEntry>> {
        let inner = self.inner.read();
        let lower_bound = inner.lower_bound;
        let upper_bound = inner.upper_bound();
        if start_block >= lower_bound && end_block <= upper_bound {
            let start = (start_block - lower_bound) as usize;
            let end = (end_block - lower_bound) as usize;
            let result = inner
                .entries
                .range(start..=end)
                .map(|fee_entry| fee_entry.clone())
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
    ) -> Vec<Option<FeeHistoryCacheEntry>> {
        let inner = self.inner.read();
        (start_block..=end_block)
            .map(|block_number| inner.get(block_number))
            .collect()
    }
}

#[derive(Debug)]
struct FeeHistoryCacheInner {
    /// Stores the lower bound of the cache
    lower_bound: u64,
    /// maximum number of blocks to store in the cache
    max_blocks: u64,
    /// Stores the entries of the cache
    entries: VecDeque<FeeHistoryCacheEntry>,
}

impl FeeHistoryCacheInner {
    pub fn new() -> Self {
        Self {
            lower_bound: 0,
            max_blocks: MAX_FEE_HISTORY_CACHE_BLOCK_COUNT,
            entries: VecDeque::new(),
        }
    }

    pub fn upper_bound(&self) -> u64 {
        self.lower_bound + self.entries.len() as u64 - 1
    }

    // if the cached history is outdated, clear the cache
    fn check_and_clear_cache(&mut self, latest_block: u64) {
        if !self.is_empty()
            && self.upper_bound() + self.max_blocks <= latest_block
        {
            self.clear_cache();
        }
    }

    pub fn clear_cache(&mut self) {
        self.entries.clear();
        self.lower_bound = 0;
    }

    fn push_back(
        &mut self, block_number: u64, entry: FeeHistoryCacheEntry,
    ) -> Result<(), String> {
        if !self.is_empty() && block_number - self.upper_bound() != 1 {
            return Err("block number is not consecutive".to_string());
        }

        self.entries.push_back(entry);

        // the first entry
        if self.lower_bound == 0 {
            self.lower_bound = block_number;
        }

        if self.entries.len() > self.max_blocks as usize {
            self.entries.pop_front();
            self.lower_bound += 1;
        }

        Ok(())
    }

    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    pub fn get(&self, height: u64) -> Option<FeeHistoryCacheEntry> {
        if height < self.lower_bound || height > self.upper_bound() {
            return None;
        }
        let key = height - self.lower_bound;
        self.entries.get(key as usize).map(|item| item.clone())
    }

    #[allow(dead_code)]
    pub fn update(&mut self, height: u64, entry: FeeHistoryCacheEntry) {
        if height < self.lower_bound || height > self.upper_bound() {
            return;
        }
        let key = height - self.lower_bound;
        if let Some(item) = self.entries.get_mut(key as usize) {
            *item = entry;
        }
    }
}
