use cfx_types::{Space, H256, U256};
use cfxcore::consensus::PhantomBlock;
use parking_lot::RwLock;
use primitives::{transaction::SignedTransaction, BlockHeader};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

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
        &self, latest_block: u64, query_len: u64, fetch_block_by_height: F,
    ) -> Result<(), String>
    where F: Fn(u64) -> Result<PhantomBlock, String> {
        self.check_and_clear_cache(latest_block);

        let start_block = if self.is_empty() {
            if latest_block <= query_len {
                0
            } else {
                latest_block - query_len + 1
            }
        } else {
            self.upper_bound() + 1
        };

        for i in start_block..=latest_block {
            let block = fetch_block_by_height(i)?;
            self.push_back(
                i,
                FeeHistoryEntry::from_block(
                    Space::Ethereum,
                    &block.pivot_header,
                    block.transactions.iter().map(|x| &**x),
                ),
            )?;
        }

        // update cache if block changes due to reorg
        if self.lower_bound() < start_block {
            let mut check = start_block - 1;
            let mut curr = self
                .get(start_block)
                .ok_or_else(|| "fee_history_entry not found")?;
            while check >= self.lower_bound() {
                let item = self
                    .get(check)
                    .ok_or_else(|| "fee_history_entry not found")?;
                if curr.parent_hash == item.header_hash {
                    break;
                }
                let block = fetch_block_by_height(check)?;
                curr = FeeHistoryEntry::from_block(
                    Space::Ethereum,
                    &block.pivot_header,
                    block.transactions.iter().map(|x| &**x),
                );
                self.update(check, curr.clone());
                check -= 1;
            }
        }

        Ok(())
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
struct FeeHistoryCacheInner {
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

#[derive(Debug, Clone)]
pub struct FeeHistoryEntry {
    /// The base fee per gas for this block.
    pub base_fee_per_gas: u64,
    /// Gas used ratio this block.
    pub gas_used_ratio: f64,
    /// Gas used by this block.
    pub gas_used: u64,
    /// Gas limit by this block.
    pub gas_limit: u64,
    /// Hash of the block.
    pub header_hash: H256,
    ///
    pub parent_hash: H256,
    /// Approximated rewards for the configured percentiles.
    pub rewards: Vec<u128>,
    /// The timestamp of the block.
    pub timestamp: u64,
}

impl FeeHistoryEntry {
    pub fn from_block<'a, I>(
        space: Space, pivot_header: &BlockHeader, transactions: I,
    ) -> Self
    where I: Clone + Iterator<Item = &'a SignedTransaction> {
        let gas_limit: u64 = if space == Space::Native {
            pivot_header.core_space_gas_limit().as_u64()
        } else {
            pivot_header.espace_gas_limit(true).as_u64()
        };

        let gas_used = transactions
            .clone()
            .map(|x| *x.gas_limit())
            .reduce(|x, y| x + y)
            .unwrap_or_default()
            .as_u64();

        let gas_used_ratio = gas_used as f64 / gas_limit as f64;

        let base_fee_per_gas =
            pivot_header.space_base_price(space).unwrap_or_default();

        let mut rewards: Vec<_> = transactions
            .map(|tx| {
                if *tx.gas_price() < base_fee_per_gas {
                    U256::zero()
                } else {
                    tx.effective_gas_price(&base_fee_per_gas)
                }
            })
            .map(|x| x.as_u128())
            .collect();

        rewards.sort_unstable();

        Self {
            base_fee_per_gas: base_fee_per_gas.as_u64(),
            gas_used_ratio,
            gas_used,
            gas_limit,
            header_hash: pivot_header.hash(),
            parent_hash: *pivot_header.parent_hash(),
            rewards,
            timestamp: pivot_header.timestamp(),
        }
    }
}
