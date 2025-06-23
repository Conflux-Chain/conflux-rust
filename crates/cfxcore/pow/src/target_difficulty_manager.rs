use crate::{ConsensusProvider, ProofOfWorkConfig};
use cfx_types::{H256, U256};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};

//FIXME: make entries replaceable
#[derive(DeriveMallocSizeOf)]
struct TargetDifficultyCacheInner {
    capacity: usize,
    meta: VecDeque<H256>,
    cache: HashMap<H256, U256>,
}

impl TargetDifficultyCacheInner {
    pub fn new(capacity: usize) -> Self {
        TargetDifficultyCacheInner {
            capacity,
            meta: Default::default(),
            cache: Default::default(),
        }
    }

    pub fn is_full(&self) -> bool { self.meta.len() >= self.capacity }

    pub fn evict_one(&mut self) {
        let hash = self.meta.pop_front();
        if let Some(h) = hash {
            self.cache.remove(&h);
        }
    }

    pub fn insert(&mut self, hash: H256, difficulty: U256) {
        self.meta.push_back(hash.clone());
        self.cache.insert(hash, difficulty);
    }
}

struct TargetDifficultyCache {
    inner: RwLock<TargetDifficultyCacheInner>,
}

impl MallocSizeOf for TargetDifficultyCache {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.inner.read().size_of(ops)
    }
}

impl TargetDifficultyCache {
    pub fn new(capacity: usize) -> Self {
        TargetDifficultyCache {
            inner: RwLock::new(TargetDifficultyCacheInner::new(capacity)),
        }
    }

    pub fn get(&self, hash: &H256) -> Option<U256> {
        let inner = self.inner.read();
        inner.cache.get(hash).map(|diff| *diff)
    }

    pub fn set(&self, hash: H256, difficulty: U256) {
        let mut inner = self.inner.write();
        while inner.is_full() {
            inner.evict_one();
        }
        inner.insert(hash, difficulty);
    }
}

//FIXME: Add logic for persisting entries
/// This is a data structure to cache the computed target difficulty
/// of a adjustment period. Each element is indexed by the hash of
/// the upper boundary block of the period.
#[derive(DeriveMallocSizeOf)]
pub struct TargetDifficultyManager {
    cache: TargetDifficultyCache,
}

impl TargetDifficultyManager {
    pub fn new(capacity: usize) -> Self {
        TargetDifficultyManager {
            cache: TargetDifficultyCache::new(capacity),
        }
    }

    pub fn get(&self, hash: &H256) -> Option<U256> { self.cache.get(hash) }

    pub fn set(&self, hash: H256, difficulty: U256) {
        self.cache.set(hash, difficulty);
    }

    /// This function computes the target difficulty of the next period
    /// based on the current period. `cur_hash` should be the hash of
    /// the block at the current period upper boundary and it must have been
    /// inserted to BlockDataManager, otherwise the function will panic.
    /// `num_blocks_in_epoch` is a function that returns the epoch size
    /// under the epoch view of a given block.
    pub fn target_difficulty<C>(
        &self, consensus: C, pow_config: &ProofOfWorkConfig, cur_hash: &H256,
    ) -> U256
    where C: ConsensusProvider {
        if let Some(target_diff) = self.get(cur_hash) {
            // The target difficulty of this period is already computed and
            // cached.
            return target_diff;
        }

        let mut cur_header = consensus
            .block_header_by_hash(cur_hash)
            .expect("Must already in BlockDataManager block_header");
        let epoch = cur_header.height();
        assert_ne!(epoch, 0);
        debug_assert!(
            epoch
                == (epoch
                    / pow_config.difficulty_adjustment_epoch_period(epoch))
                    * pow_config.difficulty_adjustment_epoch_period(epoch)
        );

        let mut cur = cur_hash.clone();
        let cur_difficulty = cur_header.difficulty().clone();
        let mut block_count = 0 as u64;
        let max_time = cur_header.timestamp();
        let mut min_time = 0;

        // Collect the total block count and the timespan in the current period
        for _ in 0..pow_config.difficulty_adjustment_epoch_period(epoch) {
            block_count += consensus.num_blocks_in_epoch(&cur);
            cur = cur_header.parent_hash().clone();
            cur_header = consensus.block_header_by_hash(&cur).unwrap();
            if cur_header.timestamp() != 0 {
                min_time = cur_header.timestamp();
            }
            assert!(max_time >= min_time);
        }

        let expected_diff = pow_config.target_difficulty(
            block_count,
            max_time - min_time,
            &cur_difficulty,
        );
        // d_{t+1}=0.8*d_t+0.2*d'
        // where d_t is the difficulty of the current period, and d' is the
        // expected difficulty to reach the ideal block_generation_period.
        let mut target_diff = if epoch < pow_config.cip86_height {
            expected_diff
        } else {
            cur_difficulty / 5 * 4 + expected_diff / 5
        };

        let (lower, upper) = pow_config.get_adjustment_bound(cur_difficulty);
        if target_diff > upper {
            target_diff = upper;
        }
        if target_diff < lower {
            target_diff = lower;
        }

        // Caching the computed target difficulty of this period.
        self.set(*cur_hash, target_diff);

        target_diff
    }
}
