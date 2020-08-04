// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod cache;
mod compute;
mod keccak;
mod seed_compute;
mod shared;

pub use self::{cache::CacheBuilder, shared::POW_STAGE_LENGTH};
use crate::hash::keccak as keccak_hash;

use crate::{block_data_manager::BlockDataManager, parameters::pow::*};
use cfx_types::{BigEndianHash, H256, U256, U512};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use parking_lot::RwLock;
use std::{
    collections::{HashMap, VecDeque},
    convert::TryFrom,
    sync::Arc,
};

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub struct ProofOfWorkProblem {
    pub block_height: u64,
    pub block_hash: H256,
    pub difficulty: U256,
    pub boundary: U256,
}

impl ProofOfWorkProblem {
    pub const NO_BOUNDARY: U256 = U256::MAX;

    pub fn new(block_height: u64, block_hash: H256, difficulty: U256) -> Self {
        let boundary = difficulty_to_boundary(&difficulty);
        Self {
            block_height,
            block_hash,
            difficulty,
            boundary,
        }
    }

    #[inline]
    pub fn validate_hash_against_boundary(
        hash: &H256, nonce: &U256, boundary: &U256,
    ) -> bool {
        let lower_bound = nonce_to_lower_bound(nonce);
        let (against_lower_bound_u256, _) =
            BigEndianHash::into_uint(hash).overflowing_sub(lower_bound);
        against_lower_bound_u256.lt(boundary)
            || boundary.eq(&ProofOfWorkProblem::NO_BOUNDARY)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ProofOfWorkSolution {
    pub nonce: U256,
}

#[derive(Debug, Clone, DeriveMallocSizeOf)]
pub struct ProofOfWorkConfig {
    pub test_mode: bool,
    pub use_octopus_in_test_mode: bool,
    pub use_stratum: bool,
    pub initial_difficulty: u64,
    pub block_generation_period: u64,
    pub difficulty_adjustment_epoch_period: u64,
    pub stratum_listen_addr: String,
    pub stratum_port: u16,
    pub stratum_secret: Option<H256>,
}

impl ProofOfWorkConfig {
    pub fn new(
        test_mode: bool, use_octopus_in_test_mode: bool, use_stratum: bool,
        initial_difficulty: Option<u64>, stratum_listen_addr: String,
        stratum_port: u16, stratum_secret: Option<H256>,
    ) -> Self
    {
        if test_mode {
            ProofOfWorkConfig {
                test_mode,
                use_octopus_in_test_mode,
                use_stratum,
                initial_difficulty: initial_difficulty.unwrap_or(4),
                block_generation_period: 1000000,
                difficulty_adjustment_epoch_period: 20,
                stratum_listen_addr,
                stratum_port,
                stratum_secret,
            }
        } else {
            ProofOfWorkConfig {
                test_mode,
                use_octopus_in_test_mode,
                use_stratum,
                initial_difficulty: INITIAL_DIFFICULTY,
                block_generation_period: TARGET_AVERAGE_BLOCK_GENERATION_PERIOD,
                difficulty_adjustment_epoch_period:
                    DIFFICULTY_ADJUSTMENT_EPOCH_PERIOD,
                stratum_listen_addr,
                stratum_port,
                stratum_secret,
            }
        }
    }

    pub fn use_octopus(&self) -> bool {
        !self.test_mode || self.use_octopus_in_test_mode
    }

    pub fn target_difficulty(
        &self, block_count: u64, timespan: u64, cur_difficulty: &U256,
    ) -> U256 {
        if timespan == 0 || block_count <= 1 || self.test_mode {
            return self.initial_difficulty.into();
        }

        let target = (U512::from(*cur_difficulty)
            * U512::from(self.block_generation_period)
            // - 1 for unbiased estimation, like stdvar
            * U512::from(block_count - 1))
            / (U512::from(timespan) * U512::from(1000000));
        if target.is_zero() {
            return 1.into();
        }
        if target > U256::max_value().into() {
            return U256::max_value();
        }
        U256::try_from(target).unwrap()
    }

    pub fn get_adjustment_bound(&self, diff: U256) -> (U256, U256) {
        let adjustment = diff / DIFFICULTY_ADJUSTMENT_FACTOR;
        let mut min_diff = diff - adjustment;
        let mut max_diff = diff + adjustment;
        let initial_diff: U256 = self.initial_difficulty.into();

        if min_diff < initial_diff {
            min_diff = initial_diff;
        }

        if max_diff < min_diff {
            max_diff = min_diff;
        }

        (min_diff, max_diff)
    }
}

// We will use the top 128 bits (excluding the highest bit) to be the lower
// bound of our PoW. The rationale is to provide a solution for block
// withholding attack among mining pools.
pub fn nonce_to_lower_bound(nonce: &U256) -> U256 {
    let mut buf = [0u8; 32];
    nonce.to_big_endian(&mut buf[..]);
    for i in 16..32 {
        buf[i] = 0;
    }
    buf[0] = buf[0] & 0x7f;
    // Note that U256::from assumes big_endian of the bytes
    let lower_bound = U256::from(buf);
    lower_bound
}

pub fn pow_hash_to_quality(hash: &H256, nonce: &U256) -> U256 {
    let hash_as_uint = BigEndianHash::into_uint(hash);
    let lower_bound = nonce_to_lower_bound(nonce);
    let (against_bound_u256, _) = hash_as_uint.overflowing_sub(lower_bound);
    if against_bound_u256.eq(&U256::MAX) {
        U256::one()
    } else {
        boundary_to_difficulty(&(against_bound_u256 + U256::one()))
    }
}

/// This should only be used in tests.
pub fn pow_quality_to_hash(pow_quality: &U256, nonce: &U256) -> H256 {
    let lower_bound = nonce_to_lower_bound(nonce);
    let hash_u256 = if pow_quality.eq(&U256::MAX) {
        U256::one()
    } else {
        let boundary = difficulty_to_boundary(&(pow_quality + U256::one()));
        let (against_bound_u256, _) = boundary.overflowing_add(lower_bound);
        against_bound_u256
    };
    BigEndianHash::from_uint(&hash_u256)
}

/// Convert boundary to its original difficulty. Basically just `f(x) = 2^256 /
/// x`.
pub fn boundary_to_difficulty(boundary: &U256) -> U256 {
    assert!(!boundary.is_zero());
    if boundary.eq(&U256::one()) {
        U256::MAX
    } else {
        compute_inv_x_times_2_pow_256_floor(boundary)
    }
}

/// Convert difficulty to the target boundary. Basically just `f(x) = 2^256 /
/// x`.
pub fn difficulty_to_boundary(difficulty: &U256) -> U256 {
    assert!(!difficulty.is_zero());
    if difficulty.eq(&U256::one()) {
        ProofOfWorkProblem::NO_BOUNDARY
    } else {
        compute_inv_x_times_2_pow_256_floor(difficulty)
    }
}

/// Compute [2^256 / x], where x >= 2 and x < 2^256.
pub fn compute_inv_x_times_2_pow_256_floor(x: &U256) -> U256 {
    let (div, modular) = U256::MAX.clone().div_mod(x.clone());
    if &(modular + U256::one()) == x {
        div + U256::one()
    } else {
        div
    }
}

pub struct PowComputer {
    use_octopus: bool,
    cache_builder: CacheBuilder,
}

impl PowComputer {
    pub fn new(use_octopus: bool) -> Self {
        PowComputer {
            use_octopus,
            cache_builder: CacheBuilder::new(),
        }
    }

    pub fn compute(
        &self, nonce: &U256, block_hash: &H256, block_height: u64,
    ) -> H256 {
        if !self.use_octopus {
            let mut buf = [0u8; 64];
            for i in 0..32 {
                buf[i] = block_hash[i];
            }
            nonce.to_little_endian(&mut buf[32..64]);
            let intermediate = keccak_hash(&buf[..]);
            let mut tmp = [0u8; 32];
            for i in 0..32 {
                tmp[i] = intermediate[i] ^ block_hash[i]
            }
            keccak_hash(tmp)
        } else {
            let light = self.cache_builder.light(block_height);
            light
                .compute(block_hash.as_fixed_bytes(), nonce.low_u64())
                .into()
        }
    }
}

pub fn validate(
    pow: Arc<PowComputer>, problem: &ProofOfWorkProblem,
    solution: &ProofOfWorkSolution,
) -> bool
{
    let nonce = solution.nonce;
    let hash = pow.compute(&nonce, &problem.block_hash, problem.block_height);
    ProofOfWorkProblem::validate_hash_against_boundary(
        &hash,
        &nonce,
        &problem.boundary,
    )
}

/// This function computes the target difficulty of the next period
/// based on the current period. `cur_hash` should be the hash of
/// the block at the current period upper boundary and it must have been
/// inserted to BlockDataManager, otherwise the function will panic.
/// `num_blocks_in_epoch` is a function that returns the epoch size
/// under the epoch view of a given block.
pub fn target_difficulty<F>(
    data_man: &BlockDataManager, pow_config: &ProofOfWorkConfig,
    cur_hash: &H256, num_blocks_in_epoch: F,
) -> U256
where
    F: Fn(&H256) -> usize,
{
    if let Some(target_diff) = data_man.target_difficulty_manager.get(cur_hash)
    {
        // The target difficulty of this period is already computed and cached.
        return target_diff;
    }

    let mut cur_header = data_man
        .block_header_by_hash(cur_hash)
        .expect("Must already in BlockDataManager block_header");
    let epoch = cur_header.height();
    assert_ne!(epoch, 0);
    debug_assert!(
        epoch
            == (epoch / pow_config.difficulty_adjustment_epoch_period)
                * pow_config.difficulty_adjustment_epoch_period
    );

    let mut cur = cur_hash.clone();
    let cur_difficulty = cur_header.difficulty().clone();
    let mut block_count = 0 as u64;
    let max_time = cur_header.timestamp();
    let mut min_time = 0;

    // Collect the total block count and the timespan in the current period
    for _ in 0..pow_config.difficulty_adjustment_epoch_period {
        block_count += num_blocks_in_epoch(&cur) as u64;
        cur = cur_header.parent_hash().clone();
        cur_header = data_man.block_header_by_hash(&cur).unwrap();
        if cur_header.timestamp() != 0 {
            min_time = cur_header.timestamp();
        }
        assert!(max_time >= min_time);
    }

    let mut target_diff = pow_config.target_difficulty(
        block_count,
        max_time - min_time,
        &cur_difficulty,
    );

    let (lower, upper) = pow_config.get_adjustment_bound(cur_difficulty);
    if target_diff > upper {
        target_diff = upper;
    }
    if target_diff < lower {
        target_diff = lower;
    }

    // Caching the computed target difficulty of this period.
    data_man
        .target_difficulty_manager
        .set(*cur_hash, target_diff);

    target_diff
}

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
}

#[test]
fn test_octopus() {
    let pow = PowComputer::new(true);

    let block_hash =
        "4d99d0b41c7eb0dd1a801c35aae2df28ae6b53bc7743f0818a34b6ec97f5b4ae"
            .parse()
            .unwrap();
    let start_nonce = 0x2333333333u64 & (!0x1f);
    pow.compute(&U256::from(start_nonce), &block_hash, 2);
}
