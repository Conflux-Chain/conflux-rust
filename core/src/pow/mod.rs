// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::hash::keccak;
use cfx_types::{H256, U256, U512};
use rlp::RlpStream;

pub const DIFFICULTY_ADJUSTMENT_EPOCH_PERIOD: u64 = 200;
// Time unit is micro-second (usec)
pub const TARGET_AVERAGE_BLOCK_GENERATION_PERIOD: u64 = 5000000;
pub const INITIAL_DIFFICULTY: u64 = 5_000_000_000;

//FIXME: May be better to place in other place.
pub const WORKER_COMPUTATION_PARALLELISM: usize = 8;

#[derive(Debug, Copy, Clone, PartialOrd, PartialEq)]
pub struct ProofOfWorkProblem {
    pub block_hash: H256,
    pub difficulty: U256,
    pub boundary: H256,
}

#[derive(Debug, Copy, Clone)]
pub struct ProofOfWorkSolution {
    pub nonce: u64,
}

#[derive(Debug, Copy, Clone)]
pub struct ProofOfWorkConfig {
    pub test_mode: bool,
    pub initial_difficulty: u64,
    pub block_generation_period: u64,
    pub difficulty_adjustment_epoch_period: u64,
}

impl ProofOfWorkConfig {
    pub fn new(test_mode: bool, initial_difficulty: Option<u64>) -> Self {
        if test_mode {
            ProofOfWorkConfig {
                test_mode: true,
                initial_difficulty: initial_difficulty.unwrap_or(4),
                block_generation_period: 1000000,
                difficulty_adjustment_epoch_period: 20,
            }
        } else {
            ProofOfWorkConfig {
                test_mode: false,
                initial_difficulty: INITIAL_DIFFICULTY,
                block_generation_period: TARGET_AVERAGE_BLOCK_GENERATION_PERIOD,
                difficulty_adjustment_epoch_period:
                    DIFFICULTY_ADJUSTMENT_EPOCH_PERIOD,
            }
        }
    }

    pub fn target_difficulty(
        &self, block_count: u64, timespan: u64, cur_difficulty: &U256,
    ) -> U256 {
        if timespan == 0 || block_count == 0 || self.test_mode {
            return self.initial_difficulty.into();
        }

        let target = (U512::from(*cur_difficulty)
            * U512::from(self.block_generation_period)
            * U512::from(block_count))
            / (U512::from(timespan) * U512::from(1000000));
        if target.is_zero() {
            return 1.into();
        }
        if target > U256::max_value().into() {
            return U256::max_value();
        }
        U256::from(target)
    }
}

/// Convert boundary to its original difficulty. Basically just `f(x) = 2^256 /
/// x`.
pub fn boundary_to_difficulty(boundary: &H256) -> U256 {
    difficulty_to_boundary_aux(&**boundary)
}

/// Convert difficulty to the target boundary. Basically just `f(x) = 2^256 /
/// x`.
pub fn difficulty_to_boundary(difficulty: &U256) -> H256 {
    difficulty_to_boundary_aux(difficulty).into()
}

pub fn difficulty_to_boundary_aux<T: Into<U512>>(difficulty: T) -> U256 {
    let difficulty = difficulty.into();
    assert!(!difficulty.is_zero());
    if difficulty == U512::one() {
        U256::max_value()
    } else {
        // difficulty > 1, so result should never overflow 256 bits
        U256::from((U512::one() << 256) / difficulty)
    }
}

pub fn compute(nonce: u64, block_hash: &H256) -> H256 {
    let mut rlp = RlpStream::new_list(2);
    rlp.append(block_hash).append(&nonce);
    keccak(rlp.out())
}

pub fn validate(
    problem: &ProofOfWorkProblem, solution: &ProofOfWorkSolution,
) -> bool {
    let nonce = solution.nonce;
    let hash = compute(nonce, &problem.block_hash);
    hash < problem.boundary
}
