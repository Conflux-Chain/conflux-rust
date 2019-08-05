// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod consensus {
    pub const DEFERRED_STATE_EPOCH_COUNT: u64 = 5;
    pub const EPOCH_SET_PERSISTENCE_DELAY: u64 = 100;

    pub const ADAPTIVE_WEIGHT_DEFAULT_ALPHA_NUM: u64 = 2;
    pub const ADAPTIVE_WEIGHT_DEFAULT_ALPHA_DEN: u64 = 3;
    pub const ADAPTIVE_WEIGHT_DEFAULT_BETA: u64 = 1000;
    pub const HEAVY_BLOCK_DEFAULT_DIFFICULTY_RATIO: u64 = 240;
    // The number of epochs per era. Each era is a potential checkpoint
    // position. The parent_edge checking and adaptive checking are defined
    // relative to the era start blocks.
    pub const ERA_DEFAULT_EPOCH_COUNT: u64 = 50000;
    // FIXME: We should use finality to determine the checkpoint moment instead.
    pub const ERA_DEFAULT_CHECKPOINT_GAP: u64 = 50000;
}

pub mod consensus_internal {
    /// `REWARD_EPOCH_COUNT` needs to be larger than
    /// `ANTICONE_PENALTY_UPPER_EPOCH_COUNT`. If we cannot cache receipts of
    /// recent `REWARD_EPOCH_COUNT` epochs, the receipts will be loaded from
    /// db, which may lead to performance downgrade
    pub const REWARD_EPOCH_COUNT: u64 = 12;
    pub const ANTICONE_PENALTY_UPPER_EPOCH_COUNT: u64 = 10;
    pub const ANTICONE_PENALTY_RATIO: u64 = 100;
    /// 900 Conflux tokens
    pub const BASE_MINING_REWARD: u64 = 900;
    /// The unit of one Conflux token: 10 ** 18
    pub const CONFLUX_TOKEN: u64 = 1_000_000_000_000_000_000;
    pub const GAS_PRICE_BLOCK_SAMPLE_SIZE: usize = 100;
    pub const GAS_PRICE_TRANSACTION_SAMPLE_SIZE: usize = 10000;

    // This is the cap of the size of the anticone barrier. If we have more than
    // this number we will use the brute_force O(n) algorithm instead.
    pub const ANTICONE_BARRIER_CAP: usize = 1000;
    // Here is the delay for us to recycle those orphaned blocks in the boundary
    // of eras.
    pub const ERA_RECYCLE_TRANSACTION_DELAY: u64 = 20;
    // A block can blame up to BLAME_BOUND ancestors that their states are
    // incorrect.
    pub const BLAME_BOUND: u32 = 1000;
}

pub mod sync {
    use std::time::Duration;

    pub const CATCH_UP_EPOCH_LAG_THRESHOLD: u64 = 3;

    pub const SYNCHRONIZATION_PROTOCOL_VERSION: u8 = 0x01;

    pub const MAX_HEADERS_TO_SEND: u64 = 512;
    pub const MAX_BLOCKS_TO_SEND: u64 = 256;
    pub const MAX_EPOCHS_TO_SEND: u64 = 128;
    pub const MAX_PACKET_SIZE: usize = 15 * 1024 * 1024 + 512 * 1024; // 15.5 MB
    lazy_static! {
        pub static ref REQUEST_START_WAITING_TIME: Duration =
            Duration::from_secs(1);
    }
    //const REQUEST_WAITING_TIME_BACKOFF: u32 = 2;
}

pub mod pow {
    // This factor N controls the bound of each difficulty adjustment.
    // The new difficulty should be in the range of [(1-1/N)*D, (1+1/N)*D],
    // where D is the old difficulty.
    pub const DIFFICULTY_ADJUSTMENT_FACTOR: usize = 2;
    pub const DIFFICULTY_ADJUSTMENT_EPOCH_PERIOD: u64 = 5000;
    // Time unit is micro-second (usec)
    pub const TARGET_AVERAGE_BLOCK_GENERATION_PERIOD: u64 = 1000000;
    pub const INITIAL_DIFFICULTY: u64 = 20_000_000;
}

pub const WORKER_COMPUTATION_PARALLELISM: usize = 8;
