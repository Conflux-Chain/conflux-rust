// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod consensus {
    pub const DEFERRED_STATE_EPOCH_COUNT: u64 = 5;
    pub const EPOCH_SET_PERSISTENCE_DELAY: u64 = 100;

    pub const ADAPTIVE_WEIGHT_DEFAULT_BETA: u64 = 1000;
    pub const HEAVY_BLOCK_DEFAULT_DIFFICULTY_RATIO: u64 = 250;
    pub const TIMER_CHAIN_BLOCK_DEFAULT_DIFFICULTY_RATIO: u64 = 180;
    pub const TIMER_CHAIN_DEFAULT_BETA: u64 = 240;
    // The number of epochs per era. Each era is a potential checkpoint
    // position. The parent_edge checking and adaptive checking are defined
    // relative to the era start blocks.
    pub const ERA_DEFAULT_EPOCH_COUNT: u64 = 20000;

    pub const SNAPSHOT_EPOCHS_CAPACITY: u32 = 10000;

    pub const NULL: usize = !0;
    pub const NULLU64: u64 = !0;

    pub const MAX_BLAME_RATIO_FOR_TRUST: f64 = 0.4;

    pub const TRANSACTION_DEFAULT_EPOCH_BOUND: u64 = 100000;
}

pub mod consensus_internal {
    /// `REWARD_EPOCH_COUNT` needs to be larger than
    /// `ANTICONE_PENALTY_UPPER_EPOCH_COUNT`. If we cannot cache receipts of
    /// recent `REWARD_EPOCH_COUNT` epochs, the receipts will be loaded from
    /// db, which may lead to performance downgrade
    pub const REWARD_EPOCH_COUNT: u64 = 12;
    pub const ANTICONE_PENALTY_UPPER_EPOCH_COUNT: u64 = 10;
    pub const ANTICONE_PENALTY_RATIO: u64 = 100;
    // The initial base mining reward in uCFX.
    pub const INITIAL_BASE_MINING_REWARD_IN_UCFX: u64 = 11_300_000;
    // The ultimate base mining reward in uCFX.
    pub const ULTIMATE_BASE_MINING_REWARD_IN_UCFX: u64 = 2_030_000;
    // The average number of blocks mined per quarter.
    pub const MINED_BLOCK_COUNT_PER_QUARTER: u64 = 15768000;
    pub const MINING_REWARD_DECAY_RATIO_PER_QUARTER: f64 = 0.958;
    // How many quarters that the mining reward keep decaying.
    pub const MINING_REWARD_DECAY_PERIOD_IN_QUARTER: usize = 40;
    /// The unit of one Conflux token: 10 ** 18
    pub const CONFLUX_TOKEN: u64 = 1_000_000_000_000_000_000;
    pub const GAS_PRICE_BLOCK_SAMPLE_SIZE: usize = 100;
    pub const GAS_PRICE_TRANSACTION_SAMPLE_SIZE: usize = 10000;

    /// This is the cap of the size of the anticone barrier. If we have more
    /// than this number we will use the brute_force O(n) algorithm instead.
    pub const ANTICONE_BARRIER_CAP: usize = 100;
    /// Here is the delay for us to recycle those orphaned blocks in the
    /// boundary of eras.
    pub const ERA_RECYCLE_TRANSACTION_DELAY: u64 = 20;
    /// This is the cap of the size of `blockset_in_own_view_of_epoch`. If we
    /// have more than this number, we will not store it in memory
    pub const BLOCKSET_IN_OWN_VIEW_OF_EPOCH_CAP: u64 = 1000;

    /// This is the minimum risk that the confirmation meter tries to maintain.
    pub const CONFIRMATION_METER_MIN_MAINTAINED_RISK: f64 = 0.00000001;
    /// The maximum number of epochs that the confirmation meter tries to
    /// maintain internally.
    pub const CONFIRMATION_METER_MAX_NUM_MAINTAINED_RISK: usize = 100;
    /// The minimum timer diff value for the adaptive test in confirmation meter
    /// to consider
    pub const CONFIRMATION_METER_ADAPTIVE_TEST_TIMER_DIFF: u64 = 140;
    /// The batch step in the confirmation meter to do the adaptive test
    pub const CONFIRMATION_METER_PSI: u64 = 30;
    /// The maximum value of adaptive block generation risk that a confirmation
    /// meter is going to consider safe to assume no adaptive blocks in the
    /// near future.
    pub const CONFIRMATION_METER_MAXIMUM_ADAPTIVE_RISK: f64 = 0.0000001;
}

pub mod sync {
    use std::time::Duration;

    /// The threshold controlling whether a node is in catch-up mode.
    /// A node is in catch-up mode if its local best epoch number is
    /// CATCH_UP_EPOCH_LAG_THRESHOLD behind the median of the epoch
    /// numbers of peers.
    pub const CATCH_UP_EPOCH_LAG_THRESHOLD: u64 = 3;
    /// This threshold controlling whether a node should request missing
    /// terminals from peers when the node is in catch-up mode.
    pub const REQUEST_TERMINAL_EPOCH_LAG_THRESHOLD: u64 = 8;

    pub const SYNCHRONIZATION_PROTOCOL_VERSION: u8 = 0x01;
    /// The max number of headers that are to be sent for header
    /// block request.
    pub const MAX_HEADERS_TO_SEND: u64 = 512;
    /// The max number of blocks that are to be sent for compact block request.
    pub const MAX_BLOCKS_TO_SEND: u64 = 128;
    /// The max number of epochs whose hashes are to be responded
    /// for request GetBlockHashesByEpoch
    pub const MAX_EPOCHS_TO_SEND: u64 = 128;
    pub const MAX_PACKET_SIZE: usize = 15 * 1024 * 1024 + 512 * 1024; // 15.5 MB

    /// The threshold controlling whether we should query local_block_info in
    /// disk when requesting block header or block. If the difference
    /// between height of the block and current best height is less than
    /// LOCAL_BLOCK_INFO_QUERY_THRESHOLD, we can request block directly through
    /// network, otherwise we should check disk first.
    pub const LOCAL_BLOCK_INFO_QUERY_THRESHOLD: u64 = 5;

    /// Measured block propagation delay in *seconds*. This will determine the
    /// conservative window when we measure confirmation risk internally in
    /// the consensus layer.
    pub const BLOCK_PROPAGATION_DELAY: u64 = 10;

    lazy_static! {
        // The waiting time duration that will be accumulated for resending a
        // timeout request.
        pub static ref REQUEST_START_WAITING_TIME: Duration =
            Duration::from_secs(1);

        // The waiting time duration before resending a request which failed
        // due to sending error.
        pub static ref FAILED_REQUEST_RESEND_WAIT: Duration =
            Duration::from_millis(50);
    }
    //const REQUEST_WAITING_TIME_BACKOFF: u32 = 2;
    pub const DEFAULT_CHUNK_SIZE: u64 = 1 * 1024 * 1024;

    /// The batch size of old-era blocks garbage-collected from database for
    /// each BLOCK_CACHE_GC_TIMER timer trigger.
    /// Note that the average block removing rate should be greater than the
    /// block generation rate, otherwise `ConsensusInner.old_era_block_set`
    /// will keep growing.
    pub const OLD_ERA_BLOCK_GC_BATCH_SIZE: usize = 50;
}

pub mod pow {
    // This factor N controls the bound of each difficulty adjustment.
    // The new difficulty should be in the range of [(1-1/N)*D, (1+1/N)*D],
    // where D is the old difficulty.
    pub const DIFFICULTY_ADJUSTMENT_FACTOR: usize = 2;
    pub const DIFFICULTY_ADJUSTMENT_EPOCH_PERIOD: u64 = 5000;
    // Time unit is micro-second (usec)
    // We target two blocks per second. This strikes a good balance between the
    // growth of the metadata, the memory consumption of the consensus graph,
    // and the confirmation speed
    pub const TARGET_AVERAGE_BLOCK_GENERATION_PERIOD: u64 = 500000;
    pub const INITIAL_DIFFICULTY: u64 = 10_000_000;
}

pub mod block {
    // The maximum block size limit in bytes
    // Consider that the simple payment transaction consumes only 100 bytes per
    // second. This would allow us to have 2000 simple payment transactions
    // per block. With two blocks per second, we will have 4000TPS at the
    // peak with only simple payment, which is good enough for now.
    pub const MAX_BLOCK_SIZE_IN_BYTES: usize = 200 * 1024;
    // The maximum number of transactions to be packed in a block given
    // `MAX_BLOCK_SIZE_IN_BYTES`, assuming 50-byte transactions.
    pub const ESTIMATED_MAX_BLOCK_SIZE_IN_TRANSACTION_COUNT: usize = 4096;
    // The maximum number of referees allowed for each block
    pub const REFEREE_DEFAULT_BOUND: usize = 200;
    // The maximal length of custom data in block header
    pub const HEADER_CUSTOM_LENGTH_BOUND: usize = 64;
    // If a new block is more than valid_time_drift ahead of the current system
    // timestamp, it will be discarded (but may get received again) and the
    // peer will be disconnected.
    pub const VALID_TIME_DRIFT: u64 = 10 * 60;
    // A new block has to be less than this drift to send to the consensus
    // graph. Otherwise, it will be queued at the synchronization layer.
    pub const ACCEPTABLE_TIME_DRIFT: u64 = 5 * 60;
    // FIXME: a block generator parameter only. We should remove this later
    pub const MAX_TRANSACTION_COUNT_PER_BLOCK: usize = 20000;
}

pub mod staking {
    use super::{
        consensus_internal::CONFLUX_TOKEN,
        pow::TARGET_AVERAGE_BLOCK_GENERATION_PERIOD,
    };
    use cfx_types::U256;

    /// This is the exchange unit between storage and CFX.
    pub const NUM_BYTES_PER_CONFLUX_TOKEN: u64 = 1024;

    /// This is the number of blocks per second.
    pub const BLOCKS_PER_SECOND: u64 =
        1000000 / TARGET_AVERAGE_BLOCK_GENERATION_PERIOD;
    /// This is the number of blocks per day.
    pub const BLOCKS_PER_DAY: u64 = BLOCKS_PER_SECOND * 60 * 60 * 24;
    /// This is the number of blocks per year.
    pub const BLOCKS_PER_YEAR: u64 = BLOCKS_PER_DAY * 365;

    lazy_static! {
        /// This is the renting fee for one byte in storage. 1 CFX for 1024 Bytes.
        pub static ref COLLATERAL_PER_BYTE: U256 = U256::from(CONFLUX_TOKEN / NUM_BYTES_PER_CONFLUX_TOKEN);
        /// This is the renting fee for one key/value pair in storage.
        /// 1 CFX for 1 KB, the storage for one key/value pair is 64 B = 1/16 CFX.
        pub static ref COLLATERAL_PER_STORAGE_KEY: U256 = *COLLATERAL_PER_BYTE * U256::from(64);
        /// This is the scale factor for accumulated interest rate: `BLOCKS_PER_YEAR * 2 ^ 80`.
        /// The actual accumulate interest rate stored will be `accumulate_interest_rate / INTEREST_RATE_SCALE`.
        pub static ref ACCUMULATED_INTEREST_RATE_SCALE: U256 = U256::from(BLOCKS_PER_YEAR) << 80;
        /// The initial annual interest is 4%, which means the initial interest rate per block will be
        /// `4% / BLOCKS_PER_YEAR`. We will multiply it with scale factor and store it as an integer.
        /// This is the scale factor of initial interest rate per block.
        pub static ref INTEREST_RATE_PER_BLOCK_SCALE: U256 = U256::from(BLOCKS_PER_YEAR * 1000000);
        /// This is the initial interest rate per block with scale: `4% / BLOCKS_PER_YEAR * INTEREST_RATE_PER_BLOCK_SCALE`.
        pub static ref INITIAL_INTEREST_RATE_PER_BLOCK: U256 = U256::from(40000);
        /// This is the service charge rate for withdraw, `SERVICE_CHARGE_RATE /
        /// SERVICE_CHARGE_RATE_SCALE = 0.05%`
        pub static ref SERVICE_CHARGE_RATE: U256 = U256::from(5);
        pub static ref SERVICE_CHARGE_RATE_SCALE: U256 = U256::from(10000);
    }
}

pub mod light {
    use std::time::Duration;

    lazy_static! {
        /// Frequency of re-triggering sync.
        pub static ref SYNC_PERIOD: Duration = Duration::from_secs(1);

        /// Frequency of checking request timeouts.
        pub static ref CLEANUP_PERIOD: Duration = Duration::from_secs(1);

        /// Request timeouts.
        pub static ref EPOCH_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
        pub static ref HEADER_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
        pub static ref WITNESS_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
        pub static ref BLOOM_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
        pub static ref RECEIPT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
        pub static ref BLOCK_TX_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
        pub static ref STATE_ROOT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
        pub static ref STATE_ENTRY_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
        pub static ref TX_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
        pub static ref TX_INFO_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

        /// Maximum time period we wait for a response for an on-demand query.
        /// After this timeout has been reached, we try another peer or give up.
        pub static ref MAX_POLL_TIME: Duration = Duration::from_secs(4);

        /// Period of time to sleep between subsequent polls for on-demand queries.
        pub static ref POLL_PERIOD: Duration = Duration::from_millis(100);

        /// Items not accessed for this amount of time are removed from the cache.
        pub static ref CACHE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
    }

    /// The threshold controlling whether a node is in catch-up mode.
    /// A node is in catch-up mode if its local best epoch number is
    /// `CATCH_UP_EPOCH_LAG_THRESHOLD` behind the median of the epoch
    /// numbers of peers.
    pub const CATCH_UP_EPOCH_LAG_THRESHOLD: u64 = 3;

    /// (Maximum) number of items requested in a single request.
    pub const EPOCH_REQUEST_BATCH_SIZE: usize = 30;
    pub const HEADER_REQUEST_BATCH_SIZE: usize = 30;
    pub const BLOOM_REQUEST_BATCH_SIZE: usize = 30;
    pub const WITNESS_REQUEST_BATCH_SIZE: usize = 10;
    pub const RECEIPT_REQUEST_BATCH_SIZE: usize = 30;
    pub const BLOCK_TX_REQUEST_BATCH_SIZE: usize = 30;
    pub const STATE_ROOT_REQUEST_BATCH_SIZE: usize = 30;
    pub const STATE_ENTRY_REQUEST_BATCH_SIZE: usize = 30;
    pub const TX_REQUEST_BATCH_SIZE: usize = 30;
    pub const TX_INFO_REQUEST_BATCH_SIZE: usize = 30;

    /// Maximum number of in-flight items at any given time.
    /// If we reach this limit, we will not request any more.
    pub const MAX_HEADERS_IN_FLIGHT: usize = 500;
    pub const MAX_WITNESSES_IN_FLIGHT: usize = 30;
    pub const MAX_BLOOMS_IN_FLIGHT: usize = 500;
    pub const MAX_RECEIPTS_IN_FLIGHT: usize = 100;
    pub const MAX_BLOCK_TXS_IN_FLIGHT: usize = 100;
    pub const MAX_STATE_ROOTS_IN_FLIGHT: usize = 100;
    pub const MAX_STATE_ENTRIES_IN_FLIGHT: usize = 100;
    pub const MAX_TXS_IN_FLIGHT: usize = 100;
    pub const MAX_TX_INFOS_IN_FLIGHT: usize = 100;

    /// Maximum number of in-flight epoch requests at any given time.
    /// Similar to `MAX_HEADERS_IN_FLIGHT`. However, it is hard to match
    /// hash responses to epoch requests, so we count the requests instead.
    pub const MAX_PARALLEL_EPOCH_REQUESTS: usize = 10;

    /// Number of epochs to request in one round (in possibly multiple batches).
    pub const NUM_EPOCHS_TO_REQUEST: usize = 200;

    /// Minimum number of missing items in the sync pipeline.
    /// If we have fewer, we will try to request some more.
    pub const NUM_WAITING_HEADERS_THRESHOLD: usize = 1000;
    pub const NUM_WAITING_WITNESSES_THRESHOLD: usize = 30;

    /// Max number of epochs/headers/txs to send to a light peer in a response.
    pub const MAX_EPOCHS_TO_SEND: usize = 128;
    pub const MAX_HEADERS_TO_SEND: usize = 512;
    pub const MAX_TXS_TO_SEND: usize = 1024;

    /// During syncing, we might transiently have enough malicious blaming
    /// blocks to consider a correct header incorrect. For this reason, we
    /// first wait for enough header to accumulate before checking blaming.
    pub const BLAME_CHECK_OFFSET: u64 = 20;

    /// During log filtering, we stream a set of items (blooms, receipts, txs)
    /// to match against. To make the process faster, we need to make sure that
    /// there's always plenty of items in flight. This way, we can reduce idle
    /// time when we're waiting to recveive an item.
    pub const LOG_FILTERING_LOOKAHEAD: usize = 100;
}

pub const WORKER_COMPUTATION_PARALLELISM: usize = 8;
