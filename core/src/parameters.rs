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

    pub const SNAPSHOT_EPOCHS_CAPACITY: u64 = 10000;

    pub const NULL: usize = !0;
    pub const NULLU64: u64 = !0;
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
    /// This is the renting fee for one key/value pair in storage.
    /// 1 token for 1024B, the storage for one key/value pair is 64B = 1/16
    /// token.
    pub const RENTAL_PRICE_PER_STORAGE_KEY: u64 = CONFLUX_TOKEN / 16;
    /// This is the scale factor for interest rate: 10^18. The interest rate per
    /// epoch will be `interest of year * epoch_duration_fraction *
    /// INTEREST_RATE_SCALE`.
    pub const INTEREST_RATE_SCALE: u64 = 1_000_000_000_000_000_000;
    /// This is the initial interest with scale: 0.04 * INTEREST_RATE_SCALE
    pub const INITIAL_INTEREST_RATE: u64 = 40_000_000_000_000_000;
    /// This is the number seconds per year
    pub const SECONDS_PER_YEAR: u64 = 60 * 60 * 24 * 365;

    // This is the cap of the size of the anticone barrier. If we have more than
    // this number we will use the brute_force O(n) algorithm instead.
    pub const ANTICONE_BARRIER_CAP: usize = 1000;
    // Here is the delay for us to recycle those orphaned blocks in the boundary
    // of eras.
    pub const ERA_RECYCLE_TRANSACTION_DELAY: u64 = 20;
    // This is the cap of the size of `blockset_in_own_view_of_epoch`. If we
    // have more than this number, we will not store it in memory
    pub const BLOCKSET_IN_OWN_VIEW_OF_EPOCH_CAP: u64 = 1000;

    // FIXME Use another method to prevent DDoS attacks if attackers control the
    // pivot chain A block can blame up to BLAME_BOUND ancestors that their
    // states are incorrect.
    //    pub const BLAME_BOUND: u32 = 1000;
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

    // The waiting time duration that will be accumulated for resending a
    // timeout request.
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

pub mod block {
    // The maximum block size limit in bytes
    pub const MAX_BLOCK_SIZE_IN_BYTES: usize = 800 * 1024;
    // The maximum number of referees allowed for each block
    pub const REFEREE_BOUND: usize = 200;
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
