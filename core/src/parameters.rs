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
    /// This is the bound for `min/max_epoch_in_other_views`. If we have more
    /// than this number, we will use the brute_force O(n) algorithm to collect
    /// blockset instead.
    pub const EPOCH_IN_OTHER_VIEWS_GAP_BOUND: u64 = 1000;

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
    /// The threshold controlling whether a node is in catch-up mode.
    /// A node is in catch-up mode if its local best epoch number is
    /// `CATCH_UP_EPOCH_LAG_THRESHOLD` behind the median of the epoch
    /// numbers of peers.
    pub const CATCH_UP_EPOCH_LAG_THRESHOLD: u64 = 3;

    /// Frequency of checking request timeouts.
    pub const CLEANUP_PERIOD_MS: u64 = 1000;

    /// Frequency of re-triggering sync.
    pub const SYNC_PERIOD_MS: u64 = 5000;

    /// Timeout for `GetBlockHashesByEpoch` and `GetBlockHeaders` requests.
    pub const EPOCH_REQUEST_TIMEOUT_MS: u64 = 2000;
    pub const HEADER_REQUEST_TIMEOUT_MS: u64 = 2000;

    /// Maximum time period we wait for a response for an on-demand query.
    /// After this timeout has been reached, we try another peer or give up.
    pub const MAX_POLL_TIME_MS: u64 = 1000;

    /// Period of time to sleep between subsequent polls for on-demand queries.
    pub const POLL_PERIOD_MS: u64 = 100;

    /// (Maximum) number of epochs/headers requested in a single request.
    pub const EPOCH_REQUEST_BATCH_SIZE: usize = 30;
    pub const HEADER_REQUEST_BATCH_SIZE: usize = 30;

    /// Maximum number of in-flight headers at any given time.
    /// If we reach this limit, we will not request any more headers.
    pub const MAX_HEADERS_IN_FLIGHT: usize = 500;

    /// Maximum number of in-flight epoch requests at any given time.
    /// Similar to `MAX_HEADERS_IN_FLIGHT`. However, it is hard to match
    /// hash responses to epoch requests, so we count the requests instead.
    pub const MAX_PARALLEL_EPOCH_REQUESTS: usize = 10;

    /// Number of epochs to request in one round (in possibly multiple batches).
    pub const NUM_EPOCHS_TO_REQUEST: usize = 200;

    /// Minimum number of missing headers during catch-up mode.
    /// If we have fewer, we will try to request some more using a
    /// `GetBlockHashesByEpoch` request.
    pub const NUM_WAITING_HEADERS_THRESHOLD: usize = 1000;

    /// Maximum number of epochs/headers to send to a light peer in a response.
    pub const MAX_EPOCHS_TO_SEND: usize = 128;
    pub const MAX_HEADERS_TO_SEND: usize = 512;
}

pub const WORKER_COMPUTATION_PARALLELISM: usize = 8;
