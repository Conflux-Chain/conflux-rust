use cfx_internal_common::ChainIdParams;

use super::{pivot_hint::{PivotHint, PivotHintConfig}, ConsensusInnerConfig};

#[derive(Clone)]
pub struct ConsensusConfig {
    /// Chain id configs.
    pub chain_id: ChainIdParams,
    /// When bench_mode is true, the PoW solution verification will be skipped.
    /// The transaction execution will also be skipped and only return the
    /// pair of (KECCAK_NULL_RLP, KECCAK_EMPTY_LIST_RLP) This is for testing
    /// only
    pub bench_mode: bool,
    /// The configuration used by inner data
    pub inner_conf: ConsensusInnerConfig,
    /// The epoch bound for processing a transaction. For a transaction being
    /// process, the epoch height of its enclosing block must be with in
    /// [tx.epoch_height - transaction_epoch_bound, tx.epoch_height +
    /// transaction_epoch_bound]
    pub transaction_epoch_bound: u64,
    /// The number of referees that are allowed for a block.
    pub referee_bound: usize,
    /// Epoch batch size used in log filtering.
    /// Larger batch sizes may improve performance but might also prevent
    /// consensus from making progress under high RPC load.
    pub get_logs_epoch_batch_size: usize,

    /// Limits on epoch and block number ranges during log filtering.
    pub get_logs_filter_max_epoch_range: Option<u64>,
    pub get_logs_filter_max_block_number_range: Option<u64>,
    /// Max limiation for logs
    pub get_logs_filter_max_limit: Option<usize>,

    /// TODO: These parameters are only utilized in catch-up now.
    /// TODO: They should be used in data garbage collection, too.
    /// TODO: States, receipts, and block bodies need separate parameters.
    /// The starting epoch that we need to sync its state and start replaying
    /// transactions.
    pub sync_state_starting_epoch: Option<u64>,
    /// The number of extra epochs that we want to keep
    /// states/receipts/transactions.
    pub sync_state_epoch_gap: Option<u64>,

    /// The file path and checksum for `PivotHint`
    pub pivot_hint_conf: Option<PivotHintConfig>,
}