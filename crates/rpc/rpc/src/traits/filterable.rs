use crate::helpers::{poll_filter::SyncPollFilter, poll_manager::PollManager};
use cfx_rpc_eth_types::{EthRpcLogFilter, Log};
use cfx_types::H256;
use cfxcore::{ConsensusGraph, SharedConsensusGraph};
use jsonrpc_core::Result as RpcResult;
use parking_lot::Mutex;
use primitives::{filter::LogFilter, EpochNumber};
use std::collections::{BTreeSet, VecDeque};

pub trait Filterable {
    /// Current best epoch number.
    fn best_executed_epoch_number(&self) -> u64;

    /// Get a block hash by block id.
    fn block_hashes(&self, epoch_num: EpochNumber) -> Option<Vec<H256>>;

    /// pending transaction hashes at the given block (unordered).
    fn pending_transaction_hashes(&self) -> BTreeSet<H256>;

    /// Get logs that match the given filter.
    fn logs(&self, filter: LogFilter) -> RpcResult<Vec<Log>>;

    /// Get logs that match the given filter for specific epoch
    fn logs_for_epoch(
        &self, filter: &LogFilter, epoch: (u64, Vec<H256>), removed: bool,
    ) -> RpcResult<Vec<Log>>;

    /// Get a reference to the poll manager.
    fn polls(&self) -> &Mutex<PollManager<SyncPollFilter<Log>>>;

    /// Get a reference to ConsensusGraph
    fn consensus_graph(&self) -> &ConsensusGraph;

    /// Get a clone of SharedConsensusGraph
    fn shared_consensus_graph(&self) -> SharedConsensusGraph;

    /// Get logs limitation
    fn get_logs_filter_max_limit(&self) -> Option<usize>;

    /// Get epochs since last query
    fn epochs_since_last_request(
        &self, last_epoch_number: u64,
        recent_reported_epochs: &VecDeque<(u64, Vec<H256>)>,
    ) -> RpcResult<(u64, Vec<(u64, Vec<H256>)>)>;

    fn into_primitive_filter(
        &self, filter: EthRpcLogFilter,
    ) -> RpcResult<LogFilter>;
}
