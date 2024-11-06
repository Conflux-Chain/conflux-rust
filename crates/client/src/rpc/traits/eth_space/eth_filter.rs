use crate::rpc::types::eth::{EthRpcLogFilter, FilterChanges, Log};
use cfx_types::H128;
use jsonrpc_core::Result;
use jsonrpc_derive::rpc;

/// Eth filters rpc api (polling).
#[rpc(server)]
pub trait EthFilter {
    /// Returns id of new filter.
    #[rpc(name = "eth_newFilter")]
    fn new_filter(&self, filter: EthRpcLogFilter) -> Result<H128>;

    /// Returns id of new block filter.
    #[rpc(name = "eth_newBlockFilter")]
    fn new_block_filter(&self) -> Result<H128>;

    /// Returns id of new block filter.
    #[rpc(name = "eth_newPendingTransactionFilter")]
    fn new_pending_transaction_filter(&self) -> Result<H128>;

    /// Returns filter changes since last poll.
    #[rpc(name = "eth_getFilterChanges")]
    fn filter_changes(&self, identifier: H128) -> Result<FilterChanges>;

    /// Returns all logs matching given filter (in a range 'from' - 'to').
    #[rpc(name = "eth_getFilterLogs")]
    fn filter_logs(&self, identifier: H128) -> Result<Vec<Log>>;

    /// Uninstalls filter.
    #[rpc(name = "eth_uninstallFilter")]
    fn uninstall_filter(&self, identifier: H128) -> Result<bool>;
}
