use crate::rpc::types::{CfxFilterChanges, CfxRpcLogFilter, Log as RpcLog};
use cfx_types::H128;
use jsonrpc_core::Result as JsonRpcResult;
use jsonrpc_derive::rpc;

/// Eth filters rpc api (polling).
#[rpc(server)]
pub trait CfxFilter {
    /// Returns id of new filter.
    #[rpc(name = "cfx_newFilter")]
    fn new_filter(&self, _: CfxRpcLogFilter) -> JsonRpcResult<H128>;

    /// Returns id of new block filter.
    #[rpc(name = "cfx_newBlockFilter")]
    fn new_block_filter(&self) -> JsonRpcResult<H128>;

    /// Returns id of new block filter.
    #[rpc(name = "cfx_newPendingTransactionFilter")]
    fn new_pending_transaction_filter(&self) -> JsonRpcResult<H128>;

    /// Returns filter changes since last poll.
    #[rpc(name = "cfx_getFilterChanges")]
    fn filter_changes(&self, _: H128) -> JsonRpcResult<CfxFilterChanges>;

    /// Returns all logs matching given filter (in a range 'from' - 'to').
    #[rpc(name = "cfx_getFilterLogs")]
    fn filter_logs(&self, _: H128) -> JsonRpcResult<Vec<RpcLog>>;

    /// Uninstalls filter.
    #[rpc(name = "cfx_uninstallFilter")]
    fn uninstall_filter(&self, _: H128) -> JsonRpcResult<bool>;
}
