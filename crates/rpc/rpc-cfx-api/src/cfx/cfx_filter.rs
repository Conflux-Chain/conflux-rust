use cfx_rpc_cfx_types::{CfxFilterChanges, CfxRpcLogFilter, Log as RpcLog};
use cfx_types::H128;
use jsonrpsee::{core::RpcResult as JsonRpcResult, proc_macros::rpc};

/// Cfx filters rpc api (polling).
#[rpc(server, namespace = "cfx")]
pub trait CfxFilterRpc {
    /// Returns id of new filter.
    #[method(name = "newFilter")]
    fn new_filter(&self, filter: CfxRpcLogFilter) -> JsonRpcResult<H128>;

    /// Returns id of new block filter.
    #[method(name = "newBlockFilter")]
    fn new_block_filter(&self) -> JsonRpcResult<H128>;

    /// Returns id of new pending transaction filter.
    #[method(name = "newPendingTransactionFilter")]
    fn new_pending_transaction_filter(&self) -> JsonRpcResult<H128>;

    /// Returns filter changes since last poll.
    #[method(name = "getFilterChanges")]
    fn filter_changes(
        &self, filter_id: H128,
    ) -> JsonRpcResult<CfxFilterChanges>;

    /// Returns all logs matching given filter (in a range 'from' - 'to').
    #[method(name = "getFilterLogs")]
    fn filter_logs(&self, filter_id: H128) -> JsonRpcResult<Vec<RpcLog>>;

    /// Uninstalls filter.
    #[method(name = "uninstallFilter")]
    fn uninstall_filter(&self, filter_id: H128) -> JsonRpcResult<bool>;
}
