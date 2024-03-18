use alloy_rpc_trace_types::geth::{GethDebugTracingOptions, GethTrace};
use cfx_types::H256;
use jsonrpc_core::Result as JsonRpcResult;
use jsonrpc_derive::rpc;

/// methods compatible with geth debug namespace methods https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-debug
#[rpc(server)]
pub trait Debug {
    #[rpc(name = "debug_dbGet")]
    fn db_get(&self, key: String) -> JsonRpcResult<Option<String>>;

    /// The `debug_traceTransaction` debugging method will attempt to run the
    /// transaction in the exact same manner as it was executed on the
    /// network. It will replay any transaction that may have been executed
    /// prior to this one before it will finally attempt to execute the
    /// transaction that corresponds to the given hash.
    #[rpc(name = "traceTransaction")]
    fn debug_trace_transaction(
        &self, tx_hash: H256, opts: Option<GethDebugTracingOptions>,
    ) -> JsonRpcResult<GethTrace>;
}
