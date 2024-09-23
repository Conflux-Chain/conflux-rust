use alloy_rpc_types_trace::geth::{
    GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace,
    TraceResult,
};
use cfx_rpc_eth_types::{BlockNumber, TransactionRequest};
use cfx_types::H256;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

#[rpc(server, namespace = "debug")]
pub trait DebugApi {
    #[method(name = "dbGet")]
    async fn db_get(&self, key: String) -> RpcResult<Option<String>>;

    /// The `debug_traceTransaction` debugging method will attempt to run the
    /// transaction in the exact same manner as it was executed on the
    /// network. It will replay any transaction that may have been executed
    /// prior to this one before it will finally attempt to execute the
    /// transaction that corresponds to the given hash.
    #[method(name = "traceTransaction")]
    async fn debug_trace_transaction(
        &self, tx_hash: H256, opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<GethTrace>;

    #[method(name = "traceBlockByHash")]
    async fn debug_trace_block_by_hash(
        &self, block: H256, opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<Vec<TraceResult>>;

    #[method(name = "traceBlockByNumber")]
    async fn debug_trace_block_by_number(
        &self, block: BlockNumber, opts: Option<GethDebugTracingOptions>,
    ) -> RpcResult<Vec<TraceResult>>;

    #[method(name = "traceCall")]
    async fn debug_trace_call(
        &self, request: TransactionRequest, block_number: Option<BlockNumber>,
        opts: Option<GethDebugTracingCallOptions>,
    ) -> RpcResult<GethTrace>;
}
