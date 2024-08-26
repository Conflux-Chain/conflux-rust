use crate::rpc::types::eth::{BlockNumber, TransactionRequest};
use alloy_rpc_types_trace::geth::{
    GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace,
    TraceResult,
};
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
    #[rpc(name = "debug_traceTransaction")]
    fn debug_trace_transaction(
        &self, tx_hash: H256, opts: Option<GethDebugTracingOptions>,
    ) -> JsonRpcResult<GethTrace>;

    #[rpc(name = "debug_traceBlockByHash")]
    fn debug_trace_block_by_hash(
        &self, block: H256, opts: Option<GethDebugTracingOptions>,
    ) -> JsonRpcResult<Vec<TraceResult>>;

    #[rpc(name = "debug_traceBlockByNumber")]
    fn debug_trace_block_by_number(
        &self, block: BlockNumber, opts: Option<GethDebugTracingOptions>,
    ) -> JsonRpcResult<Vec<TraceResult>>;

    #[rpc(name = "debug_traceCall")]
    fn debug_trace_call(
        &self, request: TransactionRequest, block_number: Option<BlockNumber>,
        opts: Option<GethDebugTracingCallOptions>,
    ) -> JsonRpcResult<GethTrace>;
}
