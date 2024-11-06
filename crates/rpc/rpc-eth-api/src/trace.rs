use cfx_rpc_eth_types::{BlockNumber, LocalizedTrace, TraceFilter};
use cfx_types::H256;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

#[rpc(server, namespace = "trace")]
pub trait TraceApi {
    /// Returns all traces produced at the given block.
    #[method(name = "block")]
    fn block_traces(
        &self, block_number: BlockNumber,
    ) -> RpcResult<Option<Vec<LocalizedTrace>>>;

    /// Returns all traces matching the provided filter.
    #[method(name = "filter")]
    fn filter_traces(
        &self, filter: TraceFilter,
    ) -> RpcResult<Option<Vec<LocalizedTrace>>>;

    /// Returns all traces produced at the given transaction.
    #[method(name = "transaction")]
    fn transaction_traces(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<Vec<LocalizedTrace>>>;
}
