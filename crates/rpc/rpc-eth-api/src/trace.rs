use cfx_rpc_eth_types::{
    BlockNumber, Index, LocalizedSetAuthTrace, LocalizedTrace, TraceFilter,
};
use cfx_types::H256;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

#[rpc(server, namespace = "trace")]
pub trait TraceApi {
    /// Returns all traces produced at the given block.
    #[method(name = "block")]
    async fn block_traces(
        &self, block_number: BlockNumber,
    ) -> RpcResult<Option<Vec<LocalizedTrace>>>;

    /// Returns all set auth traces produced at the given block.
    #[method(name = "blockSetAuth")]
    async fn block_set_auth_traces(
        &self, block_number: BlockNumber,
    ) -> RpcResult<Option<Vec<LocalizedSetAuthTrace>>>;

    /// Returns all traces matching the provided filter.
    #[method(name = "filter")]
    async fn filter_traces(
        &self, filter: TraceFilter,
    ) -> RpcResult<Vec<LocalizedTrace>>;

    #[method(name = "get")]
    async fn trace_get(
        &self, hash: H256, indices: Vec<Index>,
    ) -> RpcResult<Option<LocalizedTrace>>;

    /// Returns all traces produced at the given transaction.
    #[method(name = "transaction")]
    async fn transaction_traces(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<Vec<LocalizedTrace>>>;
}
