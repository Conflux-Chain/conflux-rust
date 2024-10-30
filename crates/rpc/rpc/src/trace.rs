use cfx_rpc_eth_api::TraceApiServer;
use cfx_rpc_eth_types::{BlockNumber, LocalizedTrace, TraceFilter};
use cfx_types::H256;
use jsonrpsee::core::RpcResult;

pub struct TraceApi;

impl TraceApi {
    pub fn new() -> TraceApi { TraceApi }
}

#[async_trait::async_trait]
impl TraceApiServer for TraceApi {
    fn block_traces(
        &self, block_number: BlockNumber,
    ) -> RpcResult<Option<Vec<LocalizedTrace>>> {
        let _ = block_number;
        todo!()
    }

    fn filter_traces(
        &self, filter: TraceFilter,
    ) -> RpcResult<Option<Vec<LocalizedTrace>>> {
        let _ = filter;
        todo!()
    }

    fn transaction_traces(
        &self, tx_hash: H256,
    ) -> RpcResult<Option<Vec<LocalizedTrace>>> {
        let _ = tx_hash;
        todo!()
    }
}
