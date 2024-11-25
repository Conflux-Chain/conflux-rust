use cfx_rpc_eth_api::EthFilterApiServer;
use cfx_rpc_eth_types::{EthRpcLogFilter as Filter, FilterChanges, Log};
use cfx_types::H128 as FilterId;
use jsonrpsee::core::RpcResult;

type PendingTransactionFilterKind = ();

pub struct EthFilterApi;

impl EthFilterApi {
    pub fn new() -> EthFilterApi { EthFilterApi }
}

#[async_trait::async_trait]
impl EthFilterApiServer for EthFilterApi {
    async fn new_filter(&self, filter: Filter) -> RpcResult<FilterId> {
        let _ = filter;
        todo!()
    }

    async fn new_block_filter(&self) -> RpcResult<FilterId> { todo!() }

    async fn new_pending_transaction_filter(
        &self, kind: Option<PendingTransactionFilterKind>,
    ) -> RpcResult<FilterId> {
        let _ = kind;
        todo!()
    }

    async fn filter_changes(&self, id: FilterId) -> RpcResult<FilterChanges> {
        let _ = id;
        todo!()
    }

    async fn filter_logs(&self, id: FilterId) -> RpcResult<Vec<Log>> {
        let _ = id;
        todo!()
    }

    async fn uninstall_filter(&self, id: FilterId) -> RpcResult<bool> {
        let _ = id;
        todo!()
    }

    async fn logs(&self, filter: Filter) -> RpcResult<Vec<Log>> {
        let _ = filter;
        todo!()
    }
}
