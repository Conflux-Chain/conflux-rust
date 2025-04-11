use async_trait::async_trait;
use cfx_rpc_eth_api::TxPoolApiServer;
use cfx_rpc_eth_types::{
    TxpoolContent, TxpoolContentFrom, TxpoolInspect, TxpoolStatus,
};
use cfx_rpc_utils::error::jsonrpsee_error_helpers::internal_error as jsonrpsee_internal_error;
use cfx_types::{Address, Space, U64};
use cfxcore::SharedTransactionPool;
use jsonrpsee::core::RpcResult;

pub struct TxPoolApi {
    tx_pool: SharedTransactionPool,
}

impl TxPoolApi {
    pub fn new(tx_pool: SharedTransactionPool) -> Self { Self { tx_pool } }
}

#[async_trait]
impl TxPoolApiServer for TxPoolApi {
    async fn txpool_status(&self) -> RpcResult<TxpoolStatus> {
        Ok(TxpoolStatus {
            pending: U64::from(
                self.tx_pool.total_pending(Some(Space::Ethereum)),
            ),
            queued: U64::from(self.tx_pool.total_queued(Some(Space::Ethereum))),
        })
    }

    async fn txpool_inspect(&self) -> RpcResult<TxpoolInspect> {
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    async fn txpool_content_from(
        &self, from: Address,
    ) -> RpcResult<TxpoolContentFrom> {
        let _ = from;
        Err(jsonrpsee_internal_error("Not implemented"))
    }

    async fn txpool_content(&self) -> RpcResult<TxpoolContent> {
        Err(jsonrpsee_internal_error("Not implemented"))
    }
}
