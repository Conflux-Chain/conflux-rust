use crate::EthApi;
use async_trait::async_trait;
use cfx_rpc_eth_api::ParityApiServer;
use cfx_rpc_eth_types::{BlockNumber as BlockId, Receipt};
use jsonrpsee::core::RpcResult;

pub struct ParityApi {
    inner: EthApi,
}

impl ParityApi {
    pub fn new(inner: EthApi) -> Self { Self { inner } }
}

#[async_trait]
impl ParityApiServer for ParityApi {
    async fn block_receipts(
        &self, block_id: BlockId,
    ) -> RpcResult<Option<Vec<Receipt>>> {
        self.inner
            .get_block_receipts(block_id)
            .map(|val| Some(val))
            .map_err(|e| e.into())
    }
}
