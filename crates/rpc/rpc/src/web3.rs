use async_trait::async_trait;
use cfx_rpc_cfx_types::traits::ChainStaticMetaProvider;
use cfx_rpc_eth_api::Web3ApiServer;
use cfx_rpc_primitives::Bytes;
use cfx_types::H256;
use jsonrpsee::core::RpcResult;
use keccak_hash::keccak;

pub struct Web3Api<ChainMeta> {
    chain_meta: ChainMeta,
}

impl<ChainMeta> Web3Api<ChainMeta> {
    pub fn new(chain_meta: ChainMeta) -> Web3Api<ChainMeta> {
        Web3Api { chain_meta }
    }
}

#[async_trait]
impl<ChainMeta> Web3ApiServer for Web3Api<ChainMeta>
where ChainMeta: ChainStaticMetaProvider + Send + Sync + 'static
{
    async fn client_version(&self) -> RpcResult<String> {
        Ok(self.chain_meta.client_version())
    }

    fn sha3(&self, input: Bytes) -> RpcResult<H256> {
        Ok(keccak(input.into_vec()))
    }
}

impl<ChainMeta> std::fmt::Debug for Web3Api<ChainMeta> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Web3Api").finish_non_exhaustive()
    }
}
