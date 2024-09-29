use cfx_rpc_cfx_types::traits::ChainMetaProvider;
use cfx_rpc_eth_api::NetApiServer;
use cfx_types::U64;
use jsonrpsee::core::RpcResult;

pub struct NetApi<ChainMeta> {
    chain_meta: ChainMeta,
}

impl<ChainMeta> NetApi<ChainMeta> {
    pub fn new(chain_meta: ChainMeta) -> Self { Self { chain_meta } }
}

impl<ChainMeta> NetApiServer for NetApi<ChainMeta>
where ChainMeta: ChainMetaProvider + Send + Sync + 'static
{
    fn version(&self) -> RpcResult<String> {
        Ok(self.chain_meta.chain_id().to_string())
    }

    fn peer_count(&self) -> RpcResult<U64> { Ok(U64::from(0)) }

    fn is_listening(&self) -> RpcResult<bool> { Ok(true) }
}
