use cfx_rpc_cfx_types::traits::ChainMetaProvider;
use cfx_rpc_eth_api::NetApiServer;
use cfx_types::U64;
use jsonrpsee::core::RpcResult;

pub struct NetApi<T> {
    chain_meta: T,
}

impl<T> NetApi<T> {
    pub fn new(chain_meta: T) -> Self { Self { chain_meta } }
}

impl<T> NetApiServer for NetApi<T>
where T: ChainMetaProvider + Send + Sync + 'static
{
    fn version(&self) -> RpcResult<String> {
        Ok(self.chain_meta.chain_id().to_string())
    }

    fn peer_count(&self) -> RpcResult<U64> { Ok(U64::from(0)) }

    fn is_listening(&self) -> RpcResult<bool> { Ok(true) }
}
