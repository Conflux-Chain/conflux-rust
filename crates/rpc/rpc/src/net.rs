use cfx_rpc_cfx_types::traits::ChainMetaProvider;
use cfx_rpc_eth_api::NetApiServer;
use cfx_types::U64;
use jsonrpsee::core::RpcResult;

pub struct NetApi {
    chain_meta: Box<dyn ChainMetaProvider + Send + Sync>,
}

impl NetApi {
    pub fn new(chain_meta: Box<dyn ChainMetaProvider + Send + Sync>) -> Self {
        Self { chain_meta }
    }
}

impl NetApiServer for NetApi {
    fn version(&self) -> RpcResult<String> {
        Ok(self.chain_meta.chain_id().to_string())
    }

    fn peer_count(&self) -> RpcResult<U64> { Ok(U64::from(0)) }

    fn is_listening(&self) -> RpcResult<bool> { Ok(true) }
}
