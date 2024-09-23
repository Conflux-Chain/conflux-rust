use cfx_rpc_eth_api::NetApiServer;
use cfx_types::U64;
use jsonrpsee::core::RpcResult;

pub struct NetApi {
    chain_id: u64,
}

impl NetApiServer for NetApi {
    fn version(&self) -> RpcResult<String> {
        // todo read chain_id from config, not in this struct
        Ok(self.chain_id.to_string())
    }

    fn peer_count(&self) -> RpcResult<U64> {
        // todo implement peer count
        Ok(U64::from(0))
    }

    fn is_listening(&self) -> RpcResult<bool> { Ok(true) }
}
