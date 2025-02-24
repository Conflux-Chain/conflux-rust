use cfx_rpc_eth_api::RpcApiServer;
use cfx_rpc_primitives::RpcModules;
use jsonrpsee::core::RpcResult;
use std::{collections::HashMap, sync::Arc};

#[derive(Debug, Clone, Default)]
pub struct RPCApi {
    rpc_modules: Arc<RpcModules>,
}

impl RPCApi {
    pub fn new(module_map: HashMap<String, String>) -> Self {
        Self {
            rpc_modules: Arc::new(RpcModules::new(module_map)),
        }
    }
}

impl RpcApiServer for RPCApi {
    fn rpc_modules(&self) -> RpcResult<RpcModules> {
        Ok(self.rpc_modules.as_ref().clone())
    }
}
