mod cfx;
mod error;
mod eth;
mod id_provider;

pub use cfx::{
    CfxRpcModule, RpcModuleBuilder as CfxRpcModuleBuilder,
    RpcModuleSelection as CfxRpcModuleSelection,
    RpcServerConfig as CfxRpcServerConfig,
    RpcServerHandle as CfxRpcServerHandle,
    TransportRpcModuleConfig as CfxTransportRpcModuleConfig,
    TransportRpcModules as CfxTransportRpcModules,
};
pub use eth::{
    RpcModuleBuilder, RpcModuleSelection, RpcServerConfig,
    TransportRpcModuleConfig,
};

use std::net::SocketAddr;

use jsonrpsee::server::{AlreadyStoppedError, ServerHandle};

#[derive(Clone, Debug)]
#[must_use = "Server stops if dropped"]
pub struct RpcServerHandle {
    pub http_local_addr: Option<SocketAddr>,
    pub ws_local_addr: Option<SocketAddr>,
    pub http: Option<ServerHandle>,
    pub ws: Option<ServerHandle>,
}

impl RpcServerHandle {
    pub const fn http_local_addr(&self) -> Option<SocketAddr> {
        self.http_local_addr
    }

    pub const fn ws_local_addr(&self) -> Option<SocketAddr> {
        self.ws_local_addr
    }

    pub fn stop(self) -> Result<(), AlreadyStoppedError> {
        if let Some(handle) = self.http {
            handle.stop()?
        }

        if let Some(handle) = self.ws {
            handle.stop()?
        }

        Ok(())
    }

    pub fn http_url(&self) -> Option<String> {
        self.http_local_addr.map(|addr| format!("http://{addr}"))
    }

    pub fn ws_url(&self) -> Option<String> {
        self.ws_local_addr.map(|addr| format!("ws://{addr}"))
    }
}
