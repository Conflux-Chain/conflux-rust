// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    http::{
        AccessControlAllowOrigin, DomainsValidation, Server as HttpServer,
        ServerBuilder as HttpServerBuilder,
    },
    tcp::{Server as TcpServer, ServerBuilder as TcpServerBuilder},
};
use jsonrpc_core::IoHandler;
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

pub mod impls;
mod traits;
mod types;

use self::{
    impls::{
        cfx::{CfxHandler, DebugRpcImpl, RpcImpl, TestRpcImpl},
        common::RpcImpl as CommonImpl,
        light::{
            CfxHandler as LightCfxHandler, DebugRpcImpl as LightDebugRpcImpl,
            RpcImpl as LightImpl, TestRpcImpl as LightTestRpcImpl,
        },
    },
    traits::cfx::{debug::DebugRpc, public::Cfx, test::TestRpc},
};

pub use self::types::Block as RpcBlock;

#[derive(Debug, PartialEq)]
pub struct TcpConfiguration {
    pub enabled: bool,
    pub address: SocketAddr,
}

impl TcpConfiguration {
    pub fn new(ip: Option<(u8, u8, u8, u8)>, port: Option<u16>) -> Self {
        let ipv4 = match ip {
            Some(ip) => Ipv4Addr::new(ip.0, ip.1, ip.2, ip.3),
            None => Ipv4Addr::new(0, 0, 0, 0),
        };
        TcpConfiguration {
            enabled: port.is_some(),
            address: SocketAddr::V4(SocketAddrV4::new(ipv4, port.unwrap_or(0))),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct HttpConfiguration {
    pub enabled: bool,
    pub address: SocketAddr,
    pub cors_domains: DomainsValidation<AccessControlAllowOrigin>,
    pub keep_alive: bool,
}

impl HttpConfiguration {
    pub fn new(
        ip: Option<(u8, u8, u8, u8)>, port: Option<u16>, cors: Option<String>,
        keep_alive: bool,
    ) -> Self
    {
        let ipv4 = match ip {
            Some(ip) => Ipv4Addr::new(ip.0, ip.1, ip.2, ip.3),
            None => Ipv4Addr::new(0, 0, 0, 0),
        };
        HttpConfiguration {
            enabled: port.is_some(),
            address: SocketAddr::V4(SocketAddrV4::new(ipv4, port.unwrap_or(0))),
            cors_domains: match cors {
                None => DomainsValidation::Disabled,
                Some(cors_list) => match cors_list.as_str() {
                    "none" => DomainsValidation::Disabled,
                    "all" => DomainsValidation::AllowOnly(vec![
                        AccessControlAllowOrigin::Any,
                    ]),
                    _ => DomainsValidation::AllowOnly(
                        cors_list.split(',').map(Into::into).collect(),
                    ),
                },
            },
            keep_alive,
        }
    }
}

pub fn setup_public_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>,
) -> IoHandler {
    let cfx = CfxHandler::new(common.clone(), rpc.clone()).to_delegate();

    // extend_with maps each method in RpcImpl object into a RPC handler
    let mut handler = IoHandler::new();
    handler.extend_with(cfx);
    handler
}

pub fn setup_debug_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>,
) -> IoHandler {
    let cfx = CfxHandler::new(common.clone(), rpc.clone()).to_delegate();
    let test = TestRpcImpl::new(common.clone(), rpc.clone()).to_delegate();
    let debug = DebugRpcImpl::new(common.clone(), rpc).to_delegate();

    // extend_with maps each method in RpcImpl object into a RPC handler
    let mut handler = IoHandler::new();
    handler.extend_with(cfx);
    handler.extend_with(test);
    handler.extend_with(debug);
    handler
}

pub fn setup_public_rpc_apis_light(
    common: Arc<CommonImpl>, rpc: Arc<LightImpl>,
) -> IoHandler {
    let cfx = LightCfxHandler::new(common.clone(), rpc.clone()).to_delegate();

    // extend_with maps each method in RpcImpl object into a RPC handler
    let mut handler = IoHandler::new();
    handler.extend_with(cfx);
    handler
}

pub fn setup_debug_rpc_apis_light(
    common: Arc<CommonImpl>, rpc: Arc<LightImpl>,
) -> IoHandler {
    let cfx = LightCfxHandler::new(common.clone(), rpc.clone()).to_delegate();
    let test = LightTestRpcImpl::new(common.clone(), rpc.clone()).to_delegate();
    let debug = LightDebugRpcImpl::new(common.clone(), rpc).to_delegate();

    // extend_with maps each method in RpcImpl object into a RPC handler
    let mut handler = IoHandler::new();
    handler.extend_with(cfx);
    handler.extend_with(test);
    handler.extend_with(debug);
    handler
}

pub fn new_tcp(
    conf: TcpConfiguration, handler: IoHandler,
) -> Result<Option<TcpServer>, String> {
    if !conf.enabled {
        return Ok(None);
    }

    match TcpServerBuilder::new(handler).start(&conf.address) {
        Ok(server) => Ok(Some(server)),
        Err(io_error) => {
            Err(format!("TCP error: {} (addr = {})", io_error, conf.address))
        }
    }
}

pub fn new_http(
    conf: HttpConfiguration, handler: IoHandler,
) -> Result<Option<HttpServer>, String> {
    if !conf.enabled {
        return Ok(None);
    }

    match HttpServerBuilder::new(handler)
        .keep_alive(conf.keep_alive)
        .cors(conf.cors_domains.clone())
        .start_http(&conf.address)
    {
        Ok(server) => Ok(Some(server)),
        Err(io_error) => Err(format!(
            "HTTP error: {} (addr = {})",
            io_error, conf.address
        )),
    }
}
