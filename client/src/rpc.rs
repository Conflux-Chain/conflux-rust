// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use jsonrpc_core::{MetaIoHandler, Result as JsonRpcResult};
use jsonrpc_http_server::{
    AccessControlAllowOrigin, DomainsValidation, Server as HttpServer,
    ServerBuilder as HttpServerBuilder,
};
use jsonrpc_tcp_server::{
    MetaExtractor as TpcMetaExtractor, Server as TcpServer,
    ServerBuilder as TcpServerBuilder,
};
use jsonrpc_ws_server::{
    MetaExtractor as WsMetaExtractor, Server as WsServer,
    ServerBuilder as WsServerBuilder,
};
use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};

mod authcodes;
pub mod error_codes;
pub mod extractor;
mod helpers;
mod http_common;
pub mod impls;
pub mod informant;
mod interceptor;
pub mod metadata;
mod traits;
mod types;

pub use cfxcore::rpc_errors::{
    Error as RpcError, ErrorKind as RpcErrorKind,
    ErrorKind::JsonRpcError as JsonRpcErrorKind, Result as RpcResult,
};

use self::{
    impls::{
        cfx::{CfxHandler, LocalRpcImpl, RpcImpl, TestRpcImpl},
        common::RpcImpl as CommonImpl,
        light::{
            CfxHandler as LightCfxHandler, DebugRpcImpl as LightDebugRpcImpl,
            RpcImpl as LightImpl, TestRpcImpl as LightTestRpcImpl,
        },
        pubsub::PubSubClient,
    },
    traits::{cfx::Cfx, debug::LocalRpc, pubsub::PubSub, test::TestRpc},
};

pub use self::types::{Block as RpcBlock, Origin};
use crate::{
    configuration::Configuration,
    rpc::{
        error_codes::request_rejected_too_many_request_error,
        interceptor::{RpcInterceptor, RpcProxy},
    },
};
pub use metadata::Metadata;
use throttling::token_bucket::{ThrottleResult, TokenBucketManager};

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

#[derive(Debug, PartialEq)]
pub struct WsConfiguration {
    pub enabled: bool,
    pub address: SocketAddr,
}

impl WsConfiguration {
    pub fn new(ip: Option<(u8, u8, u8, u8)>, port: Option<u16>) -> Self {
        let ipv4 = match ip {
            Some(ip) => Ipv4Addr::new(ip.0, ip.1, ip.2, ip.3),
            None => Ipv4Addr::new(0, 0, 0, 0),
        };
        WsConfiguration {
            enabled: port.is_some(),
            address: SocketAddr::V4(SocketAddrV4::new(ipv4, port.unwrap_or(0))),
        }
    }
}

pub fn setup_public_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: Option<PubSubClient>,
    conf: &Configuration,
) -> MetaIoHandler<Metadata>
{
    let cfx = CfxHandler::new(common, rpc).to_delegate();
    let interceptor =
        ThrottleInterceptor::new(&conf.raw_conf.throttling_conf, "rpc");

    // extend_with maps each method in RpcImpl object into a RPC handler
    let mut handler = MetaIoHandler::default();
    handler.extend_with(RpcProxy::new(cfx, interceptor));
    if let Some(pubsub) = pubsub {
        handler.extend_with(pubsub.to_delegate());
    }
    handler
}

pub fn setup_debug_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: Option<PubSubClient>,
    conf: &Configuration,
) -> MetaIoHandler<Metadata>
{
    let cfx = CfxHandler::new(common.clone(), rpc.clone()).to_delegate();
    let interceptor =
        ThrottleInterceptor::new(&conf.raw_conf.throttling_conf, "rpc_local");
    let test = TestRpcImpl::new(common.clone(), rpc.clone()).to_delegate();
    let debug = LocalRpcImpl::new(common, rpc).to_delegate();

    // extend_with maps each method in RpcImpl object into a RPC handler
    let mut handler = MetaIoHandler::default();
    handler.extend_with(RpcProxy::new(cfx, interceptor));
    handler.extend_with(test);
    handler.extend_with(debug);
    if let Some(pubsub) = pubsub {
        handler.extend_with(pubsub.to_delegate());
    }
    handler
}

pub fn setup_public_rpc_apis_light(
    common: Arc<CommonImpl>, rpc: Arc<LightImpl>, pubsub: Option<PubSubClient>,
    conf: &Configuration,
) -> MetaIoHandler<Metadata>
{
    let cfx = LightCfxHandler::new(common, rpc).to_delegate();
    let interceptor =
        ThrottleInterceptor::new(&conf.raw_conf.throttling_conf, "rpc");

    // extend_with maps each method in RpcImpl object into a RPC handler
    let mut handler = MetaIoHandler::default();
    handler.extend_with(RpcProxy::new(cfx, interceptor));
    if let Some(pubsub) = pubsub {
        handler.extend_with(pubsub.to_delegate());
    }
    handler
}

pub fn setup_debug_rpc_apis_light(
    common: Arc<CommonImpl>, rpc: Arc<LightImpl>, pubsub: Option<PubSubClient>,
) -> MetaIoHandler<Metadata> {
    let cfx = LightCfxHandler::new(common.clone(), rpc.clone()).to_delegate();
    let test = LightTestRpcImpl::new(common.clone(), rpc.clone()).to_delegate();
    let debug = LightDebugRpcImpl::new(common, rpc).to_delegate();

    // extend_with maps each method in RpcImpl object into a RPC handler
    let mut handler = MetaIoHandler::default();
    handler.extend_with(cfx);
    handler.extend_with(test);
    handler.extend_with(debug);
    if let Some(pubsub) = pubsub {
        handler.extend_with(pubsub.to_delegate());
    }
    handler
}

pub fn start_tcp<H, T>(
    conf: TcpConfiguration, handler: H, extractor: T,
) -> Result<Option<TcpServer>, String>
where
    H: Into<MetaIoHandler<Metadata>>,
    T: TpcMetaExtractor<Metadata> + 'static,
{
    if !conf.enabled {
        return Ok(None);
    }

    match TcpServerBuilder::with_meta_extractor(handler, extractor)
        .start(&conf.address)
    {
        Ok(server) => Ok(Some(server)),
        Err(io_error) => {
            Err(format!("TCP error: {} (addr = {})", io_error, conf.address))
        }
    }
}

pub fn start_http(
    conf: HttpConfiguration, handler: MetaIoHandler<Metadata>,
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

pub fn start_ws<H, T>(
    conf: WsConfiguration, handler: H, extractor: T,
) -> Result<Option<WsServer>, String>
where
    H: Into<MetaIoHandler<Metadata>>,
    T: WsMetaExtractor<Metadata> + 'static,
{
    if !conf.enabled {
        return Ok(None);
    }

    match WsServerBuilder::with_meta_extractor(handler, extractor)
        .start(&conf.address)
    {
        Ok(server) => Ok(Some(server)),
        Err(io_error) => {
            Err(format!("WS error: {} (addr = {})", io_error, conf.address))
        }
    }
}

struct ThrottleInterceptor {
    manager: TokenBucketManager,
}

impl ThrottleInterceptor {
    fn new(file: &Option<String>, section: &str) -> Self {
        let manager = match file {
            Some(file) => TokenBucketManager::load(file, Some(section))
                .expect("invalid throttling configuration file"),
            None => TokenBucketManager::default(),
        };

        ThrottleInterceptor { manager }
    }
}

impl RpcInterceptor for ThrottleInterceptor {
    fn before(&self, name: &String) -> JsonRpcResult<()> {
        let bucket = match self.manager.get(name) {
            Some(bucket) => bucket,
            None => return Ok(()),
        };

        let result = bucket.lock().throttle_default();

        match result {
            ThrottleResult::Success => Ok(()),
            ThrottleResult::Throttled(wait_time) => {
                debug!("RPC {} throttled in {:?}", name, wait_time);
                bail!(request_rejected_too_many_request_error(Some(format!(
                    "throttled in {:?}",
                    wait_time
                ))))
            }
            ThrottleResult::AlreadyThrottled => {
                debug!("RPC {} already throttled", name);
                bail!(request_rejected_too_many_request_error(Some(
                    "already throttled, please try again later".into()
                )))
            }
        }
    }
}
