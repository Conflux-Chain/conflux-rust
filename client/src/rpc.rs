// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use jsonrpc_core::{
    BoxFuture, MetaIoHandler, RemoteProcedure, Result as JsonRpcResult, Value,
};
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
pub mod rpc_apis;
mod traits;
pub mod types;

pub use cfxcore::rpc_errors::{
    BoxFuture as RpcBoxFuture, Error as RpcError, ErrorKind as RpcErrorKind,
    ErrorKind::JsonRpcError as JsonRpcErrorKind, Result as RpcResult,
};

use self::{
    impls::{
        cfx::{CfxHandler, LocalRpcImpl, RpcImpl, TestRpcImpl},
        cfx_filter::CfxFilterClient,
        common::RpcImpl as CommonImpl,
        eth_pubsub::PubSubClient as EthPubSubClient,
        light::{
            CfxHandler as LightCfxHandler, DebugRpcImpl as LightDebugRpcImpl,
            RpcImpl as LightImpl, TestRpcImpl as LightTestRpcImpl,
        },
        pool::TransactionPoolHandler,
        pos::{PoSInterceptor, PosHandler},
        pubsub::PubSubClient,
        trace::TraceHandler,
    },
    traits::{
        cfx::{Cfx, CfxFilter},
        debug::LocalRpc,
        eth_space::{
            eth::{Eth, EthFilter},
            eth_pubsub::EthPubSub,
            trace::Trace as EthTrace,
        },
        pool::TransactionPool,
        pos::Pos,
        pubsub::PubSub,
        test::TestRpc,
        trace::Trace,
    },
};

pub use self::types::{Block as RpcBlock, Origin};
use crate::{
    configuration::Configuration,
    rpc::{
        error_codes::request_rejected_too_many_request_error,
        impls::{
            eth::EthHandler, eth_filter::EthFilterClient,
            trace::EthTraceHandler, RpcImplConfiguration,
        },
        interceptor::{RpcInterceptor, RpcProxy},
        rpc_apis::{Api, ApiSet},
    },
};
use futures01::lazy;
use jsonrpc_core::futures::Future;
use lazy_static::lazy_static;
pub use metadata::Metadata;
use metrics::{register_timer_with_group, ScopeTimer, Timer};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use throttling::token_bucket::{ThrottleResult, TokenBucketManager};

lazy_static! {
    static ref METRICS_INTERCEPTOR_TIMERS: Mutex<HashMap<String, Arc<dyn Timer>>> =
        Default::default();
}

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
    // If it's Some, we will manually set the number of threads of HTTP RPC
    // server
    pub threads: Option<usize>,
}

impl HttpConfiguration {
    pub fn new(
        ip: Option<(u8, u8, u8, u8)>, port: Option<u16>, cors: Option<String>,
        keep_alive: bool, threads: Option<usize>,
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
            threads,
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct WsConfiguration {
    pub enabled: bool,
    pub address: SocketAddr,
    pub max_payload_bytes: usize,
}

impl WsConfiguration {
    pub fn new(
        ip: Option<(u8, u8, u8, u8)>, port: Option<u16>,
        max_payload_bytes: usize,
    ) -> Self
    {
        let ipv4 = match ip {
            Some(ip) => Ipv4Addr::new(ip.0, ip.1, ip.2, ip.3),
            None => Ipv4Addr::new(0, 0, 0, 0),
        };
        WsConfiguration {
            enabled: port.is_some(),
            address: SocketAddr::V4(SocketAddrV4::new(ipv4, port.unwrap_or(0))),
            max_payload_bytes,
        }
    }
}

pub fn setup_public_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: PubSubClient,
    eth_pubsub: EthPubSubClient, conf: &Configuration,
) -> MetaIoHandler<Metadata>
{
    setup_rpc_apis(
        common,
        rpc,
        pubsub,
        eth_pubsub,
        &conf.raw_conf.throttling_conf,
        "rpc",
        conf.raw_conf.public_rpc_apis.list_apis(),
    )
}

pub fn setup_public_eth_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: PubSubClient,
    eth_pubsub: EthPubSubClient, conf: &Configuration,
) -> MetaIoHandler<Metadata>
{
    setup_rpc_apis(
        common,
        rpc,
        pubsub,
        eth_pubsub,
        &conf.raw_conf.throttling_conf,
        "rpc",
        conf.raw_conf.public_evm_rpc_apis.list_apis(),
    )
}

pub fn setup_debug_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: PubSubClient,
    eth_pubsub: EthPubSubClient, conf: &Configuration,
) -> MetaIoHandler<Metadata>
{
    setup_rpc_apis(
        common,
        rpc,
        pubsub,
        eth_pubsub,
        &conf.raw_conf.throttling_conf,
        "rpc_local",
        ApiSet::All.list_apis(),
    )
}

fn setup_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: PubSubClient,
    eth_pubsub: EthPubSubClient, throttling_conf: &Option<String>,
    throttling_section: &str, apis: HashSet<Api>,
) -> MetaIoHandler<Metadata>
{
    let mut handler = MetaIoHandler::default();
    for api in &apis {
        match api {
            Api::Cfx => {
                let cfx =
                    CfxHandler::new(common.clone(), rpc.clone()).to_delegate();
                extend_with_interceptor(
                    &mut handler,
                    &rpc.config,
                    cfx,
                    throttling_conf,
                    throttling_section,
                );

                if let Some(poll_lifetime) = rpc.config.poll_lifetime_in_seconds
                {
                    if let Some(h) = pubsub.handler().upgrade() {
                        let filter_client = CfxFilterClient::new(
                            rpc.consensus.clone(),
                            rpc.tx_pool.clone(),
                            eth_pubsub.epochs_ordered(),
                            h.executor.clone(),
                            poll_lifetime,
                            rpc.config.get_logs_filter_max_limit,
                            h.network.clone(),
                        )
                        .to_delegate();

                        extend_with_interceptor(
                            &mut handler,
                            &rpc.config,
                            filter_client,
                            throttling_conf,
                            throttling_section,
                        );
                    }
                }
            }
            Api::Eth => {
                info!("Add EVM RPC");
                let evm = EthHandler::new(
                    rpc.config.clone(),
                    rpc.consensus.clone(),
                    rpc.sync.clone(),
                    rpc.tx_pool.clone(),
                )
                .to_delegate();
                let evm_trace_handler = EthTraceHandler {
                    trace_handler: TraceHandler::new(
                        rpc.consensus.get_data_manager().clone(),
                        *rpc.sync.network.get_network_type(),
                        rpc.consensus.clone(),
                    ),
                }
                .to_delegate();
                extend_with_interceptor(
                    &mut handler,
                    &rpc.config,
                    evm,
                    throttling_conf,
                    throttling_section,
                );
                handler.extend_with(evm_trace_handler);

                if let Some(poll_lifetime) = rpc.config.poll_lifetime_in_seconds
                {
                    if let Some(h) = eth_pubsub.handler().upgrade() {
                        let filter_client = EthFilterClient::new(
                            rpc.consensus.clone(),
                            rpc.tx_pool.clone(),
                            eth_pubsub.epochs_ordered(),
                            h.executor.clone(),
                            poll_lifetime,
                            rpc.config.get_logs_filter_max_limit,
                        )
                        .to_delegate();

                        extend_with_interceptor(
                            &mut handler,
                            &rpc.config,
                            filter_client,
                            throttling_conf,
                            throttling_section,
                        );
                    }
                }
            }
            Api::Debug => {
                handler.extend_with(
                    LocalRpcImpl::new(common.clone(), rpc.clone())
                        .to_delegate(),
                );
            }
            Api::Pubsub => {
                extend_with_interceptor(
                    &mut handler,
                    &rpc.config,
                    pubsub.clone().to_delegate(),
                    throttling_conf,
                    throttling_section,
                );
            }
            Api::EthPubsub => {
                info!("Add EVM pubsub");
                extend_with_interceptor(
                    &mut handler,
                    &rpc.config,
                    eth_pubsub.clone().to_delegate(),
                    throttling_conf,
                    throttling_section,
                );
            }
            Api::Test => {
                handler.extend_with(
                    TestRpcImpl::new(common.clone(), rpc.clone()).to_delegate(),
                );
            }
            Api::Trace => {
                let trace = TraceHandler::new(
                    rpc.consensus.get_data_manager().clone(),
                    *rpc.sync.network.get_network_type(),
                    rpc.consensus.clone(),
                )
                .to_delegate();
                extend_with_interceptor(
                    &mut handler,
                    &rpc.config,
                    trace,
                    throttling_conf,
                    throttling_section,
                );
            }
            Api::TxPool => {
                let txpool =
                    TransactionPoolHandler::new(common.clone()).to_delegate();
                extend_with_interceptor(
                    &mut handler,
                    &rpc.config,
                    txpool,
                    throttling_conf,
                    throttling_section,
                );
            }
            Api::Pos => {
                let pos = PosHandler::new(
                    common.pos_handler.clone(),
                    rpc.consensus.get_data_manager().clone(),
                    *rpc.sync.network.get_network_type(),
                    rpc.consensus.clone(),
                )
                .to_delegate();
                let pos_interceptor =
                    PoSInterceptor::new(common.pos_handler.clone());
                handler.extend_with(RpcProxy::new(pos, pos_interceptor));
            }
        }
    }

    add_meta_rpc_methods(handler, apis)
}

pub fn extend_with_interceptor<
    T: IntoIterator<Item = (String, RemoteProcedure<Metadata>)>,
>(
    handler: &mut MetaIoHandler<Metadata>, rpc_conf: &RpcImplConfiguration,
    rpc_impl: T, throttling_conf: &Option<String>, throttling_section: &str,
)
{
    let interceptor =
        ThrottleInterceptor::new(throttling_conf, throttling_section);
    if rpc_conf.enable_metrics {
        handler.extend_with(RpcProxy::new(
            rpc_impl,
            MetricsInterceptor::new(interceptor),
        ));
    } else {
        handler.extend_with(RpcProxy::new(rpc_impl, interceptor));
    }
}

fn add_meta_rpc_methods(
    mut handler: MetaIoHandler<Metadata>, apis: HashSet<Api>,
) -> MetaIoHandler<Metadata> {
    // rpc_methods to return all available methods
    let methods: Vec<String> =
        handler.iter().map(|(method, _)| method).cloned().collect();
    handler.add_method("rpc_methods", move |_| {
        let method_list = methods
            .clone()
            .iter()
            .map(|m| Value::String(m.to_string()))
            .collect();
        Ok(Value::Array(method_list))
    });

    // rpc_modules
    let namespaces: Vec<String> =
        apis.into_iter().map(|item| format!("{}", item)).collect();
    handler.add_method("rpc_modules", move |_| {
        let ns = namespaces
            .clone()
            .iter()
            .map(|m| Value::String(m.to_string()))
            .collect();
        Ok(Value::Array(ns))
    });

    handler
}

pub fn setup_public_rpc_apis_light(
    common: Arc<CommonImpl>, rpc: Arc<LightImpl>, pubsub: PubSubClient,
    eth_pubsub: EthPubSubClient, conf: &Configuration,
) -> MetaIoHandler<Metadata>
{
    setup_rpc_apis_light(
        common,
        rpc,
        pubsub,
        eth_pubsub,
        &conf.raw_conf.throttling_conf,
        "rpc",
        conf.raw_conf.public_rpc_apis.list_apis(),
    )
}

pub fn setup_debug_rpc_apis_light(
    common: Arc<CommonImpl>, rpc: Arc<LightImpl>, pubsub: PubSubClient,
    eth_pubsub: EthPubSubClient, conf: &Configuration,
) -> MetaIoHandler<Metadata>
{
    let mut light_debug_apis = ApiSet::All.list_apis();
    light_debug_apis.remove(&Api::Trace);
    setup_rpc_apis_light(
        common,
        rpc,
        pubsub,
        eth_pubsub,
        &conf.raw_conf.throttling_conf,
        "rpc_local",
        light_debug_apis,
    )
}

fn setup_rpc_apis_light(
    common: Arc<CommonImpl>, rpc: Arc<LightImpl>, pubsub: PubSubClient,
    eth_pubsub: EthPubSubClient, throttling_conf: &Option<String>,
    throttling_section: &str, apis: HashSet<Api>,
) -> MetaIoHandler<Metadata>
{
    let mut handler = MetaIoHandler::default();
    for api in apis {
        match api {
            Api::Cfx => {
                let cfx = LightCfxHandler::new(common.clone(), rpc.clone())
                    .to_delegate();
                let interceptor = ThrottleInterceptor::new(
                    throttling_conf,
                    throttling_section,
                );
                handler.extend_with(RpcProxy::new(cfx, interceptor));
            }
            Api::Eth => {
                warn!("Light nodes do not support evm ports.");
            }
            Api::Debug => {
                handler.extend_with(
                    LightDebugRpcImpl::new(common.clone(), rpc.clone())
                        .to_delegate(),
                );
            }
            Api::Pubsub => handler.extend_with(pubsub.clone().to_delegate()),
            Api::EthPubsub => {
                handler.extend_with(eth_pubsub.clone().to_delegate())
            }
            Api::Test => {
                handler.extend_with(
                    LightTestRpcImpl::new(common.clone(), rpc.clone())
                        .to_delegate(),
                );
            }
            Api::Trace => {
                warn!("Light nodes do not support trace RPC");
            }
            Api::TxPool => {
                warn!("Light nodes do not support txpool RPC");
            }
            Api::Pos => {
                warn!("Light nodes do not support PoS RPC");
            }
        }
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
    let mut builder = HttpServerBuilder::new(handler);
    if let Some(threads) = conf.threads {
        builder = builder.threads(threads);
    }

    match builder
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
        .max_payload(conf.max_payload_bytes)
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

struct MetricsInterceptor {
    // TODO: Chain interceptors instead of wrapping up.
    throttle_interceptor: ThrottleInterceptor,
}

impl MetricsInterceptor {
    pub fn new(throttle_interceptor: ThrottleInterceptor) -> Self {
        Self {
            throttle_interceptor,
        }
    }
}

impl RpcInterceptor for MetricsInterceptor {
    fn before(&self, name: &String) -> JsonRpcResult<()> {
        self.throttle_interceptor.before(name)?;
        // Use a global variable here because `http` and `web3` setup different
        // interceptors for the same RPC API.
        let mut timers = METRICS_INTERCEPTOR_TIMERS.lock();
        if !timers.contains_key(name) {
            let timer = register_timer_with_group("rpc", name.as_str());
            timers.insert(name.clone(), timer);
        }
        Ok(())
    }

    fn around(
        &self, name: &String, method_call: BoxFuture<Value>,
    ) -> BoxFuture<Value> {
        let maybe_timer = METRICS_INTERCEPTOR_TIMERS
            .lock()
            .get(name)
            .map(|timer| timer.clone());
        let setup = lazy(move || {
            Ok(maybe_timer
                .as_ref()
                .map(|timer| ScopeTimer::time_scope(timer.clone())))
        });
        Box::new(setup.then(|timer: Result<_, ()>| {
            method_call.then(|r| {
                drop(timer);
                r
            })
        }))
    }
}
