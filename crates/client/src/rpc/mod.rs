// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_rpc_builder::{
    RpcModuleBuilder, RpcServerConfig, RpcServerHandle,
    TransportRpcModuleConfig,
};
use cfx_tasks::TaskExecutor;
use cfxcore::{
    Notifications, SharedConsensusGraph, SharedSynchronizationService,
    SharedTransactionPool,
};
use jsonrpc_core::{MetaIoHandler, RemoteProcedure, Value};
use jsonrpc_http_server::{
    Server as HttpServer, ServerBuilder as HttpServerBuilder,
};
use jsonrpc_tcp_server::{
    MetaExtractor as TpcMetaExtractor, Server as TcpServer,
    ServerBuilder as TcpServerBuilder,
};
use jsonrpc_ws_server::{
    MetaExtractor as WsMetaExtractor, Server as WsServer,
    ServerBuilder as WsServerBuilder,
};
pub use jsonrpsee::server::ServerBuilder;
use log::{info, warn};
use std::sync::Arc;

pub mod apis;
mod authcodes;
pub mod errors;
pub mod extractor;
mod helpers;
mod http_common;
pub mod impls;
pub mod informant;
mod interceptor;
pub mod metadata;
mod traits;
pub mod types;
use tokio::runtime::Runtime;

pub use cfxcore::errors::{
    BoxFuture as CoreBoxFuture, Error as CoreError, Result as CoreResult,
};
pub use errors::{error_codes, invalid_params};

use self::{
    impls::{
        cfx::{CfxHandler, LocalRpcImpl, RpcImpl, TestRpcImpl, TraceHandler},
        cfx_filter::CfxFilterClient,
        common::RpcImpl as CommonImpl,
        light::{
            CfxHandler as LightCfxHandler, DebugRpcImpl as LightDebugRpcImpl,
            RpcImpl as LightImpl, TestRpcImpl as LightTestRpcImpl,
        },
        pool::TransactionPoolHandler,
        pos::{PoSInterceptor, PosHandler},
        pubsub::PubSubClient,
    },
    traits::{
        cfx::Cfx, cfx_filter::CfxFilter, debug::LocalRpc,
        pool::TransactionPool, pos::Pos, pubsub::PubSub, test::TestRpc,
        trace::Trace,
    },
};

pub use self::types::{Block as RpcBlock, Origin};
use crate::{
    configuration::Configuration,
    rpc::{
        apis::{Api, ApiSet},
        impls::RpcImplConfiguration,
        interceptor::{RpcInterceptor, RpcProxy},
    },
};
pub use cfx_config::rpc_server_config::{
    HttpConfiguration, TcpConfiguration, WsConfiguration,
};
use interceptor::{MetricsInterceptor, ThrottleInterceptor};
pub use metadata::Metadata;
use std::collections::HashSet;

pub fn setup_public_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: PubSubClient,
    conf: &Configuration,
) -> MetaIoHandler<Metadata> {
    setup_rpc_apis(
        common,
        rpc,
        pubsub,
        &conf.raw_conf.throttling_conf,
        "rpc",
        conf.raw_conf.public_rpc_apis.list_apis(),
    )
}

pub fn setup_debug_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: PubSubClient,
    conf: &Configuration,
) -> MetaIoHandler<Metadata> {
    setup_rpc_apis(
        common,
        rpc,
        pubsub,
        &conf.raw_conf.throttling_conf,
        "rpc_local",
        ApiSet::All.list_apis(),
    )
}

fn setup_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: PubSubClient,
    throttling_conf: &Option<String>, throttling_section: &str,
    apis: HashSet<Api>,
) -> MetaIoHandler<Metadata> {
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
                            pubsub.epochs_ordered(),
                            pubsub.executor.clone(),
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
            Api::Test => {
                handler.extend_with(
                    TestRpcImpl::new(common.clone(), rpc.clone()).to_delegate(),
                );
            }
            Api::Trace => {
                let trace = TraceHandler::new(
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
                    rpc.consensus.data_manager().clone(),
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
) {
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
    handler.add_sync_method("rpc_methods", move |_| {
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
    handler.add_sync_method("rpc_modules", move |_| {
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
    conf: &Configuration,
) -> MetaIoHandler<Metadata> {
    setup_rpc_apis_light(
        common,
        rpc,
        pubsub,
        &conf.raw_conf.throttling_conf,
        "rpc",
        conf.raw_conf.public_rpc_apis.list_apis(),
    )
}

pub fn setup_debug_rpc_apis_light(
    common: Arc<CommonImpl>, rpc: Arc<LightImpl>, pubsub: PubSubClient,
    conf: &Configuration,
) -> MetaIoHandler<Metadata> {
    let mut light_debug_apis = ApiSet::All.list_apis();
    light_debug_apis.remove(&Api::Trace);
    setup_rpc_apis_light(
        common,
        rpc,
        pubsub,
        &conf.raw_conf.throttling_conf,
        "rpc_local",
        light_debug_apis,
    )
}

fn setup_rpc_apis_light(
    common: Arc<CommonImpl>, rpc: Arc<LightImpl>, pubsub: PubSubClient,
    throttling_conf: &Option<String>, throttling_section: &str,
    apis: HashSet<Api>,
) -> MetaIoHandler<Metadata> {
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
            Api::Debug => {
                handler.extend_with(
                    LightDebugRpcImpl::new(common.clone(), rpc.clone())
                        .to_delegate(),
                );
            }
            Api::Pubsub => handler.extend_with(pubsub.clone().to_delegate()),
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

// start espace rpc server v2(async)
pub async fn launch_async_rpc_servers(
    consensus: SharedConsensusGraph, sync: SharedSynchronizationService,
    tx_pool: SharedTransactionPool, notifications: Arc<Notifications>,
    executor: TaskExecutor, runtime: Arc<Runtime>, conf: &Configuration,
    throttling_conf_file: Option<String>,
) -> Result<Option<RpcServerHandle>, String> {
    let http_config = conf.eth_http_config();
    let ws_config = conf.eth_ws_config();
    let apis = conf.raw_conf.public_evm_rpc_apis.clone();

    let (transport_rpc_module_config, server_config) =
        match (http_config.enabled, ws_config.enabled) {
            (true, true) => {
                let transport_rpc_module_config =
                    TransportRpcModuleConfig::set_http(apis.clone())
                        .with_ws(apis.clone());

                let server_config =
                    RpcServerConfig::http(ServerBuilder::default())
                        .with_ws(ServerBuilder::default())
                        .with_http_address(http_config.address)
                        .with_ws_address(ws_config.address);
                (transport_rpc_module_config, server_config)
            }
            (true, false) => {
                let transport_rpc_module_config =
                    TransportRpcModuleConfig::set_http(apis.clone());
                let server_config =
                    RpcServerConfig::http(ServerBuilder::default())
                        .with_http_address(ws_config.address);
                (transport_rpc_module_config, server_config)
            }
            (false, true) => {
                let transport_rpc_module_config =
                    TransportRpcModuleConfig::set_ws(apis.clone());
                let server_config =
                    RpcServerConfig::ws(ServerBuilder::default())
                        .with_ws_address(ws_config.address);
                (transport_rpc_module_config, server_config)
            }
            _ => return Ok(None),
        };

    info!("Enabled evm async rpc modules: {:?}", apis.into_selection());
    let rpc_conf = conf.rpc_impl_config();
    let enable_metrics = rpc_conf.enable_metrics;

    let rpc_module_builder = RpcModuleBuilder::new(
        rpc_conf,
        consensus,
        sync,
        tx_pool,
        executor,
        runtime,
        notifications,
    );

    let transport_rpc_modules =
        rpc_module_builder.build(transport_rpc_module_config);

    let server_handle = server_config
        .start(&transport_rpc_modules, throttling_conf_file, enable_metrics)
        .await
        .map_err(|e| e.to_string())?;

    Ok(Some(server_handle))
}
