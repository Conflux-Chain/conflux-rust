// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_rpc_builder::{
    RpcModuleBuilder, RpcModuleSelection, RpcServerConfig, RpcServerHandle,
    TransportRpcModuleConfig,
};
use cfx_tasks::TaskExecutor;
use cfxcore::{
    SharedConsensusGraph, SharedSynchronizationService, SharedTransactionPool,
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
use std::{net::SocketAddr, sync::Arc};

mod authcodes;
pub mod errors;
pub mod extractor;
mod helpers;
mod http_common;
pub mod impls;
pub mod informant;
mod interceptor;
pub mod metadata;
pub mod rpc_apis;
pub mod server_configuration;
mod traits;
pub mod types;

pub use cfxcore::errors::{
    BoxFuture as CoreBoxFuture, Error as CoreError, Result as CoreResult,
};
pub use errors::{error_codes, invalid_params};

use self::{
    impls::{
        cfx::{CfxHandler, LocalRpcImpl, RpcImpl, TestRpcImpl, TraceHandler},
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
    },
    traits::{
        cfx::Cfx,
        cfx_filter::CfxFilter,
        debug::LocalRpc,
        eth_space::{
            eth::Eth, eth_filter::EthFilter, eth_pubsub::EthPubSub,
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
        impls::{
            eth::{EthHandler, EthTraceHandler, GethDebugHandler},
            eth_filter::EthFilterHelper as EthFilterClient,
            RpcImplConfiguration,
        },
        interceptor::{RpcInterceptor, RpcProxy},
        rpc_apis::{Api, ApiSet},
        traits::eth_space::debug::Debug,
    },
};
use interceptor::{MetricsInterceptor, ThrottleInterceptor};
pub use metadata::Metadata;
pub use server_configuration::{
    HttpConfiguration, TcpConfiguration, WsConfiguration,
};
use std::collections::HashSet;

pub fn setup_public_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: PubSubClient,
    eth_pubsub: EthPubSubClient, conf: &Configuration, executor: TaskExecutor,
) -> MetaIoHandler<Metadata> {
    setup_rpc_apis(
        common,
        rpc,
        pubsub,
        eth_pubsub,
        &conf.raw_conf.throttling_conf,
        "rpc",
        conf.raw_conf.public_rpc_apis.list_apis(),
        executor,
    )
}

pub fn setup_public_eth_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: PubSubClient,
    eth_pubsub: EthPubSubClient, conf: &Configuration, executor: TaskExecutor,
) -> MetaIoHandler<Metadata> {
    setup_rpc_apis(
        common,
        rpc,
        pubsub,
        eth_pubsub,
        &conf.raw_conf.throttling_conf,
        "rpc",
        conf.raw_conf.public_evm_rpc_apis.list_apis(),
        executor,
    )
}

pub fn setup_debug_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: PubSubClient,
    eth_pubsub: EthPubSubClient, conf: &Configuration, executor: TaskExecutor,
) -> MetaIoHandler<Metadata> {
    setup_rpc_apis(
        common,
        rpc,
        pubsub,
        eth_pubsub,
        &conf.raw_conf.throttling_conf,
        "rpc_local",
        ApiSet::All.list_apis(),
        executor,
    )
}

fn setup_rpc_apis(
    common: Arc<CommonImpl>, rpc: Arc<RpcImpl>, pubsub: PubSubClient,
    eth_pubsub: EthPubSubClient, throttling_conf: &Option<String>,
    throttling_section: &str, apis: HashSet<Api>, executor: TaskExecutor,
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
                            eth_pubsub.epochs_ordered(),
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
            Api::Eth => {
                info!("Add EVM RPC");
                let evm = EthHandler::new(
                    rpc.config.clone(),
                    rpc.consensus.clone(),
                    rpc.sync.clone(),
                    rpc.tx_pool.clone(),
                    executor.clone(),
                )
                .to_delegate();
                let evm_trace_handler = EthTraceHandler {
                    trace_handler: TraceHandler::new(
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
                    let filter_client = EthFilterClient::new(
                        rpc.consensus.clone(),
                        rpc.tx_pool.clone(),
                        eth_pubsub.epochs_ordered(),
                        eth_pubsub.executor.clone(),
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
            Api::EthDebug => {
                info!("Add geth debug method");
                let geth_debug = GethDebugHandler::new(
                    rpc.consensus.clone(),
                    rpc.config.max_estimation_gas_limit,
                );
                extend_with_interceptor(
                    &mut handler,
                    &rpc.config,
                    geth_debug.to_delegate(),
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
    eth_pubsub: EthPubSubClient, conf: &Configuration,
) -> MetaIoHandler<Metadata> {
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
) -> MetaIoHandler<Metadata> {
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
            Api::Eth => {
                warn!("Light nodes do not support evm ports.");
            }
            Api::EthDebug => {
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

// start espace rpc server v2(async)
pub async fn launch_async_rpc_servers(
    rpc_conf: RpcImplConfiguration, throttling_conf_file: Option<String>,
    apis: RpcModuleSelection, consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService, tx_pool: SharedTransactionPool,
    addr: Option<SocketAddr>, executor: TaskExecutor,
) -> Result<Option<RpcServerHandle>, String> {
    if addr.is_none() {
        return Ok(None);
    }

    let enable_metrics = rpc_conf.enable_metrics;

    let rpc_module_builder =
        RpcModuleBuilder::new(rpc_conf, consensus, sync, tx_pool, executor);

    info!(
        "Enabled evm async rpc modules: {:?}",
        apis.clone().into_selection()
    );

    let transport_rpc_module_config = TransportRpcModuleConfig::set_http(apis);

    let transport_rpc_modules =
        rpc_module_builder.build(transport_rpc_module_config);

    // TODO: set server config according to config
    let http_server_builder = ServerBuilder::default();
    let server_config = RpcServerConfig::http(http_server_builder)
        .with_http_address(addr.unwrap());

    let server_handle = server_config
        .start(&transport_rpc_modules, throttling_conf_file, enable_metrics)
        .await
        .map_err(|e| e.to_string())?;

    Ok(Some(server_handle))
}
