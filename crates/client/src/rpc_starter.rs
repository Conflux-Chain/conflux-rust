// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use blockgen::BlockGeneratorTestApi;
use cfx_config::Configuration;
use cfx_rpc_builder::{
    CfxRpcModule, CfxRpcModuleBuilder, CfxRpcModuleSelection,
    CfxRpcServerConfig, CfxTransportRpcModuleConfig, CfxTransportRpcModules,
    RpcModuleBuilder, RpcServerConfig, RpcServerHandle,
    TransportRpcModuleConfig,
};
use cfx_rpc_cfx_api::{
    CfxDebugRpcServer, CfxRpcServer, DebugRpcServer, TestRpcServer,
};
use cfx_rpc_cfx_types::apis::ApiSet;
use cfx_tasks::TaskExecutor;
use cfxcore::{
    block_data_manager::BlockDataManager, consensus::pos_handler::PosVerifier,
    LightQueryService, Notifications, SharedConsensusGraph,
    SharedSynchronizationService, SharedTransactionPool,
};
use jsonrpsee::RpcModule;
use log::{info, warn};
use network::NetworkService;
use parking_lot::{Condvar, Mutex};
use std::sync::Arc;
use txgen::{DirectTransactionGenerator, TransactionGenerator};

// start espace rpc server v2(async)
pub async fn launch_async_rpc_servers(
    consensus: SharedConsensusGraph, sync: SharedSynchronizationService,
    tx_pool: SharedTransactionPool, notifications: Arc<Notifications>,
    executor: TaskExecutor, conf: &Configuration,
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
                    RpcServerConfig::http(conf.jsonrpsee_server_builder())
                        .with_ws(conf.jsonrpsee_server_builder())
                        .with_http_address(http_config.address)
                        .with_ws_address(ws_config.address);
                (transport_rpc_module_config, server_config)
            }
            (true, false) => {
                let transport_rpc_module_config =
                    TransportRpcModuleConfig::set_http(apis.clone());
                let server_config =
                    RpcServerConfig::http(conf.jsonrpsee_server_builder())
                        .with_http_address(http_config.address);
                (transport_rpc_module_config, server_config)
            }
            (false, true) => {
                let transport_rpc_module_config =
                    TransportRpcModuleConfig::set_ws(apis.clone());
                let server_config =
                    RpcServerConfig::ws(conf.jsonrpsee_server_builder())
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
        notifications,
    );

    let transport_rpc_modules =
        rpc_module_builder.build(transport_rpc_module_config);

    let throttling_conf_file = conf.raw_conf.throttling_conf.clone();
    let server_handle = server_config
        .start(&transport_rpc_modules, throttling_conf_file, enable_metrics)
        .await
        .map_err(|e| e.to_string())?;

    Ok(Some(server_handle))
}

// start core space rpc server v2(async)
pub async fn launch_cfx_async_rpc_servers(
    consensus: SharedConsensusGraph, sync: SharedSynchronizationService,
    tx_pool: SharedTransactionPool, data_man: Arc<BlockDataManager>,
    network: Arc<NetworkService>, pos_handler: Arc<PosVerifier>,
    notifications: Arc<Notifications>, executor: TaskExecutor,
    accounts: Arc<cfxcore_accounts::AccountProvider>,
    exit: Arc<(parking_lot::Mutex<bool>, parking_lot::Condvar)>,
    block_gen: BlockGeneratorTestApi,
    maybe_txgen: Option<Arc<TransactionGenerator>>,
    maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
    conf: &Configuration, apis: ApiSet, is_debug: bool,
) -> Result<Option<RpcServerHandle>, String> {
    let (http_config, ws_config) = if !is_debug {
        (conf.http_config(), conf.ws_config())
    } else {
        (conf.local_http_config(), conf.local_ws_config())
    };

    let (transport_rpc_module_config, server_config) =
        match (http_config.enabled, ws_config.enabled) {
            (true, true) => {
                let transport_rpc_module_config =
                    CfxTransportRpcModuleConfig::set_http(apis.clone())
                        .with_ws(apis.clone());

                let server_config =
                    CfxRpcServerConfig::http(conf.jsonrpsee_server_builder())
                        .with_ws(conf.jsonrpsee_server_builder())
                        .with_http_address(http_config.address)
                        .with_ws_address(ws_config.address);
                (transport_rpc_module_config, server_config)
            }
            (true, false) => {
                let transport_rpc_module_config =
                    CfxTransportRpcModuleConfig::set_http(apis.clone());
                let server_config =
                    CfxRpcServerConfig::http(conf.jsonrpsee_server_builder())
                        .with_http_address(http_config.address);
                (transport_rpc_module_config, server_config)
            }
            (false, true) => {
                let transport_rpc_module_config =
                    CfxTransportRpcModuleConfig::set_ws(apis.clone());
                let server_config =
                    CfxRpcServerConfig::ws(conf.jsonrpsee_server_builder())
                        .with_ws_address(ws_config.address);
                (transport_rpc_module_config, server_config)
            }
            _ => return Ok(None),
        };

    info!(
        "Enabled cfx async rpc modules: {:?}",
        CfxRpcModuleSelection::from(apis).into_selection()
    );

    let rpc_conf = conf.rpc_impl_config();
    let rpc_module_builder = CfxRpcModuleBuilder::new(
        rpc_conf,
        consensus,
        sync,
        tx_pool,
        executor,
        data_man,
        network,
        pos_handler,
        notifications,
        accounts,
        exit,
        block_gen,
        maybe_txgen,
        maybe_direct_txgen,
    );

    let transport_rpc_modules =
        rpc_module_builder.build(transport_rpc_module_config);

    let server_handle = server_config
        .start(&transport_rpc_modules)
        .await
        .map_err(|e| e.to_string())?;

    Ok(Some(server_handle))
}

// start core space light rpc server (async, jsonrpsee)
pub async fn launch_cfx_light_async_rpc_servers(
    consensus: SharedConsensusGraph, tx_pool: SharedTransactionPool,
    data_man: Arc<BlockDataManager>, network: Arc<NetworkService>,
    pos_handler: Arc<PosVerifier>,
    accounts: Arc<cfxcore_accounts::AccountProvider>,
    light: Arc<LightQueryService>, exit: Arc<(Mutex<bool>, Condvar)>,
    conf: &Configuration,
) -> Result<Option<RpcServerHandle>, String> {
    use cfx_rpc_cfx_impl::{
        common::CommonRpcImpl,
        light::{
            LightCfxHandler, LightDebugHandler, LightTestHandler,
            RpcImpl as LightRpcImpl,
        },
    };

    let http_config = conf.http_config();
    let ws_config = conf.ws_config();
    let apis =
        CfxRpcModuleSelection::from(conf.raw_conf.public_rpc_apis.clone());

    let server_config = match (http_config.enabled, ws_config.enabled) {
        (true, true) => {
            CfxRpcServerConfig::http(conf.jsonrpsee_server_builder())
                .with_ws(conf.jsonrpsee_server_builder())
                .with_http_address(http_config.address)
                .with_ws_address(ws_config.address)
        }
        (true, false) => {
            CfxRpcServerConfig::http(conf.jsonrpsee_server_builder())
                .with_http_address(http_config.address)
        }
        (false, true) => {
            CfxRpcServerConfig::ws(conf.jsonrpsee_server_builder())
                .with_ws_address(ws_config.address)
        }
        _ => return Ok(None),
    };

    let common_rpc_impl = Arc::new(CommonRpcImpl::new(
        exit,
        consensus.clone(),
        network,
        tx_pool,
        accounts.clone(),
        pos_handler,
    ));

    let light_rpc_impl =
        Arc::new(LightRpcImpl::new(light, accounts, consensus, data_man));

    let mut module = RpcModule::new(());

    for api in apis.iter_selection() {
        match api {
            CfxRpcModule::Cfx => {
                let handler = LightCfxHandler::new(
                    light_rpc_impl.clone(),
                    common_rpc_impl.clone(),
                );
                module
                    .merge(CfxRpcServer::into_rpc(handler))
                    .expect("No conflicts for Cfx module");
            }
            CfxRpcModule::Debug => {
                let cfx_debug_handler = LightCfxHandler::new(
                    light_rpc_impl.clone(),
                    common_rpc_impl.clone(),
                );
                module
                    .merge(CfxDebugRpcServer::into_rpc(cfx_debug_handler))
                    .expect("No conflicts for CfxDebug module");

                let debug_handler =
                    LightDebugHandler::new(common_rpc_impl.clone());
                module
                    .merge(DebugRpcServer::into_rpc(debug_handler))
                    .expect("No conflicts for Debug module");
            }
            CfxRpcModule::Test => {
                let handler = LightTestHandler::new(common_rpc_impl.clone());
                module
                    .merge(TestRpcServer::into_rpc(handler))
                    .expect("No conflicts for Test module");
            }
            CfxRpcModule::PubSub => {
                warn!(
                    "Light node PubSub not yet supported \
                     in async RPC"
                );
            }
            CfxRpcModule::Trace => {
                warn!("Light nodes do not support trace RPC");
            }
            CfxRpcModule::Txpool => {
                warn!("Light nodes do not support txpool RPC");
            }
            CfxRpcModule::Pos => {
                warn!("Light nodes do not support PoS RPC");
            }
        }
    }

    info!(
        "Enabled cfx light async rpc modules: {:?}",
        apis.to_selection()
    );

    let mut transport_modules = CfxTransportRpcModules::default();

    match (http_config.enabled, ws_config.enabled) {
        (true, true) => {
            transport_modules.config =
                CfxTransportRpcModuleConfig::set_http(apis.clone())
                    .with_ws(apis);
            transport_modules.http = Some(module.clone());
            transport_modules.ws = Some(module);
        }
        (true, false) => {
            transport_modules.config =
                CfxTransportRpcModuleConfig::set_http(apis);
            transport_modules.http = Some(module);
        }
        (false, true) => {
            transport_modules.config =
                CfxTransportRpcModuleConfig::set_ws(apis);
            transport_modules.ws = Some(module);
        }
        _ => unreachable!(),
    }

    let server_handle = server_config
        .start(&transport_modules)
        .await
        .map_err(|e| e.to_string())?;

    Ok(Some(server_handle))
}
