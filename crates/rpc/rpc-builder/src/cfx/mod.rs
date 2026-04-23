mod module;

pub use crate::{
    error::*, id_provider::SubscriptionIdProvider, RpcServerHandle,
};
pub use module::{CfxRpcModule, RpcModuleSelection};

use blockgen::BlockGeneratorTestApi;
use cfx_rpc_cfx_api::{
    CfxRpcServer, DebugRpcServer, PosRpcServer, PubSubApiServer, TestRpcServer,
    TraceServer, TxPoolServer,
};
use cfx_rpc_cfx_impl::{
    CfxHandler, DebugHandler, PosHandler, PubSubHandler, TestHandler,
    TraceHandler, TxPoolHandler,
};
use cfx_rpc_cfx_types::RpcImplConfiguration;
use cfx_tasks::TaskExecutor;
use cfxcore::{
    block_data_manager::BlockDataManager, consensus::pos_handler::PosVerifier,
    Notifications, SharedConsensusGraph, SharedSynchronizationService,
    SharedTransactionPool,
};
use cfxcore_accounts::AccountProvider;
use jsonrpsee::{
    core::RegisterMethodError,
    server::{IdProvider, ServerBuilder, ServerConfigBuilder},
    Methods, RpcModule,
};
use network::NetworkService;
use parking_lot::{Condvar, Mutex};
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
};
use txgen::{DirectTransactionGenerator, TransactionGenerator};

pub const DEFAULT_HTTP_PORT: u16 = 12537;
pub const DEFAULT_WS_PORT: u16 = 12538;

#[derive(Clone)]
pub struct RpcModuleBuilder {
    rpc_impl_config: RpcImplConfiguration,
    consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService,
    tx_pool: SharedTransactionPool,
    executor: TaskExecutor,
    data_man: Arc<BlockDataManager>,
    network: Arc<NetworkService>,
    pos_handler: Arc<PosVerifier>,
    notifications: Arc<Notifications>,
    accounts: Arc<AccountProvider>,
    exit: Arc<(Mutex<bool>, Condvar)>,
    block_gen: BlockGeneratorTestApi,
    maybe_txgen: Option<Arc<TransactionGenerator>>,
    maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
}

impl RpcModuleBuilder {
    pub fn new(
        rpc_impl_config: RpcImplConfiguration, consensus: SharedConsensusGraph,
        sync: SharedSynchronizationService, tx_pool: SharedTransactionPool,
        executor: TaskExecutor, data_man: Arc<BlockDataManager>,
        network: Arc<NetworkService>, pos_handler: Arc<PosVerifier>,
        notifications: Arc<Notifications>, accounts: Arc<AccountProvider>,
        exit: Arc<(Mutex<bool>, Condvar)>, block_gen: BlockGeneratorTestApi,
        maybe_txgen: Option<Arc<TransactionGenerator>>,
        maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
    ) -> Self {
        Self {
            rpc_impl_config,
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
        }
    }

    pub fn build(
        self, module_config: TransportRpcModuleConfig,
    ) -> TransportRpcModules<()> {
        let mut modules = TransportRpcModules::default();

        if !module_config.is_empty() {
            let TransportRpcModuleConfig { http, ws } = module_config.clone();

            let Self {
                rpc_impl_config,
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
            } = self;

            let mut registry = RpcRegistryInner::new(
                rpc_impl_config,
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

            modules.config = module_config;
            modules.http = registry.maybe_module(http.as_ref());
            modules.ws = registry.maybe_module(ws.as_ref());
        }

        modules
    }
}

#[derive(Clone)]
pub struct RpcRegistryInner {
    rpc_impl_config: RpcImplConfiguration,
    consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService,
    tx_pool: SharedTransactionPool,
    executor: TaskExecutor,
    data_man: Arc<BlockDataManager>,
    network: Arc<NetworkService>,
    pos_handler: Arc<PosVerifier>,
    notifications: Arc<Notifications>,
    accounts: Arc<AccountProvider>,
    exit: Arc<(Mutex<bool>, Condvar)>,
    block_gen: BlockGeneratorTestApi,
    maybe_txgen: Option<Arc<TransactionGenerator>>,
    maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
    modules: HashMap<CfxRpcModule, Methods>,
}

impl RpcRegistryInner {
    pub fn new(
        rpc_impl_config: RpcImplConfiguration, consensus: SharedConsensusGraph,
        sync: SharedSynchronizationService, tx_pool: SharedTransactionPool,
        executor: TaskExecutor, data_man: Arc<BlockDataManager>,
        network: Arc<NetworkService>, pos_handler: Arc<PosVerifier>,
        notifications: Arc<Notifications>, accounts: Arc<AccountProvider>,
        exit: Arc<(Mutex<bool>, Condvar)>, block_gen: BlockGeneratorTestApi,
        maybe_txgen: Option<Arc<TransactionGenerator>>,
        maybe_direct_txgen: Option<Arc<Mutex<DirectTransactionGenerator>>>,
    ) -> Self {
        Self {
            rpc_impl_config,
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
            modules: Default::default(),
        }
    }

    fn maybe_module(
        &mut self, config: Option<&RpcModuleSelection>,
    ) -> Option<RpcModule<()>> {
        config.map(|config| self.module_for(config))
    }

    pub fn module_for(&mut self, config: &RpcModuleSelection) -> RpcModule<()> {
        let mut module = RpcModule::new(());
        let all_methods = self.cfx_methods(config.iter_selection());
        for methods in all_methods {
            module.merge(methods).expect("No conflicts");
        }
        module
    }

    pub fn cfx_methods(
        &mut self, namespaces: impl Iterator<Item = CfxRpcModule>,
    ) -> Vec<Methods> {
        let namespaces: Vec<_> = namespaces.collect();

        let namespace_methods = |namespace| {
            self.modules
                .entry(namespace)
                .or_insert_with(|| match namespace {
                    CfxRpcModule::Debug => DebugHandler::new(
                        self.tx_pool.clone(),
                        self.consensus.clone(),
                        self.sync.clone(),
                        self.network.clone(),
                        self.accounts.clone(),
                        self.pos_handler.clone(),
                        self.exit.clone(),
                    )
                    .into_rpc()
                    .into(),
                    CfxRpcModule::Pos => {
                        let handler = PosHandler::new(
                            self.pos_handler.clone(),
                            self.data_man.clone(),
                            *self.network.get_network_type(),
                            self.consensus.clone(),
                        );
                        handler.into_rpc().into()
                    }
                    CfxRpcModule::Trace => {
                        let handler = TraceHandler::new(
                            *self.network.get_network_type(),
                            self.consensus.clone(),
                        );
                        handler.into_rpc().into()
                    }
                    CfxRpcModule::Txpool => TxPoolHandler::new(
                        self.tx_pool.clone(),
                        self.consensus.clone(),
                        *self.network.get_network_type(),
                    )
                    .into_rpc()
                    .into(),
                    CfxRpcModule::PubSub => PubSubHandler::new(
                        self.notifications.clone(),
                        self.executor.clone(),
                        self.consensus.clone(),
                        *self.network.get_network_type(),
                    )
                    .into_rpc()
                    .into(),
                    CfxRpcModule::Cfx => CfxHandler::new(
                        self.rpc_impl_config.clone(),
                        self.consensus.clone(),
                        self.sync.clone(),
                        self.tx_pool.clone(),
                        self.accounts.clone(),
                        self.pos_handler.clone(),
                        self.block_gen.clone(),
                    )
                    .into_rpc()
                    .into(),
                    CfxRpcModule::Test => TestHandler::new(
                        self.exit.clone(),
                        self.consensus.clone(),
                        self.network.clone(),
                        self.pos_handler.clone(),
                        self.tx_pool.clone(),
                        self.accounts.clone(),
                        self.block_gen.clone(),
                        self.maybe_txgen.clone(),
                        self.maybe_direct_txgen.clone(),
                        self.sync.clone(),
                    )
                    .into_rpc()
                    .into(),
                })
                .clone()
        };

        namespaces.iter().copied().map(namespace_methods).collect()
    }
}

#[derive(Debug)]
pub struct RpcServerConfig {
    http_server_config: Option<ServerConfigBuilder>,
    http_cors_domains: Option<String>,
    http_addr: Option<SocketAddr>,
    ws_server_config: Option<ServerConfigBuilder>,
    ws_cors_domains: Option<String>,
    ws_addr: Option<SocketAddr>,
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        Self {
            http_server_config: None,
            http_cors_domains: None,
            http_addr: None,
            ws_server_config: None,
            ws_cors_domains: None,
            ws_addr: None,
        }
    }
}

impl RpcServerConfig {
    pub fn http(config: ServerConfigBuilder) -> Self {
        Self::default().with_http(config)
    }

    pub fn ws(config: ServerConfigBuilder) -> Self {
        Self::default().with_ws(config)
    }

    pub fn with_http(mut self, config: ServerConfigBuilder) -> Self {
        self.http_server_config =
            Some(config.set_id_provider(SubscriptionIdProvider::default()));
        self
    }

    pub fn with_ws(mut self, config: ServerConfigBuilder) -> Self {
        self.ws_server_config =
            Some(config.set_id_provider(SubscriptionIdProvider::default()));
        self
    }

    pub fn with_cors(self, cors_domain: Option<String>) -> Self {
        self.with_http_cors(cors_domain.clone())
            .with_ws_cors(cors_domain)
    }

    pub fn with_ws_cors(mut self, cors_domain: Option<String>) -> Self {
        self.ws_cors_domains = cors_domain;
        self
    }

    pub fn with_http_cors(mut self, cors_domain: Option<String>) -> Self {
        self.http_cors_domains = cors_domain;
        self
    }

    pub const fn with_http_address(mut self, addr: SocketAddr) -> Self {
        self.http_addr = Some(addr);
        self
    }

    pub const fn with_ws_address(mut self, addr: SocketAddr) -> Self {
        self.ws_addr = Some(addr);
        self
    }

    pub fn with_id_provider<I>(mut self, id_provider: I) -> Self
    where I: IdProvider + Clone + 'static {
        if let Some(http) = self.http_server_config.take() {
            self.http_server_config =
                Some(http.set_id_provider(id_provider.clone()));
        }
        if let Some(ws) = self.ws_server_config.take() {
            self.ws_server_config =
                Some(ws.set_id_provider(id_provider.clone()));
        }

        self
    }

    pub const fn has_server(&self) -> bool {
        self.http_server_config.is_some() || self.ws_server_config.is_some()
    }

    pub const fn http_address(&self) -> Option<SocketAddr> { self.http_addr }

    pub const fn ws_address(&self) -> Option<SocketAddr> { self.ws_addr }

    pub async fn start(
        self, modules: &TransportRpcModules,
    ) -> Result<RpcServerHandle, RpcError<CfxRpcModule>> {
        let http_socket_addr = self.http_addr.unwrap_or(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, DEFAULT_HTTP_PORT),
        ));

        let ws_socket_addr = self.ws_addr.unwrap_or(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, DEFAULT_WS_PORT),
        ));

        if self.http_addr == self.ws_addr
            && self.http_server_config.is_some()
            && self.ws_server_config.is_some()
        {
            modules.config.ensure_ws_http_identical()?;

            if let Some(config) = self.http_server_config {
                let server = ServerBuilder::new()
                    .set_config(config.build())
                    .build(http_socket_addr)
                    .await
                    .map_err(|err| {
                        RpcError::server_error(
                            err,
                            ServerKind::WsHttp(http_socket_addr),
                        )
                    })?;
                let addr = server.local_addr().map_err(|err| {
                    RpcError::server_error(
                        err,
                        ServerKind::WsHttp(http_socket_addr),
                    )
                })?;
                if let Some(module) =
                    modules.http.as_ref().or(modules.ws.as_ref())
                {
                    let handle = server.start(module.clone());
                    return Ok(RpcServerHandle {
                        http_local_addr: Some(addr),
                        ws_local_addr: Some(addr),
                        http: Some(handle.clone()),
                        ws: Some(handle),
                    });
                }

                return Err(RpcError::Custom(
                    "No valid RpcModule found from modules".to_string(),
                ));
            }
        }

        let mut result = RpcServerHandle {
            http_local_addr: None,
            ws_local_addr: None,
            http: None,
            ws: None,
        };

        if let Some(config) = self.ws_server_config {
            let server = ServerBuilder::new()
                .set_config(config.ws_only().build())
                .build(ws_socket_addr)
                .await
                .map_err(|err| {
                    RpcError::server_error(err, ServerKind::WS(ws_socket_addr))
                })?;

            let addr = server.local_addr().map_err(|err| {
                RpcError::server_error(err, ServerKind::WS(ws_socket_addr))
            })?;

            let ws_local_addr = Some(addr);
            let ws_handle = Some(
                server.start(modules.ws.clone().expect("ws server error")),
            );

            result.ws = ws_handle;
            result.ws_local_addr = ws_local_addr;
        }

        if let Some(config) = self.http_server_config {
            let server = ServerBuilder::new()
                .set_config(config.http_only().build())
                .build(http_socket_addr)
                .await
                .map_err(|err| {
                    RpcError::server_error(
                        err,
                        ServerKind::Http(http_socket_addr),
                    )
                })?;
            let local_addr = server.local_addr().map_err(|err| {
                RpcError::server_error(err, ServerKind::Http(http_socket_addr))
            })?;
            let http_local_addr = Some(local_addr);
            let http_handle = Some(
                server.start(modules.http.clone().expect("http server error")),
            );

            result.http = http_handle;
            result.http_local_addr = http_local_addr;
        }

        Ok(result)
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct TransportRpcModuleConfig {
    pub http: Option<RpcModuleSelection>,
    pub ws: Option<RpcModuleSelection>,
}

impl TransportRpcModuleConfig {
    pub fn set_http(http: impl Into<RpcModuleSelection>) -> Self {
        Self::default().with_http(http)
    }

    pub fn set_ws(ws: impl Into<RpcModuleSelection>) -> Self {
        Self::default().with_ws(ws)
    }

    pub fn with_http(mut self, http: impl Into<RpcModuleSelection>) -> Self {
        self.http = Some(http.into());
        self
    }

    pub fn with_ws(mut self, ws: impl Into<RpcModuleSelection>) -> Self {
        self.ws = Some(ws.into());
        self
    }

    pub fn http_mut(&mut self) -> &mut Option<RpcModuleSelection> {
        &mut self.http
    }

    pub fn ws_mut(&mut self) -> &mut Option<RpcModuleSelection> { &mut self.ws }

    pub const fn is_empty(&self) -> bool {
        self.http.is_none() && self.ws.is_none()
    }

    pub const fn http(&self) -> Option<&RpcModuleSelection> {
        self.http.as_ref()
    }

    pub const fn ws(&self) -> Option<&RpcModuleSelection> { self.ws.as_ref() }

    fn ensure_ws_http_identical(
        &self,
    ) -> Result<(), WsHttpSamePortError<CfxRpcModule>> {
        if RpcModuleSelection::are_identical(
            self.http.as_ref(),
            self.ws.as_ref(),
        ) {
            Ok(())
        } else {
            let http_modules = self
                .http
                .as_ref()
                .map(RpcModuleSelection::to_selection)
                .unwrap_or_default();
            let ws_modules = self
                .ws
                .as_ref()
                .map(RpcModuleSelection::to_selection)
                .unwrap_or_default();

            let http_not_ws: HashSet<CfxRpcModule> =
                http_modules.difference(&ws_modules).copied().collect();
            let ws_not_http: HashSet<CfxRpcModule> =
                ws_modules.difference(&http_modules).copied().collect();
            let overlap: HashSet<CfxRpcModule> =
                http_modules.intersection(&ws_modules).copied().collect();
            // 指定泛型为 CfxRpcModule 以避免冲突
            let conflicting_modules = ConflictingModules {
                overlap,
                http_not_ws,
                ws_not_http,
            };
            Err(WsHttpSamePortError::ConflictingModules(Box::new(
                conflicting_modules,
            )))
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TransportRpcModules<Context = ()> {
    pub config: TransportRpcModuleConfig,
    pub http: Option<RpcModule<Context>>,
    pub ws: Option<RpcModule<Context>>,
}

impl TransportRpcModules {
    pub const fn module_config(&self) -> &TransportRpcModuleConfig {
        &self.config
    }

    pub fn merge_http(
        &mut self, other: impl Into<Methods>,
    ) -> Result<bool, RegisterMethodError> {
        if let Some(ref mut http) = self.http {
            return http.merge(other.into()).map(|_| true);
        }
        Ok(false)
    }

    pub fn merge_ws(
        &mut self, other: impl Into<Methods>,
    ) -> Result<bool, RegisterMethodError> {
        if let Some(ref mut ws) = self.ws {
            return ws.merge(other.into()).map(|_| true);
        }
        Ok(false)
    }

    pub fn merge_configured(
        &mut self, other: impl Into<Methods>,
    ) -> Result<(), RegisterMethodError> {
        let other = other.into();
        self.merge_http(other.clone())?;
        self.merge_ws(other.clone())?;
        Ok(())
    }

    pub fn remove_http_method(&mut self, method_name: &'static str) -> bool {
        if let Some(http_module) = &mut self.http {
            http_module.remove_method(method_name).is_some()
        } else {
            false
        }
    }

    pub fn remove_ws_method(&mut self, method_name: &'static str) -> bool {
        if let Some(ws_module) = &mut self.ws {
            ws_module.remove_method(method_name).is_some()
        } else {
            false
        }
    }

    pub fn remove_method_from_configured(
        &mut self, method_name: &'static str,
    ) -> bool {
        let http_removed = self.remove_http_method(method_name);
        let ws_removed = self.remove_ws_method(method_name);

        http_removed || ws_removed
    }
}
