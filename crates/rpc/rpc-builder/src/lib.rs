// Copyright 2023-2024 Paradigm.xyz
// This file is part of reth.
// Reth is a modular, contributor-friendly and blazing-fast implementation of
// the Ethereum protocol

// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:

// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
mod constants;
mod error;
mod id_provider;
mod module;

use cfx_rpc_middlewares::{Metrics, Throttle};
pub use error::*;
pub use id_provider::EthSubscriptionIdProvider;
use log::debug;
pub use module::{EthRpcModule, RpcModuleSelection};

use cfx_rpc::{helpers::ChainInfo, *};
use cfx_rpc_cfx_types::RpcImplConfiguration;
use cfx_rpc_eth_api::*;
use cfxcore::{
    SharedConsensusGraph, SharedSynchronizationService, SharedTransactionPool,
};
pub use jsonrpsee::server::ServerBuilder;
use jsonrpsee::{
    core::RegisterMethodError,
    server::{
        // middleware::rpc::{RpcService, RpcServiceT},
        AlreadyStoppedError,
        IdProvider,
        RpcServiceBuilder,
        ServerHandle,
    },
    Methods, RpcModule,
};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    /* time::{Duration, SystemTime, UNIX_EPOCH}, */
};
pub use tower::layer::util::{Identity, Stack};
// use tower::Layer;
use cfx_tasks::TaskExecutor;

/// A builder type to configure the RPC module: See [`RpcModule`]
///
/// This is the main entrypoint and the easiest way to configure an RPC server.
#[derive(Clone)]
pub struct RpcModuleBuilder {
    config: RpcImplConfiguration,
    consensus: SharedConsensusGraph,
    sync: SharedSynchronizationService,
    tx_pool: SharedTransactionPool,
    executor: TaskExecutor,
}

impl RpcModuleBuilder {
    pub fn new(
        config: RpcImplConfiguration, consensus: SharedConsensusGraph,
        sync: SharedSynchronizationService, tx_pool: SharedTransactionPool,
        executor: TaskExecutor,
    ) -> Self {
        Self {
            config,
            consensus,
            sync,
            tx_pool,
            executor,
        }
    }

    /// Configures all [`RpcModule`]s specific to the given
    /// [`TransportRpcModuleConfig`] which can be used to start the
    /// transport server(s).
    pub fn build(
        self, module_config: TransportRpcModuleConfig,
    ) -> TransportRpcModules<()> {
        let mut modules = TransportRpcModules::default();

        if !module_config.is_empty() {
            let TransportRpcModuleConfig { http, ws } = module_config.clone();

            let Self {
                config,
                consensus,
                sync,
                tx_pool,
                executor,
            } = self;

            let mut registry = RpcRegistryInner::new(
                config, consensus, sync, tx_pool, executor,
            );

            modules.config = module_config;
            modules.http = registry.maybe_module(http.as_ref());
            modules.ws = registry.maybe_module(ws.as_ref());
        }

        modules
    }
}

/// A Helper type the holds instances of the configured modules.
#[derive(Clone)]
pub struct RpcRegistryInner {
    consensus: SharedConsensusGraph,
    config: RpcImplConfiguration,
    sync: SharedSynchronizationService,
    tx_pool: SharedTransactionPool,
    modules: HashMap<EthRpcModule, Methods>,
    executor: TaskExecutor,
}

impl RpcRegistryInner {
    pub fn new(
        config: RpcImplConfiguration, consensus: SharedConsensusGraph,
        sync: SharedSynchronizationService, tx_pool: SharedTransactionPool,
        executor: TaskExecutor,
    ) -> Self {
        Self {
            consensus,
            config,
            sync,
            tx_pool,
            modules: Default::default(),
            executor,
        }
    }

    /// Returns all installed methods
    pub fn methods(&self) -> Vec<Methods> {
        self.modules.values().cloned().collect()
    }

    /// Returns a merged `RpcModule`
    pub fn module(&self) -> RpcModule<()> {
        let mut module = RpcModule::new(());
        for methods in self.modules.values().cloned() {
            module.merge(methods).expect("No conflicts");
        }
        module
    }
}

impl RpcRegistryInner {
    pub fn web3_api(&self) -> Web3Api { Web3Api }

    pub fn register_web3(&mut self) -> &mut Self {
        let web3api = self.web3_api();
        self.modules
            .insert(EthRpcModule::Web3, web3api.into_rpc().into());
        self
    }

    pub fn trace_api(&self) -> TraceApi {
        TraceApi::new(
            self.consensus.clone(),
            self.sync.network.get_network_type().clone(),
        )
    }

    pub fn debug_api(&self) -> DebugApi {
        DebugApi::new(
            self.consensus.clone(),
            self.config.max_estimation_gas_limit,
        )
    }

    pub fn net_api(&self) -> NetApi {
        NetApi::new(Box::new(ChainInfo::new(self.consensus.clone())))
    }

    /// Helper function to create a [`RpcModule`] if it's not `None`
    fn maybe_module(
        &mut self, config: Option<&RpcModuleSelection>,
    ) -> Option<RpcModule<()>> {
        config.map(|config| self.module_for(config))
    }

    /// Populates a new [`RpcModule`] based on the selected [`EthRpcModule`]s in
    /// the given [`RpcModuleSelection`]
    pub fn module_for(&mut self, config: &RpcModuleSelection) -> RpcModule<()> {
        let mut module = RpcModule::new(());
        let all_methods = self.eth_methods(config.iter_selection());
        for methods in all_methods {
            module.merge(methods).expect("No conflicts");
        }
        module
    }

    pub fn eth_methods(
        &mut self, namespaces: impl Iterator<Item = EthRpcModule>,
    ) -> Vec<Methods> {
        let namespaces: Vec<_> = namespaces.collect();
        let module_version = namespaces
            .iter()
            .map(|module| (module.to_string(), "1.0".to_string()))
            .collect::<HashMap<String, String>>();

        let namespace_methods = |namespace| {
            self.modules
                .entry(namespace)
                .or_insert_with(|| match namespace {
                    EthRpcModule::Debug => DebugApi::new(
                        self.consensus.clone(),
                        self.config.max_estimation_gas_limit,
                    )
                    .into_rpc()
                    .into(),
                    EthRpcModule::Eth => EthApi::new(
                        self.config.clone(),
                        self.consensus.clone(),
                        self.sync.clone(),
                        self.tx_pool.clone(),
                        self.executor.clone(),
                    )
                    .into_rpc()
                    .into(),
                    EthRpcModule::Net => NetApi::new(Box::new(ChainInfo::new(
                        self.consensus.clone(),
                    )))
                    .into_rpc()
                    .into(),
                    EthRpcModule::Trace => TraceApi::new(
                        self.consensus.clone(),
                        self.sync.network.get_network_type().clone(),
                    )
                    .into_rpc()
                    .into(),
                    EthRpcModule::Web3 => Web3Api.into_rpc().into(),
                    EthRpcModule::Rpc => {
                        RPCApi::new(module_version.clone()).into_rpc().into()
                    }
                    EthRpcModule::Parity => {
                        let eth_api = EthApi::new(
                            self.config.clone(),
                            self.consensus.clone(),
                            self.sync.clone(),
                            self.tx_pool.clone(),
                            self.executor.clone(),
                        );
                        ParityApi::new(eth_api).into_rpc().into()
                    }
                    EthRpcModule::Txpool => {
                        TxPoolApi::new(self.tx_pool.clone()).into_rpc().into()
                    }
                })
                .clone()
        };

        namespaces
            .iter()
            .copied()
            .map(namespace_methods)
            .collect::<Vec<_>>()
    }
}

/// A builder type for configuring and launching the servers that will handle
/// RPC requests.
///
/// Supported server transports are:
///    - http
///    - ws
///
/// Http and WS share the same settings: [`ServerBuilder`].
///
/// Once the [`RpcModule`] is built via [`RpcModuleBuilder`] the servers can be
/// started, See also [`ServerBuilder::build`] and
/// [`Server::start`](jsonrpsee::server::Server::start).
#[derive(Debug)]
pub struct RpcServerConfig {
    /// Configs for JSON-RPC Http.
    http_server_config: Option<ServerBuilder<Identity, Identity>>,
    /// Allowed CORS Domains for http
    http_cors_domains: Option<String>,
    /// Address where to bind the http server to
    http_addr: Option<SocketAddr>,
    /// Configs for WS server
    ws_server_config: Option<ServerBuilder<Identity, Identity>>,
    /// Allowed CORS Domains for ws.
    ws_cors_domains: Option<String>,
    /// Address where to bind the ws server to
    ws_addr: Option<SocketAddr>,
    // /// Configurable RPC middleware
    // #[allow(dead_code)]
    // rpc_middleware: RpcServiceBuilder<RpcMiddleware>,
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
            // rpc_middleware: RpcServiceBuilder::new(),
        }
    }
}

impl RpcServerConfig {
    /// Creates a new config with only http set
    pub fn http(config: ServerBuilder<Identity, Identity>) -> Self {
        Self::default().with_http(config)
    }

    /// Creates a new config with only ws set
    pub fn ws(config: ServerBuilder<Identity, Identity>) -> Self {
        Self::default().with_ws(config)
    }

    /// Configures the http server
    ///
    /// Note: this always configures an [`EthSubscriptionIdProvider`]
    /// [`IdProvider`] for convenience. To set a custom [`IdProvider`],
    /// please use [`Self::with_id_provider`].
    pub fn with_http(
        mut self, config: ServerBuilder<Identity, Identity>,
    ) -> Self {
        self.http_server_config =
            Some(config.set_id_provider(EthSubscriptionIdProvider::default()));
        self
    }

    /// Configures the ws server
    ///
    /// Note: this always configures an [`EthSubscriptionIdProvider`]
    /// [`IdProvider`] for convenience. To set a custom [`IdProvider`],
    /// please use [`Self::with_id_provider`].
    pub fn with_ws(
        mut self, config: ServerBuilder<Identity, Identity>,
    ) -> Self {
        self.ws_server_config =
            Some(config.set_id_provider(EthSubscriptionIdProvider::default()));
        self
    }
}

impl RpcServerConfig {
    /// Configure rpc middleware
    // pub fn set_rpc_middleware<T>(
    //     self, rpc_middleware: RpcServiceBuilder<T>,
    // ) -> RpcServerConfig<T> {
    //     RpcServerConfig {
    //         http_server_config: self.http_server_config,
    //         http_cors_domains: self.http_cors_domains,
    //         http_addr: self.http_addr,
    //         ws_server_config: self.ws_server_config,
    //         ws_cors_domains: self.ws_cors_domains,
    //         ws_addr: self.ws_addr,
    //         rpc_middleware,
    //     }
    // }

    /// Configure the cors domains for http _and_ ws
    pub fn with_cors(self, cors_domain: Option<String>) -> Self {
        self.with_http_cors(cors_domain.clone())
            .with_ws_cors(cors_domain)
    }

    /// Configure the cors domains for WS
    pub fn with_ws_cors(mut self, cors_domain: Option<String>) -> Self {
        self.ws_cors_domains = cors_domain;
        self
    }

    /// Configure the cors domains for HTTP
    pub fn with_http_cors(mut self, cors_domain: Option<String>) -> Self {
        self.http_cors_domains = cors_domain;
        self
    }

    /// Configures the [`SocketAddr`] of the http server
    ///
    /// Default is [`Ipv4Addr::LOCALHOST`] and
    pub const fn with_http_address(mut self, addr: SocketAddr) -> Self {
        self.http_addr = Some(addr);
        self
    }

    /// Configures the [`SocketAddr`] of the ws server
    ///
    /// Default is [`Ipv4Addr::LOCALHOST`] and
    pub const fn with_ws_address(mut self, addr: SocketAddr) -> Self {
        self.ws_addr = Some(addr);
        self
    }

    /// Sets a custom [`IdProvider`] for all configured transports.
    ///
    /// By default all transports use [`EthSubscriptionIdProvider`]
    pub fn with_id_provider<I>(mut self, id_provider: I) -> Self
    where I: IdProvider + Clone + 'static {
        if let Some(http) = self.http_server_config {
            self.http_server_config =
                Some(http.set_id_provider(id_provider.clone()));
        }
        if let Some(ws) = self.ws_server_config {
            self.ws_server_config =
                Some(ws.set_id_provider(id_provider.clone()));
        }

        self
    }

    /// Returns true if any server is configured.
    ///
    /// If no server is configured, no server will be launched on
    /// [`RpcServerConfig::start`].
    pub const fn has_server(&self) -> bool {
        self.http_server_config.is_some() || self.ws_server_config.is_some()
    }

    /// Returns the [`SocketAddr`] of the http server
    pub const fn http_address(&self) -> Option<SocketAddr> { self.http_addr }

    /// Returns the [`SocketAddr`] of the ws server
    pub const fn ws_address(&self) -> Option<SocketAddr> { self.ws_addr }

    // Builds and starts the configured server(s): http, ws, ipc.
    //
    // If both http and ws are on the same port, they are combined into one
    // server.
    //
    // Returns the [`RpcServerHandle`] with the handle to the started servers.
    pub async fn start(
        self, modules: &TransportRpcModules,
        throttling_conf_file: Option<String>, enable_metrics: bool,
    ) -> Result<RpcServerHandle, RpcError> {
        // TODO: handle enable metrics
        debug!("enable metrics: {}", enable_metrics);

        let rpc_middleware = RpcServiceBuilder::new()
            .layer_fn(move |s| {
                Throttle::new(
                    throttling_conf_file.as_ref().map(|s| s.as_str()),
                    "rpc",
                    s,
                )
            })
            .layer_fn(|s| Metrics::new(s));

        let http_socket_addr =
            self.http_addr.unwrap_or(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::LOCALHOST,
                constants::DEFAULT_HTTP_PORT,
            )));

        let ws_socket_addr = self.ws_addr.unwrap_or(SocketAddr::V4(
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, constants::DEFAULT_WS_PORT),
        ));

        // If both are configured on the same port, we combine them into one
        // server.
        if self.http_addr == self.ws_addr
            && self.http_server_config.is_some()
            && self.ws_server_config.is_some()
        {
            // let cors = match (self.ws_cors_domains.as_ref(),
            // self.http_cors_domains.as_ref()) {
            //     (Some(ws_cors), Some(http_cors)) => {
            //         if ws_cors.trim() != http_cors.trim() {
            //             return
            // Err(WsHttpSamePortError::ConflictingCorsDomains {
            //                 http_cors_domains: Some(http_cors.clone()),
            //                 ws_cors_domains: Some(ws_cors.clone()),
            //             }
            //             .into());
            //         }
            //         Some(ws_cors)
            //     }
            //     (a, b) => a.or(b),
            // }
            // .cloned();

            // we merge this into one server using the http setup
            modules.config.ensure_ws_http_identical()?;

            if let Some(builder) = self.http_server_config {
                let server = builder
                    .set_rpc_middleware(rpc_middleware)
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
                    let http_handle = Some(handle.clone());
                    let ws_handle = Some(handle);

                    return Ok(RpcServerHandle {
                        http_local_addr: Some(addr),
                        ws_local_addr: Some(addr),
                        http: http_handle,
                        ws: ws_handle,
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
        if let Some(builder) = self.ws_server_config {
            let server = builder
                .ws_only()
                .set_rpc_middleware(rpc_middleware.clone())
                .build(ws_socket_addr)
                .await
                .map_err(|err| {
                    RpcError::server_error(err, ServerKind::WS(ws_socket_addr))
                })?;

            let addr = server.local_addr().map_err(|err| {
                RpcError::server_error(err, ServerKind::WS(ws_socket_addr))
            })?;

            let ws_local_addr = Some(addr);
            let ws_server = Some(server);
            let ws_handle = ws_server.map(|ws_server| {
                ws_server.start(modules.ws.clone().expect("ws server error"))
            });

            result.ws = ws_handle;
            result.ws_local_addr = ws_local_addr;
        }

        if let Some(builder) = self.http_server_config {
            let server = builder
                .http_only()
                .set_rpc_middleware(rpc_middleware)
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
            let http_server = Some(server);
            let http_handle = http_server.map(|http_server| {
                http_server
                    .start(modules.http.clone().expect("http server error"))
            });

            result.http = http_handle;
            result.http_local_addr = http_local_addr;
        }

        Ok(result)
    }
}

/// Holds modules to be installed per transport type
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct TransportRpcModuleConfig {
    /// http module configuration
    http: Option<RpcModuleSelection>,
    /// ws module configuration
    ws: Option<RpcModuleSelection>,
}

impl TransportRpcModuleConfig {
    /// Creates a new config with only http set
    pub fn set_http(http: impl Into<RpcModuleSelection>) -> Self {
        Self::default().with_http(http)
    }

    /// Creates a new config with only ws set
    pub fn set_ws(ws: impl Into<RpcModuleSelection>) -> Self {
        Self::default().with_ws(ws)
    }

    /// Sets the [`RpcModuleSelection`] for the http transport.
    pub fn with_http(mut self, http: impl Into<RpcModuleSelection>) -> Self {
        self.http = Some(http.into());
        self
    }

    /// Sets the [`RpcModuleSelection`] for the ws transport.
    pub fn with_ws(mut self, ws: impl Into<RpcModuleSelection>) -> Self {
        self.ws = Some(ws.into());
        self
    }

    /// Get a mutable reference to the
    pub fn http_mut(&mut self) -> &mut Option<RpcModuleSelection> {
        &mut self.http
    }

    /// Get a mutable reference to the
    pub fn ws_mut(&mut self) -> &mut Option<RpcModuleSelection> { &mut self.ws }

    /// Returns true if no transports are configured
    pub const fn is_empty(&self) -> bool {
        self.http.is_none() && self.ws.is_none()
    }

    /// Returns the [`RpcModuleSelection`] for the http transport
    pub const fn http(&self) -> Option<&RpcModuleSelection> {
        self.http.as_ref()
    }

    /// Returns the [`RpcModuleSelection`] for the ws transport
    pub const fn ws(&self) -> Option<&RpcModuleSelection> { self.ws.as_ref() }

    /// Ensures that both http and ws are configured and that they are
    /// configured to use the same port.
    fn ensure_ws_http_identical(&self) -> Result<(), WsHttpSamePortError> {
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

            let http_not_ws =
                http_modules.difference(&ws_modules).copied().collect();
            let ws_not_http =
                ws_modules.difference(&http_modules).copied().collect();
            let overlap =
                http_modules.intersection(&ws_modules).copied().collect();

            Err(WsHttpSamePortError::ConflictingModules(Box::new(
                ConflictingModules {
                    overlap,
                    http_not_ws,
                    ws_not_http,
                },
            )))
        }
    }
}

/// Holds installed modules per transport type.
#[derive(Debug, Clone, Default)]
pub struct TransportRpcModules<Context = ()> {
    /// The original config
    config: TransportRpcModuleConfig,
    /// rpcs module for http
    http: Option<RpcModule<Context>>,
    /// rpcs module for ws
    ws: Option<RpcModule<Context>>,
}

// === impl TransportRpcModules ===

impl TransportRpcModules {
    /// Returns the [`TransportRpcModuleConfig`] used to configure this
    /// instance.
    pub const fn module_config(&self) -> &TransportRpcModuleConfig {
        &self.config
    }

    /// Merge the given [Methods] in the configured http methods.
    ///
    /// Fails if any of the methods in other is present already.
    ///
    /// Returns [Ok(false)] if no http transport is configured.
    pub fn merge_http(
        &mut self, other: impl Into<Methods>,
    ) -> Result<bool, RegisterMethodError> {
        if let Some(ref mut http) = self.http {
            return http.merge(other.into()).map(|_| true);
        }
        Ok(false)
    }

    /// Merge the given [Methods] in the configured ws methods.
    ///
    /// Fails if any of the methods in other is present already.
    ///
    /// Returns [Ok(false)] if no ws transport is configured.
    pub fn merge_ws(
        &mut self, other: impl Into<Methods>,
    ) -> Result<bool, RegisterMethodError> {
        if let Some(ref mut ws) = self.ws {
            return ws.merge(other.into()).map(|_| true);
        }
        Ok(false)
    }

    /// Merge the given [Methods] in all configured methods.
    ///
    /// Fails if any of the methods in other is present already.
    pub fn merge_configured(
        &mut self, other: impl Into<Methods>,
    ) -> Result<(), RegisterMethodError> {
        let other = other.into();
        self.merge_http(other.clone())?;
        self.merge_ws(other.clone())?;
        Ok(())
    }

    /// Removes the method with the given name from the configured http methods.
    ///
    /// Returns `true` if the method was found and removed, `false` otherwise.
    ///
    /// Be aware that a subscription consist of two methods, `subscribe` and
    /// `unsubscribe` and it's the caller responsibility to remove both
    /// `subscribe` and `unsubscribe` methods for subscriptions.
    pub fn remove_http_method(&mut self, method_name: &'static str) -> bool {
        if let Some(http_module) = &mut self.http {
            http_module.remove_method(method_name).is_some()
        } else {
            false
        }
    }

    /// Removes the method with the given name from the configured ws methods.
    ///
    /// Returns `true` if the method was found and removed, `false` otherwise.
    ///
    /// Be aware that a subscription consist of two methods, `subscribe` and
    /// `unsubscribe` and it's the caller responsibility to remove both
    /// `subscribe` and `unsubscribe` methods for subscriptions.
    pub fn remove_ws_method(&mut self, method_name: &'static str) -> bool {
        if let Some(ws_module) = &mut self.ws {
            ws_module.remove_method(method_name).is_some()
        } else {
            false
        }
    }

    /// Removes the method with the given name from all configured transports.
    ///
    /// Returns `true` if the method was found and removed, `false` otherwise.
    pub fn remove_method_from_configured(
        &mut self, method_name: &'static str,
    ) -> bool {
        let http_removed = self.remove_http_method(method_name);
        let ws_removed = self.remove_ws_method(method_name);

        http_removed || ws_removed
    }
}

/// A handle to the spawned servers.
///
/// When this type is dropped or [`RpcServerHandle::stop`] has been called the
/// server will be stopped.
#[derive(Clone, Debug)]
#[must_use = "Server stops if dropped"]
pub struct RpcServerHandle {
    /// The address of the http/ws server
    http_local_addr: Option<SocketAddr>,
    ws_local_addr: Option<SocketAddr>,
    http: Option<ServerHandle>,
    ws: Option<ServerHandle>,
}

impl RpcServerHandle {
    /// Returns the [`SocketAddr`] of the http server if started.
    pub const fn http_local_addr(&self) -> Option<SocketAddr> {
        self.http_local_addr
    }

    /// Returns the [`SocketAddr`] of the ws server if started.
    pub const fn ws_local_addr(&self) -> Option<SocketAddr> {
        self.ws_local_addr
    }

    /// Tell the server to stop without waiting for the server to stop.
    pub fn stop(self) -> Result<(), AlreadyStoppedError> {
        if let Some(handle) = self.http {
            handle.stop()?
        }

        if let Some(handle) = self.ws {
            handle.stop()?
        }

        Ok(())
    }

    /// Returns the url to the http server
    pub fn http_url(&self) -> Option<String> {
        self.http_local_addr.map(|addr| format!("http://{addr}"))
    }

    /// Returns the url to the ws server
    pub fn ws_url(&self) -> Option<String> {
        self.ws_local_addr.map(|addr| format!("ws://{addr}"))
    }
}
