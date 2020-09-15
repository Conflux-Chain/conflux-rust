// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::sync::Arc;

use parking_lot::{Condvar, Mutex};
use secret_store::SecretStore;

use jsonrpc_http_server::Server as HttpServer;
use jsonrpc_tcp_server::Server as TcpServer;
use jsonrpc_ws_server::Server as WsServer;

use crate::{
    common::{initialize_common_modules, ClientComponents},
    configuration::Configuration,
    rpc::{
        extractor::RpcExtractor, impls::light::RpcImpl,
        setup_debug_rpc_apis_light, setup_public_rpc_apis_light,
    },
};
use blockgen::BlockGenerator;
use cfxcore::{
    pow::PowComputer, ConsensusGraph, LightQueryService, NodeType,
    TransactionPool,
};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use runtime::Runtime;

pub struct LightClientExtraComponents {
    pub consensus: Arc<ConsensusGraph>,
    pub debug_rpc_http_server: Option<HttpServer>,
    pub light: Arc<LightQueryService>,
    pub rpc_http_server: Option<HttpServer>,
    pub rpc_tcp_server: Option<TcpServer>,
    pub rpc_ws_server: Option<WsServer>,
    pub runtime: Runtime,
    pub secret_store: Arc<SecretStore>,
    pub txpool: Arc<TransactionPool>,
    pub pow: Arc<PowComputer>,
}

impl MallocSizeOf for LightClientExtraComponents {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { unimplemented!() }
}

pub struct LightClient {}

impl LightClient {
    // Start all key components of Conflux and pass out their handles
    pub fn start(
        conf: Configuration, exit: Arc<(Mutex<bool>, Condvar)>,
    ) -> Result<
        Box<ClientComponents<BlockGenerator, LightClientExtraComponents>>,
        String,
    > {
        let (
            _machine,
            secret_store,
            _genesis_accounts,
            data_man,
            pow,
            txpool,
            consensus,
            sync_graph,
            network,
            common_impl,
            accounts,
            notifications,
            pubsub,
            runtime,
        ) = initialize_common_modules(&conf, exit.clone(), NodeType::Light)?;

        let light = Arc::new(LightQueryService::new(
            consensus.clone(),
            sync_graph,
            network.clone(),
            conf.raw_conf.throttling_conf.clone(),
            notifications,
        ));
        light.register().unwrap();

        let rpc_impl = Arc::new(RpcImpl::new(
            conf.rpc_impl_config(),
            light.clone(),
            accounts,
        ));
        let debug_rpc_http_server = super::rpc::start_http(
            conf.local_http_config(),
            setup_debug_rpc_apis_light(
                common_impl.clone(),
                rpc_impl.clone(),
                None,
            ),
        )?;

        let rpc_tcp_server = super::rpc::start_tcp(
            conf.tcp_config(),
            if conf.is_test_mode() {
                setup_debug_rpc_apis_light(
                    common_impl.clone(),
                    rpc_impl.clone(),
                    Some(pubsub.clone()),
                )
            } else {
                setup_public_rpc_apis_light(
                    common_impl.clone(),
                    rpc_impl.clone(),
                    Some(pubsub.clone()),
                    &conf,
                )
            },
            RpcExtractor,
        )?;

        let rpc_ws_server = super::rpc::start_ws(
            conf.ws_config(),
            if conf.is_test_mode() {
                setup_debug_rpc_apis_light(
                    common_impl.clone(),
                    rpc_impl.clone(),
                    Some(pubsub),
                )
            } else {
                setup_public_rpc_apis_light(
                    common_impl.clone(),
                    rpc_impl.clone(),
                    Some(pubsub),
                    &conf,
                )
            },
            RpcExtractor,
        )?;

        let rpc_http_server = super::rpc::start_http(
            conf.http_config(),
            if conf.is_test_mode() {
                setup_debug_rpc_apis_light(common_impl, rpc_impl, None)
            } else {
                setup_public_rpc_apis_light(common_impl, rpc_impl, None, &conf)
            },
        )?;

        Ok(Box::new(ClientComponents {
            data_manager_weak_ptr: Arc::downgrade(&data_man),
            blockgen: None,
            other_components: LightClientExtraComponents {
                consensus,
                debug_rpc_http_server,
                light,
                rpc_http_server,
                rpc_tcp_server,
                rpc_ws_server,
                runtime,
                secret_store,
                txpool,
                pow,
            },
        }))
    }
}
