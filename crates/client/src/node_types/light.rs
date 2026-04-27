// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::sync::Arc;

use cfx_rpc_cfx_types::apis::ApiSet;
use parking_lot::{Condvar, Mutex};
use secret_store::SecretStore;

use cfx_rpc_builder::RpcServerHandle;

use crate::{
    common::{initialize_common_modules, ClientComponents},
    configuration::Configuration,
    rpc_starter::launch_cfx_light_async_rpc_servers,
};
use blockgen::BlockGenerator;
use cfxcore::{
    pow::PowComputer, ConsensusGraph, LightQueryService, NodeType,
    TransactionPool,
};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};

pub struct LightClientExtraComponents {
    pub consensus: Arc<ConsensusGraph>,
    pub cfx_rpc_server_handle: Option<RpcServerHandle>,
    pub debug_cfx_rpc_server_handle: Option<RpcServerHandle>,
    pub light: Arc<LightQueryService>,
    pub secret_store: Arc<SecretStore>,
    pub txpool: Arc<TransactionPool>,
    pub pow: Arc<PowComputer>,
}

impl MallocSizeOf for LightClientExtraComponents {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { unimplemented!() }
}

pub struct LightClient {}

impl LightClient {
    // Start all key components of Conflux and pass out
    // their handles
    pub fn start(
        mut conf: Configuration, exit: Arc<(Mutex<bool>, Condvar)>,
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
            pos_verifier,
            txpool,
            consensus,
            sync_graph,
            network,
            accounts,
            notifications,
            tokio_runtime,
        ) = initialize_common_modules(
            &mut conf,
            exit.clone(),
            NodeType::Light,
        )?;

        let light = Arc::new(LightQueryService::new(
            consensus.clone(),
            sync_graph.clone(),
            network.clone(),
            conf.raw_conf.throttling_conf.clone(),
            notifications,
            conf.light_node_config(),
        ));
        light.register().unwrap();

        sync_graph.recover_graph_from_db();

        // Start the new jsonrpsee-based core space RPC
        // servers for the light node.
        let cfx_rpc_server_handle =
            tokio_runtime.block_on(launch_cfx_light_async_rpc_servers(
                consensus.clone(),
                txpool.clone(),
                data_man.clone(),
                network.clone(),
                pos_verifier.clone(),
                accounts.clone(),
                light.clone(),
                exit.clone(),
                &conf,
                conf.raw_conf.public_rpc_apis.clone(),
                false,
            ))?;

        let debug_cfx_rpc_server_handle =
            tokio_runtime.block_on(launch_cfx_light_async_rpc_servers(
                consensus.clone(),
                txpool.clone(),
                data_man.clone(),
                network.clone(),
                pos_verifier.clone(),
                accounts,
                light.clone(),
                exit,
                &conf,
                ApiSet::All,
                true,
            ))?;

        network.start();

        Ok(Box::new(ClientComponents {
            data_manager_weak_ptr: Arc::downgrade(&data_man),
            blockgen: None,
            pos_handler: Some(pos_verifier),
            other_components: LightClientExtraComponents {
                consensus,
                cfx_rpc_server_handle,
                debug_cfx_rpc_server_handle,
                light,
                secret_store,
                txpool,
                pow,
            },
        }))
    }
}
