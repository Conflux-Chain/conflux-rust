// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    common::{initialize_not_light_node_modules, ClientComponents},
    configuration::Configuration,
};
use blockgen::BlockGenerator;
use cfx_rpc_builder::RpcServerHandle;
use cfx_tasks::TaskManager;
use cfxcore::{
    pow::PowComputer, ConsensusGraph, NodeType, SynchronizationService,
    TransactionPool,
};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use parking_lot::{Condvar, Mutex};
use std::sync::Arc;
use tokio::runtime::Runtime as TokioRuntime;

pub struct ArchiveClientExtraComponents {
    pub consensus: Arc<ConsensusGraph>,
    pub sync: Arc<SynchronizationService>,
    pub txpool: Arc<TransactionPool>,
    pub pow: Arc<PowComputer>,
    /// Handle to the started ETH RPC server. This is version 2 of the ETH RPC.
    /// Which use Rust async I/O
    pub eth_rpc_server_handle: Option<RpcServerHandle>,
    /// Handle to the started CFX RPC server. This is version 2 of the core
    /// space RPC. Which use Rust async I/O. Only active when
    /// `core_space_rpc_use_old_impl` is false.
    pub cfx_rpc_server_handle: Option<RpcServerHandle>,
    /// Debug handle for CFX RPC server with all APIs enabled when using the
    /// new core space RPC implementation.
    pub debug_cfx_rpc_server_handle: Option<RpcServerHandle>,
    pub tokio_runtime: Arc<TokioRuntime>,
    pub task_manager: TaskManager,
}

impl MallocSizeOf for ArchiveClientExtraComponents {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let tx_pool_size = self.txpool.size_of(ops);
        let consensus_graph_size = self.consensus.size_of(ops);
        let sync_graph_size =
            self.sync.get_synchronization_graph().size_of(ops);
        tx_pool_size + consensus_graph_size + sync_graph_size
    }
}

pub struct ArchiveClient {}

impl ArchiveClient {
    // Start all key components of Conflux and pass out their handles
    pub fn start(
        mut conf: Configuration, exit: Arc<(Mutex<bool>, Condvar)>,
    ) -> Result<
        Box<ClientComponents<BlockGenerator, ArchiveClientExtraComponents>>,
        String,
    > {
        Self::process_config(&mut conf);
        let (
            data_man,
            pow,
            txpool,
            consensus,
            sync,
            blockgen,
            pos_handler,
            tokio_runtime,
            eth_rpc_server_handle,
            cfx_rpc_server_handle,
            debug_cfx_rpc_server_handle,
            task_manager,
        ) = initialize_not_light_node_modules(
            &mut conf,
            exit,
            NodeType::Archive,
        )?;
        Ok(Box::new(ClientComponents {
            data_manager_weak_ptr: Arc::downgrade(&data_man),
            blockgen: Some(blockgen),
            pos_handler: Some(pos_handler),
            other_components: ArchiveClientExtraComponents {
                consensus,
                sync,
                txpool,
                pow,
                eth_rpc_server_handle,
                cfx_rpc_server_handle,
                debug_cfx_rpc_server_handle,
                tokio_runtime,
                task_manager,
            },
        }))
    }

    fn process_config(conf: &mut Configuration) {
        if conf.raw_conf.max_outgoing_peers_archive.is_none() {
            conf.raw_conf.max_outgoing_peers_archive = Some(8);
        }
    }
}
