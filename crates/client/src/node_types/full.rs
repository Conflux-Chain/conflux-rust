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

pub struct FullClientExtraComponents {
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
    pub tokio_runtime: Arc<TokioRuntime>,
    pub task_manager: TaskManager,
}

impl MallocSizeOf for FullClientExtraComponents {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { unimplemented!() }
}

pub struct FullClient {}

impl FullClient {
    // Start all key components of Conflux and pass out their handles
    pub fn start(
        mut conf: Configuration, exit: Arc<(Mutex<bool>, Condvar)>,
    ) -> Result<
        Box<ClientComponents<BlockGenerator, FullClientExtraComponents>>,
        String,
    > {
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
            task_manager,
        ) = initialize_not_light_node_modules(&mut conf, exit, NodeType::Full)?;
        Ok(Box::new(ClientComponents {
            data_manager_weak_ptr: Arc::downgrade(&data_man),
            blockgen: Some(blockgen),
            pos_handler: Some(pos_handler),
            other_components: FullClientExtraComponents {
                consensus,
                sync,
                txpool,
                pow,
                eth_rpc_server_handle,
                cfx_rpc_server_handle,
                tokio_runtime,
                task_manager,
            },
        }))
    }
}
