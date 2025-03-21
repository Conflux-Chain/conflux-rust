// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use jsonrpc_http_server::Server as HttpServer;
use jsonrpc_tcp_server::Server as TcpServer;
use jsonrpc_ws_server::Server as WsServer;

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
    pub debug_rpc_http_server: Option<HttpServer>,
    pub rpc_http_server: Option<HttpServer>,
    pub debug_rpc_tpc_server: Option<TcpServer>,
    pub rpc_tcp_server: Option<TcpServer>,
    pub debug_rpc_ws_server: Option<WsServer>,
    pub rpc_ws_server: Option<WsServer>,
    pub sync: Arc<SynchronizationService>,
    pub txpool: Arc<TransactionPool>,
    pub pow: Arc<PowComputer>,
    pub eth_rpc_http_server: Option<HttpServer>,
    pub eth_rpc_ws_server: Option<WsServer>,
    /// Handle to the started ETH RPC server. This is version 2 of the ETH RPC.
    /// Which use Rust async I/O
    pub eth_rpc_server_handle: Option<RpcServerHandle>,
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
            debug_rpc_http_server,
            rpc_http_server,
            debug_rpc_tpc_server,
            rpc_tcp_server,
            debug_rpc_ws_server,
            rpc_ws_server,
            pos_handler,
            eth_rpc_http_server,
            eth_rpc_ws_server,
            tokio_runtime,
            eth_rpc_server_handle,
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
                debug_rpc_http_server,
                rpc_http_server,
                debug_rpc_tpc_server,
                rpc_tcp_server,
                debug_rpc_ws_server,
                rpc_ws_server,
                sync,
                txpool,
                pow,
                eth_rpc_http_server,
                eth_rpc_ws_server,
                eth_rpc_server_handle,
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
