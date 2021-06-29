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
use cfxcore::{
    pow::PowComputer, ConsensusGraph, NodeType, SynchronizationService,
    TransactionPool,
};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use parking_lot::{Condvar, Mutex};
use runtime::Runtime;
use std::sync::Arc;

pub struct ArchiveClientExtraComponents {
    pub consensus: Arc<ConsensusGraph>,
    pub debug_rpc_http_server: Option<HttpServer>,
    pub rpc_http_server: Option<HttpServer>,
    pub debug_rpc_tpc_server: Option<TcpServer>,
    pub rpc_tcp_server: Option<TcpServer>,
    pub debug_rpc_ws_server: Option<WsServer>,
    pub rpc_ws_server: Option<WsServer>,
    pub runtime: Runtime,
    pub sync: Arc<SynchronizationService>,
    pub txpool: Arc<TransactionPool>,
    pub pow: Arc<PowComputer>,
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
            runtime,
        ) = initialize_not_light_node_modules(&conf, exit, NodeType::Archive)?;
        Ok(Box::new(ClientComponents {
            data_manager_weak_ptr: Arc::downgrade(&data_man),
            blockgen: Some(blockgen),
            other_components: ArchiveClientExtraComponents {
                consensus,
                debug_rpc_http_server,
                rpc_http_server,
                debug_rpc_tpc_server,
                rpc_tcp_server,
                debug_rpc_ws_server,
                rpc_ws_server,
                runtime,
                sync,
                txpool,
                pow,
            },
        }))
    }

    fn process_config(conf: &mut Configuration) {
        if conf.raw_conf.max_outgoing_peers_archive.is_none() {
            conf.raw_conf.max_outgoing_peers_archive = Some(8);
        }
    }
}
