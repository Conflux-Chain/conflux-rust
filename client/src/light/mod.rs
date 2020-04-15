// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{sync::Arc, thread, time::Duration};

use cfx_types::{Address, U256};
use network::NetworkService;
use parking_lot::{Condvar, Mutex};
use runtime::Runtime;
use secret_store::SecretStore;
use threadpool::ThreadPool;

use crate::{
    configuration::Configuration,
    rpc::{
        extractor::RpcExtractor,
        impls::{
            common::RpcImpl as CommonImpl, light::RpcImpl, pubsub::PubSubClient,
        },
        setup_debug_rpc_apis_light, setup_public_rpc_apis_light,
    },
};
use cfxcore::{
    block_data_manager::BlockDataManager, genesis, statistics::Statistics,
    storage::StorageManager, vm_factory::VmFactory, ConsensusGraph,
    LightQueryService, Notifications, SynchronizationGraph, TransactionPool,
    WORKER_COMPUTATION_PARALLELISM,
};
use std::str::FromStr;

use super::{
    http::Server as HttpServer, tcp::Server as TcpServer, TESTNET_VERSION,
};
use crate::common::ClientComponents;
use blockgen::BlockGenerator;
use cfxcore::genesis::genesis_block;

pub struct LightClientExtraComponents {
    pub consensus: Arc<ConsensusGraph>,
    pub debug_rpc_http_server: Option<HttpServer>,
    pub light: Arc<LightQueryService>,
    pub rpc_http_server: Option<HttpServer>,
    pub rpc_tcp_server: Option<TcpServer>,
    pub secret_store: Arc<SecretStore>,
    pub txpool: Arc<TransactionPool>,
    pub runtime: Runtime,
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
        info!("Working directory: {:?}", std::env::current_dir());

        metrics::initialize(conf.metrics_config());

        let worker_thread_pool = Arc::new(Mutex::new(ThreadPool::with_name(
            "Tx Recover".into(),
            WORKER_COMPUTATION_PARALLELISM,
        )));

        let network_config = conf.net_config()?;
        let cache_config = conf.cache_config();

        let db_config = conf.db_config();
        let ledger_db =
            db::open_database(conf.raw_conf.block_db_dir.as_str(), &db_config)
                .map_err(|e| format!("Failed to open database {:?}", e))?;

        let secret_store = Arc::new(SecretStore::new());
        let storage_manager = Arc::new(
            StorageManager::new(conf.storage_config())
                .expect("Failed to initialize storage."),
        );
        {
            let storage_manager_log_weak_ptr = Arc::downgrade(&storage_manager);
            let exit_clone = exit.clone();
            thread::spawn(move || loop {
                let mut exit_lock = exit_clone.0.lock();
                if exit_clone
                    .1
                    .wait_for(&mut exit_lock, Duration::from_millis(5000))
                    .timed_out()
                {
                    let manager = storage_manager_log_weak_ptr.upgrade();
                    match manager {
                        None => return,
                        Some(manager) => manager.log_usage(),
                    };
                } else {
                    return;
                }
            });
        }

        let genesis_accounts = if conf.is_test_mode() {
            match conf.raw_conf.genesis_secrets {
                Some(ref file) => {
                    genesis::load_secrets_file(file, secret_store.as_ref())?
                }
                None => genesis::default(conf.is_test_or_dev_mode()),
            }
        } else {
            match conf.raw_conf.genesis_accounts {
                Some(ref file) => genesis::load_file(file)?,
                None => genesis::default(conf.is_test_or_dev_mode()),
            }
        };

        let genesis_block = genesis_block(
            &storage_manager,
            genesis_accounts,
            Address::from_str(TESTNET_VERSION).unwrap(),
            U256::zero(),
        );
        debug!("Initialize genesis_block={:?}", genesis_block);

        let data_man = Arc::new(BlockDataManager::new(
            cache_config,
            Arc::new(genesis_block),
            ledger_db.clone(),
            storage_manager,
            worker_thread_pool,
            conf.data_mananger_config(),
        ));

        let txpool = Arc::new(TransactionPool::new(
            conf.txpool_config(),
            conf.verification_config(),
            data_man.clone(),
        ));

        let statistics = Arc::new(Statistics::new());

        let vm = VmFactory::new(1024 * 32);
        let pow_config = conf.pow_config();
        let notifications = Notifications::init();

        let consensus = Arc::new(ConsensusGraph::new(
            conf.consensus_config(),
            vm,
            txpool.clone(),
            statistics,
            data_man.clone(),
            pow_config.clone(),
            notifications.clone(),
            conf.execution_config(),
            conf.verification_config(),
        ));

        let _protocol_config = conf.protocol_config();
        let verification_config = conf.verification_config();
        let sync_config = conf.sync_graph_config();

        let sync_graph = Arc::new(SynchronizationGraph::new(
            consensus.clone(),
            verification_config,
            pow_config,
            sync_config,
            notifications.clone(),
            false,
        ));

        let network = {
            let mut network = NetworkService::new(network_config);
            network.start().unwrap();
            Arc::new(network)
        };

        let light = Arc::new(LightQueryService::new(
            consensus.clone(),
            sync_graph,
            network.clone(),
            conf.raw_conf.throttling_conf.clone(),
        ));
        light.register().unwrap();

        let rpc_impl = Arc::new(RpcImpl::new(light.clone()));

        let common_impl = Arc::new(CommonImpl::new(
            exit,
            consensus.clone(),
            network,
            txpool.clone(),
        ));

        let runtime = Runtime::with_default_thread_count();
        let pubsub = PubSubClient::new(
            runtime.executor(),
            consensus.clone(),
            notifications,
        );

        let debug_rpc_http_server = super::rpc::start_http(
            super::rpc::HttpConfiguration::new(
                Some((127, 0, 0, 1)),
                conf.raw_conf.jsonrpc_local_http_port,
                conf.raw_conf.jsonrpc_cors.clone(),
                conf.raw_conf.jsonrpc_http_keep_alive,
            ),
            setup_debug_rpc_apis_light(
                common_impl.clone(),
                rpc_impl.clone(),
                None,
            ),
        )?;

        let rpc_tcp_server = super::rpc::start_tcp(
            super::rpc::TcpConfiguration::new(
                None,
                conf.raw_conf.jsonrpc_tcp_port,
            ),
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
            super::rpc::HttpConfiguration::new(
                None,
                conf.raw_conf.jsonrpc_http_port,
                conf.raw_conf.jsonrpc_cors.clone(),
                conf.raw_conf.jsonrpc_http_keep_alive,
            ),
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
                secret_store,
                txpool,
                runtime,
            },
        }))
    }
}
