// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use jsonrpc_http_server::Server as HttpServer;
use jsonrpc_tcp_server::Server as TcpServer;
use jsonrpc_ws_server::Server as WsServer;

use super::TESTNET_VERSION;
use crate::{
    common::{initialize_txgens, ClientComponents},
    configuration::Configuration,
    rpc::{
        extractor::RpcExtractor,
        impls::{
            cfx::RpcImpl, common::RpcImpl as CommonImpl, pubsub::PubSubClient,
        },
        setup_debug_rpc_apis, setup_public_rpc_apis,
    },
};
use blockgen::BlockGenerator;
use cfx_types::{Address, U256};
use cfxcore::{
    block_data_manager::BlockDataManager,
    genesis::{self, genesis_block},
    machine::new_machine_with_builtin,
    statistics::Statistics,
    storage::StorageManager,
    sync::SyncPhaseType,
    vm_factory::VmFactory,
    ConsensusGraph, LightProvider, Notifications, SynchronizationGraph,
    SynchronizationService, TransactionPool, WORKER_COMPUTATION_PARALLELISM,
};
use network::NetworkService;
use parking_lot::{Condvar, Mutex};
use runtime::Runtime;
use secret_store::SecretStore;
use std::{str::FromStr, sync::Arc, thread, time::Duration};
use threadpool::ThreadPool;

pub struct ArchiveClientExtraComponents {
    pub consensus: Arc<ConsensusGraph>,
    pub debug_rpc_http_server: Option<HttpServer>,
    pub rpc_http_server: Option<HttpServer>,
    pub rpc_tcp_server: Option<TcpServer>,
    pub rpc_ws_server: Option<WsServer>,
    pub runtime: Runtime,
    pub secret_store: Arc<SecretStore>,
    pub sync: Arc<SynchronizationService>,
    pub txpool: Arc<TransactionPool>,
}

pub struct ArchiveClient {}

impl ArchiveClient {
    // Start all key components of Conflux and pass out their handles
    pub fn start(
        conf: Configuration, exit: Arc<(Mutex<bool>, Condvar)>,
    ) -> Result<
        Box<ClientComponents<BlockGenerator, ArchiveClientExtraComponents>>,
        String,
    > {
        info!("Working directory: {:?}", std::env::current_dir());

        metrics::initialize(conf.metrics_config());

        let worker_thread_pool = Arc::new(Mutex::new(ThreadPool::with_name(
            "Tx Recover".into(),
            WORKER_COMPUTATION_PARALLELISM,
        )));

        let mut network_config = conf.net_config()?;
        network_config.max_outgoing_peers_archive = 8;
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

        let genesis_accounts = if conf.is_test_or_dev_mode() {
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

        let machine = Arc::new(new_machine_with_builtin());

        let txpool = Arc::new(TransactionPool::new(
            conf.txpool_config(),
            conf.verification_config(),
            data_man.clone(),
            machine.clone(),
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

        let protocol_config = conf.protocol_config();
        let verification_config = conf.verification_config();
        let sync_config = conf.sync_graph_config();

        let sync_graph = Arc::new(SynchronizationGraph::new(
            consensus.clone(),
            verification_config,
            pow_config.clone(),
            sync_config,
            notifications.clone(),
            false,
            machine.clone(),
        ));

        let network = {
            let mut network = NetworkService::new(network_config);
            network.start().unwrap();
            Arc::new(network)
        };

        let light_provider = Arc::new(LightProvider::new(
            consensus.clone(),
            sync_graph.clone(),
            Arc::downgrade(&network),
            txpool.clone(),
            conf.raw_conf.throttling_conf.clone(),
        ));
        light_provider.register(network.clone()).unwrap();

        let initial_sync_phase = SyncPhaseType::CatchUpRecoverBlockFromDB;
        let sync = Arc::new(SynchronizationService::new(
            false,
            network.clone(),
            sync_graph.clone(),
            protocol_config,
            conf.state_sync_config(),
            initial_sync_phase,
            light_provider,
        ));
        sync.register().unwrap();

        let (maybe_txgen, maybe_direct_txgen) = initialize_txgens(
            consensus.clone(),
            txpool.clone(),
            sync.clone(),
            secret_store.clone(),
            &conf,
            network.net_key_pair().unwrap(),
        );

        let maybe_author: Option<Address> = conf.raw_conf.mining_author.clone().map(|hex_str| Address::from_str(hex_str.as_str()).expect("mining-author should be 40-digit hex string without 0x prefix"));
        let blockgen = Arc::new(BlockGenerator::new(
            sync_graph,
            txpool.clone(),
            sync.clone(),
            maybe_txgen.clone(),
            pow_config.clone(),
            maybe_author.clone().unwrap_or_default(),
        ));
        if conf.raw_conf.start_mining {
            if maybe_author.is_none() {
                panic!("mining-author is not set correctly, so you'll not get mining rewards!!!");
            }
            let bg = blockgen.clone();
            info!("Start mining with pow config: {:?}", pow_config);
            thread::Builder::new()
                .name("mining".into())
                .spawn(move || {
                    BlockGenerator::start_mining(bg, 0);
                })
                .expect("Mining thread spawn error");
        } else {
            if conf.is_dev_mode() {
                let bg = blockgen.clone();
                let interval_ms = conf.raw_conf.dev_block_interval_ms;
                info!("Start auto block generation");
                thread::Builder::new()
                    .name("auto_mining".into())
                    .spawn(move || {
                        bg.auto_block_generation(interval_ms);
                    })
                    .expect("Mining thread spawn error");
            }
        }

        let rpc_impl = Arc::new(RpcImpl::new(
            consensus.clone(),
            sync.clone(),
            blockgen.clone(),
            txpool.clone(),
            maybe_txgen.clone(),
            maybe_direct_txgen,
            conf.rpc_impl_config(),
            machine.clone(),
        ));

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
            conf.local_http_config(),
            setup_debug_rpc_apis(
                common_impl.clone(),
                rpc_impl.clone(),
                None,
                &conf,
            ),
        )?;

        let rpc_tcp_server = super::rpc::start_tcp(
            conf.tcp_config(),
            if conf.is_test_or_dev_mode() {
                setup_debug_rpc_apis(
                    common_impl.clone(),
                    rpc_impl.clone(),
                    Some(pubsub.clone()),
                    &conf,
                )
            } else {
                setup_public_rpc_apis(
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
            if conf.is_test_or_dev_mode() {
                setup_debug_rpc_apis(
                    common_impl.clone(),
                    rpc_impl.clone(),
                    Some(pubsub.clone()),
                    &conf,
                )
            } else {
                setup_public_rpc_apis(
                    common_impl.clone(),
                    rpc_impl.clone(),
                    Some(pubsub.clone()),
                    &conf,
                )
            },
            RpcExtractor,
        )?;

        let rpc_http_server = super::rpc::start_http(
            conf.http_config(),
            if conf.is_test_or_dev_mode() {
                setup_debug_rpc_apis(common_impl, rpc_impl, None, &conf)
            } else {
                setup_public_rpc_apis(common_impl, rpc_impl, None, &conf)
            },
        )?;

        Ok(Box::new(ClientComponents {
            data_manager_weak_ptr: Arc::downgrade(&data_man),
            blockgen: Some(blockgen),
            other_components: ArchiveClientExtraComponents {
                consensus,
                debug_rpc_http_server,
                rpc_http_server,
                rpc_tcp_server,
                rpc_ws_server,
                runtime,
                secret_store,
                sync,
                txpool,
            },
        }))
    }
}
