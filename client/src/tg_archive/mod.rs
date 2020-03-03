// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    http::Server as HttpServer, tcp::Server as TcpServer, TESTNET_VERSION,
};
pub use crate::configuration::Configuration;
use executable_helpers::helpers::setup_executable;
use libra_config::config::{ConsensusKeyPair, NodeConfig};
use libra_crypto::secp256k1::Secp256k1PrivateKey;
use libra_metrics::metric_server;
use libradb::LibraDB;

use crate::rpc::{
    extractor::RpcExtractor,
    impls::{
        alliance::RpcImpl, common::RpcImpl as CommonImpl, pubsub::PubSubClient,
    },
    setup_debug_rpc_apis_alliance, setup_public_rpc_apis_alliance,
};
use cfx_types::{Address, H256, U256};
use cfxcore::{
    alliance_tree_graph::{
        bft::{
            consensus::consensus_provider::{
                make_consensus_provider, ConsensusProvider,
            },
            executor::Executor,
        },
        blockgen::TGBlockGenerator,
        consensus::TreeGraphConsensus,
    },
    block_data_manager::BlockDataManager,
    genesis,
    statistics::Statistics,
    storage::StorageManager,
    sync::{ProtocolConfiguration, SyncPhaseType},
    transaction_pool::DEFAULT_MAX_BLOCK_GAS_LIMIT,
    vm_factory::VmFactory,
    LightProvider, Notifications, SharedSynchronizationService,
    SynchronizationGraph, SynchronizationService, TransactionPool,
    WORKER_COMPUTATION_PARALLELISM,
};
use ctrlc::CtrlC;
use keccak_hash::keccak;
use keylib::public_to_address;
use network::NetworkService;
use parking_lot::{Condvar, Mutex};
use runtime::Runtime;
use secret_store::SecretStore;
use std::{
    any::Any,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Weak},
    thread,
    time::{Duration, Instant},
};
use threadpool::ThreadPool;
use txgen::{
    propagate::DataPropagation, SpecialTransactionGenerator,
    TransactionGenerator,
};

pub struct TgArchiveClientHandle {
    pub debug_rpc_http_server: Option<HttpServer>,
    pub rpc_tcp_server: Option<TcpServer>,
    pub rpc_http_server: Option<HttpServer>,
    pub tg_consensus_provider: Option<Box<dyn ConsensusProvider>>,
    pub txpool: Arc<TransactionPool>,
    pub sync: SharedSynchronizationService,
    pub txgen: Arc<TransactionGenerator>,
    pub txgen_join_handle: Option<thread::JoinHandle<()>>,
    pub blockgen: Arc<TGBlockGenerator>,
    pub secret_store: Arc<SecretStore>,
    pub block_data_manager: Weak<BlockDataManager>,
    pub runtime: Runtime,
}

impl TgArchiveClientHandle {
    pub fn into_be_dropped(
        self,
    ) -> (Weak<BlockDataManager>, Arc<TGBlockGenerator>, Box<dyn Any>) {
        (
            self.block_data_manager,
            self.blockgen,
            Box::new((
                self.tg_consensus_provider,
                self.debug_rpc_http_server,
                self.rpc_tcp_server,
                self.rpc_http_server,
                self.txpool,
                self.sync,
                self.txgen,
                self.secret_store,
                self.txgen_join_handle,
            )),
        )
    }
}

pub struct TgArchiveClient {}

impl TgArchiveClient {
    // Start all key components of Conflux and pass out their handles
    pub fn start(
        mut conf: Configuration, exit: Arc<(Mutex<bool>, Condvar)>,
    ) -> Result<TgArchiveClientHandle, String> {
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
                    genesis::default(secret_store.as_ref());
                    genesis::load_secrets_file(file, secret_store.as_ref())?
                }
                None => genesis::default(secret_store.as_ref()),
            }
        } else {
            match conf.raw_conf.genesis_accounts {
                Some(ref file) => genesis::load_file(file)?,
                None => genesis::default(secret_store.as_ref()),
            }
        };

        // FIXME: move genesis block to a dedicated directory near all conflux
        // FIXME: parameters.
        let genesis_block = storage_manager.initialize(
            genesis_accounts,
            DEFAULT_MAX_BLOCK_GAS_LIMIT.into(),
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
            data_man.clone(),
        ));

        let statistics = Arc::new(Statistics::new());

        let pow_config = conf.pow_config();
        let notifications = Notifications::init();
        let vm = VmFactory::new(1024 * 32);
        let tg_consensus = Arc::new(TreeGraphConsensus::new(
            conf.tg_consensus_config(),
            vm,
            txpool.clone(),
            statistics,
            data_man.clone(),
            pow_config.clone(),
        ));

        let protocol_config = conf.protocol_config();
        let verification_config = conf.verification_config();
        let sync_config = conf.sync_graph_config();

        let sync_graph = Arc::new(SynchronizationGraph::new(
            tg_consensus.clone(),
            verification_config,
            pow_config.clone(),
            sync_config,
            notifications.clone(),
            false,
        ));

        let network = {
            let mut network = NetworkService::new(network_config);
            network.start_io_service().unwrap();
            Arc::new(network)
        };

        let light_provider = Arc::new(LightProvider::new(
            tg_consensus.clone(),
            sync_graph.clone(),
            Arc::downgrade(&network),
            txpool.clone(),
            conf.raw_conf.throttling_conf.clone(),
        ));
        light_provider.clone().register(network.clone()).unwrap();

        let initial_sync_phase = SyncPhaseType::CatchUpSyncBlock;
        let sync =
            SharedSynchronizationService::new(SynchronizationService::new(
                false,
                network.clone(),
                sync_graph.clone(),
                protocol_config.clone(),
                conf.state_sync_config(),
                initial_sync_phase,
                light_provider,
            ));
        sync.register().unwrap();

        let tg_config_path = match conf.raw_conf.tg_config_path.as_ref() {
            Some(path) => Some(PathBuf::from(path)),
            None => None,
        };

        let secret = Secp256k1PrivateKey::from_secret(
            network
                .net_key_pair()
                .expect("Error node key")
                .secret()
                .clone(),
        );
        let keypair = ConsensusKeyPair::load(secret);
        let mut config = setup_executable(
            tg_config_path.as_ref().map(PathBuf::as_path),
            true, /* no_logging */
            Some(keypair),
        );

        let own_node_hash =
            keccak(network.net_key_pair().expect("Error node key").public());
        let consensus_provider = Self::setup_tg_environment(
            &mut config,
            sync.clone(),
            network.clone(),
            own_node_hash,
            protocol_config.clone(),
        );

        if conf.is_test_mode() && conf.raw_conf.data_propagate_enabled {
            let dp = Arc::new(DataPropagation::new(
                conf.raw_conf.data_propagate_interval_ms,
                conf.raw_conf.data_propagate_size,
            ));
            DataPropagation::register(dp, network.clone())?;
        }

        let txgen = Arc::new(TransactionGenerator::new(
            tg_consensus.clone(),
            txpool.clone(),
            sync.clone(),
            secret_store.clone(),
            network.net_key_pair().ok(),
        ));

        let _special_txgen =
            Arc::new(Mutex::new(SpecialTransactionGenerator::new(
                network.net_key_pair().unwrap(),
                &public_to_address(secret_store.get_keypair(0).public()),
                U256::from_dec_str("10000000000000000").unwrap(),
                U256::from_dec_str("10000000000000000").unwrap(),
            )));

        let maybe_author: Option<Address> = conf.raw_conf.mining_author.clone().map(|hex_str| Address::from_str(hex_str.as_str()).expect("mining-author should be 40-digit hex string without 0x prefix"));
        let blockgen = Arc::new(TGBlockGenerator::new(
            data_man.clone(),
            txpool.clone(),
            sync.clone(),
            //txgen.clone(),
            //special_txgen,
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
                    bg.start();
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

        let tx_conf = conf.tx_gen_config();
        let txgen_handle = if tx_conf.generate_tx {
            let txgen_clone = txgen.clone();
            let t = if conf.is_test_mode() {
                match conf.raw_conf.genesis_secrets {
                    Some(ref _file) => {
                        thread::Builder::new()
                            .name("txgen".into())
                            .spawn(move || {
                                TransactionGenerator::generate_transactions_with_multiple_genesis_accounts(
                                    txgen_clone,
                                    tx_conf,
                                );
                            })
                            .expect("should succeed")
                    }
                    None =>{
                        thread::Builder::new()
                            .name("txgen".into())
                            .spawn(move || {
                                TransactionGenerator::generate_transactions(
                                    txgen_clone,
                                    tx_conf,
                                )
                                    .unwrap();
                            })
                            .expect("should succeed")
                    }
                }
            } else {
                thread::Builder::new()
                    .name("txgen".into())
                    .spawn(move || {
                        TransactionGenerator::generate_transactions(
                            txgen_clone,
                            tx_conf,
                        )
                        .unwrap();
                    })
                    .expect("should succeed")
            };
            Some(t)
        } else {
            None
        };

        let rpc_impl = Arc::new(RpcImpl::new(
            tg_consensus.clone(),
            sync.clone(),
            blockgen.clone(),
            txpool.clone(),
            txgen.clone(),
            conf.rpc_impl_config(),
        ));

        let common_impl = Arc::new(CommonImpl::new(
            exit,
            tg_consensus.clone(),
            network,
            txpool.clone(),
        ));

        let runtime = Runtime::with_default_thread_count();
        let pubsub = PubSubClient::new(
            runtime.executor(),
            tg_consensus.clone(),
            notifications,
        );

        let debug_rpc_http_server = super::rpc::start_http(
            super::rpc::HttpConfiguration::new(
                Some((127, 0, 0, 1)),
                conf.raw_conf.jsonrpc_local_http_port,
                conf.raw_conf.jsonrpc_cors.clone(),
                conf.raw_conf.jsonrpc_http_keep_alive,
            ),
            setup_debug_rpc_apis_alliance(
                common_impl.clone(),
                rpc_impl.clone(),
                None, /* pubsub */
                &conf,
            ),
        )?;

        if conf.is_dev_mode() {
            if conf.raw_conf.jsonrpc_tcp_port.is_none() {
                conf.raw_conf.jsonrpc_tcp_port = Some(12536);
            }
            if conf.raw_conf.jsonrpc_http_port.is_none() {
                conf.raw_conf.jsonrpc_http_port = Some(12537);
            }
        };
        let rpc_tcp_server = super::rpc::start_tcp(
            super::rpc::TcpConfiguration::new(
                None,
                conf.raw_conf.jsonrpc_tcp_port,
            ),
            if conf.is_test_or_dev_mode() {
                setup_debug_rpc_apis_alliance(
                    common_impl.clone(),
                    rpc_impl.clone(),
                    Some(pubsub),
                    &conf,
                )
            } else {
                setup_public_rpc_apis_alliance(
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
            if conf.is_test_or_dev_mode() {
                setup_debug_rpc_apis_alliance(
                    common_impl,
                    rpc_impl,
                    None, /* pubsub */
                    &conf,
                )
            } else {
                setup_public_rpc_apis_alliance(
                    common_impl,
                    rpc_impl,
                    None, /* pubsub */
                    &conf,
                )
            },
        )?;

        Ok(TgArchiveClientHandle {
            block_data_manager: Arc::downgrade(&data_man),
            debug_rpc_http_server,
            rpc_http_server,
            rpc_tcp_server,
            txpool,
            txgen,
            txgen_join_handle: txgen_handle,
            blockgen,
            tg_consensus_provider: consensus_provider,
            secret_store,
            sync,
            runtime,
        })
    }

    fn setup_tg_environment(
        node_config: &mut NodeConfig, tg_sync: SharedSynchronizationService,
        network: Arc<NetworkService>, own_node_hash: H256,
        protocol_config: ProtocolConfiguration,
    ) -> Option<Box<dyn ConsensusProvider>>
    {
        // Some of our code uses the rayon global thread pool. Name the rayon
        // threads so it doesn't cause confusion, otherwise the threads
        // would have their parent's name.
        rayon::ThreadPoolBuilder::new()
            .thread_name(|index| format!("rayon-global-{}", index))
            .build_global()
            .expect("Building rayon global thread pool should work.");

        let mut instant = Instant::now();
        let libra_db = Arc::new(LibraDB::new("./bft_db"));
        debug!(
            "BFT database started in {} ms",
            instant.elapsed().as_millis()
        );

        instant = Instant::now();
        let executor = Arc::new(Executor::new(node_config, libra_db.clone()));
        debug!("Executor setup in {} ms", instant.elapsed().as_millis());

        let metrics_port = node_config.debug_interface.metrics_server_port;
        let metric_host = node_config.debug_interface.address.clone();
        thread::spawn(move || {
            metric_server::start_server(metric_host, metrics_port, false)
        });
        let public_metrics_port =
            node_config.debug_interface.public_metrics_server_port;
        let public_metric_host = node_config.debug_interface.address.clone();
        thread::spawn(move || {
            metric_server::start_server(
                public_metric_host,
                public_metrics_port,
                true,
            )
        });

        // Initialize and start consensus.
        instant = Instant::now();
        let mut consensus_provider =
            make_consensus_provider(node_config, executor, tg_sync);
        consensus_provider
            .start(network, own_node_hash, protocol_config)
            .expect("Failed to start consensus. Can't proceed.");
        debug!("Consensus started in {} ms", instant.elapsed().as_millis());

        Some(consensus_provider)
    }

    /// Use a Weak pointer to ensure that other Arc pointers are released
    fn wait_for_drop<T>(w: Weak<T>) {
        let sleep_duration = Duration::from_secs(1);
        let warn_timeout = Duration::from_secs(5);
        let max_timeout = Duration::from_secs(10);
        let instant = Instant::now();
        let mut warned = false;
        while instant.elapsed() < max_timeout {
            if w.upgrade().is_none() {
                return;
            }
            if !warned && instant.elapsed() > warn_timeout {
                warned = true;
                warn!("Shutdown is taking longer than expected.");
            }
            thread::sleep(sleep_duration);
        }
        eprintln!("Shutdown timeout reached, exiting uncleanly.");
    }

    pub fn close(handle: TgArchiveClientHandle) {
        let (ledger_db, blockgen, to_drop) = handle.into_be_dropped();
        blockgen.stop();
        drop(blockgen);
        drop(to_drop);

        // Make sure ledger_db is properly dropped, so rocksdb can be closed
        // cleanly
        TgArchiveClient::wait_for_drop(ledger_db);
    }

    pub fn run_until_closed(
        exit: Arc<(Mutex<bool>, Condvar)>, keep_alive: TgArchiveClientHandle,
    ) {
        CtrlC::set_handler({
            let e = exit.clone();
            move || {
                *e.0.lock() = true;
                e.1.notify_all();
            }
        });

        let mut lock = exit.0.lock();
        if !*lock {
            exit.1.wait(&mut lock);
        }

        TgArchiveClient::close(keep_alive);
    }
}
