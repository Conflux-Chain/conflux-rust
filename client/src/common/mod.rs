// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    collections::HashMap,
    fs::create_dir_all,
    path::Path,
    str::FromStr,
    sync::{Arc, Weak},
    thread,
    time::{Duration, Instant},
};

use jsonrpc_http_server::Server as HttpServer;
use jsonrpc_tcp_server::Server as TcpServer;
use jsonrpc_ws_server::Server as WSServer;
use parking_lot::{Condvar, Mutex};
use rand_08::{prelude::StdRng, rngs::OsRng, SeedableRng};
use threadpool::ThreadPool;

use blockgen::BlockGenerator;
use cfx_storage::StorageManager;
use cfx_types::{address_util::AddressUtil, Address, Space, U256};
pub use cfxcore::pos::pos::PosDropHandle;
use cfxcore::{
    block_data_manager::BlockDataManager,
    consensus::pos_handler::{PosConfiguration, PosVerifier},
    machine::{new_machine_with_builtin, Machine},
    pow::PowComputer,
    spec::genesis::{self, genesis_block, DEV_GENESIS_KEY_PAIR_2},
    statistics::Statistics,
    sync::SyncPhaseType,
    vm_factory::VmFactory,
    ConsensusGraph, LightProvider, NodeType, Notifications, Stopable,
    SynchronizationGraph, SynchronizationService, TransactionPool,
    WORKER_COMPUTATION_PARALLELISM,
};
use cfxcore_accounts::AccountProvider;
use cfxkey::public_to_address;
use diem_config::keys::ConfigKey;
use diem_crypto::{
    key_file::{load_pri_key, save_pri_key},
    PrivateKey, Uniform,
};
use diem_types::validator_config::{
    ConsensusPrivateKey, ConsensusVRFPrivateKey,
};
use keylib::KeyPair;
use malloc_size_of::{new_malloc_size_ops, MallocSizeOf, MallocSizeOfOps};
use network::NetworkService;
use runtime::Runtime;
use secret_store::{SecretStore, SharedSecretStore};
use txgen::{DirectTransactionGenerator, TransactionGenerator};

pub use crate::configuration::Configuration;
use crate::{
    accounts::{account_provider, keys_path},
    configuration::parse_config_address_string,
    rpc::{
        extractor::RpcExtractor,
        impls::{
            cfx::RpcImpl, common::RpcImpl as CommonRpcImpl,
            eth_pubsub::PubSubClient as EthPubSubClient, pubsub::PubSubClient,
        },
        setup_debug_rpc_apis, setup_public_eth_rpc_apis, setup_public_rpc_apis,
    },
    GENESIS_VERSION,
};
use cfxcore::consensus::pos_handler::read_initial_nodes_from_file;

/// Hold all top-level components for a type of client.
/// This struct implement ClientShutdownTrait.
pub struct ClientComponents<BlockGenT, Rest> {
    pub data_manager_weak_ptr: Weak<BlockDataManager>,
    pub blockgen: Option<Arc<BlockGenT>>,
    pub pos_handler: Option<Arc<PosVerifier>>,
    pub other_components: Rest,
}

impl<BlockGenT, Rest: MallocSizeOf> MallocSizeOf
    for ClientComponents<BlockGenT, Rest>
{
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        if let Some(data_man) = self.data_manager_weak_ptr.upgrade() {
            let data_manager_size = data_man.size_of(ops);
            data_manager_size + self.other_components.size_of(ops)
        } else {
            // If data_man is `None`, we will be just shutting down (dropping
            // components) so we don't care about the size
            0
        }
    }
}

impl<BlockGenT: 'static + Stopable, Rest> ClientTrait
    for ClientComponents<BlockGenT, Rest>
{
    fn take_out_components_for_shutdown(
        &self,
    ) -> (
        Weak<BlockDataManager>,
        Option<Arc<PosVerifier>>,
        Option<Arc<dyn Stopable>>,
    ) {
        debug!("take_out_components_for_shutdown");
        let data_manager_weak_ptr = self.data_manager_weak_ptr.clone();
        let blockgen: Option<Arc<dyn Stopable>> = match self.blockgen.clone() {
            Some(blockgen) => Some(blockgen),
            None => None,
        };

        (data_manager_weak_ptr, self.pos_handler.clone(), blockgen)
    }
}

pub trait ClientTrait {
    fn take_out_components_for_shutdown(
        &self,
    ) -> (
        Weak<BlockDataManager>,
        Option<Arc<PosVerifier>>,
        Option<Arc<dyn Stopable>>,
    );
}

pub mod client_methods {
    use std::{
        sync::{Arc, Weak},
        thread,
        time::{Duration, Instant},
    };

    use ctrlc::CtrlC;
    use parking_lot::{Condvar, Mutex};

    use super::ClientTrait;

    pub fn run(
        this: Box<dyn ClientTrait>, exit_cond_var: Arc<(Mutex<bool>, Condvar)>,
    ) -> bool {
        CtrlC::set_handler({
            let e = exit_cond_var.clone();
            move || {
                *e.0.lock() = true;
                e.1.notify_all();
            }
        });

        let mut lock = exit_cond_var.0.lock();
        if !*lock {
            exit_cond_var.1.wait(&mut lock);
        }

        shutdown(this)
    }

    /// Returns whether the shutdown is considered clean.
    pub fn shutdown(this: Box<dyn ClientTrait>) -> bool {
        let (ledger_db, maybe_pos_handler, maybe_blockgen) =
            this.take_out_components_for_shutdown();
        drop(this);
        if let Some(blockgen) = maybe_blockgen {
            blockgen.stop();
            drop(blockgen);
        }
        let maybe_pos_db = if let Some(pos_handler) = maybe_pos_handler {
            let maybe_pos_db = pos_handler.stop();
            drop(pos_handler);
            maybe_pos_db
        } else {
            None
        };

        // Make sure ledger_db is properly dropped, so rocksdb can be closed
        // cleanly
        let mut graceful = true;
        graceful &= check_graceful_shutdown(ledger_db);
        debug!("ledger_db drop: graceful = {}", graceful);
        if let Some((pos_ledger_db, consensus_db)) = maybe_pos_db {
            graceful &= check_graceful_shutdown(pos_ledger_db);
            debug!("pos_ledger_db drop: graceful = {}", graceful);
            graceful &= check_graceful_shutdown(consensus_db);
            debug!("consensus_db drop: graceful = {}", graceful);
        }
        graceful
    }

    /// Most Conflux components references block data manager.
    /// When block data manager is freed, all background threads must have
    /// already stopped.
    fn check_graceful_shutdown<T>(blockdata_manager_weak_ptr: Weak<T>) -> bool {
        let sleep_duration = Duration::from_secs(1);
        let warn_timeout = Duration::from_secs(5);
        let max_timeout = Duration::from_secs(1200);
        let instant = Instant::now();
        let mut warned = false;
        while instant.elapsed() < max_timeout {
            if blockdata_manager_weak_ptr.upgrade().is_none() {
                return true;
            }
            if !warned && instant.elapsed() > warn_timeout {
                warned = true;
                warn!("Shutdown is taking longer than expected.");
            }
            thread::sleep(sleep_duration);
        }
        eprintln!("Shutdown timeout reached, exiting uncleanly.");
        false
    }
}

pub fn initialize_common_modules(
    conf: &mut Configuration, exit: Arc<(Mutex<bool>, Condvar)>,
    node_type: NodeType,
) -> Result<
    (
        Arc<Machine>,
        Arc<SecretStore>,
        HashMap<Address, U256>,
        Arc<BlockDataManager>,
        Arc<PowComputer>,
        Arc<PosVerifier>,
        Arc<TransactionPool>,
        Arc<ConsensusGraph>,
        Arc<SynchronizationGraph>,
        Arc<NetworkService>,
        Arc<CommonRpcImpl>,
        Arc<AccountProvider>,
        Arc<Notifications>,
        PubSubClient,
        Runtime,
        EthPubSubClient,
    ),
    String,
>
{
    info!("Working directory: {:?}", std::env::current_dir());

    // TODO(lpl): Keep it properly and allow not running pos.
    let (self_pos_private_key, self_vrf_private_key) = {
        let key_path = Path::new(&conf.raw_conf.pos_private_key_path);
        let default_passwd = if conf.is_test_or_dev_mode() {
            Some(vec![])
        } else {
            conf.raw_conf
                .dev_pos_private_key_encryption_password
                .clone()
                // If the password is not set in the config file, read it from
                // the environment variable.
                .or(std::env::var("CFX_POS_KEY_ENCRYPTION_PASSWORD").ok())
                .map(|s| s.into_bytes())
        };
        if key_path.exists() {
            let passwd = match default_passwd {
                Some(p) => p,
                None => rpassword::read_password_from_tty(Some("PoS key detected, please input your encryption password.\nPassword:")).map_err(|e| format!("{:?}", e))?.into_bytes()
            };
            let (sk, vrf_sk): (ConsensusPrivateKey, ConsensusVRFPrivateKey) =
                load_pri_key(key_path, &passwd).unwrap();
            (ConfigKey::new(sk), ConfigKey::new(vrf_sk))
        } else {
            create_dir_all(key_path.parent().unwrap()).unwrap();
            let passwd = match default_passwd {
                Some(p) => p,
                None => {
                    let p = rpassword::read_password_from_tty(Some("PoS key is not detected and will be generated instead, please input your encryption password. This password is needed when you restart the node\nPassword:")).map_err(|e| format!("{:?}", e))?.into_bytes();
                    let p2 = rpassword::read_password_from_tty(Some(
                        "Repeat Password:",
                    ))
                    .map_err(|e| format!("{:?}", e))?
                    .into_bytes();
                    if p != p2 {
                        bail!("Passwords do not match!");
                    }
                    p
                }
            };
            let mut rng = StdRng::from_rng(OsRng).unwrap();
            let private_key = ConsensusPrivateKey::generate(&mut rng);
            let vrf_private_key = ConsensusVRFPrivateKey::generate(&mut rng);
            save_pri_key(key_path, &passwd, &(&private_key, &vrf_private_key))
                .expect("error saving private key");
            (ConfigKey::new(private_key), ConfigKey::new(vrf_private_key))
        }
    };

    metrics::initialize(conf.metrics_config());

    let worker_thread_pool = Arc::new(Mutex::new(ThreadPool::with_name(
        "Tx Recover".into(),
        WORKER_COMPUTATION_PARALLELISM,
    )));

    let network_config = conf.net_config()?;
    let cache_config = conf.cache_config();

    let (db_path, db_config) = conf.db_config();
    let ledger_db = db::open_database(db_path.to_str().unwrap(), &db_config)
        .map_err(|e| format!("Failed to open database {:?}", e))?;

    let secret_store = Arc::new(SecretStore::new());
    let storage_manager = Arc::new(
        StorageManager::new(conf.storage_config(&node_type))
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
            Some(ref file) => genesis::load_file(file, |addr_str| {
                parse_config_address_string(
                    addr_str,
                    network_config.get_network_type(),
                )
            })?,
            None => genesis::default(conf.is_test_or_dev_mode()),
        }
    };

    // Only try to setup PoW genesis block if pos is enabled from genesis.
    let initial_nodes = if conf.raw_conf.pos_reference_enable_height == 0 {
        Some(
            read_initial_nodes_from_file(
                conf.raw_conf.pos_initial_nodes_path.as_str(),
            )
            .expect("Genesis must have been initialized with pos"),
        )
    } else {
        None
    };

    let consensus_conf = conf.consensus_config();
    let vm = VmFactory::new(1024 * 32);
    let machine = Arc::new(new_machine_with_builtin(conf.common_params(), vm));

    let genesis_block = genesis_block(
        &storage_manager,
        genesis_accounts.clone(),
        Address::from_str(GENESIS_VERSION).unwrap(),
        U256::zero(),
        machine.clone(),
        conf.raw_conf.execute_genesis, /* need_to_execute */
        conf.raw_conf.chain_id,
        &initial_nodes,
    );
    storage_manager.notify_genesis_hash(genesis_block.hash());
    let mut genesis_accounts = genesis_accounts;
    let genesis_accounts = genesis_accounts
        .drain()
        .filter(|(addr, _)| addr.space == Space::Native)
        .map(|(addr, x)| (addr.address, x))
        .collect();
    debug!("Initialize genesis_block={:?}", genesis_block);
    if conf.raw_conf.pos_genesis_pivot_decision.is_none() {
        conf.raw_conf.pos_genesis_pivot_decision = Some(genesis_block.hash());
    }

    let pow_config = conf.pow_config();
    let pow = Arc::new(PowComputer::new(pow_config.use_octopus()));

    let data_man = Arc::new(BlockDataManager::new(
        cache_config,
        Arc::new(genesis_block),
        ledger_db.clone(),
        storage_manager,
        worker_thread_pool,
        conf.data_mananger_config(),
        pow.clone(),
    ));

    let network = {
        let mut rng = StdRng::from_rng(OsRng).unwrap();
        let private_key = ConsensusPrivateKey::generate(&mut rng);
        let vrf_private_key = ConsensusVRFPrivateKey::generate(&mut rng);
        let mut network = NetworkService::new(network_config.clone());
        network
            .initialize((
                private_key.public_key(),
                vrf_private_key.public_key(),
            ))
            .unwrap();
        Arc::new(network)
    };

    let pos_verifier = Arc::new(PosVerifier::new(
        Some(network.clone()),
        PosConfiguration {
            bls_key: self_pos_private_key,
            vrf_key: self_vrf_private_key,
            diem_conf_path: conf.raw_conf.pos_config_path.clone(),
            protocol_conf: conf.protocol_config(),
            pos_initial_nodes_path: conf
                .raw_conf
                .pos_initial_nodes_path
                .clone(),
            vrf_proposal_threshold: conf.raw_conf.vrf_proposal_threshold,
            pos_state_config: conf.pos_state_config(),
        },
        conf.raw_conf.pos_reference_enable_height,
    ));
    let verification_config =
        conf.verification_config(machine.clone(), pos_verifier.clone());
    let txpool = Arc::new(TransactionPool::new(
        conf.txpool_config(),
        verification_config.clone(),
        data_man.clone(),
        machine.clone(),
    ));

    let statistics = Arc::new(Statistics::new());
    let notifications = Notifications::init();

    let consensus = Arc::new(ConsensusGraph::new(
        consensus_conf,
        txpool.clone(),
        statistics,
        data_man.clone(),
        pow_config.clone(),
        pow.clone(),
        notifications.clone(),
        conf.execution_config(),
        verification_config.clone(),
        node_type,
        pos_verifier.clone(),
    ));

    for terminal in data_man
        .terminals_from_db()
        .unwrap_or(vec![data_man.get_cur_consensus_era_genesis_hash()])
    {
        if data_man.block_height_by_hash(&terminal).unwrap()
            >= conf.raw_conf.pos_reference_enable_height
        {
            pos_verifier.initialize(consensus.clone())?;
            break;
        }
    }

    let sync_config = conf.sync_graph_config();

    let sync_graph = Arc::new(SynchronizationGraph::new(
        consensus.clone(),
        verification_config,
        pow_config,
        pow.clone(),
        sync_config,
        notifications.clone(),
        machine.clone(),
        pos_verifier.clone(),
    ));
    let refresh_time =
        Duration::from_millis(conf.raw_conf.account_provider_refresh_time_ms);

    let accounts = Arc::new(
        account_provider(
            Some(keys_path()),
            None, /* sstore_iterations */
            Some(refresh_time),
        )
        .expect("failed to initialize account provider"),
    );

    let common_impl = Arc::new(CommonRpcImpl::new(
        exit,
        consensus.clone(),
        network.clone(),
        txpool.clone(),
        accounts.clone(),
        pos_verifier.clone(),
    ));

    let runtime = Runtime::with_default_thread_count();
    let pubsub = PubSubClient::new(
        runtime.executor(),
        consensus.clone(),
        notifications.clone(),
        *network.get_network_type(),
    );

    let eth_pubsub = EthPubSubClient::new(
        runtime.executor(),
        consensus.clone(),
        notifications.clone(),
    );

    Ok((
        machine,
        secret_store,
        genesis_accounts,
        data_man,
        pow,
        pos_verifier,
        txpool,
        consensus,
        sync_graph,
        network,
        common_impl,
        accounts,
        notifications,
        pubsub,
        runtime,
        eth_pubsub,
    ))
}

pub fn initialize_not_light_node_modules(
    conf: &mut Configuration, exit: Arc<(Mutex<bool>, Condvar)>,
    node_type: NodeType,
) -> Result<
    (
        Arc<BlockDataManager>,
        Arc<PowComputer>,
        Arc<TransactionPool>,
        Arc<ConsensusGraph>,
        Arc<SynchronizationService>,
        Arc<BlockGenerator>,
        Option<HttpServer>,
        Option<HttpServer>,
        Option<TcpServer>,
        Option<TcpServer>,
        Option<WSServer>,
        Option<WSServer>,
        Arc<PosVerifier>,
        Runtime,
        Option<HttpServer>,
        Option<WSServer>,
    ),
    String,
>
{
    let (
        _machine,
        secret_store,
        genesis_accounts,
        data_man,
        pow,
        pos_verifier,
        txpool,
        consensus,
        sync_graph,
        network,
        common_impl,
        accounts,
        _notifications,
        pubsub,
        runtime,
        eth_pubsub,
    ) = initialize_common_modules(conf, exit.clone(), node_type)?;

    let light_provider = Arc::new(LightProvider::new(
        consensus.clone(),
        sync_graph.clone(),
        Arc::downgrade(&network),
        txpool.clone(),
        conf.raw_conf.throttling_conf.clone(),
        node_type,
    ));
    light_provider.register(network.clone()).unwrap();

    let sync = Arc::new(SynchronizationService::new(
        node_type,
        network.clone(),
        sync_graph.clone(),
        conf.protocol_config(),
        conf.state_sync_config(),
        SyncPhaseType::CatchUpRecoverBlockHeaderFromDB,
        light_provider,
        consensus.clone(),
    ));
    sync.register().unwrap();

    if let Some(print_memory_usage_period_s) =
        conf.raw_conf.print_memory_usage_period_s
    {
        let secret_store = secret_store.clone();
        let data_man = data_man.clone();
        let txpool = txpool.clone();
        let consensus = consensus.clone();
        let sync = sync.clone();
        thread::Builder::new().name("MallocSizeOf".into()).spawn(
            move || loop {
                let start = Instant::now();
                let mb = 1_000_000;
                let mut ops = new_malloc_size_ops();
                let secret_store_size = secret_store.size_of(&mut ops) / mb;
                // Note `db_manager` is not wrapped in Arc, so it will still be included
                // in `data_man_size`.
                let data_manager_db_cache_size = data_man.db_manager.size_of(&mut ops) / mb;
                let storage_manager_size = data_man.storage_manager.size_of(&mut ops) / mb;
                let data_man_size = data_man.size_of(&mut ops) / mb;
                let tx_pool_size = txpool.size_of(&mut ops) / mb;
                let consensus_graph_size = consensus.size_of(&mut ops) / mb;
                let sync_graph_size =
                    sync.get_synchronization_graph().size_of(&mut ops) / mb;
                let sync_service_size = sync.size_of(&mut ops) / mb;
                info!(
                    "Malloc Size(MB): secret_store={} data_manager_db_cache_size={} \
                    storage_manager_size={} data_man={} txpool={} consensus={} sync_graph={}\
                    sync_service={}, \
                    time elapsed={:?}",
                    secret_store_size,data_manager_db_cache_size,storage_manager_size,
                    data_man_size, tx_pool_size, consensus_graph_size, sync_graph_size,
                    sync_service_size, start.elapsed(),
                );
                thread::sleep(Duration::from_secs(
                    print_memory_usage_period_s,
                ));
            },
        ).expect("Memory usage thread start fails");
    }

    let (maybe_txgen, maybe_direct_txgen) = initialize_txgens(
        consensus.clone(),
        txpool.clone(),
        sync.clone(),
        secret_store.clone(),
        genesis_accounts,
        &conf,
        network.net_key_pair().unwrap(),
    );

    let maybe_author: Option<Address> =
        conf.raw_conf.mining_author.as_ref().map(|addr_str| {
            parse_config_address_string(addr_str, network.get_network_type())
                .unwrap_or_else(|err| {
                    panic!("Error parsing mining-author {}", err)
                })
        });
    let blockgen = Arc::new(BlockGenerator::new(
        sync_graph,
        txpool.clone(),
        sync.clone(),
        maybe_txgen.clone(),
        conf.pow_config(),
        pow.clone(),
        maybe_author.clone().unwrap_or_default(),
        pos_verifier.clone(),
    ));
    if conf.is_dev_mode() {
        // If `dev_block_interval_ms` is None, blocks are generated after
        // receiving RPC `cfx_sendRawTransaction`.
        if let Some(interval_ms) = conf.raw_conf.dev_block_interval_ms {
            // Automatic block generation with fixed interval.
            let bg = blockgen.clone();
            info!("Start auto block generation");
            thread::Builder::new()
                .name("auto_mining".into())
                .spawn(move || {
                    bg.auto_block_generation(interval_ms);
                })
                .expect("Mining thread spawn error");
        }
    } else if let Some(author) = maybe_author {
        if !author.is_genesis_valid_address() || author.is_builtin_address() {
            panic!("mining-author must be user address or contract address, otherwise you will not get mining rewards!!!");
        }
        if blockgen.pow_config.enable_mining() {
            let bg = blockgen.clone();
            thread::Builder::new()
                .name("mining".into())
                .spawn(move || {
                    BlockGenerator::start_mining(bg, 0);
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
        accounts,
    ));

    let debug_rpc_http_server = super::rpc::start_http(
        conf.local_http_config(),
        setup_debug_rpc_apis(
            common_impl.clone(),
            rpc_impl.clone(),
            pubsub.clone(),
            eth_pubsub.clone(),
            &conf,
        ),
    )?;

    let debug_rpc_tcp_server = super::rpc::start_tcp(
        conf.local_tcp_config(),
        setup_debug_rpc_apis(
            common_impl.clone(),
            rpc_impl.clone(),
            pubsub.clone(),
            eth_pubsub.clone(),
            &conf,
        ),
        RpcExtractor,
    )?;

    let rpc_tcp_server = super::rpc::start_tcp(
        conf.tcp_config(),
        setup_public_rpc_apis(
            common_impl.clone(),
            rpc_impl.clone(),
            pubsub.clone(),
            eth_pubsub.clone(),
            &conf,
        ),
        RpcExtractor,
    )?;

    let debug_rpc_ws_server = super::rpc::start_ws(
        conf.local_ws_config(),
        setup_public_rpc_apis(
            common_impl.clone(),
            rpc_impl.clone(),
            pubsub.clone(),
            eth_pubsub.clone(),
            &conf,
        ),
        RpcExtractor,
    )?;

    let rpc_ws_server = super::rpc::start_ws(
        conf.ws_config(),
        setup_public_rpc_apis(
            common_impl.clone(),
            rpc_impl.clone(),
            pubsub.clone(),
            eth_pubsub.clone(),
            &conf,
        ),
        RpcExtractor,
    )?;

    let eth_rpc_http_server = super::rpc::start_http(
        conf.eth_http_config(),
        setup_public_eth_rpc_apis(
            common_impl.clone(),
            rpc_impl.clone(),
            pubsub.clone(),
            eth_pubsub.clone(),
            &conf,
        ),
    )?;

    let eth_rpc_ws_server = super::rpc::start_ws(
        conf.eth_ws_config(),
        setup_public_eth_rpc_apis(
            common_impl.clone(),
            rpc_impl.clone(),
            pubsub.clone(),
            eth_pubsub.clone(),
            &conf,
        ),
        RpcExtractor,
    )?;

    let rpc_http_server = super::rpc::start_http(
        conf.http_config(),
        setup_public_rpc_apis(
            common_impl,
            rpc_impl,
            pubsub,
            eth_pubsub.clone(),
            &conf,
        ),
    )?;

    network.start();

    Ok((
        data_man,
        pow,
        txpool,
        consensus,
        sync,
        blockgen,
        debug_rpc_http_server,
        rpc_http_server,
        debug_rpc_tcp_server,
        rpc_tcp_server,
        debug_rpc_ws_server,
        rpc_ws_server,
        pos_verifier,
        runtime,
        eth_rpc_http_server,
        eth_rpc_ws_server,
    ))
}

pub fn initialize_txgens(
    consensus: Arc<ConsensusGraph>, txpool: Arc<TransactionPool>,
    sync: Arc<SynchronizationService>, secret_store: SharedSecretStore,
    genesis_accounts: HashMap<Address, U256>, conf: &Configuration,
    network_key_pair: KeyPair,
) -> (
    Option<Arc<TransactionGenerator>>,
    Option<Arc<Mutex<DirectTransactionGenerator>>>,
)
{
    // This tx generator directly push simple transactions and erc20
    // transactions into blocks.
    let maybe_direct_txgen_with_contract = if conf.is_test_or_dev_mode() {
        Some(Arc::new(Mutex::new(DirectTransactionGenerator::new(
            network_key_pair,
            &public_to_address(DEV_GENESIS_KEY_PAIR_2.public(), true),
            U256::from_dec_str("10000000000000000").unwrap(),
            U256::from_dec_str("10000000000000000").unwrap(),
        ))))
    } else {
        None
    };

    // This tx generator generates transactions from preconfigured multiple
    // genesis accounts and it pushes transactions into transaction pool.
    let maybe_multi_genesis_txgen = if let Some(txgen_conf) =
        conf.tx_gen_config()
    {
        let multi_genesis_txgen = Arc::new(TransactionGenerator::new(
            consensus.clone(),
            txpool.clone(),
            sync.clone(),
            secret_store.clone(),
        ));
        if txgen_conf.generate_tx {
            let txgen_clone = multi_genesis_txgen.clone();
            let join_handle =
                thread::Builder::new()
                    .name("txgen".into())
                    .spawn(move || {
                        TransactionGenerator::generate_transactions_with_multiple_genesis_accounts(
                            txgen_clone,
                            txgen_conf,
                            genesis_accounts,
                        );
                    })
                    .expect("should succeed");
            multi_genesis_txgen.set_join_handle(join_handle);
        }
        Some(multi_genesis_txgen)
    } else {
        None
    };

    (maybe_multi_genesis_txgen, maybe_direct_txgen_with_contract)
}

pub mod delegate_convert {
    use std::convert::Into as StdInto;

    use jsonrpc_core::{
        futures::{future::IntoFuture, Future},
        BoxFuture, Error as JsonRpcError, Result as JsonRpcResult,
    };

    use crate::rpc::{RpcBoxFuture, RpcError, RpcResult};

    pub trait Into<T> {
        fn into(x: Self) -> T;
    }

    impl<T> Into<JsonRpcResult<T>> for JsonRpcResult<T> {
        fn into(x: Self) -> JsonRpcResult<T> { x }
    }

    impl<T: Send + Sync + 'static> Into<BoxFuture<T>> for BoxFuture<T> {
        fn into(x: Self) -> BoxFuture<T> { x }
    }

    impl<T: Send + Sync + 'static> Into<BoxFuture<T>> for RpcBoxFuture<T> {
        fn into(x: Self) -> BoxFuture<T> {
            Box::new(x.map_err(|rpc_error| Into::into(rpc_error)))
        }
    }

    impl Into<JsonRpcError> for RpcError {
        fn into(e: Self) -> JsonRpcError { e.into() }
    }

    pub fn into_jsonrpc_result<T>(r: RpcResult<T>) -> JsonRpcResult<T> {
        match r {
            Ok(t) => Ok(t),
            Err(e) => Err(Into::into(e)),
        }
    }

    impl<T> Into<JsonRpcResult<T>> for RpcResult<T> {
        fn into(x: Self) -> JsonRpcResult<T> { into_jsonrpc_result(x) }
    }

    /// Sometimes an rpc method is implemented asynchronously, then the rpc
    /// trait definition must use BoxFuture for the return type.
    ///
    /// This into conversion allow non-async rpc implementation method to
    /// return RpcResult straight-forward. The delegate! macro with  #\[into\]
    /// attribute will automatically call this method to do the return type
    /// conversion.
    impl<T: Send + Sync + 'static> Into<BoxFuture<T>> for RpcResult<T> {
        fn into(x: Self) -> BoxFuture<T> {
            into_jsonrpc_result(x).into_future().boxed()
        }
    }

    /*
    /// It's a bad idea to convert a BoxFuture return type to a JsonRpcResult
    /// return type for rpc call. Simply imagine how the code below runs.
    impl<T: Send + Sync + 'static> Into<JsonRpcResult<T>> for BoxFuture<T> {
        fn into(x: Self) -> JsonRpcResult<T> {
            thread::Builder::new()
                .name("rpc async waiter".into())
                .spawn(move || x.wait())
                .map_err(|e| {
                    let mut rpc_err = JsonRpcError::internal_error();
                    rpc_err.message = format!("thread creation error: {}", e);

                    rpc_err
                })?
                .join()
                .map_err(|_| {
                    let mut rpc_err = JsonRpcError::internal_error();
                    rpc_err.message = format!("thread join error.");

                    rpc_err
                })?
        }
    }
    */
}
