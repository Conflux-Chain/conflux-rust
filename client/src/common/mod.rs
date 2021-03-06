// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Hold all top-level components for a type of client.
/// This struct implement ClientShutdownTrait.
pub struct ClientComponents<BlockGenT, Rest> {
    pub data_manager_weak_ptr: Weak<BlockDataManager>,
    pub blockgen: Option<Arc<BlockGenT>>,
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
    ) -> (Weak<BlockDataManager>, Option<Arc<dyn Stopable>>) {
        let data_manager_weak_ptr = self.data_manager_weak_ptr.clone();
        let blockgen: Option<Arc<dyn Stopable>> = match self.blockgen.clone() {
            Some(blockgen) => Some(blockgen),
            None => None,
        };

        (data_manager_weak_ptr, blockgen)
    }
}

pub trait ClientTrait {
    fn take_out_components_for_shutdown(
        &self,
    ) -> (Weak<BlockDataManager>, Option<Arc<dyn Stopable>>);
}

pub mod client_methods {
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
        let (ledger_db, maybe_blockgen) =
            this.take_out_components_for_shutdown();
        drop(this);
        if let Some(blockgen) = maybe_blockgen {
            blockgen.stop();
            drop(blockgen);
        }

        // Make sure ledger_db is properly dropped, so rocksdb can be closed
        // cleanly
        check_graceful_shutdown(ledger_db)
    }

    /// Most Conflux components references block data manager.
    /// When block data manager is freed, all background threads must have
    /// already stopped.
    fn check_graceful_shutdown(
        blockdata_manager_weak_ptr: Weak<BlockDataManager>,
    ) -> bool {
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
    use super::ClientTrait;
    use cfxcore::block_data_manager::BlockDataManager;
    use ctrlc::CtrlC;
    use parking_lot::{Condvar, Mutex};
    use std::{
        sync::{Arc, Weak},
        thread,
        time::{Duration, Instant},
    };
}

pub fn initialize_common_modules(
    conf: &Configuration, exit: Arc<(Mutex<bool>, Condvar)>,
    node_type: NodeType,
) -> Result<
    (
        Arc<Machine>,
        Arc<SecretStore>,
        HashMap<Address, U256>,
        Arc<BlockDataManager>,
        Arc<PowComputer>,
        Arc<TransactionPool>,
        Arc<ConsensusGraph>,
        Arc<SynchronizationGraph>,
        Arc<NetworkService>,
        Arc<CommonRpcImpl>,
        Arc<AccountProvider>,
        Arc<Notifications>,
        PubSubClient,
        Runtime,
    ),
    String,
>
{
    info!("Working directory: {:?}", std::env::current_dir());

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
            Some(ref file) => genesis::load_file(file, |addr_str| {
                parse_config_address_string(
                    addr_str,
                    network_config.get_network_type(),
                )
            })?,
            None => genesis::default(conf.is_test_or_dev_mode()),
        }
    };

    let mut consensus_conf = conf.consensus_config();
    match node_type {
        NodeType::Archive => {
            consensus_conf.sync_state_starting_epoch = Some(0);
        }
        NodeType::Full | NodeType::Light => {
            consensus_conf.sync_state_epoch_gap =
                Some(CATCH_UP_EPOCH_LAG_THRESHOLD);
        }
        NodeType::Unknown => {}
    }
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
    );
    debug!("Initialize genesis_block={:?}", genesis_block);

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

    let verification_config = conf.verification_config(machine.clone());
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
        conf.verification_config(machine.clone()),
        node_type,
    ));

    let sync_config = conf.sync_graph_config();

    let sync_graph = Arc::new(SynchronizationGraph::new(
        consensus.clone(),
        verification_config,
        pow_config,
        pow.clone(),
        sync_config,
        notifications.clone(),
        machine.clone(),
    ));

    let network = {
        let mut network = NetworkService::new(network_config);
        network.start().unwrap();
        Arc::new(network)
    };

    let refresh_time =
        Duration::from_millis(conf.raw_conf.account_provider_refresh_time_ms);

    let accounts = Arc::new(
        account_provider(
            Some(keys_path()),
            None, /* sstore_iterations */
            Some(refresh_time),
        )
        .ok()
        .expect("failed to initialize account provider"),
    );

    let common_impl = Arc::new(CommonRpcImpl::new(
        exit,
        consensus.clone(),
        network.clone(),
        txpool.clone(),
        accounts.clone(),
    ));

    let runtime = Runtime::with_default_thread_count();
    let pubsub = PubSubClient::new(
        runtime.executor(),
        consensus.clone(),
        notifications.clone(),
        *network.get_network_type(),
    );
    Ok((
        machine,
        secret_store,
        genesis_accounts,
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
    ))
}

pub fn initialize_not_light_node_modules(
    conf: &Configuration, exit: Arc<(Mutex<bool>, Condvar)>,
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
        Option<WSServer>,
        Runtime,
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
        txpool,
        consensus,
        sync_graph,
        network,
        common_impl,
        accounts,
        _notifications,
        pubsub,
        runtime,
    ) = initialize_common_modules(&conf, exit.clone(), node_type)?;

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
    ));
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
    } else if let Some(author) = maybe_author {
        if !author.is_valid_address() || author.is_builtin_address() {
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
    Ok((
        data_man,
        pow,
        txpool,
        consensus,
        sync,
        blockgen,
        debug_rpc_http_server,
        rpc_http_server,
        rpc_tcp_server,
        rpc_ws_server,
        runtime,
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
            &public_to_address(DEV_GENESIS_KEY_PAIR_2.public()),
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
    use crate::rpc::{
        error_codes::{codes::EXCEPTION_ERROR, invalid_params},
        JsonRpcErrorKind, RpcBoxFuture, RpcError, RpcErrorKind, RpcResult,
    };
    use jsonrpc_core::{
        futures::{future::IntoFuture, Future},
        BoxFuture, Error as JsonRpcError, Result as JsonRpcResult,
    };
    use std::hint::unreachable_unchecked;

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
        fn into(e: Self) -> JsonRpcError {
            match e.0 {
                JsonRpcErrorKind(j) => j,
                RpcErrorKind::InvalidParam(param, details) => {
                    invalid_params(&param, details)
                }
                RpcErrorKind::Msg(_)
                | RpcErrorKind::Decoder(_)

                // TODO(thegaram): consider returning InvalidParams instead
                | RpcErrorKind::FilterError(_)

                // TODO(thegaram): make error conversion more fine-grained here
                | RpcErrorKind::LightProtocol(_)
                | RpcErrorKind::StateDb(_)
                | RpcErrorKind::Storage(_) => JsonRpcError {
                    code: jsonrpc_core::ErrorCode::ServerError(EXCEPTION_ERROR),
                    message: format!("Error processing request: {}", e),
                    data: None,
                },
                // We exhausted all possible ErrorKinds here, however
                // https://stackoverflow.com/questions/36440021/whats-purpose-of-errorkind-nonexhaustive
                RpcErrorKind::__Nonexhaustive {} => unsafe {
                    unreachable_unchecked()
                },
            }
        }
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
    /// return RpcResult straight-forward. The delegate! macro with  #[into]
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

pub use crate::configuration::Configuration;
use crate::{
    accounts::{account_provider, keys_path},
    configuration::parse_config_address_string,
    rpc::{
        extractor::RpcExtractor,
        impls::{
            cfx::RpcImpl, common::RpcImpl as CommonRpcImpl,
            pubsub::PubSubClient,
        },
        setup_debug_rpc_apis, setup_public_rpc_apis,
    },
    GENESIS_VERSION,
};
use blockgen::BlockGenerator;
use cfx_parameters::sync::CATCH_UP_EPOCH_LAG_THRESHOLD;
use cfx_storage::StorageManager;
use cfx_types::{address_util::AddressUtil, Address, U256};
use cfxcore::{
    block_data_manager::BlockDataManager,
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
use jsonrpc_http_server::Server as HttpServer;
use jsonrpc_tcp_server::Server as TcpServer;
use jsonrpc_ws_server::Server as WSServer;
use keylib::KeyPair;
use malloc_size_of::{new_malloc_size_ops, MallocSizeOf, MallocSizeOfOps};
use network::NetworkService;
use parking_lot::{Condvar, Mutex};
use runtime::Runtime;
use secret_store::{SecretStore, SharedSecretStore};
use std::{
    collections::HashMap,
    str::FromStr,
    sync::{Arc, Weak},
    thread,
    time::{Duration, Instant},
};
use threadpool::ThreadPool;
use txgen::{DirectTransactionGenerator, TransactionGenerator};
