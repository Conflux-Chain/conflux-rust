// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![allow(deprecated)]

use jsonrpc_http_server as http;
use jsonrpc_tcp_server as tcp;
#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

#[macro_use]
mod config_macro;
mod configuration;
mod rpc;
#[cfg(test)]
mod tests;

use self::{http::Server as HttpServer, tcp::Server as TcpServer};
pub use crate::configuration::Configuration;
use blockgen::BlockGenerator;
use cfxcore::{
    cache_manager::CacheManager, genesis, pow::WORKER_COMPUTATION_PARALLELISM,
    statistics::Statistics, storage::StorageManager,
    transaction_pool::DEFAULT_MAX_BLOCK_GAS_LIMIT, vm_factory::VmFactory,
    ConsensusGraph, SynchronizationService, TransactionPool,
};

use crate::rpc::{
    impls::cfx::RpcImpl, setup_debug_rpc_apis, setup_public_rpc_apis, RpcBlock,
};
use cfx_types::Address;
use ctrlc::CtrlC;
use db::SystemDB;
use parking_lot::{Condvar, Mutex};
use primitives::Block;
use secret_store::SecretStore;
use std::{
    any::Any,
    fs::File,
    io::BufReader,
    path::Path,
    str::FromStr,
    sync::{Arc, Weak},
    thread,
    time::{Duration, Instant},
};
use threadpool::ThreadPool;
use txgen::TransactionGenerator;

/// Used in Genesis author to indicate testnet version
/// Increase by one for every test net reset
const TESTNET_VERSION: &'static str =
    "0000000000000000000000000000000000000003";

pub struct ClientHandle {
    pub debug_rpc_http_server: Option<HttpServer>,
    pub rpc_tcp_server: Option<TcpServer>,
    pub rpc_http_server: Option<HttpServer>,
    pub consensus: Arc<ConsensusGraph>,
    pub txpool: Arc<TransactionPool>,
    pub sync: Arc<SynchronizationService>,
    pub txgen: Arc<TransactionGenerator>,
    pub txgen_join_handle: Option<thread::JoinHandle<()>>,
    pub blockgen: Arc<BlockGenerator>,
    pub secret_store: Arc<SecretStore>,
    pub ledger_db: Weak<SystemDB>,
}

impl ClientHandle {
    pub fn into_be_dropped(
        self,
    ) -> (Weak<SystemDB>, Arc<BlockGenerator>, Box<Any>) {
        (
            self.ledger_db,
            self.blockgen,
            Box::new((
                self.debug_rpc_http_server,
                self.rpc_tcp_server,
                self.rpc_http_server,
                self.consensus,
                self.txpool,
                self.sync,
                self.txgen,
                self.secret_store,
                self.txgen_join_handle,
            )),
        )
    }
}

pub struct Client {}

impl Client {
    // Start all key components of Conflux and pass out their handles
    pub fn start(
        conf: Configuration, exit: Arc<(Mutex<bool>, Condvar)>,
    ) -> Result<ClientHandle, String> {
        info!("Working directory: {:?}", std::env::current_dir());

        let worker_thread_pool = Arc::new(Mutex::new(ThreadPool::with_name(
            "Tx Recover".into(),
            WORKER_COMPUTATION_PARALLELISM,
        )));

        let network_config = conf.net_config();
        let cache_config = conf.cache_config();

        let db_config = conf.db_config();
        let ledger_db = db::open_database(
            conf.raw_conf.db_dir.as_ref().unwrap(),
            &db_config,
        )
        .map_err(|e| format!("Failed to open database {:?}", e))?;

        let secret_store = Arc::new(SecretStore::new());
        let storage_manager = Arc::new(StorageManager::new(
            ledger_db.clone(),
            conf.storage_config(),
        ));
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

        let genesis_accounts = if conf.raw_conf.test_mode {
            match conf.raw_conf.genesis_accounts {
                Some(ref file) => genesis::load_file(file)?,
                None => genesis::default(secret_store.as_ref()),
            }
        } else {
            genesis::default(secret_store.as_ref())
        };

        let genesis_block = storage_manager.initialize(
            genesis_accounts,
            DEFAULT_MAX_BLOCK_GAS_LIMIT.into(),
            TESTNET_VERSION.into(),
        );
        debug!("Initialize genesis_block={:?}", genesis_block);

        let mb = 1024 * 1024;
        let max_cache_size = cache_config.ledger_mb() * mb;
        let pref_cache_size = max_cache_size * 3 / 4;
        // 400 is the average size of the key. TODO(ming): make sure this again.
        let cache_man = Arc::new(Mutex::new(CacheManager::new(
            pref_cache_size,
            max_cache_size,
            3 * mb,
        )));

        let txpool = Arc::new(TransactionPool::with_capacity(
            conf.raw_conf.tx_pool_size,
            storage_manager.clone(),
            worker_thread_pool.clone(),
            cache_man.clone(),
        ));

        let statistics = Arc::new(Statistics::new());

        let vm = VmFactory::new(1024 * 32);
        let pow_config = conf.pow_config();
        let consensus = Arc::new(ConsensusGraph::with_genesis_block(
            genesis_block,
            storage_manager.clone(),
            vm.clone(),
            txpool.clone(),
            statistics.clone(),
            ledger_db.clone(),
            cache_man.clone(),
            pow_config.clone(),
        ));

        let sync_config = cfxcore::SynchronizationConfiguration {
            network: network_config,
            consensus: consensus.clone(),
        };
        let verification_config = conf.verification_config();
        let protocol_config = conf.protocol_config();
        let mut sync = cfxcore::SynchronizationService::new(
            sync_config,
            protocol_config,
            verification_config,
            pow_config.clone(),
            conf.fast_recover(),
        );
        sync.start().unwrap();
        let sync = Arc::new(sync);
        let sync_graph = sync.get_synchronization_graph();

        let txgen = Arc::new(TransactionGenerator::new(
            consensus.clone(),
            storage_manager.clone(),
            txpool.clone(),
            secret_store.clone(),
            sync.net_key_pair().ok(),
        ));

        let blockgen_config = conf.blockgen_config();
        if let Some(chain_path) = blockgen_config.test_chain_path {
            let file_path = Path::new(&chain_path);
            let file = File::open(file_path).map_err(|e| {
                format!("Failed to open test-chain file {:?}", e)
            })?;
            let reader = BufReader::new(file);
            let rpc_blocks: Vec<RpcBlock> = serde_json::from_reader(reader)
                .map_err(|e| {
                    format!("Failed to parse blocks from json {:?}", e)
                })?;
            if rpc_blocks.is_empty() {
                return Err(format!(
                    "Error: The json data should not be empty."
                ));
            }
            for rpc_block in rpc_blocks.into_iter().skip(1) {
                let primitive_block: Block = rpc_block.into_primitive().map_err(|e| {
                    format!("Failed to convert from a rpc_block to primitive block {:?}", e)
                })?;
                sync.on_mined_block(primitive_block);
            }
        }

        let maybe_author: Option<Address> = conf.raw_conf.mining_author.clone().map(|hex_str| Address::from_str(hex_str.as_str()).expect("mining-author should be 40-digit hex string without 0x prefix"));
        let blockgen = Arc::new(BlockGenerator::new(
            sync_graph.clone(),
            txpool.clone(),
            sync.clone(),
            txgen.clone(),
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
        }

        let tx_conf = conf.tx_gen_config();
        let txgen_handle = if tx_conf.generate_tx {
            let txgen_clone = txgen.clone();
            Some(
                thread::Builder::new()
                    .name("txgen".into())
                    .spawn(move || {
                        TransactionGenerator::generate_transactions(
                            txgen_clone,
                            tx_conf,
                        )
                        .unwrap();
                    })
                    .expect("should succeed"),
            )
        } else {
            None
        };

        let rpc_impl = Arc::new(RpcImpl::new(
            consensus.clone(),
            sync.clone(),
            storage_manager.clone(),
            blockgen.clone(),
            txpool.clone(),
            exit,
        ));

        let debug_rpc_http_server = rpc::new_http(
            rpc::HttpConfiguration::new(
                Some((127, 0, 0, 1)),
                conf.raw_conf.jsonrpc_local_http_port,
                conf.raw_conf.jsonrpc_cors.clone(),
                conf.raw_conf.jsonrpc_http_keep_alive,
            ),
            setup_debug_rpc_apis(rpc_impl.clone()),
        )?;

        let rpc_tcp_server = rpc::new_tcp(
            rpc::TcpConfiguration::new(None, conf.raw_conf.jsonrpc_tcp_port),
            if conf.raw_conf.test_mode {
                setup_debug_rpc_apis(rpc_impl.clone())
            } else {
                setup_public_rpc_apis(rpc_impl.clone())
            },
        )?;

        let rpc_http_server = rpc::new_http(
            rpc::HttpConfiguration::new(
                None,
                conf.raw_conf.jsonrpc_http_port,
                conf.raw_conf.jsonrpc_cors.clone(),
                conf.raw_conf.jsonrpc_http_keep_alive,
            ),
            if conf.raw_conf.test_mode {
                setup_debug_rpc_apis(rpc_impl.clone())
            } else {
                setup_public_rpc_apis(rpc_impl.clone())
            },
        )?;

        Ok(ClientHandle {
            ledger_db: Arc::downgrade(&ledger_db),
            debug_rpc_http_server,
            rpc_http_server,
            rpc_tcp_server,
            txpool,
            txgen,
            txgen_join_handle: txgen_handle,
            blockgen,
            consensus,
            secret_store,
            sync,
        })
    }

    /// Use a Weak pointer to ensure that other Arc pointers are released
    fn wait_for_drop<T>(w: Weak<T>) {
        let sleep_duration = Duration::from_secs(1);
        let warn_timeout = Duration::from_secs(10);
        let max_timeout = Duration::from_secs(60);
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
        warn!("Shutdown timeout reached, exiting uncleanly.");
    }

    pub fn close(handle: ClientHandle) -> i32 {
        let (ledger_db, blockgen, to_drop) = handle.into_be_dropped();
        BlockGenerator::stop(&blockgen);
        drop(blockgen);
        drop(to_drop);

        // Make sure ledger_db is properly dropped, so rocksdb can be closed
        // cleanly
        Client::wait_for_drop(ledger_db);
        0
    }

    pub fn run_until_closed(
        exit: Arc<(Mutex<bool>, Condvar)>, keep_alive: ClientHandle,
    ) -> i32 {
        CtrlC::set_handler({
            let e = exit.clone();
            move || {
                *e.0.lock() = true;
                e.1.notify_all();
            }
        });

        let mut lock = exit.0.lock();
        if !*lock {
            let _ = exit.1.wait(&mut lock);
        }
        Client::close(keep_alive)
    }
}
