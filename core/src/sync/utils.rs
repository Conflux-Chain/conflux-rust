use crate::{
    block_data_manager::{BlockDataManager, DataManagerConfiguration, DbType},
    cache_config::CacheConfig,
    consensus::{ConsensusConfig, ConsensusInnerConfig},
    db::NUM_COLUMNS,
    parameters::WORKER_COMPUTATION_PARALLELISM,
    pow::ProofOfWorkConfig,
    statistics::Statistics,
    storage::{StorageConfiguration, StorageManager},
    sync::{SyncGraphConfig, SynchronizationGraph},
    transaction_pool::{TxPoolConfig, DEFAULT_MAX_BLOCK_GAS_LIMIT},
    verification::VerificationConfig,
    vm_factory::VmFactory,
    ConsensusGraph, Notifications, TransactionPool,
};
use cfx_types::{Address, H256, U256};
use core::str::FromStr;
use parking_lot::Mutex;
use primitives::{Block, BlockHeaderBuilder};
use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};
use threadpool::ThreadPool;

pub fn create_simple_block_impl(
    parent_hash: H256, ref_hashes: Vec<H256>, height: u64, nonce: u64,
    diff: U256, block_weight: u32, adaptive: bool,
) -> (H256, Block)
{
    let mut b = BlockHeaderBuilder::new();
    let mut header = b
        .with_parent_hash(parent_hash)
        .with_height(height)
        .with_referee_hashes(ref_hashes)
        .with_nonce(nonce)
        .with_difficulty(diff)
        .with_adaptive(adaptive)
        .build();
    header.compute_hash();
    header.pow_quality = if block_weight > 1 {
        diff * block_weight
    } else {
        diff
    };
    let block = Block::new(header, vec![]);
    (block.hash(), block)
}

pub fn create_simple_block(
    sync: Arc<SynchronizationGraph>, parent_hash: H256, ref_hashes: Vec<H256>,
    height: u64, block_weight: u32, adaptive: bool,
) -> (H256, Block)
{
    //    sync.consensus.wait_for_generation(&parent_hash);
    // let parent_header = sync.block_header_by_hash(&parent_hash).unwrap();
    //    let exp_diff = sync.expected_difficulty(&parent_hash);
    //    assert!(
    //        exp_diff == U256::from(10),
    //        "Difficulty hike in bench is not supported yet!"
    //    );
    // Note that because we do not fill the timestamp, it should keep at the
    // minimum difficulty of 10.
    let exp_diff = U256::from(10);
    let nonce = sync.block_count() as u64 + 1;
    create_simple_block_impl(
        parent_hash,
        ref_hashes,
        height,
        nonce,
        exp_diff,
        block_weight,
        adaptive,
    )
}

pub fn initialize_data_manager(
    db_dir: &str, dbtype: DbType,
) -> (Arc<BlockDataManager>, Arc<Block>) {
    let ledger_db = db::open_database(
        db_dir,
        &db::db_config(
            Path::new(db_dir),
            Some(128),
            db::DatabaseCompactionProfile::default(),
            NUM_COLUMNS,
            false,
        ),
    )
    .map_err(|e| format!("Failed to open database {:?}", e))
    .unwrap();

    let worker_thread_pool = Arc::new(Mutex::new(ThreadPool::with_name(
        "Tx Recover".into(),
        WORKER_COMPUTATION_PARALLELISM,
    )));

    let storage_manager = Arc::new(
        StorageManager::new(StorageConfiguration::new_default(
            db_dir.to_string(),
        ))
        .expect("Failed to initialize storage."),
    );

    let mut genesis_accounts = HashMap::new();
    genesis_accounts.insert(
        Address::from_str("0000000000000000000000000000000000000008").unwrap(),
        U256::from(0),
    );

    let genesis_block = Arc::new(storage_manager.initialize(
        genesis_accounts,
        DEFAULT_MAX_BLOCK_GAS_LIMIT.into(),
        Address::from_str("0000000000000000000000000000000000000008").unwrap(),
        U256::from(10),
    ));

    let data_man = Arc::new(BlockDataManager::new(
        CacheConfig::default(),
        genesis_block.clone(),
        ledger_db.clone(),
        storage_manager,
        worker_thread_pool,
        DataManagerConfiguration::new(
            false,                          /* do not record transaction
                                             * address */
            Duration::from_millis(300_000), /* max cached tx count */
            dbtype,
        ),
    ));
    (data_man, genesis_block)
}

pub fn initialize_synchronization_graph_with_data_manager(
    data_man: Arc<BlockDataManager>, beta: u64, h: u64, tcr: u64, tcb: u64,
    era_epoch_count: u64,
) -> (Arc<SynchronizationGraph>, Arc<ConsensusGraph>)
{
    let txpool = Arc::new(TransactionPool::new(
        TxPoolConfig::default(),
        data_man.clone(),
    ));
    let statistics = Arc::new(Statistics::new());

    let vm = VmFactory::new(1024 * 32);
    let pow_config = ProofOfWorkConfig::new(
        true,  /* test_mode */
        false, /* use_stratum */
        Some(10),
        String::from(""), /* stratum_listen_addr */
        0,                /* stratum_port */
        None,             /* stratum_secret */
    );
    let sync_config = SyncGraphConfig {
        enable_state_expose: false,
        is_consortium: false,
    };
    let notifications = Notifications::init();
    let consensus = Arc::new(ConsensusGraph::new(
        ConsensusConfig {
            debug_dump_dir_invalid_state_root: "./invalid_state_root/"
                .to_string(),
            inner_conf: ConsensusInnerConfig {
                adaptive_weight_beta: beta,
                heavy_block_difficulty_ratio: h,
                timer_chain_block_difficulty_ratio: tcr,
                timer_chain_beta: tcb,
                era_epoch_count,
                enable_optimistic_execution: false,
                enable_state_expose: false,
            },
            bench_mode: true, /* Set bench_mode to true so that we skip
                               * execution */
        },
        vm.clone(),
        txpool.clone(),
        statistics.clone(),
        data_man.clone(),
        pow_config.clone(),
        notifications.clone(),
    ));

    let verification_config = VerificationConfig::new(true);
    let sync = Arc::new(SynchronizationGraph::new(
        consensus.clone(),
        verification_config,
        pow_config,
        sync_config,
        notifications,
        false,
    ));

    (sync, consensus)
}

/// This method is only used in tests and benchmarks.
pub fn initialize_synchronization_graph(
    db_dir: &str, beta: u64, h: u64, tcr: u64, tcb: u64, era_epoch_count: u64,
    dbtype: DbType,
) -> (
    Arc<SynchronizationGraph>,
    Arc<ConsensusGraph>,
    Arc<BlockDataManager>,
    Arc<Block>,
)
{
    let (data_man, genesis_block) = initialize_data_manager(db_dir, dbtype);

    let (sync, consensus) = initialize_synchronization_graph_with_data_manager(
        data_man.clone(),
        beta,
        h,
        tcr,
        tcb,
        era_epoch_count,
    );

    (sync, consensus, data_man, genesis_block)
}
