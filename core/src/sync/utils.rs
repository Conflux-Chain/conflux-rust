use crate::{
    block_data_manager::{BlockDataManager, DataManagerConfiguration, DbType},
    cache_config::CacheConfig,
    consensus::{ConsensusConfig, ConsensusInnerConfig},
    db::NUM_COLUMNS,
    parameters::{
        consensus::ERA_DEFAULT_CHECKPOINT_GAP, WORKER_COMPUTATION_PARALLELISM,
    },
    pow::ProofOfWorkConfig,
    state_exposer::{SharedStateExposer, StateExposer},
    statistics::Statistics,
    storage::{state_manager::StorageConfiguration, StorageManager},
    sync::SynchronizationGraph,
    transaction_pool::DEFAULT_MAX_BLOCK_GAS_LIMIT,
    verification::VerificationConfig,
    vm_factory::VmFactory,
    ConsensusGraph, TransactionPool,
};
use cfx_types::{Address, H256, U256};
use core::str::FromStr;
use parking_lot::Mutex;
use primitives::{Block, BlockHeaderBuilder};
use std::{collections::HashMap, path::Path, sync::Arc};
use threadpool::ThreadPool;

pub fn create_simple_block_impl(
    parent_hash: H256, ref_hashes: Vec<H256>, height: u64, nonce: u64,
    diff: U256, block_weight: u32,
) -> (H256, Block)
{
    let mut b = BlockHeaderBuilder::new();
    let mut header = b
        .with_parent_hash(parent_hash)
        .with_height(height)
        .with_referee_hashes(ref_hashes)
        .with_nonce(nonce)
        .with_difficulty(diff)
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
    block_weight: u32,
) -> (H256, Block)
{
    //    sync.consensus.wait_for_generation(&parent_hash);
    let parent_header = sync.block_header_by_hash(&parent_hash).unwrap();
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
        parent_header.height() + 1,
        nonce,
        exp_diff,
        block_weight,
    )
}

pub fn initialize_synchronization_graph(
    db_dir: &str, alpha_den: u64, alpha_num: u64, beta: u64, h: u64,
    era_epoch_count: u64,
) -> (Arc<SynchronizationGraph>, Arc<ConsensusGraph>, Arc<Block>)
{
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

    let storage_manager = Arc::new(StorageManager::new(
        ledger_db.clone(),
        StorageConfiguration::default(),
    ));

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
            false,  /* do not record transaction address */
            250000, /* max cached tx count */
            DbType::Rocksdb,
        ),
    ));

    let txpool =
        Arc::new(TransactionPool::with_capacity(500_000, data_man.clone()));
    let statistics = Arc::new(Statistics::new());
    let state_exposer = SharedStateExposer::new(StateExposer::new());

    let vm = VmFactory::new(1024 * 32);
    let pow_config = ProofOfWorkConfig::new(
        true,  /* test_mode */
        false, /* use_stratum */
        Some(10),
        String::from(""), /* stratum_listen_addr */
        0,                /* stratum_port */
        None,             /* stratum_secret */
    );
    let consensus = Arc::new(ConsensusGraph::new(
        ConsensusConfig {
            debug_dump_dir_invalid_state_root: "./invalid_state_root/"
                .to_string(),
            inner_conf: ConsensusInnerConfig {
                adaptive_weight_alpha_num: alpha_num,
                adaptive_weight_alpha_den: alpha_den,
                adaptive_weight_beta: beta,
                heavy_block_difficulty_ratio: h,
                era_epoch_count,
                era_checkpoint_gap: ERA_DEFAULT_CHECKPOINT_GAP,
                enable_optimistic_execution: false,
            },
            bench_mode: true, /* Set bench_mode to true so that we skip
                               * execution */
        },
        vm.clone(),
        txpool.clone(),
        statistics.clone(),
        data_man.clone(),
        pow_config.clone(),
        state_exposer.clone(),
    ));

    let verification_config = VerificationConfig::new(true);
    let sync = Arc::new(SynchronizationGraph::new(
        consensus.clone(),
        verification_config,
        pow_config,
        false,
    ));

    (sync, consensus, genesis_block)
}
