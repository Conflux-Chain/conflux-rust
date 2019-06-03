use cfx_types::{Address, H256, U256};
use cfxcore::{
    cache_manager::CacheManager,
    consensus::ConsensusGraph,
    pow::{ProofOfWorkConfig, WORKER_COMPUTATION_PARALLELISM},
    statistics::Statistics,
    storage::{state_manager::StorageConfiguration, StorageManager},
    sync::SynchronizationGraph,
    verification::VerificationConfig,
    vm_factory::VmFactory,
    TransactionPool,
};
use parking_lot::Mutex;
use primitives::{Block, BlockHeader, BlockHeaderBuilder};
use std::{path::Path, sync::Arc, thread, time};
use threadpool::ThreadPool;
use log4rs::{
    append::{console::ConsoleAppender, file::FileAppender},
    config::{Appender, Config as LogConfig, Logger, Root},
    encode::pattern::PatternEncoder,
};
use log::LevelFilter;

fn create_simple_block_impl(
    parent_hash: H256, ref_hashes: Vec<H256>, height: u64, nonce: u64,
    diff: U256,
) -> (H256, Block)
{
    let mut b = BlockHeaderBuilder::new();
    let header = b
        .with_parent_hash(parent_hash)
        .with_height(height)
        .with_referee_hashes(ref_hashes)
        .with_nonce(nonce)
        .with_difficulty(diff)
        .build();
    let block = Block::new(header, vec![]);
    (block.hash(), block)
}

fn create_simple_block(
    sync: Arc<SynchronizationGraph>,
    parent_hash: H256, ref_hashes: Vec<H256>,
) -> (H256, Block)
{
    let parent_header = sync.block_header_by_hash(&parent_hash).unwrap();
    let exp_diff = sync
        .inner
        .read()
        .expected_difficulty(&parent_hash);
    let nonce = sync.block_count() as u64 + 1;
    create_simple_block_impl(
        parent_hash,
        ref_hashes,
        parent_header.height() + 1,
        nonce,
        exp_diff,
    )
}

fn initialize_consensus_graph_for_test(
    genesis_block: Block, db_dir: &str,
) -> (Arc<SynchronizationGraph>, Arc<ConsensusGraph>) {
    let ledger_db = db::open_database(
        db_dir,
        &db::db_config(
            Path::new(db_dir),
            Some(128),
            db::DatabaseCompactionProfile::default(),
            Some(5),
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

    let mb = 1024 * 1024;
    let max_cache_size = 2048 * mb; // DEFAULT_LEDGER_CACHE_SIZE
    let pref_cache_size = max_cache_size * 3 / 4;

    let cache_man = Arc::new(Mutex::new(CacheManager::new(
        pref_cache_size,
        max_cache_size,
        3 * mb,
    )));

    let txpool = Arc::new(TransactionPool::with_capacity(
        500_000,
        storage_manager.clone(),
        worker_thread_pool.clone(),
        cache_man.clone(),
    ));
    let statistics = Arc::new(Statistics::new());

    let vm = VmFactory::new(1024 * 32);
    let pow_config = ProofOfWorkConfig::new(true, Some(10));
    let consensus = Arc::new(ConsensusGraph::with_genesis_block(
        genesis_block,
        storage_manager.clone(),
        vm.clone(),
        txpool.clone(),
        statistics.clone(),
        ledger_db.clone(),
        cache_man.clone(),
        pow_config.clone(),
        true,
        false,
        true, // Set bench_mode to true so that we skip execution
    ));

    let verification_config = VerificationConfig::new(true);
    let sync = Arc::new(SynchronizationGraph::new(
        consensus.clone(),
        verification_config,
        pow_config,
        true,
    ));

    (sync, consensus)
}

fn initialize_logger(log_file: &str, log_level: LevelFilter) {
    let log_config = {
        let mut conf_builder =
            LogConfig::builder().appender(Appender::builder().build(
                "stdout",
                Box::new(ConsoleAppender::builder().build()),
            ));
        let mut root_builder = Root::builder().appender("stdout");
        conf_builder =
            conf_builder.appender(Appender::builder().build(
                "logfile",
                Box::new(
                    FileAppender::builder().encoder(Box::new(PatternEncoder::new("{d} {h({l}):5.5} {T:<20.20} {t:12.12} - {m}{n}"))).build("./__consensus_bench.log").unwrap(),
                ),
            ));
        root_builder = root_builder.appender("logfile");
        // Should add new crate names here
        for crate_name in [
            "blockgen",
            "cfxcore",
            "conflux",
            "db",
            "keymgr",
            "network",
            "txgen",
            "client",
            "primitives",
        ]
            .iter()
            {
                conf_builder = conf_builder.logger(
                    Logger::builder()
                        .build(*crate_name, LevelFilter::Info),
                );
            }
        conf_builder
            .build(root_builder.build(LevelFilter::Info))
            .unwrap()
    };

    log4rs::init_config(log_config).unwrap();
}

fn main() {
    // initialize_logger("./__consensus_bench.log", LevelFilter::Info);

    let (genesis_hash, genesis_block) =
        create_simple_block_impl(H256::default(), vec![], 0, 0, U256::from(10));

    let (sync, consensus) = initialize_consensus_graph_for_test(
        genesis_block,
        "./__consensus_bench_db",
    );

    let mut last_hash = genesis_hash;
    let start_time = time::SystemTime::now();
    for i in 0..10000 {
        let (new_hash, mut new_block) =
            create_simple_block(sync.clone(), last_hash, vec![]);
        sync.insert_block_header(&mut new_block.block_header, false, true);
        sync.insert_block(new_block, false, false, false);
        last_hash = new_hash;
    }

    while sync.block_count() != consensus.block_count() {
        thread::sleep(time::Duration::from_millis(50));
    }

    println!("Block count: {}", consensus.block_count());
    println!("Pivot chain hash: {}", consensus.best_block_hash());
    println!("Last block hash: {}", last_hash);
    println!("Elapsed {}", start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0);
}
