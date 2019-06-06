// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![allow(unused)]
use cfx_types::{Address, H256, U256};
use cfxcore::{
    cache_manager::CacheManager,
    consensus::{ConsensusConfig, ConsensusGraph},
    consensus::ConsensusInnerConfig,
    consensus::ADAPTIVE_WEIGHT_DEFAULT_ALPHA_DEN,
    consensus::ADAPTIVE_WEIGHT_DEFAULT_ALPHA_NUM,
    consensus::ADAPTIVE_WEIGHT_DEFAULT_BETA,
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
use std::fs;
use std::str::FromStr;
use std::env;
use std::collections::HashSet;

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
        ConsensusConfig {
            debug_dump_dir_invalid_state_root: "./invalid_state_root/".to_string(),
            record_tx_address: true,
            inner_conf: ConsensusInnerConfig {
                adaptive_weight_alpha_num: ADAPTIVE_WEIGHT_DEFAULT_ALPHA_NUM,
                adaptive_weight_alpha_den: ADAPTIVE_WEIGHT_DEFAULT_ALPHA_DEN,
                adaptive_weight_beta: ADAPTIVE_WEIGHT_DEFAULT_BETA,
                enable_optimistic_execution: false,
            },
            bench_mode: true, // Set bench_mode to true so that we skip execution
        },
        genesis_block,
        storage_manager.clone(),
        vm.clone(),
        txpool.clone(),
        statistics.clone(),
        ledger_db.clone(),
        cache_man.clone(),
        pow_config.clone(),
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

    let args: Vec<String> = env::args().collect();
    let mut input_file = "./seq.in";
    if args.len() >= 2 {
        input_file = &*args[1];
    }
    let db_dir = "./__consensus_bench_db";

    let (genesis_hash, genesis_block) =
        create_simple_block_impl(H256::default(), vec![], 0, 0, U256::from(10));

    let (sync, consensus) = initialize_consensus_graph_for_test(
        genesis_block.clone(),
        db_dir,
    );

    let mut hashes = Vec::new();
    hashes.push(genesis_block.hash());
    let content = fs::read_to_string(input_file).expect("Cannot open the block sequence input file!");
    let lines = content.split("\n");

    let start_time = time::SystemTime::now();
    let mut last_check_time = start_time;
    let mut last_sync_block_cnt = sync.block_count();
    let mut last_consensus_block_cnt = consensus.block_count();
    let mut valid_indices = HashSet::new();
    for s in lines {
        if s.starts_with("//") {
            continue;
        }
        let tokens = s.split_whitespace();
        let mut cnt = 0;
        let mut parent_idx = 0;
        let mut ref_idxs = Vec::new();
        let mut is_valid = 0;
        for w in tokens {
            if cnt == 0 {
                is_valid = u32::from_str(w).expect("Cannot parse the input file!");
            } else if cnt == 1 {
                parent_idx = usize::from_str(w).expect("Cannot parse the input file!");
            } else {
                let ref_idx = usize::from_str(w).expect("Cannot parse the input file!");
                ref_idxs.push(ref_idx);
            }
            cnt += 1;
        }
        if cnt == 0 {
            continue;
        }
        if is_valid == 1 {
            valid_indices.insert(hashes.len());
        }
        let mut ref_hashes = Vec::new();
        for ref_idx in ref_idxs.iter() {
            ref_hashes.push(hashes[*ref_idx]);
        }
        let (new_hash, mut new_block) =
            create_simple_block(sync.clone(), hashes[parent_idx], ref_hashes);
        hashes.push(new_hash);
        sync.insert_block_header(&mut new_block.block_header, false, true);
        sync.insert_block(new_block, false, false, false);
        if last_check_time.elapsed().unwrap().as_secs() >= 5 {
            let last_time_elapsed = last_check_time.elapsed().unwrap().as_millis() as f64 / 1_000.0;
            last_check_time = time::SystemTime::now();
            let sync_block_cnt = sync.block_count();
            let consensus_block_cnt = consensus.block_count();
            println!("Sync count {}, Consensus count {}, Sync block {}/s, Consensus block {}/s, Elapsed {}",
                     sync_block_cnt, consensus_block_cnt,
                     (sync_block_cnt - last_sync_block_cnt) as f64 / last_time_elapsed,
                     (consensus_block_cnt - last_consensus_block_cnt) as f64 / last_time_elapsed,
                     start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0);
            last_sync_block_cnt = sync_block_cnt;
            last_consensus_block_cnt = consensus_block_cnt;
        }
    }

    while sync.block_count() != consensus.block_count() {
        if last_check_time.elapsed().unwrap().as_secs() >= 5 {
            let last_time_elapsed = last_check_time.elapsed().unwrap().as_millis() as f64 / 1_000.0;
            last_check_time = time::SystemTime::now();
            let consensus_block_cnt = consensus.block_count();
            println!("Consensus count {}, Consensus block {}/s, Elapsed {}",
                     consensus_block_cnt,
                     (consensus_block_cnt - last_consensus_block_cnt) as f64 / last_time_elapsed,
                     start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0);
            last_consensus_block_cnt = consensus_block_cnt;
        }
        thread::sleep(time::Duration::from_millis(100));
    }

    println!("Block count: {}", consensus.block_count());
    println!("Pivot chain hash: {}", consensus.best_block_hash());
    println!("Last block hash: {}", hashes[hashes.len() - 1]);
    println!("Elapsed {}", start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0);

    let n = hashes.len();
    for i in 1..n {
        let partial_invalid = consensus.inner.read().is_partial_invalid(&hashes[i]).unwrap();
        let invalid = !valid_indices.contains(&i);
        assert!(partial_invalid == invalid, "Block {} partial invalid status: Consensus graph {} != actual {}", i, partial_invalid, invalid);
    }

}
