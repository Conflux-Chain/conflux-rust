// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![allow(unused)]
use cfx_types::{Address, H256, U256};
use cfxcore::{
    block_data_manager::BlockDataManager,
    cache_manager::CacheManager,
    consensus::{
        ConsensusConfig, ConsensusGraph, ConsensusInnerConfig,
        ADAPTIVE_WEIGHT_DEFAULT_ALPHA_DEN, ADAPTIVE_WEIGHT_DEFAULT_ALPHA_NUM,
        ADAPTIVE_WEIGHT_DEFAULT_BETA,
    },
    pow::{ProofOfWorkConfig, WORKER_COMPUTATION_PARALLELISM},
    statistics::Statistics,
    storage::{state_manager::StorageConfiguration, StorageManager},
    sync::{
        request_manager::tx_handler::ReceivedTransactionContainer,
        SynchronizationGraph,
    },
    verification::VerificationConfig,
    vm_factory::VmFactory,
    TransactionPool,
};
use log::LevelFilter;
use log4rs::{
    append::{console::ConsoleAppender, file::FileAppender},
    config::{Appender, Config as LogConfig, Logger, Root},
    encode::pattern::PatternEncoder,
};
use parking_lot::{Mutex, RwLock};
use primitives::{Block, BlockHeader, BlockHeaderBuilder};
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    path::Path,
    str::FromStr,
    sync::Arc,
    thread, time,
};
use threadpool::ThreadPool;

fn create_simple_block_impl(
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

fn create_simple_block(
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

fn initialize_consensus_graph_for_test(
    genesis_block: Block, db_dir: &str, alpha_den: u64, alpha_num: u64,
    beta: u64, h: u64, era_epoch_count: u64,
) -> (Arc<SynchronizationGraph>, Arc<ConsensusGraph>)
{
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

    let data_man = Arc::new(BlockDataManager::new(
        Arc::new(genesis_block),
        ledger_db.clone(),
        storage_manager,
        cache_man,
        false,
    ));

    let txpool = Arc::new(TransactionPool::with_capacity(
        500_000,
        worker_thread_pool.clone(),
        data_man.clone(),
    ));
    let statistics = Arc::new(Statistics::new());

    let vm = VmFactory::new(1024 * 32);
    let pow_config = ProofOfWorkConfig::new(true, Some(10));
    let consensus = Arc::new(ConsensusGraph::with_genesis_block(
        ConsensusConfig {
            debug_dump_dir_invalid_state_root: "./invalid_state_root/"
                .to_string(),
            inner_conf: ConsensusInnerConfig {
                adaptive_weight_alpha_num: alpha_num,
                adaptive_weight_alpha_den: alpha_den,
                adaptive_weight_beta: beta,
                heavy_block_difficulty_ratio: h,
                era_epoch_count,
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
        let mut conf_builder = LogConfig::builder().appender(
            Appender::builder()
                .build("stdout", Box::new(ConsoleAppender::builder().build())),
        );
        let mut root_builder = Root::builder().appender("stdout");
        conf_builder = conf_builder.appender(
            Appender::builder().build(
                "logfile",
                Box::new(
                    FileAppender::builder()
                        .encoder(Box::new(PatternEncoder::new(
                            "{d} {h({l}):5.5} {T:<20.20} {t:12.12} - {m}{n}",
                        )))
                        .build("./__consensus_bench.log")
                        .unwrap(),
                ),
            ),
        );
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
            conf_builder = conf_builder
                .logger(Logger::builder().build(*crate_name, log_level));
        }
        conf_builder.build(root_builder.build(log_level)).unwrap()
    };

    log4rs::init_config(log_config).unwrap();
}

fn check_results(
    start: usize, end: usize, consensus: Arc<ConsensusGraph>,
    hashes: &Vec<H256>, valid_indices: &HashMap<usize, i32>,
    stable_indices: &HashMap<usize, i32>,
    adaptive_indices: &HashMap<usize, i32>,
)
{
    for i in start..end {
        let pending = consensus.inner.read().is_pending(&hashes[i]);
        if pending == None {
            //println!("Block {} is skipped!", i);
            continue;
        }
        if let Some(true) = pending {
            println!("Block {} is pending, skip the checking!", i);
            continue;
        }
        let partial_invalid = consensus
            .inner
            .read()
            .is_partial_invalid(&hashes[i])
            .unwrap();
        let valid = *valid_indices.get(&i).unwrap();
        let invalid = (valid == 0);
        if valid != -1 {
            assert!(partial_invalid == invalid, "Block {} partial invalid status: Consensus graph {} != actual {}", i, partial_invalid, invalid);
        }
        let stable0 = consensus.inner.read().is_stable(&hashes[i]).unwrap();
        let stable_v = *stable_indices.get(&i).unwrap();
        if !invalid && stable_v != -1 {
            let stable1 = (stable_v == 1);
            assert!(
                stable0 == stable1,
                "Block {} stable status: Consensus graph {} != actual {}",
                i,
                stable0,
                stable1
            );
        }
        let adaptive0 = consensus.inner.read().is_adaptive(&hashes[i]).unwrap();
        let adaptive_v = *adaptive_indices.get(&i).unwrap();
        if !invalid && adaptive_v != -1 {
            let adaptive1 = (adaptive_v == 1);
            assert!(
                adaptive0 == adaptive1,
                "Block {} adaptive status: Consensus graph {} != actual {}",
                i,
                adaptive0,
                adaptive1
            );
        }
    }
}

fn main() {
    // initialize_logger("./__consensus_bench.log", LevelFilter::Debug);

    let args: Vec<String> = env::args().collect();
    let mut input_file = "./seq.in";
    if args.len() >= 2 {
        input_file = &*args[1];
    }
    let db_dir = "./__consensus_bench_db";

    // Parse adaptive weight parameters
    let content = fs::read_to_string(input_file)
        .expect("Cannot open the block sequence input file!");
    let mut lines = content.split("\n");
    let line = lines.next().unwrap();
    let mut tokens = line.split_whitespace();
    let alpha_num = u64::from_str(tokens.next().unwrap())
        .expect("Cannot parse the input file!");
    let alpha_den = u64::from_str(tokens.next().unwrap())
        .expect("Cannot parse the input file!");
    let beta = u64::from_str(tokens.next().unwrap())
        .expect("Cannot parse the input file!");
    let h_ratio = u64::from_str(tokens.next().unwrap())
        .expect("Cannot parse the input file!");
    let era_epoch_count = u64::from_str(tokens.next().unwrap())
        .expect("Cannot parse the input file!");
    println!(
        "alpha = {}/{} beta = {} h = {} era_epoch_count = {}",
        alpha_num, alpha_den, beta, h_ratio, era_epoch_count
    );

    let (genesis_hash, genesis_block) = create_simple_block_impl(
        H256::default(),
        vec![],
        0,
        0,
        U256::from(10),
        1,
    );

    let (sync, consensus) = initialize_consensus_graph_for_test(
        genesis_block.clone(),
        db_dir,
        alpha_den,
        alpha_num,
        beta,
        h_ratio,
        era_epoch_count,
    );

    let mut hashes = Vec::new();
    hashes.push(genesis_block.hash());

    let start_time = time::SystemTime::now();
    let mut last_check_time = start_time;
    let mut last_consensus_block_cnt = consensus.block_count();
    let mut valid_indices = HashMap::new();
    let mut stable_indices = HashMap::new();
    let mut adaptive_indices = HashMap::new();
    let mut check_batch_size = era_epoch_count as usize;
    let mut last_checked = 1;

    for s in lines {
        if s.starts_with("//") {
            continue;
        }
        let tokens = s.split_whitespace();
        let mut cnt = 0;
        let mut parent_idx = 0;
        let mut ref_idxs = Vec::new();
        let mut is_valid = 0;
        let mut is_stable = 0;
        let mut is_adaptive = 0;
        let mut block_weight = 1;
        for w in tokens {
            if cnt == 0 {
                is_valid =
                    i32::from_str(w).expect("Cannot parse the input file!");
            } else if cnt == 1 {
                is_stable =
                    i32::from_str(w).expect("Cannot parse the input file!");
            } else if cnt == 2 {
                is_adaptive =
                    i32::from_str(w).expect("Cannot parse the input file!");
            } else if cnt == 3 {
                block_weight =
                    u32::from_str(w).expect("Cannot parse the input file!");
            } else if cnt == 4 {
                parent_idx =
                    usize::from_str(w).expect("Cannot parse the input file!");
            } else {
                let ref_idx =
                    usize::from_str(w).expect("Cannot parse the input file!");
                ref_idxs.push(ref_idx);
            }
            cnt += 1;
        }
        if cnt == 0 {
            continue;
        }
        let idx = hashes.len();
        valid_indices.insert(idx, is_valid);
        stable_indices.insert(idx, is_stable);
        adaptive_indices.insert(idx, is_adaptive);
        let mut ref_hashes = Vec::new();
        for ref_idx in ref_idxs.iter() {
            ref_hashes.push(hashes[*ref_idx]);
        }
        let (new_hash, mut new_block) = create_simple_block(
            sync.clone(),
            hashes[parent_idx],
            ref_hashes,
            block_weight,
        );
        hashes.push(new_hash);
        sync.insert_block_header(&mut new_block.block_header, false, true);
        sync.insert_block(new_block, false, false, false);
        if last_check_time.elapsed().unwrap().as_secs() >= 5 {
            let last_time_elapsed =
                last_check_time.elapsed().unwrap().as_millis() as f64 / 1_000.0;
            last_check_time = time::SystemTime::now();
            let consensus_block_cnt = hashes.len();
            println!(
                "Consensus count {}, Consensus block {}/s, Elapsed {}",
                consensus_block_cnt,
                (consensus_block_cnt - last_consensus_block_cnt) as f64
                    / last_time_elapsed,
                start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0
            );
            last_consensus_block_cnt = consensus_block_cnt;
        }

        let n = hashes.len();
        if (n != 0) && (n % check_batch_size == 0) {
            let last_hash = hashes[n - 1];
            while consensus.get_total_processed_blocks() != n {
                thread::sleep(time::Duration::from_millis(100));
            }
            check_results(
                last_checked,
                n,
                consensus.clone(),
                &hashes,
                &valid_indices,
                &stable_indices,
                &adaptive_indices,
            );
            last_checked = n;
        }
    }

    let n = hashes.len();
    let last_hash = hashes[n - 1];
    while consensus.get_total_processed_blocks() != n {
        if last_check_time.elapsed().unwrap().as_secs() >= 5 {
            let last_time_elapsed =
                last_check_time.elapsed().unwrap().as_millis() as f64 / 1_000.0;
            last_check_time = time::SystemTime::now();
            let consensus_block_cnt = hashes.len();
            println!(
                "Consensus count {}, Consensus block {}/s, Elapsed {}",
                consensus_block_cnt,
                (consensus_block_cnt - last_consensus_block_cnt) as f64
                    / last_time_elapsed,
                start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0
            );
            last_consensus_block_cnt = consensus_block_cnt;
        }
        thread::sleep(time::Duration::from_millis(100));
    }
    check_results(
        last_checked,
        n,
        consensus.clone(),
        &hashes,
        &valid_indices,
        &stable_indices,
        &adaptive_indices,
    );

    println!("Total Block count: {}", n);
    println!("Final Consensus Block count: {}", consensus.block_count());
    println!("Pivot chain hash: {}", consensus.best_block_hash());
    println!("Last block hash: {}", hashes[hashes.len() - 1]);
    println!(
        "Elapsed {}",
        start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0
    );
}
