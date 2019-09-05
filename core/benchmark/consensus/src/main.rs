// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![allow(unused)]
use cfx_types::{Address, H256, U256};
use cfxcore::{
    block_data_manager::{BlockDataManager, DataManagerConfiguration},
    cache_config::CacheConfig,
    cache_manager::CacheManager,
    consensus::{ConsensusConfig, ConsensusGraph, ConsensusInnerConfig},
    consensus_parameters::*,
    db::NUM_COLUMNS,
    pow::ProofOfWorkConfig,
    statistics::Statistics,
    storage::{state_manager::StorageConfiguration, StorageManager},
    sync::{
        request_manager::tx_handler::ReceivedTransactionContainer,
        utils::{
            create_simple_block, create_simple_block_impl,
            initialize_synchronization_graph,
        },
        SynchronizationGraph,
    },
    transaction_pool::DEFAULT_MAX_BLOCK_GAS_LIMIT,
    verification::VerificationConfig,
    vm_factory::VmFactory,
    TransactionPool, WORKER_COMPUTATION_PARALLELISM,
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

    let (sync, consensus, genesis_block) = initialize_synchronization_graph(
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
        sync.insert_block_header(
            &mut new_block.block_header,
            false, // need_to_verify
            true,  // bench_mode
            false, // insert_to_consensus
            true,  // persistent
        );
        sync.insert_block(
            new_block, false, /* need_to_verify */
            false, /* persistent */
            false, /* recover_from_db */
        );
        if last_check_time.elapsed().unwrap().as_secs() >= 5 {
            let last_time_elapsed =
                last_check_time.elapsed().unwrap().as_millis() as f64 / 1_000.0;
            last_check_time = time::SystemTime::now();
            let consensus_block_cnt =
                consensus.get_processed_block_count() as u64;
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
            while consensus.get_processed_block_count() != n - 1 {
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
    while consensus.get_processed_block_count() != n - 1 {
        if last_check_time.elapsed().unwrap().as_secs() >= 5 {
            let last_time_elapsed =
                last_check_time.elapsed().unwrap().as_millis() as f64 / 1_000.0;
            last_check_time = time::SystemTime::now();
            let consensus_block_cnt =
                consensus.get_processed_block_count() as u64;
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
