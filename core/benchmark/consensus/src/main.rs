// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::H256;
use cfxcore::{
    block_data_manager::DbType,
    consensus::{ConsensusGraph, ConsensusGraphTrait},
    pow::PowComputer,
    sync::utils::{
        create_simple_block, initialize_synchronization_graph,
        initialize_synchronization_graph_with_data_manager,
    },
};
use log::LevelFilter;
use log4rs::{
    append::{console::ConsoleAppender, file::FileAppender},
    config::{Appender, Config as LogConfig, Logger, Root},
    encode::pattern::PatternEncoder,
};
use std::{
    collections::HashMap, env, fs, str::FromStr, sync::Arc, thread, time,
};

pub const CHECKER_SLEEP_PERIOD: u64 = 50;

fn initialize_logger(_log_file: &str, log_level: LevelFilter) {
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
    timer_indices: &HashMap<usize, i32>,
    adaptive_indices: &HashMap<usize, i32>,
)
{
    let mut pending_cnt = 0;
    let consensus_read = consensus.inner.read();
    for i in start..end {
        let pending = consensus_read.is_pending(&hashes[i]);
        if pending == None {
            //println!("Block {} is skipped!", i);
            continue;
        }
        if let Some(true) = pending {
            pending_cnt += 1;
            continue;
        }
        let partial_invalid_opt = consensus_read.is_partial_invalid(&hashes[i]);
        // This one is outside the era and eliminated. We will skip and count it
        // as pending as well.
        if partial_invalid_opt.is_none() {
            pending_cnt += 1;
            continue;
        }
        let partial_invalid = partial_invalid_opt.unwrap();
        let valid = *valid_indices.get(&i).unwrap();
        let invalid = valid == 0;
        if valid != -1 {
            assert!(partial_invalid == invalid, "Block {} {} partial invalid status: Consensus graph {} != actual {}", i, hashes[i], partial_invalid, invalid);
        }
        let timer0 = consensus_read.is_timer_block(&hashes[i]).unwrap();
        let timer_v = *timer_indices.get(&i).unwrap();
        if !invalid && timer_v != -1 {
            let timer1 = timer_v == 1;
            assert!(
                timer0 == timer1,
                "Block {} {} timer status: Consensus graph {} != actual {}",
                i,
                hashes[i],
                timer0,
                timer1
            );
        }
        let adaptive0 = consensus_read.is_adaptive(&hashes[i]).unwrap();
        let adaptive_v = *adaptive_indices.get(&i).unwrap();
        if !invalid && adaptive_v != -1 {
            let adaptive1 = adaptive_v == 1;
            assert!(
                adaptive0 == adaptive1,
                "Block {} {} adaptive status: Consensus graph {} != actual {}",
                i,
                hashes[i],
                adaptive0,
                adaptive1
            );
        }
    }
    if pending_cnt > 0 {
        println!(
            "There are {} blocks pending, skipped checking.",
            pending_cnt
        );
    }
}

fn main() {
    if let Ok(_) = env::var("DEBUGLOG") {
        initialize_logger("./__consensus_bench.log", LevelFilter::Debug);
    }

    let args: Vec<String> = env::args().collect();
    let mut input_file = "./seq.in";
    if args.len() >= 2 {
        input_file = &*args[1];
    }
    let db_dir = "./__consensus_bench_db";

    // Parse adaptive weight parameters
    let content = fs::read_to_string(input_file)
        .expect("Cannot open the block sequence input file!");
    let mut lines = content.split('\n');
    let line = lines.next().unwrap();
    let mut tokens = line.split_whitespace();
    let timer_ratio = u64::from_str(tokens.next().unwrap())
        .expect("Cannot parse the input file!");
    let timer_beta = u64::from_str(tokens.next().unwrap())
        .expect("Cannot parse the input file!");
    let beta = u64::from_str(tokens.next().unwrap())
        .expect("Cannot parse the input file!");
    let h_ratio = u64::from_str(tokens.next().unwrap())
        .expect("Cannot parse the input file!");
    let era_epoch_count = u64::from_str(tokens.next().unwrap())
        .expect("Cannot parse the input file!");
    println!(
        "timer_ratio = {}, timer_beta = {}, beta = {} h = {} era_epoch_count = {}",
        timer_ratio, timer_beta, beta, h_ratio, era_epoch_count
    );

    let (sync, consensus, data_man, genesis_block) =
        initialize_synchronization_graph(
            db_dir,
            beta,
            h_ratio,
            timer_ratio,
            timer_beta,
            era_epoch_count,
            DbType::Sqlite,
        );

    let mut hashes = Vec::new();
    hashes.push(genesis_block.hash());

    let start_time = time::SystemTime::now();
    let mut last_check_time = start_time;
    let mut last_consensus_block_cnt = consensus.block_count();
    let mut valid_indices = HashMap::new();
    let mut stable_indices = HashMap::new();
    let mut adaptive_indices = HashMap::new();
    let mut block_heights = Vec::new();
    block_heights.push(0);
    let mut blocks = Vec::new();
    blocks.push((*genesis_block).clone());
    let check_batch_size = era_epoch_count as usize;
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
        let adaptive_fill = is_adaptive == 1;
        let parent_height = block_heights[parent_idx];
        let height = parent_height + 1;
        block_heights.push(height);
        let (new_hash, mut new_block) = create_simple_block(
            sync.clone(),
            hashes[parent_idx],
            ref_hashes,
            height,
            block_weight,
            adaptive_fill,
        );
        hashes.push(new_hash);
        sync.insert_block_header(
            &mut new_block.block_header,
            false, // need_to_verify
            true,  // bench_mode
            false, // insert_to_consensus
            true,  // persistent
        );
        blocks.push(new_block.clone());
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
            let checked_count = consensus.get_processed_block_count();
            if checked_count != n - 1 {
                thread::sleep(time::Duration::from_millis(
                    CHECKER_SLEEP_PERIOD,
                ));
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
            last_checked = checked_count + 1;
        }
    }

    let n = hashes.len();
    while sync.is_consensus_worker_busy() {
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
        thread::sleep(time::Duration::from_millis(CHECKER_SLEEP_PERIOD));
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

    let genesis_hash = data_man.get_cur_consensus_era_genesis_hash();
    let stable_hash = data_man.get_cur_consensus_era_stable_hash();

    if genesis_hash == genesis_block.block_header.hash() {
        println!("No checkpoint created, test finished!");
        return;
    }

    data_man.initialize_instance_id();

    let pow = Arc::new(PowComputer::new(true));
    let (_sync_n, consensus_n) =
        initialize_synchronization_graph_with_data_manager(
            data_man,
            beta,
            h_ratio,
            timer_ratio,
            timer_beta,
            era_epoch_count,
            pow,
        );

    println!("Checkpoint generated in the process. Going to test the last checkpoint recovery, genesis hash {} stable hash {}.", genesis_hash, stable_hash);
    let mut encounter_genesis = false;
    let mut genesis_idx = 0;
    for i in 0..blocks.len() {
        if blocks[i].block_header.hash() == genesis_hash {
            encounter_genesis = true;
            genesis_idx = i;
            println!(
                "Going to check the recovery phase with genesis at index {}",
                i
            );
        }
        if encounter_genesis == false {
            continue;
        }
        if genesis_idx != i {
            let h = blocks[i].hash();
            consensus_n.on_new_block(&h, true, false);
        }
    }

    println!("Waiting for the last phase being processed again...");
    while consensus_n.get_processed_block_count()
        != blocks.len() - genesis_idx - 1
    {
        println!(
            "Processed count {} / {}",
            consensus_n.get_processed_block_count(),
            blocks.len() - genesis_idx - 1
        );
        thread::sleep(time::Duration::from_millis(CHECKER_SLEEP_PERIOD));
    }
    check_results(
        genesis_idx + 1,
        blocks.len(),
        consensus_n.clone(),
        &hashes,
        &valid_indices,
        &stable_indices,
        &adaptive_indices,
    );
    println!("Done!");
}
