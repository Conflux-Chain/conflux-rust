// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfxcore::sync::utils::{
    create_simple_block, initialize_synchronization_graph,
};
use std::{env, str::FromStr, thread, time};

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut alpha_num = 2;
    let mut alpha_den = 3;
    let mut beta = 150;
    let mut h_ratio = 10;
    let mut era_epoch_count: usize = 50000;
    if args.len() >= 6 {
        alpha_num =
            u64::from_str(&args[1]).expect("Cannot parse the input file!");
        alpha_den =
            u64::from_str(&args[2]).expect("Cannot parse the input file!");
        beta = u64::from_str(&args[3]).expect("Cannot parse the input file!");
        h_ratio =
            u64::from_str(&args[4]).expect("Cannot parse the input file!");
        era_epoch_count = u64::from_str(&args[5])
            .expect("Cannot parse the input file!")
            as usize;
    }
    let db_dir = "./__consensus_attack_db";

    println!(
        "alpha = {}/{} beta = {} h = {} era_epoch_count = {}",
        alpha_num, alpha_den, beta, h_ratio, era_epoch_count
    );
    let start_time = time::SystemTime::now();

    let (sync, consensus, genesis_block) = initialize_synchronization_graph(
        db_dir,
        alpha_den,
        alpha_num,
        beta,
        h_ratio,
        era_epoch_count as u64,
    );

    let mut hashes = Vec::new();
    hashes.push(genesis_block.hash());

    println!(
        "{} blocks inserted len={}, elapsed={}",
        consensus.get_processed_block_count(),
        hashes.len(),
        start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0
    );

    // Assume that honest nodes take control of 70% and tha bad nodes take the
    // rest 30%. In average, if all the nodes are honest, the number of blocks
    // in each epoch are about 10. So in an era, about 50w blocks are mined by
    // honest nodes, and about 21w blocks are mined by bad nodes.
    // Let `block[i]` be the `i`-th blocks among the 21w blocks, if
    // `block[i].parent = block[1].hash` and `block[i].referee = vec![block[i -
    // 1].hash]`, we can build a graph such that the total size of
    // `blockset_in_own_view_of_epoch` in each block will be (21w + 1) * 21w / 2
    // ≈ 22 billion and the memory usage is about 164GB
    for i in 1..era_epoch_count {
        let (new_hash, mut new_block) =
            create_simple_block(sync.clone(), hashes[i - 1], Vec::new(), 1);
        hashes.push(new_hash);
        sync.insert_block_header(
            &mut new_block.block_header,
            false, // need_to_verify
            true,  // bench_mode
            false, // insert_to_consensus
            true,  // persistent
        );
        sync.insert_block(new_block, false, false, false);
    }
    while consensus.get_processed_block_count() != era_epoch_count - 1 {
        thread::sleep(time::Duration::from_millis(100));
    }
    println!(
        "{} blocks inserted len={}, elapsed={}",
        consensus.get_processed_block_count(),
        hashes.len(),
        start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0
    );
    for i in era_epoch_count..era_epoch_count * 10 / 7 * 3 {
        let ref_hashes = {
            if i == era_epoch_count {
                Vec::new()
            } else {
                vec![hashes[i - 1]]
            }
        };
        let (new_hash, mut new_block) =
            create_simple_block(sync.clone(), hashes[2], ref_hashes, 1);
        hashes.push(new_hash);
        sync.insert_block_header(
            &mut new_block.block_header,
            false, // need_to_verify
            true,  // bench_mode
            false, // insert_to_consensus
            true,  // persistent
        );
        sync.insert_block(new_block, false, false, false);
        if (i - era_epoch_count + 1) % 10000 == 0 {
            while consensus.get_processed_block_count() != i {
                thread::sleep(time::Duration::from_millis(100));
            }
            println!(
                "{} blocks inserted, elapsed {}",
                i,
                start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0
            );
        }
    }
    println!(
        "{} blocks inserted len={}, elapsed={}",
        consensus.get_processed_block_count(),
        hashes.len(),
        start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0
    );
}
