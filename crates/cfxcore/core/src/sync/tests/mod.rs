// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::DbType,
    sync::{
        utils::{create_simple_block_impl, initialize_synchronization_graph},
        SynchronizationGraphNode,
    },
};
use cfx_types::{BigEndianHash, H256, U256};
use primitives::Block;
use std::{
    fs,
    sync::Arc,
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[test]
fn test_remove_expire_blocks() {
    {
        let (sync, _, _, _) = initialize_synchronization_graph(
            "./test.db/",
            1,
            1,
            1,
            1,
            50000,
            DbType::Rocksdb,
        );
        // test initialization
        {
            let inner = sync.inner.read();
            assert!(inner.arena.len() == 1);
            assert!(inner.hash_to_arena_indices.len() == 1);
            assert!(inner.not_ready_blocks_frontier.len() == 0);
        }

        // prepare graph data
        {
            let mut blocks: Vec<Block> = Vec::new();
            let parent: Vec<i64> =
                vec![-1, 0, 0, 0, 3, 100, 2, 100, 4, 100, 9, 7];
            let childrens: Vec<Vec<usize>> = vec![
                vec![1, 2, 3],
                vec![],
                vec![6],
                vec![4],
                vec![8],
                vec![],
                vec![],
                vec![11],
                vec![],
                vec![10],
                vec![],
                vec![],
            ];
            let referrers: Vec<Vec<usize>> = vec![
                vec![],
                vec![4],
                vec![],
                vec![],
                vec![6],
                vec![4],
                vec![],
                vec![4],
                vec![],
                vec![],
                vec![11],
                vec![],
            ];
            let referee: Vec<Vec<usize>> = vec![
                vec![],
                vec![],
                vec![],
                vec![],
                vec![1, 5, 7],
                vec![],
                vec![4],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![10],
            ];
            let graph_status = vec![4, 4, 4, 4, 2, 1, 1, 1, 1, 1, 1, 1];
            for i in 0..12 {
                let parent_hash = {
                    if parent[i as usize] == -1 {
                        H256::default()
                    } else if parent[i as usize] >= i {
                        BigEndianHash::from_uint(&U256::from(100 + i as usize))
                    } else {
                        blocks[parent[i as usize] as usize].hash()
                    }
                };
                let (_, block) = create_simple_block_impl(
                    parent_hash,
                    vec![],
                    0,
                    U256::from(i),
                    U256::from(10),
                    1,
                    false,
                );
                blocks.push(block);
            }

            let mut inner = sync.inner.write();
            for i in 1..12 {
                let parent_index = if parent[i] > 12 {
                    !0 as usize
                } else {
                    parent[i] as usize
                };
                let me = inner.arena.insert(SynchronizationGraphNode {
                    graph_status: graph_status[i as usize],
                    block_ready: false,
                    parent_reclaimed: false,
                    parent: parent_index,
                    children: childrens[i as usize].clone(),
                    referees: referee[i as usize].clone(),
                    pending_referee_count: 0,
                    referrers: referrers[i as usize].clone(),
                    block_header: Arc::new(blocks[i].block_header.clone()),
                    last_update_timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        - 100,
                });
                assert_eq!(me, i);
                inner
                    .hash_to_arena_indices
                    .insert(blocks[i as usize].hash(), me);
                if graph_status[i as usize] != 4
                    && (parent_index > 12 || graph_status[parent_index] == 4)
                {
                    let status = {
                        if parent_index > 12 {
                            5
                        } else {
                            graph_status[parent_index]
                        }
                    };
                    println!(
                        "insert {} parent {} parent_status {}",
                        i, parent_index, status
                    );
                    inner.not_ready_blocks_frontier.insert(me);
                }
            }

            println!(
                "not_ready_blocks_frontier={:?}",
                inner.not_ready_blocks_frontier.get_frontier()
            );
            assert!(inner.arena.len() == 12);
            assert!(inner.hash_to_arena_indices.len() == 12);
            assert!(inner.not_ready_blocks_frontier.len() == 5);
            assert!(inner.not_ready_blocks_frontier.contains(&(4 as usize)));
            assert!(inner.not_ready_blocks_frontier.contains(&(5 as usize)));
            assert!(inner.not_ready_blocks_frontier.contains(&(6 as usize)));
            assert!(inner.not_ready_blocks_frontier.contains(&(7 as usize)));
            assert!(inner.not_ready_blocks_frontier.contains(&(9 as usize)));
        }

        // not expire any blocks
        {
            sync.remove_expire_blocks(1000 /* expire_time */);
            let inner = sync.inner.read();
            assert!(inner.arena.len() == 12);
            assert!(inner.hash_to_arena_indices.len() == 12);
            assert!(inner.not_ready_blocks_frontier.len() == 5);
            assert!(inner.not_ready_blocks_frontier.contains(&(4 as usize)));
            assert!(inner.not_ready_blocks_frontier.contains(&(5 as usize)));
            assert!(inner.not_ready_blocks_frontier.contains(&(6 as usize)));
            assert!(inner.not_ready_blocks_frontier.contains(&(7 as usize)));
            assert!(inner.not_ready_blocks_frontier.contains(&(9 as usize)));
        }

        // expire [10, 11]
        {
            let mut inner = sync.inner.write();
            inner.arena[10].last_update_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 1000;
        }
        {
            sync.remove_expire_blocks(500 /* expire_time */);
            let inner = sync.inner.read();
            assert!(inner.arena.len() == 10);
            assert!(inner.hash_to_arena_indices.len() == 10);
            assert!(inner.not_ready_blocks_frontier.len() == 5);
            assert!(inner.not_ready_blocks_frontier.contains(&(4 as usize)));
            assert!(inner.not_ready_blocks_frontier.contains(&(5 as usize)));
            assert!(inner.not_ready_blocks_frontier.contains(&(6 as usize)));
            assert!(inner.not_ready_blocks_frontier.contains(&(7 as usize)));
            assert!(inner.not_ready_blocks_frontier.contains(&(9 as usize)));
        }

        // expire [9, 7]
        {
            let mut inner = sync.inner.write();
            inner.arena[7].last_update_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 1000;
            inner.arena[9].last_update_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 1000;
        }
        {
            sync.remove_expire_blocks(500 /* expire_time */);
            let inner = sync.inner.read();
            assert!(inner.arena.len() == 5);
            assert!(inner.hash_to_arena_indices.len() == 5);
            assert!(inner.not_ready_blocks_frontier.len() == 1);
            assert!(inner.not_ready_blocks_frontier.contains(&(5 as usize)));
        }
    }

    let mut retry = 3;
    while let Err(e) = fs::remove_dir_all("./test.db") {
        println!("failed to remove directory test.db, err = {:?}", e);
        assert!(retry > 0);
        retry -= 1;
        sleep(Duration::from_millis(300));
    }
}

// During catch-up `insert_block` does not run `propagate_graph_status`, so a
// body is only checked against its parent header when
// `complete_filling_block_bodies` promotes the block.
#[test]
fn catch_up_body_is_checked_against_parent_before_promotion() {
    use crate::{
        sync::synchronization_graph::BlockInsertionResult,
        verification::compute_transaction_root,
    };
    use cfx_parameters::consensus::GENESIS_GAS_LIMIT;
    use cfx_types::{Address, AddressUtil};
    use cfxkey::{Generator, Random};
    use primitives::{
        transaction::native_transaction::{
            NativeTransaction, TypedNativeTransaction,
        },
        Action, BlockHeaderBuilder, Transaction,
    };

    let db_dir = std::env::temp_dir()
        .join(format!("conflux-catch-up-body-{}", std::process::id()));
    let db_dir = db_dir.to_str().unwrap();
    {
        let (sync, _, data_man, genesis_block) =
            initialize_synchronization_graph(
                db_dir,
                1,
                1,
                1,
                1,
                50000,
                DbType::Rocksdb,
            );
        let chain_id = sync.consensus.best_chain_id().in_native_space();
        let keypair = Random.generate().unwrap();

        // A block whose only transaction passes every per-transaction check
        // and packs `gas` in total.
        let make_block = |parent: H256, height: u64, gas: u64, nonce: u64| {
            let tx = Arc::new(
                Transaction::Native(TypedNativeTransaction::Cip155(
                    NativeTransaction {
                        nonce: 0.into(),
                        gas_price: U256::one(),
                        gas: gas.into(),
                        action: Action::Create,
                        value: U256::zero(),
                        storage_limit: 0,
                        epoch_height: height,
                        chain_id,
                        data: vec![],
                    },
                ))
                .sign(keypair.secret()),
            );
            let txs = vec![tx];
            let mut author = Address::zero();
            author.set_user_account_type_bits();
            let header = BlockHeaderBuilder::new()
                .with_parent_hash(parent)
                .with_height(height)
                .with_gas_limit(GENESIS_GAS_LIMIT.into())
                .with_nonce(U256::from(nonce))
                .with_difficulty(U256::from(10))
                .with_author(author)
                .with_transactions_root(compute_transaction_root(&txs))
                .build();
            Block::new(header, txs)
        };
        let mut good = make_block(genesis_block.hash(), 1, 100_000, 1);
        let mut bad =
            make_block(genesis_block.hash(), 1, GENESIS_GAS_LIMIT + 1, 2);
        let mut bad_child = make_block(bad.hash(), 2, 100_000, 3);
        let good_hash = good.hash();
        let bad_hash = bad.hash();
        let bad_child_hash = bad_child.hash();

        for block in [&mut good, &mut bad, &mut bad_child] {
            let (result, _) = sync.insert_block_header(
                &mut block.block_header,
                false, /* need_to_verify */
                true,  /* bench_mode */
                false, /* insert_to_consensus */
                true,  /* persistent */
            );
            assert!(result.is_new_valid());
        }

        sync.inner.write().locked_for_catchup = true;
        for block in [good, bad, bad_child] {
            assert!(matches!(
                sync.insert_block(block, true, true, false),
                BlockInsertionResult::AlreadyProcessed
            ));
        }

        assert!(sync.complete_filling_block_bodies());

        let inner = sync.inner.read();
        assert!(!inner.locked_for_catchup);
        // Only graph ready blocks survive the promotion.
        assert!(inner.hash_to_arena_indices.contains_key(&good_hash));
        assert!(!inner.hash_to_arena_indices.contains_key(&bad_hash));
        assert!(!inner.hash_to_arena_indices.contains_key(&bad_child_hash));
        assert!(!data_man.verified_invalid(&good_hash).0);
        assert!(data_man.verified_invalid(&bad_hash).0);
        assert!(data_man.verified_invalid(&bad_child_hash).0);
    }
    fs::remove_dir_all(db_dir).unwrap();
}
