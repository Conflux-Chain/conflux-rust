// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::sync::{
    utils::{create_simple_block_impl, initialize_synchronization_graph},
    SynchronizationGraphNode,
};
use cfx_types::{H256, U256};
use primitives::Block;
use std::{
    fs,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn test_remove_expire_blocks() {
    let (sync, _, _) =
        initialize_synchronization_graph("./test.db", 1, 1, 1, 1, 50000);
    // test initialization
    {
        let inner = sync.inner.read();
        assert!(inner.genesis_block_index == 0);
        assert!(inner.arena.len() == 1);
        assert!(inner.hash_to_arena_indices.len() == 1);
        assert!(inner.not_ready_blocks_count == 0);
        assert!(inner.not_ready_blocks_frontier.len() == 0);
    }

    // prepare graph data
    {
        let mut blocks: Vec<Block> = Vec::new();
        let parent: Vec<i64> =
            vec![-1, 0, 0, 0, 3, 100, 2, 100, 4, 100, 9, 100];
        let childrens: Vec<Vec<usize>> = vec![
            vec![1, 2, 3],
            vec![],
            vec![6],
            vec![4],
            vec![8],
            vec![],
            vec![],
            vec![],
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
                    H256::from(U256::from(100 + i as usize))
                } else {
                    blocks[parent[i as usize] as usize].hash()
                }
            };
            let (_, block) = create_simple_block_impl(
                parent_hash,
                vec![],
                0,
                i as u64,
                U256::from(10),
                1,
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
        inner.not_ready_blocks_count = 8;

        println!("{:?}", inner.not_ready_blocks_frontier);
        assert!(inner.arena.len() == 12);
        assert!(inner.hash_to_arena_indices.len() == 12);
        assert!(inner.not_ready_blocks_count == 8);
        assert!(inner.not_ready_blocks_frontier.len() == 6);
        assert!(inner.not_ready_blocks_frontier.contains(&(4 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(5 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(6 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(7 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(9 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(11 as usize)));
    }

    // not expire any blocks
    {
        sync.remove_expire_blocks(1000, false);
        let inner = sync.inner.read();
        assert!(inner.arena.len() == 12);
        assert!(inner.hash_to_arena_indices.len() == 12);
        assert!(inner.not_ready_blocks_count == 8);
        assert!(inner.not_ready_blocks_frontier.len() == 6);
        assert!(inner.not_ready_blocks_frontier.contains(&(4 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(5 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(6 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(7 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(9 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(11 as usize)));
    }

    // expire [9, 10, 14]
    {
        let mut inner = sync.inner.write();
        inner.arena[9].last_update_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 1000;
    }
    {
        sync.remove_expire_blocks(500, false);
        let inner = sync.inner.read();
        assert!(inner.arena.len() == 9);
        assert!(inner.hash_to_arena_indices.len() == 9);
        assert!(inner.not_ready_blocks_count == 5);
        assert!(inner.not_ready_blocks_frontier.len() == 4);
        assert!(inner.not_ready_blocks_frontier.contains(&(4 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(5 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(6 as usize)));
        assert!(inner.not_ready_blocks_frontier.contains(&(7 as usize)));
    }

    // expire [7]
    {
        let mut inner = sync.inner.write();
        inner.arena[7].last_update_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 1000;
    }
    {
        sync.remove_expire_blocks(500, false);
        let inner = sync.inner.read();
        assert!(inner.arena.len() == 5);
        assert!(inner.hash_to_arena_indices.len() == 5);
        assert!(inner.not_ready_blocks_count == 1);
        assert!(inner.not_ready_blocks_frontier.len() == 1);
        assert!(inner.not_ready_blocks_frontier.contains(&(5 as usize)));
    }

    fs::remove_dir_all("./test.db")
        .expect("failed to remove directory test.db");
}
