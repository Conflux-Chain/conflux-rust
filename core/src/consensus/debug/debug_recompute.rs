// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub fn log_debug_epoch_computation(
    epoch_arena_index: usize, inner: &mut ConsensusGraphInner,
    executor: &ConsensusExecutor, block_hash: H256, block_height: u64,
    state_root: &StateRootWithAuxInfo,
) -> ComputeEpochDebugRecord
{
    // Parent state root.
    let parent_arena_index = inner.arena[epoch_arena_index].parent;
    let parent_epoch_hash = inner.arena[parent_arena_index].hash;
    let parent_state_root = inner
        .data_man
        .get_epoch_execution_commitment(&parent_epoch_hash)
        .unwrap()
        .state_root_with_aux_info
        .clone();

    let reward_index = inner.get_pivot_reward_index(epoch_arena_index);

    let reward_execution_info =
        executor.get_reward_execution_info_from_index(inner, reward_index);
    let task = EpochExecutionTask::new(
        epoch_arena_index,
        inner,
        reward_execution_info,
        false, /* on_local_pivot */
        false, /* force_recompute */
    );
    let mut debug_record = ComputeEpochDebugRecord::default();
    {
        debug_record.block_height = block_height;
        debug_record.block_hash = block_hash;
        debug_record.state_root_after_applying_rewards = state_root.clone();
        debug_record.parent_epoch_hash = parent_epoch_hash;
        debug_record.parent_state_root = parent_state_root;
        debug_record.reward_epoch_hash =
            if let Some((reward_epoch_block, _)) = reward_index.clone() {
                Some(inner.arena[reward_epoch_block].hash)
            } else {
                None
            };
        debug_record.anticone_penalty_cutoff_epoch_hash =
            if let Some((_, anticone_penalty_cutoff_epoch_block)) =
                reward_index.clone()
            {
                Some(inner.arena[anticone_penalty_cutoff_epoch_block].hash)
            } else {
                None
            };

        let epoch_block_hashes =
            inner.get_epoch_block_hashes(epoch_arena_index);
        let blocks = epoch_block_hashes
            .iter()
            .map(|hash| {
                inner
                    .data_man
                    .block_by_hash(hash, false /* update_cache */)
                    .unwrap()
            })
            .collect::<Vec<_>>();

        debug_record.block_hashes = epoch_block_hashes;
        debug_record.block_txs = blocks
            .iter()
            .map(|block| block.transactions.len())
            .collect::<Vec<_>>();
        debug_record.transactions = blocks
            .iter()
            .flat_map(|block| block.transactions.clone())
            .collect::<Vec<_>>();

        debug_record.block_authors = blocks
            .iter()
            .map(|block| *block.block_header.author())
            .collect::<Vec<_>>();
    }
    executor.compute_epoch(task, Some(&mut debug_record));

    debug_record
}

pub fn log_invalid_state_root(
    deferred: usize, inner: &mut ConsensusGraphInner,
    executor: &ConsensusExecutor, block_hash: H256, block_height: u64,
    state_root: &StateRootWithAuxInfo,
) -> std::io::Result<()>
{
    if let Some(dump_dir) =
        inner.inner_conf.debug_dump_dir_invalid_state_root.clone()
    {
        let invalid_state_root_path =
            dump_dir.clone() + &format!("{}_{:?}", block_height, block_hash);
        let txt_path = invalid_state_root_path.clone() + ".txt";
        if Path::new(&txt_path).exists() {
            return Ok(());
        }

        // TODO: refactor the consensus executor to make it run at background.
        let debug_record = log_debug_epoch_computation(
            deferred,
            inner,
            executor,
            block_hash,
            block_height,
            state_root,
        );
        let deferred_block_hash = inner.arena[deferred].hash;
        let got_state_root = inner
            .data_man
            .get_epoch_execution_commitment(&deferred_block_hash)
            .unwrap()
            .state_root_with_aux_info
            .clone();

        {
            std::fs::create_dir_all(dump_dir)?;

            let mut debug_file = File::create(&txt_path)?;
            debug_file.write_all(format!("{:?}", debug_record).as_bytes())?;
            let json_path = invalid_state_root_path + ".json.txt";
            let mut json_file = File::create(&json_path)?;
            json_file
                .write_all(serde_json::to_string(&debug_record)?.as_bytes())?;
        }

        warn!(
            "State debug recompute: got {:?}, deferred block: {:?}, block hash: {:?}\
            reward epoch bock: {:?}, anticone cutoff block: {:?}, \
            number of blocks in epoch: {:?}, number of transactions in epoch: {:?}, rewards: {:?}",
            got_state_root,
            deferred_block_hash,
            block_hash,
            debug_record.reward_epoch_hash,
            debug_record.anticone_penalty_cutoff_epoch_hash,
            debug_record.block_hashes.len(),
            debug_record.transactions.len(),
            debug_record.merged_rewards_by_author,
        );
    }

    Ok(())
}

use crate::consensus::{
    consensus_inner::consensus_executor::{
        ConsensusExecutor, EpochExecutionTask,
    },
    debug::ComputeEpochDebugRecord,
    ConsensusGraphInner,
};
use cfx_internal_common::StateRootWithAuxInfo;
use cfx_types::H256;
use serde_json;
use std::{fs::File, io::Write, path::Path};
