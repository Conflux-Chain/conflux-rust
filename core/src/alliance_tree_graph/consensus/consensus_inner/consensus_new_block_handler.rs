// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::{
    consensus_inner::{
        consensus_executor::{ConsensusExecutor, EpochExecutionTask},
        ConsensusGraphInner, NULL,
    },
    ConsensusConfig,
};

use crate::{
    block_data_manager::{BlockDataManager, BlockStatus, LocalBlockInfo},
    statistics::SharedStatistics,
    sync::delta::CHECKPOINT_DUMP_MANAGER,
    SharedTransactionPool,
};
use cfx_types::H256;
use hibitset::BitSetLike;
use primitives::{BlockHeader, SignedTransaction};
use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

pub struct ConsensusNewBlockHandler {
    //conf: ConsensusConfig,
    txpool: SharedTransactionPool,
    data_man: Arc<BlockDataManager>,
    executor: Arc<ConsensusExecutor>,
    statistics: SharedStatistics,
}

/// ConsensusNewBlockHandler contains all sub-routines for handling new arriving
/// blocks from network or db. It manipulates and updates ConsensusGraphInner
/// object accordingly.
impl ConsensusNewBlockHandler {
    pub fn new(
        _conf: ConsensusConfig, txpool: SharedTransactionPool,
        data_man: Arc<BlockDataManager>, executor: Arc<ConsensusExecutor>,
        statistics: SharedStatistics,
    ) -> Self
    {
        Self {
            // conf,
            txpool,
            data_man,
            executor,
            statistics,
        }
    }

    #[allow(dead_code)]
    fn make_checkpoint_at(
        inner: &mut ConsensusGraphInner, new_era_block_arena_index: usize,
        _will_execute: bool,
    )
    {
        let new_era_height = inner.arena[new_era_block_arena_index].height;
        let new_era_stable_height =
            new_era_height + inner.inner_conf.era_epoch_count;

        // We first compute the set of blocks inside the new era.
        let mut new_era_block_arena_index_set = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(new_era_block_arena_index);
        new_era_block_arena_index_set.insert(new_era_block_arena_index);
        while let Some(x) = queue.pop_front() {
            for child in &inner.arena[x].children {
                if !new_era_block_arena_index_set.contains(child) {
                    queue.push_back(*child);
                    new_era_block_arena_index_set.insert(*child);
                }
            }
            for referrer in &inner.arena[x].referrers {
                if !new_era_block_arena_index_set.contains(referrer) {
                    queue.push_back(*referrer);
                    new_era_block_arena_index_set.insert(*referrer);
                }
            }
        }
        // This is the arena indices for legacy blocks
        let mut new_era_genesis_subtree = HashSet::new();
        queue.push_back(new_era_block_arena_index);
        while let Some(x) = queue.pop_front() {
            new_era_genesis_subtree.insert(x);
            for child in &inner.arena[x].children {
                queue.push_back(*child);
            }
        }
        let new_era_legacy_block_arena_index_set: HashSet<_> =
            new_era_block_arena_index_set
                .difference(&new_era_genesis_subtree)
                .collect();

        // Now we topologically sort the blocks outside the era
        let mut outside_block_arena_indices = HashSet::new();
        for (index, _) in inner.arena.iter() {
            if !new_era_block_arena_index_set.contains(&index) {
                outside_block_arena_indices.insert(index);
            }
        }
        // Next we are going to recompute all referee and referrer information
        // in arena
        let new_era_pivot_index = inner.height_to_pivot_index(new_era_height);
        for v in new_era_block_arena_index_set.iter() {
            let me = *v;
            inner.arena[me]
                .referees
                .retain(|v| new_era_block_arena_index_set.contains(v));
            inner.arena[me]
                .referrers
                .retain(|v| new_era_block_arena_index_set.contains(v));
        }
        // reassign the parent for outside era blocks
        for v in new_era_legacy_block_arena_index_set {
            let me = *v;
            let mut parent =
                inner.arena[me].parent.expect("parent must exists");
            if inner.arena[me].era_block != NULL {
                inner.split_root(me);
            }
            if !new_era_block_arena_index_set.contains(&parent) {
                parent = new_era_block_arena_index;
            }
            inner.arena[me].parent = Some(parent);
            inner.arena[me].era_block = NULL;
            inner.terminal_hashes.remove(&inner.arena[me].hash);
        }
        // Now we are ready to cleanup outside blocks in inner data structures
        {
            let mut old_era_block_set = inner.old_era_block_set.lock();
            for index in outside_block_arena_indices {
                let hash = inner.arena[index].hash;
                old_era_block_set.push_back(hash);
                inner.hash_to_arena_indices.remove(&hash);
                inner.terminal_hashes.remove(&hash);
                inner.arena.remove(index);
                // remove useless data in BlockDataManager
                inner.data_man.remove_epoch_execution_commitment(&hash);
                inner.data_man.remove_epoch_execution_context(&hash);
            }
        }
        assert!(new_era_pivot_index < inner.pivot_chain.len());
        inner.pivot_chain = inner.pivot_chain.split_off(new_era_pivot_index);
        inner.pivot_chain_metadata =
            inner.pivot_chain_metadata.split_off(new_era_pivot_index);
        for metadata in inner.pivot_chain_metadata.iter_mut() {
            metadata
                .blockset_in_epoch
                .retain(|v| new_era_block_arena_index_set.contains(v));
            metadata
                .ordered_executable_epoch_blocks
                .retain(|v| new_era_block_arena_index_set.contains(v));
        }

        // Chop off all link-cut-trees in the inner data structure
        inner.split_root(new_era_block_arena_index);

        inner.cur_era_genesis_block_arena_index = new_era_block_arena_index;
        inner.cur_era_genesis_height = new_era_height;
        inner.cur_era_stable_height = new_era_stable_height;
        inner.state_boundary_height = new_era_stable_height;

        let cur_era_hash = inner.arena[new_era_block_arena_index].hash.clone();
        let next_era_arena_index =
            inner.pivot_chain[inner.inner_conf.era_epoch_count as usize];
        let next_era_hash = inner.arena[next_era_arena_index].hash.clone();

        inner
            .data_man
            .set_cur_consensus_era_genesis_hash(&cur_era_hash, &next_era_hash);

        CHECKPOINT_DUMP_MANAGER.read().dump_async(next_era_hash);
    }

    #[allow(dead_code)]
    fn recycle_tx_in_block(
        &self, inner: &ConsensusGraphInner, arena_index: usize,
    ) {
        let block = inner
            .data_man
            .block_by_hash(
                &inner.arena[arena_index].hash,
                true, /* update_cache */
            )
            .expect("Block should always found in the data manager!");
        self.txpool.recycle_transactions(block.transactions.clone());
    }

    /// This recycles txs in all blocks outside the era represented by the era
    /// block.
    #[allow(dead_code)]
    fn recycle_tx_outside_era(
        &self, inner: &mut ConsensusGraphInner, era_block: usize,
    ) {
        let past = inner.compute_past_bitset(era_block);
        let future = inner.compute_future_bitset(era_block);

        // Recycle transactions in anticone
        for (index, _) in inner.arena.iter() {
            if !past.contains(index as u32) && !future.contains(index as u32) {
                self.recycle_tx_in_block(inner, index);
            }
        }

        // Recycle transactions in future, but not in subtree of `era_block`.
        for idx in future.iter() {
            let index = idx as usize;
            if inner.arena[index].parent.is_some() {
                let lca = inner.lca(index, era_block);
                if lca != era_block {
                    self.recycle_tx_in_block(inner, index);
                }
            }
        }
    }

    #[allow(dead_code)]
    fn should_form_checkpoint_at(
        &self, inner: &mut ConsensusGraphInner,
    ) -> usize {
        // FIXME: We should use finality to implement this function
        let best_height = inner.best_epoch_number();
        if best_height <= inner.inner_conf.era_checkpoint_gap {
            return inner.cur_era_genesis_block_arena_index;
        }
        let stable_height = best_height - inner.inner_conf.era_checkpoint_gap;
        let stable_era_genesis_height =
            inner.get_era_genesis_height(stable_height - 1, 0);
        if stable_era_genesis_height < inner.inner_conf.era_epoch_count {
            return inner.cur_era_genesis_block_arena_index;
        }
        let safe_era_height =
            stable_era_genesis_height - inner.inner_conf.era_epoch_count;
        if inner.cur_era_genesis_height > safe_era_height {
            return inner.cur_era_genesis_block_arena_index;
        }
        let safe_era_pivot_index = inner.height_to_pivot_index(safe_era_height);
        inner.pivot_chain[safe_era_pivot_index]
    }

    fn persist_terminals(&self, inner: &ConsensusGraphInner) {
        self.data_man.insert_terminals_to_db(
            inner.terminal_hashes.iter().cloned().collect(),
        );
    }

    /// The top level function invoked by ConsensusGraph to insert a new block.
    pub fn on_new_block(
        &self, inner: &mut ConsensusGraphInner, hash: &H256,
        block_header: &BlockHeader,
        transactions: Option<&Vec<Arc<SignedTransaction>>>,
    )
    {
        let block_status_in_db = self
            .data_man
            .local_block_info_from_db(hash)
            .map(|info| info.get_status())
            .unwrap_or(BlockStatus::Pending);
        let (me, indices_len, sn) = inner.insert(&block_header);
        let block_info = LocalBlockInfo::new(
            block_status_in_db,
            sn,
            self.data_man.get_instance_id(),
        );
        self.data_man
            .insert_local_block_info_to_db(hash, block_info);
        self.statistics
            .set_consensus_graph_inserted_block_count(indices_len);
        if me == NULL {
            return;
        }

        self.persist_terminal_and_block_info(
            inner,
            me,
            block_status_in_db,
            transactions.is_some(),
        );
        debug!("Finish processing block in ConsensusGraph: hash={:?}", hash);
    }

    fn persist_terminal_and_block_info(
        &self, inner: &mut ConsensusGraphInner, me: usize,
        block_status: BlockStatus, persist_terminal: bool,
    )
    {
        if persist_terminal {
            self.persist_terminals(inner);
        }

        let block_info = LocalBlockInfo::new(
            block_status,
            inner.arena[me].sequence_number,
            self.data_man.get_instance_id(),
        );
        self.data_man
            .insert_local_block_info_to_db(&inner.arena[me].hash, block_info);
    }

    /// construct_pivot_state() rebuild pivot chain state info from db
    /// avoiding intermediate redundant computation triggered by
    /// on_new_block().
    /// It also recovers receipts_root and logs_bloom_hash in pivot chain.
    /// This function is only invoked from recover_graph_from_db with
    /// header_only being false.
    pub fn construct_pivot_state(&self, inner: &mut ConsensusGraphInner) {
        let start_pivot_index = (inner.state_boundary_height
            - inner.cur_era_genesis_height)
            as usize;
        let start_hash = inner.arena[inner.pivot_chain[start_pivot_index]].hash;
        // Here, we should ensure the epoch_execution_commitment for stable hash
        // must be loaded into memory.
        if start_hash != inner.data_man.true_genesis.hash()
            && self
                .data_man
                .get_epoch_execution_commitment(&start_hash)
                .is_none()
        {
            self.data_man.load_epoch_execution_commitment_from_db(&start_hash)
                .expect("epoch_execution_commitment for stable hash must exist in disk");
        }
        for pivot_index in start_pivot_index + 1..inner.pivot_chain.len() {
            let arena_index = inner.pivot_chain[pivot_index];
            let pivot_hash = inner.arena[arena_index].hash;

            // Ensure that the commitments for the blocks on
            // pivot_chain after cur_era_stable_genesis are kept in memory.
            if self
                .data_man
                .load_epoch_execution_commitment_from_db(&pivot_hash)
                .is_none()
            {
                // We should recompute the epochs that should have been executed
                // but fail to persist their
                // execution_commitments before shutdown
                let reward_execution_info =
                    self.executor.get_reward_execution_info(inner, arena_index);
                let epoch_block_hashes =
                    inner.get_epoch_block_hashes(arena_index);
                let start_block_number =
                    inner.get_epoch_start_block_number(arena_index);
                self.executor.compute_epoch(EpochExecutionTask::new(
                    pivot_hash,
                    epoch_block_hashes,
                    start_block_number,
                    reward_execution_info,
                    false,
                ));
            }
        }
    }
}
