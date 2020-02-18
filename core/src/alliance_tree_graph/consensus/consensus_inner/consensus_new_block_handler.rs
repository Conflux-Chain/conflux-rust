// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::{
    consensus_inner::{
        consensus_executor::{ConsensusExecutor, EpochExecutionTask},
        ConsensusGraphInner, NewCandidatePivotCallbackType,
        NextSelectedPivotCallbackType, NULL,
    },
    ConsensusConfig,
};

use crate::{
    alliance_tree_graph::blockgen::TGBlockGenerator,
    block_data_manager::{BlockDataManager, BlockStatus, LocalBlockInfo},
    parameters::{consensus::*, consensus_internal::*},
    statistics::SharedStatistics,
    sync::delta::CHECKPOINT_DUMP_MANAGER,
    transaction_pool::DEFAULT_MAX_BLOCK_GAS_LIMIT,
    SharedTransactionPool,
};
use cfx_types::H256;
use hibitset::BitSetLike;
use libra_types::block_info::PivotBlockDecision;
use primitives::{Block, BlockHeader};
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
        will_execute: bool, executor: &ConsensusExecutor,
    )
    {
        let new_era_height = inner.arena[new_era_block_arena_index].height;
        let new_era_stable_height =
            new_era_height + inner.inner_conf.era_epoch_count;

        // In transaction-execution phases (`RecoverBlockFromDb` or `Normal`),
        // ensure all blocks on the pivot chain before stable_era_genesis
        // have state_valid computed
        if will_execute {
            // Make sure state execution is finished before setting lower_bound
            // to the new_checkpoint_era_genesis.
            executor
                .wait_for_result(inner.arena[new_era_block_arena_index].hash);
        }

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
            let mut parent = inner.arena[me].parent;
            if inner.arena[me].era_block != NULL {
                inner.split_root(me);
            }
            if !new_era_block_arena_index_set.contains(&parent) {
                parent = new_era_block_arena_index;
            }
            inner.arena[me].parent = parent;
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
            let lca = inner.lca(index, era_block);
            if lca != era_block {
                self.recycle_tx_in_block(inner, index);
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

    fn generate_block(
        &self, inner: &mut ConsensusGraphInner, parent: H256,
        referees: Vec<H256>,
    ) -> Block
    {
        let parent_height = self
            .data_man
            .block_header_by_hash(&parent)
            .expect("parent header exists")
            .height();
        let deferred_height = if parent_height > DEFERRED_STATE_EPOCH_COUNT - 1
        {
            parent_height - DEFERRED_STATE_EPOCH_COUNT + 1
        } else {
            0
        };
        let deferred_epoch_hash = inner
            .epoch_hash(deferred_height)
            .expect("should be a valid epoch_height");
        let deferred_exec_commitment =
            self.executor.wait_for_result(deferred_epoch_hash);
        let deferred_state_root = deferred_exec_commitment
            .state_root_with_aux_info
            .state_root
            .compute_state_root_hash();
        let deferred_receipt_root =
            deferred_exec_commitment.receipts_root.clone();
        let deferred_logs_bloom_hash =
            deferred_exec_commitment.logs_bloom_hash.clone();
        // TODO: pack some transactions
        TGBlockGenerator::assemble_new_block(
            &self.data_man,
            parent,
            referees,
            deferred_state_root,
            deferred_receipt_root,
            deferred_logs_bloom_hash,
            DEFAULT_MAX_BLOCK_GAS_LIMIT.into(),
            vec![], /* transactions */
        )
    }

    pub fn on_new_block(
        &self, inner: &mut ConsensusGraphInner, block_header: &BlockHeader,
    ) {
        let hash = block_header.hash();
        let parent_hash = block_header.parent_hash();
        let parent_index = inner.hash_to_arena_indices.get(&parent_hash);
        let block_status = self
            .data_man
            .local_block_info_from_db(&hash)
            .map(|info| info.get_status())
            .unwrap_or(BlockStatus::Pending);
        // current block is outside era or it's parent is outside era
        if parent_index.is_none()
            || inner.arena[*parent_index.unwrap()].era_block == NULL
        {
            debug!(
                "parent={:?} not in consensus graph, set header to pending",
                parent_hash
            );
            let sn = inner.insert_out_era_block(block_header);
            let block_info = LocalBlockInfo::new(
                block_status,
                sn,
                self.data_man.get_instance_id(),
            );
            self.data_man
                .insert_local_block_info_to_db(&hash, block_info);
            return;
        }

        let (me, indices_len) = inner.insert(&block_header);
        self.statistics
            .set_consensus_graph_inserted_block_count(indices_len);

        // handle pending callbacks
        if let Some(callback) =
            inner.next_selected_pivot_waiting_list.remove(&hash)
        {
            debug!("next_selected_pivot callback for block={:?}", hash);
            callback
                .send(Ok(PivotBlockDecision {
                    height: block_header.height(),
                    block_hash: hash,
                    parent_hash: *block_header.parent_hash(),
                }))
                .expect("send pivot block decision back should succeed");
        }

        if let Some(callback) =
            inner.new_candidate_pivot_waiting_list.remove(&hash)
        {
            debug!("new_candidate_pivot callback for block={:?}", hash);
            let height = block_header.height();
            callback
                .send(Ok(inner.validate_and_add_candidate_pivot(
                    &hash,
                    parent_hash,
                    height,
                )))
                .expect("send new candidate pivot back should succeed");
        }

        // FIXME: fill the correctly value of `persist_terminal`.
        self.persist_terminal_and_block_info(
            inner,
            me,
            block_status,
            true, /* persist_terminal */
        );

        debug!("Finish processing block in ConsensusGraph: hash={:?}", hash);
    }

    pub fn on_new_candidate_pivot(
        &self, inner: &mut ConsensusGraphInner,
        pivot_decision: &PivotBlockDecision,
        callback: NewCandidatePivotCallbackType,
    ) -> bool
    {
        debug!(
            "on_new_candidate_pivot, pivot_decision={:?}",
            pivot_decision
        );
        inner.new_candidate_pivot(
            &pivot_decision.block_hash,
            &pivot_decision.parent_hash,
            pivot_decision.height,
            callback,
        )
    }

    pub fn on_next_selected_pivot_block(
        &self, inner: &mut ConsensusGraphInner, last_pivot_hash: Option<&H256>,
        callback: NextSelectedPivotCallbackType,
    ) -> Option<Block>
    {
        debug!(
            "on_next_selected_pivot_block, last_pivot_hash={:?}",
            last_pivot_hash
        );
        let last_pivot_hash = if let Some(p) = last_pivot_hash {
            *p
        } else {
            inner.data_man.true_genesis.hash()
        };

        let arena_index = *inner
            .hash_to_arena_indices
            .get(&last_pivot_hash)
            .expect("must exist");
        if inner.arena[arena_index].children.is_empty() {
            let block = self.generate_block(
                inner,
                last_pivot_hash,
                inner.terminal_hashes.iter().cloned().collect(),
            );
            debug!("inser to next_selected_pivot_waiting_list block={:?}", block.hash());
            inner
                .next_selected_pivot_waiting_list
                .insert(block.hash(), callback);
            Some(block)
        } else {
            assert!(inner.candidate_pivot_tree.contains(arena_index));
            let mut next_pivot = NULL;
            // Find a non-selected child with maximum block hash.
            for child in &inner.arena[arena_index].children {
                if (next_pivot == NULL
                    || inner.arena[*child].hash > inner.arena[next_pivot].hash)
                    && !inner.candidate_pivot_tree.contains(*child)
                {
                    next_pivot = *child;
                }
            }
            if next_pivot == NULL {
                // FIXME: maybe we should send error back
                let block = self.generate_block(
                    inner,
                    last_pivot_hash,
                    inner.terminal_hashes.iter().cloned().collect(),
                );
                debug!("inser to next_selected_pivot_waiting_list block={:?}", block.hash());
                inner
                    .next_selected_pivot_waiting_list
                    .insert(block.hash(), callback);
                Some(block)
            } else {
                callback
                    .send(Ok(PivotBlockDecision {
                        height: inner.arena[next_pivot].height,
                        block_hash: inner.arena[next_pivot].hash,
                        parent_hash: last_pivot_hash,
                    }))
                    .expect("send pivot block decision back should succeed");
                None
            }
        }
    }

    pub fn on_commit(
        &self, inner: &mut ConsensusGraphInner, block_hashes: &Vec<H256>,
    ) {
        debug!("on_commit: block_hashes={:?}", block_hashes);
        for block_hash in block_hashes {
            inner.commit(block_hash);

            // Note that after the checkpoint (if happens), the
            // old_pivot_chain_len value will become obsolete
            let pivot_arena_index = *inner.pivot_chain.last().unwrap();
            let new_pivot_era_block =
                inner.get_era_genesis_block_with_parent(pivot_arena_index, 0);
            let new_era_height = inner.arena[new_pivot_era_block].height;
            let new_checkpoint_era_genesis =
                self.should_form_checkpoint_at(inner);
            if new_checkpoint_era_genesis
                != inner.cur_era_genesis_block_arena_index
            {
                info!(
                    "Working on new checkpoint, old checkpoint block {} height {}",
                    &inner.arena[inner.cur_era_genesis_block_arena_index].hash,
                    inner.cur_era_genesis_height
                );

                // FIXME: fill correct value of `will_execute`
                ConsensusNewBlockHandler::make_checkpoint_at(
                    inner,
                    new_checkpoint_era_genesis,
                    true, /* will_execute */
                    &self.executor,
                );

                let stable_era_genesis_arena_index = inner.ancestor_at(
                    pivot_arena_index,
                    inner.cur_era_stable_height,
                );
                info!(
                    "New checkpoint formed at block {} stable block {} height {}",
                    &inner.arena[inner.cur_era_genesis_block_arena_index].hash,
                    &inner.arena[stable_era_genesis_arena_index].hash,
                    inner.cur_era_genesis_height
                );
            }

            // recycle out era transactions
            if new_era_height + ERA_RECYCLE_TRANSACTION_DELAY
                < inner.pivot_index_to_height(inner.pivot_chain.len())
                && inner.last_recycled_era_block != new_pivot_era_block
            {
                self.recycle_tx_outside_era(inner, new_pivot_era_block);
                inner.last_recycled_era_block = new_pivot_era_block;
            }
            // TODO: change block_status_in_db in disk
            // FIXME: fill correct value
            self.executor.enqueue_epoch(EpochExecutionTask::new(
                inner.arena[pivot_arena_index].hash,
                inner.get_epoch_block_hashes(pivot_arena_index),
                inner.get_epoch_start_block_number(pivot_arena_index),
                None,  /* reward_info */
                false, /* debug_record */
            ));
        }
    }

    pub fn set_pivot_chain(
        &self, inner: &mut ConsensusGraphInner, block_hash: &H256,
    ) {
        inner.set_to_pivot(block_hash);
        self.construct_pivot_state(inner);
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
        debug!(
            "construct_pivot_state from [{}] to [{}]",
            start_pivot_index,
            inner.pivot_chain.len() - 1
        );
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
