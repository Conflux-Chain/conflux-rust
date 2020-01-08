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
    parameters::consensus::*,
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
    conf: ConsensusConfig,
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
        conf: ConsensusConfig, txpool: SharedTransactionPool,
        data_man: Arc<BlockDataManager>, executor: Arc<ConsensusExecutor>,
        statistics: SharedStatistics,
    ) -> Self
    {
        Self {
            conf,
            txpool,
            data_man,
            executor,
            statistics,
        }
    }

    fn make_checkpoint_at(
        inner: &mut ConsensusGraphInner, new_era_block_arena_index: usize,
        _will_execute: bool,
    )
    {
        let new_era_height = inner.arena[new_era_block_arena_index].height;
        let new_era_stable_height =
            new_era_height + inner.inner_conf.era_epoch_count;

        // We first compute the set of blocks inside the new era and we
        // recompute the past_weight inside the stable height.
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
        for d in inner.pivot_chain_metadata.iter_mut() {
            d.blockset_in_own_view_of_epoch
                .retain(|v| new_era_block_arena_index_set.contains(v));
            d.ordered_executable_epoch_blocks
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

    /// Subroutine called by on_new_block()
    fn insert_block_initial(
        &self, inner: &mut ConsensusGraphInner, block_header: &BlockHeader,
    ) -> usize {
        let (me, indices_len) = inner.insert(&block_header);
        self.statistics
            .set_consensus_graph_inserted_block_count(indices_len);
        me
    }

    fn process_outside_block(
        &self, inner: &mut ConsensusGraphInner, block_header: &BlockHeader,
    ) -> u64 {
        inner.insert_out_era_block(block_header)
    }

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

    /// Determine the parent edges of given blocks and also extend the pivot
    /// chain.
    pub fn commit(_blocks: Vec<H256>) {}

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
        // TODO: decide the logic of legacy blocks

        let me = self.insert_block_initial(inner, &block_header);
        /*let parent = inner.arena[me].parent;
        let era_genesis_height =
            inner.get_era_genesis_height(inner.arena[parent].height, 0);
        let mut fully_valid = true;
        let cur_pivot_era_block = if inner
            .pivot_index_to_height(inner.pivot_chain.len())
            > era_genesis_height
        {
            inner.get_pivot_block_arena_index(era_genesis_height)
        } else {
            NULL
        };
        let era_block = inner.get_era_genesis_block_with_parent(parent, 0);

        let pending = {
            // It's pending if it has a different stable block or is before our
            // stable block or we are still recovering
            let me_stable_arena_index =
                inner.ancestor_at(parent, inner.cur_era_stable_height);
            (inner.pivot_chain.len() as u64 - 1) + inner.cur_era_genesis_height
                < inner.cur_era_stable_height
                || me_stable_arena_index
                    != inner.get_pivot_block_arena_index(
                        inner.cur_era_stable_height,
                    )
        };

        let anticone_barrier =
            ConsensusNewBlockHandler::compute_anticone(inner, me);

        let weight_tuple = if anticone_barrier.len() >= ANTICONE_BARRIER_CAP {
            Some(inner.compute_subtree_weights(me, &anticone_barrier))
        } else {
            None
        };

        self.update_lcts_initial(inner, me);

        let mut stable = true;
        if !pending {
            let (stable_v, adaptive) = inner.adaptive_weight(
                me,
                &anticone_barrier,
                weight_tuple.as_ref(),
            );
            stable = stable_v;

            fully_valid = self.check_block_full_validity(
                me,
                &block_header,
                inner,
                adaptive,
                &anticone_barrier,
                weight_tuple.as_ref(),
            );

            if !fully_valid {
                // for partial_invalid block, no need to store it in memory
                inner.arena[me].data.blockset_in_own_view_of_epoch =
                    Default::default();
                inner.arena[me].data.ordered_executable_epoch_blocks =
                    Default::default();
            }

            inner.arena[me].stable = stable;
            if self.conf.bench_mode && fully_valid {
                inner.arena[me].adaptive = adaptive;
            }
        }

        let block_status = if pending {
            block_status_in_db
        } else if fully_valid {
            BlockStatus::Valid
        } else {
            BlockStatus::PartialInvalid
        };

        if pending {
            inner.arena[me].data.pending = true;
            ConsensusNewBlockHandler::try_clear_blockset_in_own_view_of_epoch(
                inner, me,
            );
            if block_status == BlockStatus::PartialInvalid {
                inner.arena[me].data.partial_invalid = true;
            }
            debug!("Block {} (hash = {}) is pending", me, inner.arena[me].hash);
        } else if !fully_valid {
            inner.arena[me].data.partial_invalid = true;
            debug!(
                "Block {} (hash = {}) is partially invalid",
                me, inner.arena[me].hash
            );
        } else {
            debug!(
                "Block {} (hash = {}) is fully valid",
                me, inner.arena[me].hash
            );
        }

        let my_weight = self.update_lcts_finalize(inner, me, stable);
        let mut extend_pivot = false;
        let mut pivot_changed = false;
        let mut fork_at =
            inner.pivot_index_to_height(inner.pivot_chain.len() + 1);
        let old_pivot_chain_len = inner.pivot_chain.len();
        if fully_valid && !pending {
            meter.aggregate_total_weight_in_past(my_weight);

            let last = inner.pivot_chain.last().cloned().unwrap();
            if inner.arena[me].parent == last {
                inner.pivot_chain.push(me);
                inner.set_epoch_number_in_epoch(
                    me,
                    inner.pivot_index_to_height(inner.pivot_chain.len()) - 1,
                );
                inner.pivot_chain_metadata.push(Default::default());
                extend_pivot = true;
                pivot_changed = true;
                fork_at = inner.pivot_index_to_height(old_pivot_chain_len)
            } else {
                let lca = inner.lca(last, me);
                if inner.arena[lca].height < inner.cur_era_stable_height {
                    debug!("Fork point is past stable block, do not switch pivot chain");
                    fork_at = inner.pivot_index_to_height(old_pivot_chain_len);
                } else {
                    fork_at = inner.arena[lca].height + 1;
                    let prev = inner.get_pivot_block_arena_index(fork_at);
                    let prev_weight = inner.weight_tree.get(prev);
                    let new = inner.ancestor_at(me, fork_at);
                    let new_weight = inner.weight_tree.get(new);

                    if ConsensusGraphInner::is_heavier(
                        (new_weight, &inner.arena[new].hash),
                        (prev_weight, &inner.arena[prev].hash),
                    ) {
                        // The new subtree is heavier, update pivot chain
                        for discarded_idx in inner
                            .pivot_chain
                            .split_off(inner.height_to_pivot_index(fork_at))
                        {
                            // Reset the epoch_number of the discarded fork
                            inner.reset_epoch_number_in_epoch(discarded_idx);
                            ConsensusNewBlockHandler::try_clear_blockset_in_own_view_of_epoch(inner, discarded_idx);
                        }
                        let mut u = new;
                        loop {
                            if inner.arena[u].data.blockset_cleared {
                                inner.collect_blockset_in_own_view_of_epoch(u);
                            }
                            inner.pivot_chain.push(u);
                            inner.set_epoch_number_in_epoch(
                                u,
                                inner.pivot_index_to_height(
                                    inner.pivot_chain.len(),
                                ) - 1,
                            );
                            let mut heaviest = NULL;
                            let mut heaviest_weight = 0;
                            for index in &inner.arena[u].children {
                                if inner.arena[*index].data.partial_invalid {
                                    continue;
                                }
                                let weight = inner.weight_tree.get(*index);
                                if heaviest == NULL
                                    || ConsensusGraphInner::is_heavier(
                                        (weight, &inner.arena[*index].hash),
                                        (
                                            heaviest_weight,
                                            &inner.arena[heaviest].hash,
                                        ),
                                    )
                                {
                                    heaviest = *index;
                                    heaviest_weight = weight;
                                }
                            }
                            if heaviest == NULL {
                                break;
                            }
                            u = heaviest;
                        }
                        pivot_changed = true;
                    } else {
                        // The previous subtree is still heavier, nothing is
                        // updated
                        debug!(
                            "Old pivot chain is heavier, pivot chain unchanged"
                        );
                        fork_at =
                            inner.pivot_index_to_height(old_pivot_chain_len);
                    }
                }
            };
            debug!(
                "Forked at height {}, fork parent block {}",
                fork_at,
                &inner.arena[inner.get_pivot_block_arena_index(fork_at - 1)]
                    .hash
            );
        }

        // Now compute last_pivot_in_block and update pivot_metadata.
        // Note that we need to do this for partially invalid blocks to
        // propagate information!
        if !extend_pivot {
            let update_at = fork_at - 1;
            let mut last_pivot_to_update = HashSet::new();
            last_pivot_to_update.insert(me);
            if pivot_changed {
                let update_pivot_index = inner.height_to_pivot_index(update_at);
                for pivot_index in update_pivot_index..old_pivot_chain_len {
                    for x in &inner.pivot_chain_metadata[pivot_index]
                        .last_pivot_in_past_blocks
                    {
                        last_pivot_to_update.insert(*x);
                    }
                }
                inner.recompute_metadata(fork_at, last_pivot_to_update);
            } else {
                // pivot chain not extend and not change
                ConsensusNewBlockHandler::try_clear_blockset_in_own_view_of_epoch(inner, me);
                inner.recompute_metadata(
                    inner.get_pivot_height(),
                    last_pivot_to_update,
                );
            }
        } else {
            let height = inner.arena[me].height;
            inner.arena[me].last_pivot_in_past = height;
            let pivot_index = inner.height_to_pivot_index(height);
            inner.pivot_chain_metadata[pivot_index]
                .last_pivot_in_past_blocks
                .insert(me);
        }

        // Now we can safely return
        if !fully_valid || pending {
            self.persist_terminal_and_block_info(
                inner,
                me,
                block_status,
                transactions.is_some(),
            );
            return;
        }

        if pivot_changed {
            if inner.pivot_chain.len() > EPOCH_SET_PERSISTENCE_DELAY as usize {
                let fork_at_pivot_index = inner.height_to_pivot_index(fork_at);
                // Starting from old_len ensures that all epochs within
                // [old_len - delay, new_len - delay) will be inserted to db, so
                // no epochs will be skipped. Starting from
                // fork_at ensures that any epoch set change will be
                // overwritten.
                let start_pivot_index = if old_pivot_chain_len
                    >= EPOCH_SET_PERSISTENCE_DELAY as usize
                {
                    min(
                        fork_at_pivot_index,
                        old_pivot_chain_len
                            - EPOCH_SET_PERSISTENCE_DELAY as usize,
                    )
                } else {
                    fork_at_pivot_index
                };
                let to_persist_pivot_index = inner.pivot_chain.len()
                    - EPOCH_SET_PERSISTENCE_DELAY as usize;
                for pivot_index in start_pivot_index..to_persist_pivot_index {
                    inner.persist_epoch_set_hashes(pivot_index);
                }
            }
        }

        inner.adjust_difficulty(*inner.pivot_chain.last().expect("not empty"));
        meter.update_confirmation_risks(inner);

        // Note that after the checkpoint (if happens), the old_pivot_chain_len
        // value will become obsolete
        let old_pivot_chain_height =
            inner.pivot_index_to_height(old_pivot_chain_len);
        let new_pivot_era_block = inner.get_era_genesis_block_with_parent(
            *inner.pivot_chain.last().unwrap(),
            0,
        );
        let new_era_height = inner.arena[new_pivot_era_block].height;
        let new_checkpoint_era_genesis = self.should_form_checkpoint_at(inner);
        if new_checkpoint_era_genesis != inner.cur_era_genesis_block_arena_index
        {
            info!(
                "Working on new checkpoint, old checkpoint block {} height {}",
                &inner.arena[inner.cur_era_genesis_block_arena_index].hash,
                inner.cur_era_genesis_height
            );
            ConsensusNewBlockHandler::make_checkpoint_at(
                inner,
                new_checkpoint_era_genesis,
                transactions.is_some(),
                &self.executor,
            );
            let stable_era_genesis_arena_index =
                inner.ancestor_at(me, inner.cur_era_stable_height);
            meter.reset_for_checkpoint(
                inner.weight_tree.get(stable_era_genesis_arena_index),
                inner.cur_era_stable_height,
            );
            meter.update_confirmation_risks(inner);
            info!(
                "New checkpoint formed at block {} stable block {} height {}",
                &inner.arena[inner.cur_era_genesis_block_arena_index].hash,
                &inner.arena[stable_era_genesis_arena_index].hash,
                inner.cur_era_genesis_height
            );
        }
        // FIXME: we need a function to compute the deferred epoch
        // FIXME: number. the current codebase may not be
        // FIXME: consistent at all places.
        let mut confirmed_height = meter.get_confirmed_epoch_num(
            inner.cur_era_genesis_height
                + 2 * self.data_man.get_snapshot_epoch_count() as u64
                + DEFERRED_STATE_EPOCH_COUNT,
        );
        if confirmed_height < DEFERRED_STATE_EPOCH_COUNT {
            confirmed_height = 0;
        } else {
            confirmed_height -= DEFERRED_STATE_EPOCH_COUNT;
        }
        // We can not assume that confirmed epoch are already executed,
        // but we can assume that the deferred block are executed.
        let confirmed_epoch_hash = inner
            .get_hash_from_epoch_number(confirmed_height)
            // FIXME: shouldn't unwrap but the function doesn't return error...
            .expect(&concat!(file!(), ":", line!(), ":", column!()));
        // FIXME: we also need more helper function to get the execution result
        // FIXME: for block deferred or not.
        if let Some(confirmed_epoch) = &*self
            .data_man
            .get_epoch_execution_commitment(&confirmed_epoch_hash)
        {
            if confirmed_height
                > self.data_man.state_availability_boundary.read().lower_bound
            {
                // FIXME: how about archive node?
                self.data_man
                    .storage_manager
                    .get_storage_manager()
                    .maintain_snapshots_pivot_chain_confirmed(
                        confirmed_height,
                        &confirmed_epoch_hash,
                        &confirmed_epoch.state_root_with_aux_info,
                        &self.data_man.state_availability_boundary,
                    )
                    // FIXME: propogate error.
                    .expect(&concat!(file!(), ":", line!(), ":", column!()));
            }
        }

        // FIXME: this is header only.
        // If we are inserting header only, we will skip execution and
        // tx_pool-related operations
        if transactions.is_some() {
            // It's only correct to set tx stale after the block is considered
            // terminal for mining.
            // Note that we conservatively only mark those blocks inside the
            // current pivot era
            if era_block == cur_pivot_era_block {
                self.txpool
                    .set_tx_packed(transactions.expect("Already checked"));
            }
            if new_era_height + ERA_RECYCLE_TRANSACTION_DELAY
                < inner.pivot_index_to_height(inner.pivot_chain.len())
                && inner.last_recycled_era_block != new_pivot_era_block
            {
                self.recycle_tx_outside_era(inner, new_pivot_era_block);
                inner.last_recycled_era_block = new_pivot_era_block;
            }

            let to_state_pos = if inner
                .pivot_index_to_height(inner.pivot_chain.len())
                < DEFERRED_STATE_EPOCH_COUNT
            {
                0
            } else {
                inner.pivot_index_to_height(inner.pivot_chain.len())
                    - DEFERRED_STATE_EPOCH_COUNT
                    + 1
            };
            inner.optimistic_executed_height = if to_state_pos > 0 {
                Some(to_state_pos)
            } else {
                None
            };
            let mut state_at = fork_at;
            if fork_at + DEFERRED_STATE_EPOCH_COUNT > old_pivot_chain_height {
                if old_pivot_chain_height > DEFERRED_STATE_EPOCH_COUNT {
                    state_at =
                        old_pivot_chain_height - DEFERRED_STATE_EPOCH_COUNT + 1;
                } else {
                    state_at = 1;
                }
            }
            // For full node, we don't execute blocks before available states
            // This skip should only happen in `SyncBlockPhase` for full nodes
            if state_at < inner.state_boundary_height + 1 {
                state_at = inner.state_boundary_height + 1;
            }

            // Apply transactions in the determined total order
            while state_at < to_state_pos {
                let epoch_arena_index =
                    inner.get_pivot_block_arena_index(state_at);
                let reward_execution_info = self
                    .executor
                    .get_reward_execution_info(inner, epoch_arena_index);
                self.executor.enqueue_epoch(EpochExecutionTask::new(
                    inner.arena[epoch_arena_index].hash,
                    inner.get_epoch_block_hashes(epoch_arena_index),
                    inner.get_epoch_start_block_number(epoch_arena_index),
                    reward_execution_info,
                    true,
                    false,
                ));
                state_at += 1;
            }
        }*/

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
        if inner.pivot_chain.len() < DEFERRED_STATE_EPOCH_COUNT as usize {
            return;
        }
        let start_pivot_index = (inner.state_boundary_height
            - inner.cur_era_genesis_height)
            as usize;
        let start_hash = inner.arena[inner.pivot_chain[start_pivot_index]].hash;
        // Here, we should ensure the epoch_execution_commitment for stable hash
        // must be loaded into memory. Since, in some rare cases, the number of
        // blocks between stable and best_epoch is less than
        // DEFERRED_STATE_EPOCH_COUNT, the for loop below will not load
        // epoch_execution_commitment for stable hash.
        if start_hash != inner.data_man.true_genesis.hash()
            && self
                .data_man
                .get_epoch_execution_commitment(&start_hash)
                .is_none()
        {
            self.data_man.load_epoch_execution_commitment_from_db(&start_hash)
                .expect("epoch_execution_commitment for stable hash must exist in disk");
        }
        for pivot_index in start_pivot_index + 1
            ..inner.pivot_chain.len() - DEFERRED_STATE_EPOCH_COUNT as usize + 1
        {
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
                    true,
                    false,
                ));
            }
        }
    }
}
