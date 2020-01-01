// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::{BlockDataManager, BlockStatus, LocalBlockInfo},
    consensus::{
        consensus_inner::{
            confirmation_meter::ConfirmationMeter,
            consensus_executor::{ConsensusExecutor, EpochExecutionTask},
            ConsensusGraphInner, NULL,
        },
        debug::ComputeEpochDebugRecord,
        ConsensusConfig,
    },
    parameters::{consensus::*, consensus_internal::*},
    rlp::Encodable,
    statistics::SharedStatistics,
    storage::{
        storage_db::{
            OpenSnapshotMptTrait, SnapshotInfo, SnapshotMptTraitReadOnly,
        },
        StateIndex, StateRootWithAuxInfo,
    },
    SharedTransactionPool,
};
use cfx_types::H256;
use hibitset::{BitSet, BitSetLike, DrainableBitSet};
use parity_bytes::ToPretty;
use primitives::{BlockHeader, SignedTransaction, NULL_EPOCH};
use std::{
    cmp::{max, min},
    collections::{HashMap, HashSet, VecDeque},
    io::Write,
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

    /// recompute past_weight under stable_genesis
    fn recompute_stable_past_weight(
        inner: &mut ConsensusGraphInner, stable_genesis: usize,
    ) {
        let mut stable_genesis_subtree =
            BitSet::with_capacity(inner.arena.len() as u32);
        let mut queue = VecDeque::new();
        stable_genesis_subtree.add(stable_genesis as u32);
        queue.push_back(stable_genesis);
        while let Some(x) = queue.pop_front() {
            for child in &inner.arena[x].children {
                queue.push_back(*child);
                stable_genesis_subtree.add(*child as u32);
            }
        }

        let mut stack = Vec::new();
        let mut visited = BitSet::with_capacity(inner.arena.capacity() as u32);
        stack.push((0, inner.cur_era_genesis_block_arena_index, Vec::new()));
        while let Some((state, me, mut blockset)) = stack.pop() {
            if state == 0 {
                // compute blockset_in_own_view_of_epoch first
                if !inner.arena[me].data.blockset_cleared {
                    for index in
                        &inner.arena[me].data.blockset_in_own_view_of_epoch
                    {
                        if !visited.contains(*index as u32) {
                            visited.add(*index as u32);
                            blockset.push(*index);
                        }
                    }
                } else {
                    let mut queue = VecDeque::new();
                    for referee in &inner.arena[me].referees {
                        if !visited.contains(*referee as u32) {
                            visited.add(*referee as u32);
                            queue.push_back(*referee);
                        }
                    }
                    while let Some(index) = queue.pop_front() {
                        blockset.push(index);
                        let parent = inner.arena[index].parent;
                        if !visited.contains(parent as u32) {
                            visited.add(parent as u32);
                            queue.push_back(parent);
                        }
                        for referee in &inner.arena[index].referees {
                            if !visited.contains(*referee as u32) {
                                visited.add(*referee as u32);
                                queue.push_back(*referee);
                            }
                        }
                    }
                }

                // compute past_weight
                if stable_genesis_subtree.contains(me as u32) {
                    let parent = inner.arena[me].parent;
                    if stable_genesis_subtree.contains(parent as u32) {
                        inner.arena[me].past_weight = inner.arena[parent]
                            .past_weight
                            + inner.block_weight(
                                parent, false, /* inclusive */
                            );
                    } else {
                        inner.arena[me].past_weight = 0;
                    }

                    for index in &blockset {
                        if stable_genesis_subtree.contains(*index as u32) {
                            inner.arena[me].past_weight += inner.block_weight(
                                *index, false, /* inclusive */
                            );
                        }
                    }
                }

                stack.push((1, me, blockset));
                visited.add(me as u32);
                for child in &inner.arena[me].children {
                    if !inner.arena[*child].data.partial_invalid {
                        stack.push((0, *child, Vec::new()));
                    }
                }
            } else {
                visited.remove(me as u32);
                for index in blockset {
                    visited.remove(index as u32);
                }
            }
        }
    }

    fn make_checkpoint_at(
        inner: &mut ConsensusGraphInner, new_era_block_arena_index: usize,
        will_execute: bool,
    )
    {
        let new_era_height = inner.arena[new_era_block_arena_index].height;
        let new_era_stable_height =
            new_era_height + inner.inner_conf.era_epoch_count;
        let stable_era_genesis =
            inner.get_pivot_block_arena_index(new_era_stable_height);

        // In transaction-execution phases (`RecoverBlockFromDb` or `Normal`),
        // ensure all blocks on the pivot chain before stable_era_genesis
        // have state_valid computed
        if will_execute {
            inner
                .compute_state_valid(stable_era_genesis)
                .expect("Old cur_era_stable_height has available state_valid");
        }

        // We first compute the set of blocks inside the new era and we
        // recompute the past_weight inside the stable height.
        let mut new_era_block_arena_index_set = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(new_era_block_arena_index);
        new_era_block_arena_index_set.insert(new_era_block_arena_index);
        while let Some(x) = queue.pop_front() {
            inner.arena[x].past_weight = 0;
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

        ConsensusNewBlockHandler::recompute_stable_past_weight(
            inner,
            stable_era_genesis,
        );

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
            // We no longer need to consider blocks outside our era when
            // computing blockset_in_epoch
            inner.arena[me]
                .data
                .blockset_in_own_view_of_epoch
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
            inner
                .pastset_cache
                .intersect_update(&outside_block_arena_indices);
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
            d.last_pivot_in_past_blocks
                .retain(|v| new_era_block_arena_index_set.contains(v));
        }
        inner
            .anticone_cache
            .intersect_update(&new_era_genesis_subtree);

        // Chop off all link-cut-trees in the inner data structure
        inner.split_root(new_era_block_arena_index);

        inner.cur_era_genesis_block_arena_index = new_era_block_arena_index;
        inner.cur_era_genesis_height = new_era_height;
        inner.cur_era_stable_height = new_era_stable_height;
        // TODO: maybe archive node has other logic.
        inner
            .data_man
            .state_availability_boundary
            .write()
            .adjust_lower_bound(new_era_height);

        let cur_era_hash = inner.arena[new_era_block_arena_index].hash.clone();
        let next_era_arena_index =
            inner.pivot_chain[inner.inner_conf.era_epoch_count as usize];
        let next_era_hash = inner.arena[next_era_arena_index].hash.clone();

        inner
            .data_man
            .set_cur_consensus_era_genesis_hash(&cur_era_hash, &next_era_hash);
    }

    pub fn compute_anticone_bruteforce(
        inner: &ConsensusGraphInner, me: usize,
    ) -> BitSet {
        let parent = inner.arena[me].parent;
        if parent == NULL {
            // This is genesis, so the anticone should be empty
            return BitSet::new();
        }
        let mut last_in_pivot = inner.arena[parent].last_pivot_in_past;
        for referee in &inner.arena[me].referees {
            last_in_pivot =
                max(last_in_pivot, inner.arena[*referee].last_pivot_in_past);
        }
        let mut visited = BitSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(me);
        visited.add(me as u32);
        while let Some(index) = queue.pop_front() {
            let parent = inner.arena[index].parent;
            if parent != NULL
                && inner.arena[parent].data.epoch_number > last_in_pivot
                && !visited.contains(parent as u32)
            {
                visited.add(parent as u32);
                queue.push_back(parent);
            }
            for referee in &inner.arena[index].referees {
                if inner.arena[*referee].data.epoch_number > last_in_pivot
                    && !visited.contains(*referee as u32)
                {
                    visited.add(*referee as u32);
                    queue.push_back(*referee);
                }
            }
        }
        // Now we traverse all future of me, when adding new block, this is
        // empty
        queue.clear();
        queue.push_back(me);
        while let Some(index) = queue.pop_front() {
            for child in &inner.arena[index].children {
                if !visited.contains(*child as u32) {
                    visited.add(*child as u32);
                    queue.push_back(*child);
                }
            }
            for referrer in &inner.arena[index].referrers {
                if !visited.contains(*referrer as u32) {
                    visited.add(*referrer as u32);
                    queue.push_back(*referrer);
                }
            }
        }

        let mut anticone = BitSet::with_capacity(inner.arena.capacity() as u32);
        for (i, node) in inner.arena.iter() {
            if node.data.epoch_number > last_in_pivot
                && !visited.contains(i as u32)
            {
                anticone.add(i as u32);
            }
        }
        anticone
    }

    fn compute_anticone(inner: &mut ConsensusGraphInner, me: usize) -> BitSet {
        let parent = inner.arena[me].parent;
        debug_assert!(parent != NULL);
        debug_assert!(inner.arena[me].children.is_empty());
        debug_assert!(inner.arena[me].referrers.is_empty());

        // If we do not have the anticone of its parent, we compute it with
        // brute force!
        let parent_anticone_opt = inner.anticone_cache.get(parent);
        let mut anticone;
        if parent_anticone_opt.is_none() {
            anticone = ConsensusNewBlockHandler::compute_anticone_bruteforce(
                inner, me,
            );
        } else {
            // anticone = parent_anticone + parent_future - my_past
            // Compute future set of parent
            anticone = inner.compute_future_bitset(parent);
            anticone.remove(me as u32);

            for index in parent_anticone_opt.unwrap() {
                anticone.add(*index as u32);
            }
            let mut my_past = BitSet::new();
            let mut queue: VecDeque<usize> = VecDeque::new();
            queue.push_back(me);
            while let Some(index) = queue.pop_front() {
                if my_past.contains(index as u32) {
                    continue;
                }

                debug_assert!(index != parent);
                if index != me {
                    my_past.add(index as u32);
                }

                let idx_parent = inner.arena[index].parent;
                debug_assert!(idx_parent != NULL);
                if anticone.contains(idx_parent as u32) {
                    queue.push_back(idx_parent);
                }

                for referee in &inner.arena[index].referees {
                    if anticone.contains(*referee as u32) {
                        queue.push_back(*referee);
                    }
                }
            }
            for index in my_past.drain() {
                anticone.remove(index);
            }
        }

        // We only consider non-lagacy blocks when computing anticone.
        for index in anticone.clone().iter() {
            if inner.arena[index as usize].era_block == NULL {
                anticone.remove(index);
            }
        }

        inner.anticone_cache.update(me, &anticone);

        let mut anticone_barrier = BitSet::new();
        for index in anticone.clone().iter() {
            let parent = inner.arena[index as usize].parent as u32;
            if !anticone.contains(parent) {
                anticone_barrier.add(index);
            }
        }

        debug!(
            "Block {} anticone size {}",
            inner.arena[me].hash,
            anticone.len()
        );

        anticone_barrier
    }

    fn check_correct_parent_brutal(
        inner: &mut ConsensusGraphInner, me: usize, subtree_weight: &Vec<i128>,
    ) -> bool {
        let mut valid = true;
        let parent = inner.arena[me].parent;
        let parent_height = inner.arena[parent].height;
        let era_genesis_height = inner.get_era_genesis_height(parent_height, 0);

        // Check the pivot selection decision.
        for consensus_arena_index_in_epoch in
            inner.arena[me].data.blockset_in_own_view_of_epoch.iter()
        {
            if inner.arena[*consensus_arena_index_in_epoch]
                .data
                .partial_invalid
            {
                continue;
            }

            let lca = inner.lca(*consensus_arena_index_in_epoch, parent);
            assert!(lca != *consensus_arena_index_in_epoch);
            // If it is outside current era, we will skip!
            if lca == NULL || inner.arena[lca].height < era_genesis_height {
                continue;
            }
            if lca == parent {
                valid = false;
                break;
            }

            let fork = inner.ancestor_at(
                *consensus_arena_index_in_epoch,
                inner.arena[lca].height + 1,
            );
            let pivot = inner.ancestor_at(parent, inner.arena[lca].height + 1);

            let fork_subtree_weight = subtree_weight[fork];
            let pivot_subtree_weight = subtree_weight[pivot];

            if ConsensusGraphInner::is_heavier(
                (fork_subtree_weight, &inner.arena[fork].hash),
                (pivot_subtree_weight, &inner.arena[pivot].hash),
            ) {
                valid = false;
                break;
            }
        }

        valid
    }

    fn check_correct_parent(
        inner: &mut ConsensusGraphInner, me: usize, anticone_barrier: &BitSet,
        weight_tuple: Option<&(Vec<i128>, Vec<i128>, Vec<i128>)>,
    ) -> bool
    {
        if let Some((subtree_weight, _, _)) = weight_tuple {
            return ConsensusNewBlockHandler::check_correct_parent_brutal(
                inner,
                me,
                subtree_weight,
            );
        }
        let mut valid = true;
        let parent = inner.arena[me].parent;
        let parent_height = inner.arena[parent].height;
        let era_genesis_height = inner.get_era_genesis_height(parent_height, 0);

        let mut weight_delta = HashMap::new();

        for index in anticone_barrier {
            weight_delta
                .insert(index as usize, inner.weight_tree.get(index as usize));
        }

        // Remove weight contribution of anticone
        for (index, delta) in &weight_delta {
            inner.weight_tree.path_apply(*index, -delta);
        }

        // Check the pivot selection decision.
        for consensus_arena_index_in_epoch in
            inner.arena[me].data.blockset_in_own_view_of_epoch.iter()
        {
            if inner.arena[*consensus_arena_index_in_epoch]
                .data
                .partial_invalid
            {
                continue;
            }

            let lca = inner.lca(*consensus_arena_index_in_epoch, parent);
            assert!(lca != *consensus_arena_index_in_epoch);
            // If it is outside the era, we will skip!
            if lca == NULL || inner.arena[lca].height < era_genesis_height {
                continue;
            }
            if lca == parent {
                valid = false;
                break;
            }

            let fork = inner.ancestor_at(
                *consensus_arena_index_in_epoch,
                inner.arena[lca].height + 1,
            );
            let pivot = inner.ancestor_at(parent, inner.arena[lca].height + 1);

            let fork_subtree_weight = inner.weight_tree.get(fork);
            let pivot_subtree_weight = inner.weight_tree.get(pivot);

            if ConsensusGraphInner::is_heavier(
                (fork_subtree_weight, &inner.arena[fork].hash),
                (pivot_subtree_weight, &inner.arena[pivot].hash),
            ) {
                valid = false;
                break;
            }
        }

        for (index, delta) in &weight_delta {
            inner.weight_tree.path_apply(*index, *delta);
        }

        valid
    }

    #[allow(dead_code)]
    fn log_debug_epoch_computation(
        &self, epoch_arena_index: usize, inner: &mut ConsensusGraphInner,
    ) -> ComputeEpochDebugRecord {
        let epoch_block_hash = inner.arena[epoch_arena_index].hash;

        let epoch_block_hashes =
            inner.get_epoch_block_hashes(epoch_arena_index);

        // Parent state root.
        let parent_arena_index = inner.arena[epoch_arena_index].parent;
        let parent_block_hash = inner.arena[parent_arena_index].hash;
        let parent_state_root = inner
            .data_man
            .get_epoch_execution_commitment(&parent_block_hash)
            .unwrap()
            .state_root_with_aux_info
            .clone();

        let reward_index = inner.get_pivot_reward_index(epoch_arena_index);

        let reward_execution_info = self
            .executor
            .get_reward_execution_info_from_index(inner, reward_index);
        let task = EpochExecutionTask::new(
            epoch_block_hash,
            epoch_block_hashes.clone(),
            inner.get_epoch_start_block_number(epoch_arena_index),
            reward_execution_info,
            false,
            true,
        );
        let debug_record_data = task.debug_record.clone();
        {
            let mut debug_record_data_locked = debug_record_data.lock();
            let debug_record = debug_record_data_locked.as_mut().unwrap();

            debug_record.parent_block_hash = parent_block_hash;
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

            let blocks = epoch_block_hashes
                .iter()
                .map(|hash| {
                    self.data_man
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
        self.executor.enqueue_epoch(task);
        self.executor.wait_for_result(epoch_block_hash);

        Arc::try_unwrap(debug_record_data)
            .unwrap()
            .into_inner()
            .unwrap()
    }

    #[allow(dead_code)]
    fn log_invalid_state_root(
        &self, expected_state_root: &StateRootWithAuxInfo,
        got_state_root: &StateRootWithAuxInfo, deferred: usize,
        inner: &mut ConsensusGraphInner,
    ) -> std::io::Result<()>
    {
        let debug_record = self.log_debug_epoch_computation(deferred, inner);
        let debug_record_rlp = debug_record.rlp_bytes();

        let deferred_block_hash = inner.arena[deferred].hash;

        warn!(
            "Invalid state root: should be {:?}, got {:?}, deferred block: {:?}, \
            reward epoch bock: {:?}, anticone cutoff block: {:?}, \
            number of blocks in epoch: {:?}, number of transactions in epoch: {:?}, rewards: {:?}",
            expected_state_root,
            got_state_root,
            deferred_block_hash,
            debug_record.reward_epoch_hash,
            debug_record.anticone_penalty_cutoff_epoch_hash,
            debug_record.block_hashes.len(),
            debug_record.transactions.len(),
            debug_record.merged_rewards_by_author,
        );

        let dump_dir = &self.conf.debug_dump_dir_invalid_state_root;
        let invalid_state_root_path =
            dump_dir.clone() + &deferred_block_hash.to_hex();
        std::fs::create_dir_all(dump_dir)?;

        if std::path::Path::new(&invalid_state_root_path).exists() {
            return Ok(());
        }
        let mut file = std::fs::File::create(&invalid_state_root_path)?;
        file.write_all(&debug_record_rlp)?;

        Ok(())
    }

    fn check_block_full_validity(
        &self, new: usize, block_header: &BlockHeader,
        inner: &mut ConsensusGraphInner, adaptive: bool,
        anticone_barrier: &BitSet,
        weight_tuple: Option<&(Vec<i128>, Vec<i128>, Vec<i128>)>,
    ) -> bool
    {
        let parent = inner.arena[new].parent;
        if inner.arena[parent].data.partial_invalid {
            warn!(
                "Partially invalid due to partially invalid parent. {:?}",
                block_header.clone()
            );
            return false;
        }

        // Check whether the new block select the correct parent block
        if !ConsensusNewBlockHandler::check_correct_parent(
            inner,
            new,
            anticone_barrier,
            weight_tuple,
        ) {
            warn!(
                "Partially invalid due to picking incorrect parent. {:?}",
                block_header.clone()
            );
            return false;
        }

        // Check whether difficulty is set correctly
        if inner.arena[new].difficulty
            != inner.expected_difficulty(&inner.arena[parent].hash)
        {
            warn!(
                "Partially invalid due to wrong difficulty. {:?}",
                block_header.clone()
            );
            return false;
        }

        // Check adaptivity match. Note that in bench mode we do not check
        // the adaptive field correctness. We simply override its value
        // with the right one.
        if !self.conf.bench_mode {
            if inner.arena[new].adaptive != adaptive {
                warn!(
                    "Partially invalid due to invalid adaptive field. {:?}",
                    block_header.clone()
                );
                return false;
            }
        }

        return true;
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

    /// Subroutine called by on_new_block()
    fn update_lcts_initial(&self, inner: &mut ConsensusGraphInner, me: usize) {
        let parent = inner.arena[me].parent;

        inner.weight_tree.make_tree(me);
        inner.weight_tree.link(parent, me);
        inner.inclusive_weight_tree.make_tree(me);
        inner.inclusive_weight_tree.link(parent, me);
        inner.stable_weight_tree.make_tree(me);
        inner.stable_weight_tree.link(parent, me);

        inner.stable_tree.make_tree(me);
        inner.stable_tree.link(parent, me);
        let past_era_weight = if inner.arena[parent].height
            % inner.inner_conf.era_epoch_count
            == 0
        {
            0
        } else {
            inner.arena[parent].past_era_weight
        };
        inner.stable_tree.set(
            me,
            (inner.inner_conf.adaptive_weight_alpha_num as i128)
                * (inner.block_weight(parent, false /* inclusive */)
                    + past_era_weight),
        );

        inner.adaptive_tree.make_tree(me);
        inner.adaptive_tree.link(parent, me);
        let parent_w = inner.weight_tree.get(parent);
        inner.adaptive_tree.set(
            me,
            -parent_w * (inner.inner_conf.adaptive_weight_alpha_num as i128),
        );

        inner.inclusive_adaptive_tree.make_tree(me);
        inner.inclusive_adaptive_tree.link(parent, me);
        let parent_iw = inner.inclusive_weight_tree.get(parent);
        inner.inclusive_adaptive_tree.set(
            me,
            -parent_iw * (inner.inner_conf.adaptive_weight_alpha_num as i128),
        );
    }

    /// Subroutine called by on_new_block()
    fn update_lcts_finalize(
        &self, inner: &mut ConsensusGraphInner, me: usize, stable: bool,
    ) -> i128 {
        let parent = inner.arena[me].parent;
        let weight = inner.block_weight(me, false /* inclusive */);
        let inclusive_weight =
            inner.block_weight(me, true /* inclusive */);

        inner.weight_tree.path_apply(me, weight);
        inner.inclusive_weight_tree.path_apply(me, inclusive_weight);
        if stable {
            inner.stable_weight_tree.path_apply(me, weight);
        }

        inner.stable_tree.path_apply(
            me,
            (inner.inner_conf.adaptive_weight_alpha_den as i128) * weight,
        );
        if stable {
            inner.adaptive_tree.path_apply(
                me,
                (inner.inner_conf.adaptive_weight_alpha_den as i128) * weight,
            );
        }
        inner.adaptive_tree.caterpillar_apply(
            parent,
            -weight * (inner.inner_conf.adaptive_weight_alpha_num as i128),
        );

        inner.inclusive_adaptive_tree.path_apply(
            me,
            (inner.inner_conf.adaptive_weight_alpha_den as i128)
                * inclusive_weight,
        );
        inner.inclusive_adaptive_tree.caterpillar_apply(
            parent,
            -inclusive_weight
                * (inner.inner_conf.adaptive_weight_alpha_num as i128),
        );

        weight
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
        let mut anticone_tmp = HashSet::new();
        let anticone = if let Some(x) = inner.anticone_cache.get(era_block) {
            x
        } else {
            let anticone_bitset =
                ConsensusNewBlockHandler::compute_anticone_bruteforce(
                    inner, era_block,
                );
            for idx in anticone_bitset.iter() {
                anticone_tmp.insert(idx as usize);
            }
            &anticone_tmp
        };

        for idx in anticone.iter() {
            self.recycle_tx_in_block(inner, *idx);
        }

        let future = inner.compute_future_bitset(era_block);
        for idx in future.iter() {
            let index = idx as usize;
            let lca = inner.lca(index, era_block);
            if lca != era_block {
                self.recycle_tx_in_block(inner, index);
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
        let mut terminals = Vec::with_capacity(inner.terminal_hashes.len());
        for h in &inner.terminal_hashes {
            terminals.push(h.clone());
        }
        self.data_man.insert_terminals_to_db(terminals);
    }

    fn try_clear_blockset_in_own_view_of_epoch(
        inner: &mut ConsensusGraphInner, me: usize,
    ) {
        if inner.arena[me].data.blockset_in_own_view_of_epoch.len() as u64
            > BLOCKSET_IN_OWN_VIEW_OF_EPOCH_CAP
        {
            inner.arena[me].data.blockset_in_own_view_of_epoch =
                Default::default();
            inner.arena[me].data.ordered_executable_epoch_blocks =
                Default::default();
            inner.arena[me].data.blockset_cleared = true;
        }
    }

    /// The top level function invoked by ConsensusGraph to insert a new block.
    pub fn on_new_block(
        &self, inner: &mut ConsensusGraphInner, meter: &ConfirmationMeter,
        hash: &H256, block_header: &BlockHeader,
        transactions: Option<&Vec<Arc<SignedTransaction>>>,
    )
    {
        let parent_hash = block_header.parent_hash();
        let parent_index = inner.hash_to_arena_indices.get(&parent_hash);
        let block_status_in_db = self
            .data_man
            .local_block_info_from_db(hash)
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
            let sn = self.process_outside_block(inner, &block_header);
            let block_info = LocalBlockInfo::new(
                block_status_in_db,
                sn,
                self.data_man.get_instance_id(),
            );
            self.data_man
                .insert_local_block_info_to_db(hash, block_info);
            return;
        }

        let me = self.insert_block_initial(inner, &block_header);
        let parent = inner.arena[me].parent;
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
        //        let mut confirmed_height = meter.get_confirmed_epoch_num();
        //        if confirmed_height < DEFERRED_STATE_EPOCH_COUNT {
        //            confirmed_height = DEFERRED_STATE_EPOCH_COUNT;
        //        }
        // We can not assume that confirmed epoch are already executed,
        // but we can assume that the deferred block are executed.
        // FIXME: shouldn't unwrap but the function doesn't return error...

        // FIXME Handle snapshot maintain
        //        let confirmed_epoch_hash = inner
        //            .get_hash_from_epoch_number(
        //                // FIXME: we need a function to compute the deferred
        // epoch                // FIXME: number. the current codebase
        // may not be                // FIXME: consistent at all places.
        //                confirmed_height - DEFERRED_STATE_EPOCH_COUNT,
        //            )
        //            .unwrap();
        //        // FIXME: we also need more helper function to get the
        // execution result        // FIXME: for block deferred or not.
        //        if let Some(confirmed_epoch) = &*self
        //            .data_man
        //            .get_epoch_execution_commitment(&confirmed_epoch_hash)
        //        {
        //            self.data_man
        //                .storage_manager
        //                .get_storage_manager()
        //                .maintain_snapshots_pivot_chain_confirmed(
        //                    confirmed_height,
        //                    &confirmed_epoch_hash,
        //                    &confirmed_epoch.state_root_with_aux_info,
        //                )
        //                // FIXME: handle error.
        //                .ok();
        //        }

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
            let mut state_at = fork_at;
            if fork_at + DEFERRED_STATE_EPOCH_COUNT > old_pivot_chain_height {
                if old_pivot_chain_height > DEFERRED_STATE_EPOCH_COUNT {
                    state_at =
                        old_pivot_chain_height - DEFERRED_STATE_EPOCH_COUNT + 1;
                } else {
                    state_at = 1;
                }
            }
            {
                let mut state_availability_boundary =
                    inner.data_man.state_availability_boundary.write();
                assert!(fork_at > state_availability_boundary.lower_bound);
                if pivot_changed {
                    if extend_pivot {
                        state_availability_boundary.pivot_chain.push(*hash);
                    } else {
                        let split_off_index =
                            fork_at - state_availability_boundary.lower_bound;
                        state_availability_boundary
                            .pivot_chain
                            .split_off(split_off_index as usize);
                        for i in inner.height_to_pivot_index(fork_at)
                            ..inner.pivot_chain.len()
                        {
                            state_availability_boundary
                                .pivot_chain
                                .push(inner.arena[inner.pivot_chain[i]].hash);
                        }
                        if state_availability_boundary.upper_bound >= fork_at {
                            state_availability_boundary.upper_bound =
                                fork_at - 1;
                        }
                    }
                    state_availability_boundary.optimistic_executed_height =
                        if to_state_pos > 0 {
                            Some(to_state_pos)
                        } else {
                            None
                        };
                }
                // For full node, we don't execute blocks before available
                // states. This skip should only happen in
                // `SyncBlockPhase` for full nodes
                if state_at < state_availability_boundary.lower_bound + 1 {
                    state_at = state_availability_boundary.lower_bound + 1;
                }
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
        }

        self.persist_terminal_and_block_info(
            inner,
            me,
            block_status,
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
            inner.arena[me].data.sequence_number,
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
    /// FIXME Ensure we have snapshot at state_boundary_height
    pub fn construct_pivot_state(&self, inner: &mut ConsensusGraphInner) {
        if inner.pivot_chain.len() < DEFERRED_STATE_EPOCH_COUNT as usize {
            return;
        }
        let state_boundary_height =
            self.data_man.state_availability_boundary.read().lower_bound;
        let start_pivot_index =
            (state_boundary_height - inner.cur_era_genesis_height) as usize;
        let mut start_hash =
            inner.arena[inner.pivot_chain[start_pivot_index]].hash;
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
        {
            let mut state_availability_boundary =
                self.data_man.state_availability_boundary.write();
            assert!(
                state_availability_boundary.lower_bound
                    == state_availability_boundary.upper_bound
            );
            for pivot_index in start_pivot_index + 1..inner.pivot_chain.len() {
                state_availability_boundary
                    .pivot_chain
                    .push(inner.arena[inner.pivot_chain[pivot_index]].hash);
            }
        }
        if state_boundary_height == 0 {
            start_hash = NULL_EPOCH;
        }
        let storage_manager =
            self.data_man.storage_manager.get_storage_manager();
        let mut parent_snapshot_id = start_hash;
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
            } else {
                self.data_man
                    .state_availability_boundary
                    .write()
                    .upper_bound += 1;
            }
            if pivot_index as u64
                % (storage_manager.get_snapshot_epoch_count() as u64)
                == 0
            {
                // FIXME Most are fake because not used now
                let mut snapshot_info = SnapshotInfo {
                    serve_one_step_sync: false,
                    merkle_root: Default::default(),
                    parent_snapshot_height: inner.arena[arena_index].height
                        - storage_manager.get_snapshot_epoch_count() as u64,
                    height: inner.arena[arena_index].height,
                    parent_snapshot_epoch_id: parent_snapshot_id,
                    pivot_chain_parts: vec![pivot_hash],
                };
                match storage_manager
                    .get_snapshot_manager()
                    .get_snapshot_by_epoch_id(&pivot_hash)
                    .expect("No db error")
                {
                    Some(mut snapshot) => {
                        snapshot_info.merkle_root = snapshot
                            .open_snapshot_mpt_read_only()
                            .expect("No db error")
                            .get_merkle_root();
                        storage_manager
                            .register_new_snapshot(snapshot_info)
                            .expect("No db error");
                        // Setup delta_mpt
                        storage_manager
                            .get_delta_mpt(&pivot_hash)
                            .expect("No db error");
                    }
                    None => {
                        // TODO Resume the unfinished snapshot making. Maybe
                        // better handling?
                        let (_guard, maybe_commitment) = self
                            .data_man
                            .get_epoch_execution_commitment(&pivot_hash)
                            .into();
                        let height = self
                            .data_man
                            .block_header_by_hash(&pivot_hash)
                            .expect("header exist")
                            .height();
                        let state_index = StateIndex::new_for_next_epoch(
                            &pivot_hash,
                            &maybe_commitment
                                .unwrap()
                                .state_root_with_aux_info
                                .aux_info,
                            height,
                            self.data_man.get_snapshot_epoch_count(),
                        );
                        let state = self
                            .data_man
                            .storage_manager
                            .get_state_trees_for_next_epoch(&state_index)
                            .unwrap()
                            .unwrap();
                        let intermediate_root = state.intermediate_trie_root;
                        let maybe_intermediate_trie =
                            state.maybe_intermediate_trie;
                        self.data_man
                            .storage_manager
                            .check_make_snapshot(
                                maybe_intermediate_trie,
                                intermediate_root,
                                &pivot_hash,
                                inner.arena[arena_index].height,
                            )
                            .expect("No db error");
                        storage_manager
                            .in_progress_snapshoting_tasks
                            .write()
                            .remove(&pivot_hash)
                            .expect("Just inserted")
                            .thread
                            .join()
                            .unwrap();
                        storage_manager
                            .get_delta_mpt(&pivot_hash)
                            .expect("No db error");
                    }
                }
                parent_snapshot_id = pivot_hash;
            }
        }
    }
}
