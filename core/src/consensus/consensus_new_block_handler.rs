use crate::{
    block_data_manager::{BlockDataManager, BlockStatus},
    consensus::{
        consensus_executor::{ConsensusExecutor, EpochExecutionTask},
        debug::ComputeEpochDebugRecord,
        ConsensusConfig, ConsensusGraphInner, ANTICONE_BARRIER_CAP,
        DEFERRED_STATE_EPOCH_COUNT, ERA_CHECKPOINT_GAP,
        ERA_RECYCLE_TRANSACTION_DELAY, MAX_NUM_MAINTAINED_RISK,
        MIN_MAINTAINED_RISK, NULL, NULLU64,
    },
    rlp::Encodable,
    statistics::SharedStatistics,
    storage::{
        state::StateTrait, state_manager::StateManagerTrait,
        SnapshotAndEpochIdRef,
    },
    SharedTransactionPool,
};
use cfx_types::{into_i128, H256};
use hibitset::{BitSet, BitSetLike};
use parking_lot::RwLock;
use primitives::{
    Block, BlockHeaderBuilder, StateRoot, StateRootAuxInfo,
    StateRootWithAuxInfo,
};
use std::{
    cmp::max,
    collections::{HashSet, VecDeque},
    io::Write,
    sync::Arc,
};

pub struct FinalityManager {
    pub lowest_epoch_num: u64,
    pub risks_less_than: VecDeque<f64>,
}

pub struct ConsensusNewBlockHandler {
    conf: ConsensusConfig,
    txpool: SharedTransactionPool,
    data_man: Arc<BlockDataManager>,
    executor: Arc<ConsensusExecutor>,
    statistics: SharedStatistics,
    finality_manager: RwLock<FinalityManager>,
}

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
            finality_manager: RwLock::new(FinalityManager {
                lowest_epoch_num: 0,
                risks_less_than: VecDeque::new(),
            }),
        }
    }

    pub fn confirmation_risk_by_hash(
        &self, inner: &ConsensusGraphInner, hash: H256,
    ) -> Option<f64> {
        let index = *inner.indices.get(&hash)?;
        let epoch_num = inner.arena[index].data.epoch_number;
        if epoch_num == NULLU64 {
            return None;
        }

        if epoch_num == 0 {
            return Some(0.0);
        }

        let finality = self.finality_manager.read();

        if epoch_num < finality.lowest_epoch_num {
            return Some(MIN_MAINTAINED_RISK);
        }

        let idx = (epoch_num - finality.lowest_epoch_num) as usize;
        if idx < finality.risks_less_than.len() {
            let mut max_risk = 0.0;
            for i in 0..idx + 1 {
                let risk = *finality.risks_less_than.get(i).unwrap();
                if max_risk < risk {
                    max_risk = risk;
                }
            }
            Some(max_risk)
        } else {
            None
        }
    }

    fn confirmation_risk(
        &self, inner: &mut ConsensusGraphInner, w_0: i128, w_4: i128,
        epoch_num: u64,
    ) -> f64
    {
        // Compute w_1
        let idx = inner.get_pivot_block_index(epoch_num);
        let w_1 = inner.block_weight(idx, false);

        // Compute w_2
        let parent = inner.arena[idx].parent;
        assert!(parent != NULL);
        let mut max_weight = 0;
        for child in inner.arena[parent].children.iter() {
            if *child == idx || inner.arena[*child].data.partial_invalid {
                continue;
            }

            let child_weight = inner.block_weight(*child, false);
            if child_weight > max_weight {
                max_weight = child_weight;
            }
        }
        let w_2 = max_weight;

        // Compute w_3
        let w_3 = inner.arena[idx].past_weight;

        // Compute d
        let d = into_i128(&inner.current_difficulty);

        // Compute n
        let w_2_4 = w_2 + w_4;
        let n = if w_1 >= w_2_4 { w_1 - w_2_4 } else { 0 };

        let n = (n / d) + 1;

        // Compute m
        let m = if w_0 >= w_3 { w_0 - w_3 } else { 0 };

        let m = m / d;

        // Compute risk
        let m_2 = 2i128 * m;
        let e_1 = m_2 / 5i128;
        let e_2 = m_2 / 7i128;
        let n_min_1 = e_1 + 13i128;
        let n_min_2 = e_2 + 36i128;
        let n_min = if n_min_1 < n_min_2 { n_min_1 } else { n_min_2 };

        let mut risk = 0.9;
        if n <= n_min {
            return risk;
        }

        risk = 0.0001;

        let n_min_1 = e_1 + 19i128;
        let n_min_2 = e_2 + 57i128;
        let n_min = if n_min_1 < n_min_2 { n_min_1 } else { n_min_2 };

        if n <= n_min {
            return risk;
        }

        risk = 0.000001;
        risk
    }

    fn update_confirmation_risks(
        &self, inner: &mut ConsensusGraphInner, w_4: i128,
    ) {
        if inner.pivot_chain.len() > DEFERRED_STATE_EPOCH_COUNT as usize {
            let w_0 = inner.weight_tree.get(inner.cur_era_genesis_block_index);
            let mut risks = VecDeque::new();
            let mut epoch_num = inner
                .pivot_index_to_height(inner.pivot_chain.len())
                - DEFERRED_STATE_EPOCH_COUNT;
            let mut count = 0;
            while epoch_num > 0 && count < MAX_NUM_MAINTAINED_RISK {
                let risk = self.confirmation_risk(inner, w_0, w_4, epoch_num);
                if risk <= MIN_MAINTAINED_RISK {
                    break;
                }
                risks.push_front(risk);
                epoch_num -= 1;
                count += 1;
            }

            if risks.is_empty() {
                epoch_num = 0;
            } else {
                epoch_num += 1;
            }

            let mut finality = self.finality_manager.write();
            finality.lowest_epoch_num = epoch_num;
            finality.risks_less_than = risks;
        }
    }

    pub fn compute_state_for_block(
        &self, block_hash: &H256, inner: &mut ConsensusGraphInner,
    ) -> Result<(StateRootWithAuxInfo, H256), String> {
        // If we already computed the state of the block before, we should not
        // do it again
        debug!("compute_state_for_block {:?}", block_hash);
        {
            if let Ok(maybe_cached_state) =
                self.data_man.storage_manager.get_state_no_commit(
                    SnapshotAndEpochIdRef::new(&block_hash.clone(), None),
                )
            {
                match maybe_cached_state {
                    Some(cached_state) => {
                        if let Some(receipts_root) =
                            self.data_man.get_receipts_root(&block_hash)
                        {
                            return Ok((
                                cached_state.get_state_root().unwrap().unwrap(),
                                receipts_root,
                            ));
                        }
                    }
                    None => {}
                }
            } else {
                return Err("Internal storage error".to_owned());
            }
        }
        let me_opt = inner.indices.get(block_hash);
        if me_opt == None {
            return Err("Block hash not found!".to_owned());
        }
        let me: usize = *me_opt.unwrap();
        let block_height = inner.arena[me].height;
        let mut fork_height = block_height;
        let mut chain: Vec<usize> = Vec::new();
        let mut idx = me;
        while fork_height > 0
            && (fork_height >= inner.get_pivot_height()
                || inner.get_pivot_block_index(fork_height) != idx)
        {
            chain.push(idx);
            fork_height -= 1;
            idx = inner.arena[idx].parent;
        }
        // Because we have genesis at height 0, this should always be true
        debug_assert!(inner.get_pivot_block_index(fork_height) == idx);
        debug!("Forked at index {} height {}", idx, fork_height);
        chain.push(idx);
        chain.reverse();
        let start_index = inner.find_start_index(&chain);
        debug!("Start execution from index {}", start_index);

        // We need the state of the fork point to start executing the fork
        if start_index != 0 {
            let mut last_state_height =
                if inner.get_pivot_height() > DEFERRED_STATE_EPOCH_COUNT {
                    inner.get_pivot_height() - DEFERRED_STATE_EPOCH_COUNT
                } else {
                    0
                };

            last_state_height += 1;
            while last_state_height <= fork_height {
                let epoch_index =
                    inner.get_pivot_block_index(last_state_height);
                let reward_execution_info = inner
                    .get_reward_execution_info(&self.data_man, epoch_index);
                self.executor.enqueue_epoch(EpochExecutionTask::new(
                    inner.arena[epoch_index].hash,
                    inner.get_epoch_block_hashes(epoch_index),
                    reward_execution_info,
                    false,
                    false,
                ));
                last_state_height += 1;
            }
        }

        for fork_index in start_index..chain.len() {
            let epoch_index = chain[fork_index];
            let reward_index = inner.get_pivot_reward_index(epoch_index);

            let reward_execution_info = inner
                .get_reward_execution_info_from_index(
                    &self.data_man,
                    reward_index,
                );
            self.executor.enqueue_epoch(EpochExecutionTask::new(
                inner.arena[epoch_index].hash,
                inner.get_epoch_block_hashes(epoch_index),
                reward_execution_info,
                false,
                false,
            ));
        }

        let (state_root, receipts_root) =
            self.executor.wait_for_result(*block_hash);
        debug!(
            "Epoch {:?} has state_root={:?} receipts_root={:?}",
            inner.arena[me].hash, state_root, receipts_root
        );

        Ok((state_root, receipts_root))
    }

    fn log_debug_epoch_computation(
        &self, epoch_index: usize, inner: &ConsensusGraphInner,
    ) -> ComputeEpochDebugRecord {
        let epoch_block_hash = inner.arena[epoch_index].hash;

        let epoch_block_hashes = inner.get_epoch_block_hashes(epoch_index);

        // Parent state root.
        let parent_index = inner.arena[epoch_index].parent;
        let parent_block_hash = inner.arena[parent_index].hash;
        let parent_state_root = inner
            .data_man
            .storage_manager
            .get_state_no_commit(SnapshotAndEpochIdRef::new(
                &parent_block_hash,
                None,
            ))
            .unwrap()
            // Unwrapping is safe because the state exists.
            .unwrap()
            .get_state_root()
            .unwrap()
            .unwrap();

        let reward_index = inner.get_pivot_reward_index(epoch_index);

        let reward_execution_info = inner
            .get_reward_execution_info_from_index(&self.data_man, reward_index);
        let task = EpochExecutionTask::new(
            epoch_block_hash,
            epoch_block_hashes.clone(),
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
                .map(|hash| self.data_man.block_by_hash(hash, false).unwrap())
                .collect::<Vec<_>>();

            debug_record.block_hashes = epoch_block_hashes;
            debug_record.block_txs = blocks
                .iter()
                .map(|block| block.transactions.len())
                .collect::<Vec<_>>();;
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

    fn log_invalid_state_root(
        &self, expected_state_root: &StateRootWithAuxInfo,
        got_state_root: (&StateRoot, &StateRootAuxInfo), deferred: usize,
        inner: &ConsensusGraphInner,
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
            dump_dir.clone() + &deferred_block_hash.hex();
        std::fs::create_dir_all(dump_dir)?;

        if std::path::Path::new(&invalid_state_root_path).exists() {
            return Ok(());
        }
        let mut file = std::fs::File::create(&invalid_state_root_path)?;
        file.write_all(&debug_record_rlp)?;

        Ok(())
    }

    fn check_block_full_validity(
        &self, new: usize, block: &Block, inner: &mut ConsensusGraphInner,
        adaptive: bool, anticone_barrier: &BitSet,
        weight_tuple: Option<&(Vec<i128>, Vec<i128>, Vec<i128>)>,
    ) -> bool
    {
        let parent = inner.arena[new].parent;
        if inner.arena[parent].data.partial_invalid {
            warn!(
                "Partially invalid due to partially invalid parent. {:?}",
                block.block_header.clone()
            );
            return false;
        }

        // Check whether the new block select the correct parent block
        if !inner.check_correct_parent(new, anticone_barrier, weight_tuple) {
            warn!(
                "Partially invalid due to picking incorrect parent. {:?}",
                block.block_header.clone()
            );
            return false;
        }

        // Check whether difficulty is set correctly
        if inner.arena[new].difficulty
            != inner.expected_difficulty(&inner.arena[parent].hash)
        {
            warn!(
                "Partially invalid due to wrong difficulty. {:?}",
                block.block_header.clone()
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
                    block.block_header.clone()
                );
                return false;
            }
        }

        // Check if the state root is correct or not
        // TODO: We may want to optimize this because now on the chain switch we
        // are going to compute state twice
        let state_root_valid = if block.block_header.height()
            < DEFERRED_STATE_EPOCH_COUNT
        {
            *block.block_header.deferred_state_root()
                == inner.genesis_block_state_root
                && *block.block_header.deferred_receipts_root()
                    == inner.genesis_block_receipts_root
        } else {
            let mut deferred = new;
            for _ in 0..DEFERRED_STATE_EPOCH_COUNT {
                deferred = inner.arena[deferred].parent;
            }
            debug_assert!(
                block.block_header.height() - DEFERRED_STATE_EPOCH_COUNT
                    == inner.arena[deferred].height
            );
            debug!("Deferred block is {:?}", inner.arena[deferred].hash);

            let correct_receipts_root =
                self.data_man.get_receipts_root(&inner.arena[deferred].hash);
            if self
                .data_man
                .storage_manager
                .contains_state(SnapshotAndEpochIdRef::new(
                    &inner.arena[deferred].hash,
                    None,
                ))
                .unwrap()
                && correct_receipts_root.is_some()
            {
                let mut valid = true;
                let correct_state_root = self
                    .data_man
                    .storage_manager
                    .get_state_no_commit(SnapshotAndEpochIdRef::new(
                        &inner.arena[deferred].hash,
                        None,
                    ))
                    .unwrap()
                    // Unwrapping is safe because the state exists.
                    .unwrap()
                    .get_state_root()
                    .unwrap()
                    .unwrap();
                if *block.block_header.deferred_state_root()
                    != correct_state_root.state_root
                {
                    self.log_invalid_state_root(
                        &correct_state_root,
                        block.block_header.deferred_state_root_with_aux_info(),
                        deferred,
                        inner,
                    )
                    .ok();
                    valid = false;
                }
                if *block.block_header.deferred_receipts_root()
                    != correct_receipts_root.unwrap()
                {
                    warn!(
                        "Invalid receipt root: should be {:?}",
                        correct_receipts_root
                    );
                    valid = false;
                }
                valid
            } else {
                // Call the expensive function to check this state root
                let deferred_hash = inner.arena[deferred].hash;
                let (state_root, receipts_root) = self
                    .compute_state_for_block(&deferred_hash, inner)
                    .unwrap();

                if state_root.state_root
                    != *block.block_header.deferred_state_root()
                {
                    self.log_invalid_state_root(
                        &state_root,
                        block.block_header.deferred_state_root_with_aux_info(),
                        deferred,
                        inner,
                    )
                    .ok();
                }

                *block.block_header.deferred_state_root()
                    == state_root.state_root
                    && *block.block_header.deferred_receipts_root()
                        == receipts_root
            }
        };

        if !state_root_valid {
            warn!(
                "Partially invalid in fork due to deferred block. me={:?}",
                block.block_header.clone()
            );
            return false;
        }
        return true;
    }

    /// Recompute metadata associated information on pivot chain changes
    fn recompute_metadata(
        &self, inner: &mut ConsensusGraphInner, start_at: u64,
        mut to_update: HashSet<usize>,
    )
    {
        inner
            .pivot_chain_metadata
            .resize_with(inner.pivot_chain.len(), Default::default);
        let pivot_height = inner.get_pivot_height();
        for i in start_at..pivot_height {
            let me = inner.get_pivot_block_index(i);
            inner.arena[me].last_pivot_in_past = i;
            let i_index = inner.height_to_pivot_index(i);
            inner.pivot_chain_metadata[i_index]
                .last_pivot_in_past_blocks
                .clear();
            inner.pivot_chain_metadata[i_index]
                .last_pivot_in_past_blocks
                .insert(me);
            to_update.remove(&me);
        }
        let mut stack = Vec::new();
        let to_visit = to_update.clone();
        for i in &to_update {
            stack.push((0, *i));
        }
        while !stack.is_empty() {
            let (stage, me) = stack.pop().unwrap();
            if !to_visit.contains(&me) {
                continue;
            }
            let parent = inner.arena[me].parent;
            if stage == 0 {
                if to_update.contains(&me) {
                    to_update.remove(&me);
                    stack.push((1, me));
                    stack.push((0, parent));
                    for referee in &inner.arena[me].referees {
                        stack.push((0, *referee));
                    }
                }
            } else if stage == 1 && me != inner.cur_era_genesis_block_index {
                let mut last_pivot = inner.arena[parent].last_pivot_in_past;
                for referee in &inner.arena[me].referees {
                    let x = inner.arena[*referee].last_pivot_in_past;
                    last_pivot = max(last_pivot, x);
                }
                inner.arena[me].last_pivot_in_past = last_pivot;
                let last_pivot_index = inner.height_to_pivot_index(last_pivot);
                inner.pivot_chain_metadata[last_pivot_index]
                    .last_pivot_in_past_blocks
                    .insert(me);
            }
        }
    }

    /// Subroutine called by on_new_block() and on_new_block_construction_only()
    fn insert_block_initial(
        &self, inner: &mut ConsensusGraphInner, block: Arc<Block>,
    ) -> usize {
        let (me, indices_len) = inner.insert(block.as_ref());
        self.statistics
            .set_consensus_graph_inserted_block_count(indices_len);
        me
    }

    /// Subroutine called by on_new_block() and on_new_block_construction_only()
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
                * (inner.block_weight(parent, false) + past_era_weight),
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

    /// Subroutine called by on_new_block() and on_new_block_construction_only()
    fn update_lcts_finalize(
        &self, inner: &mut ConsensusGraphInner, me: usize, stable: bool,
    ) -> i128 {
        let parent = inner.arena[me].parent;
        let weight = inner.block_weight(me, false);
        let inclusive_weight = inner.block_weight(me, true);

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
        inner.adaptive_tree.catepillar_apply(
            parent,
            -weight * (inner.inner_conf.adaptive_weight_alpha_num as i128),
        );

        inner.inclusive_adaptive_tree.path_apply(
            me,
            (inner.inner_conf.adaptive_weight_alpha_den as i128)
                * inclusive_weight,
        );
        inner.inclusive_adaptive_tree.catepillar_apply(
            parent,
            -inclusive_weight
                * (inner.inner_conf.adaptive_weight_alpha_num as i128),
        );

        weight
    }

    fn process_outside_block(
        &self, inner: &mut ConsensusGraphInner, block: Arc<Block>,
    ) {
        let mut referees = Vec::new();
        for hash in block.block_header.referee_hashes().iter() {
            if let Some(x) = inner.indices.get(hash) {
                inner.insert_referee_if_not_duplicate(&mut referees, *x);
            } else if let Some(r) = inner.legacy_refs.get(hash) {
                for index in r {
                    inner
                        .insert_referee_if_not_duplicate(&mut referees, *index);
                }
            }
        }
        inner
            .legacy_refs
            .insert(block.block_header.hash(), referees);
    }

    fn recycle_tx_in_block(&self, inner: &ConsensusGraphInner, index: usize) {
        let block = inner
            .data_man
            .block_by_hash(&inner.arena[index].hash, true)
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
            let anticone_bitset = inner.compute_anticone_bruteforce(era_block);
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
        if best_height <= ERA_CHECKPOINT_GAP {
            return inner.cur_era_genesis_block_index;
        }
        let stable_height = best_height - ERA_CHECKPOINT_GAP;
        let stable_era_height = inner.get_era_height(stable_height - 1, 0);
        if stable_era_height < inner.inner_conf.era_epoch_count {
            return inner.cur_era_genesis_block_index;
        }
        let safe_era_height =
            stable_era_height - inner.inner_conf.era_epoch_count;
        if inner.cur_era_genesis_height > safe_era_height {
            return inner.cur_era_genesis_block_index;
        }
        let safe_era_pivot_index = inner.height_to_pivot_index(safe_era_height);
        inner.pivot_chain[safe_era_pivot_index]
    }

    pub fn construct_pivot_info(&self, inner: &mut ConsensusGraphInner) {
        assert_eq!(inner.pivot_chain.len(), 1);
        assert_eq!(inner.pivot_chain[0], inner.cur_era_genesis_block_index);

        let mut new_pivot_chain = Vec::new();
        let mut u = inner.cur_era_genesis_block_index;
        loop {
            new_pivot_chain.push(u);
            let mut heaviest = NULL;
            let mut heaviest_weight = 0;
            for index in &inner.arena[u].children {
                let weight = inner.weight_tree.get(*index);
                if heaviest == NULL
                    || ConsensusGraphInner::is_heavier(
                        (weight, &inner.arena[*index].hash),
                        (heaviest_weight, &inner.arena[heaviest].hash),
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

        // Construct epochs
        let mut height = inner.cur_era_genesis_height + 1;
        while inner.height_to_pivot_index(height) < new_pivot_chain.len() {
            let pivot_index = inner.height_to_pivot_index(height);
            // First, identify all the blocks in the current epoch
            inner.set_epoch_number_in_epoch(
                new_pivot_chain[pivot_index],
                height,
            );

            // Construct in-memory receipts root
            if inner.pivot_index_to_height(new_pivot_chain.len())
                >= DEFERRED_STATE_EPOCH_COUNT
                && height
                    < inner.pivot_index_to_height(new_pivot_chain.len())
                        - DEFERRED_STATE_EPOCH_COUNT
            {
                // This block's deferred block is pivot_index, so the
                // deferred_receipts_root in its header is the
                // receipts_root of pivot_index
                let future_block_hash = inner.arena[new_pivot_chain[inner
                    .height_to_pivot_index(
                        height + DEFERRED_STATE_EPOCH_COUNT,
                    )]]
                .hash
                .clone();
                self.data_man.insert_receipts_root(
                    inner.arena[new_pivot_chain[pivot_index]].hash,
                    self.data_man
                        .block_header_by_hash(&future_block_hash)
                        .unwrap()
                        .deferred_receipts_root()
                        .clone(),
                );
            }
            height += 1;
        }

        // If the db is not corrupted, all unwrap in the following should
        // pass.
        // TODO Verify db state in case of data missing
        // TODO Recompute missing data if needed
        inner.adjust_difficulty(*new_pivot_chain.last().expect("not empty"));
        inner.pivot_chain = new_pivot_chain;

        // Now we construct pivot_chain_metadata and compute
        // last_pivot_in_past
        let mut metadata_to_update = HashSet::new();
        for (i, _) in inner.arena.iter() {
            metadata_to_update.insert(i);
        }
        self.recompute_metadata(inner, 0, metadata_to_update);
    }

    pub fn construct_state_info(&self, inner: &ConsensusGraphInner) {
        // Compute receipts root for the deferred block of the mining block,
        // which is not in the db
        if inner.pivot_index_to_height(inner.pivot_chain.len())
            > DEFERRED_STATE_EPOCH_COUNT
        {
            let state_height = inner
                .pivot_index_to_height(inner.pivot_chain.len())
                - DEFERRED_STATE_EPOCH_COUNT;
            let pivot_index = inner.get_pivot_block_index(state_height);
            let pivot_hash = inner.arena[pivot_index].hash.clone();
            let epoch_indexes = &inner.arena[pivot_index]
                .data
                .ordered_executable_epoch_blocks;
            let mut epoch_receipts = Vec::with_capacity(epoch_indexes.len());

            let mut receipts_correct = true;
            for i in epoch_indexes {
                if let Some(r) = self.data_man.block_results_by_hash_with_epoch(
                    &inner.arena[*i].hash,
                    &pivot_hash,
                    true,
                ) {
                    epoch_receipts.push(r.receipts);
                } else {
                    // Constructed pivot chain does not match receipts in
                    // db, so we have to recompute
                    // the receipts of this epoch
                    receipts_correct = false;
                    break;
                }
            }
            if receipts_correct {
                self.data_man.insert_receipts_root(
                    pivot_hash,
                    BlockHeaderBuilder::compute_block_receipts_root(
                        &epoch_receipts,
                    ),
                );
            } else {
                let reward_execution_info = inner.get_reward_execution_info(
                    &self.data_man,
                    inner.get_pivot_block_index(state_height),
                );
                let epoch_block_hashes = inner.get_epoch_block_hashes(
                    inner.get_pivot_block_index(state_height),
                );
                self.executor.compute_epoch(EpochExecutionTask::new(
                    pivot_hash,
                    epoch_block_hashes,
                    reward_execution_info,
                    true,
                    false,
                ));
            }
        }
    }

    /// This is the function to insert a new block into the consensus graph
    /// during construction. We by pass many verifications because those
    /// blocks are from our own database so we trust them. After inserting
    /// all blocks with this function, we need to call construct_pivot() to
    /// finish the building from db!ss
    pub fn on_new_block_construction_only(
        &self, inner: &mut ConsensusGraphInner, hash: &H256, block: Arc<Block>,
    ) {
        let parent_hash = block.block_header.parent_hash();
        if !inner.indices.contains_key(&parent_hash) {
            self.process_outside_block(inner, block);
            return;
        }

        let me = self.insert_block_initial(inner, block.clone());

        let anticone_barrier = inner.compute_anticone(me);
        let weight_tuple = if anticone_barrier.len() >= ANTICONE_BARRIER_CAP {
            Some(inner.compute_subtree_weights(me, &anticone_barrier))
        } else {
            None
        };
        let (fully_valid, pending) = match self
            .data_man
            .block_status_from_db(hash)
        {
            Some(BlockStatus::Valid) => (true, false),
            Some(BlockStatus::Pending) => (true, true),
            Some(BlockStatus::PartialInvalid) => (false, false),
            None => {
                // FIXME If the status of a block close to terminals is missing
                // (likely to happen) and we try to check its validity with the
                // commented code, we will recompute the whole DAG from genesis
                // because the pivot chain is empty now, which is not what we
                // want for fast recovery. A better solution is
                // to assume it's partial invalid, construct the pivot chain and
                // other data like block_receipts_root first, and then check its
                // full validity. The pivot chain might need to be updated
                // depending on the validity result.

                // The correct logic here should be as follows, but this
                // solution is very costly
                // ```
                // let valid = self.check_block_full_validity(me, &block, inner, sync_inner);
                // self.insert_block_status_to_db(hash, !valid);
                // valid
                // ```

                // The assumed value should be false after we fix this issue.
                // Now we optimistically hope that they are valid.
                debug!("Assume block {} is valid/pending", hash);
                (true, true)
            }
            Some(BlockStatus::Invalid) => {
                // Blocks marked invalid should not exist in database, so should
                // not be inserted during construction.
                unreachable!()
            }
        };

        inner.arena[me].data.partial_invalid = !fully_valid;
        inner.arena[me].data.pending = pending;

        self.update_lcts_initial(inner, me);

        let (stable, adaptive) =
            inner.adaptive_weight(me, &anticone_barrier, weight_tuple.as_ref());
        inner.arena[me].stable = stable;
        if self.conf.bench_mode && fully_valid {
            inner.arena[me].adaptive = adaptive;
        }

        self.update_lcts_finalize(inner, me, stable);
    }

    /// This is the main function that SynchronizationGraph calls to deliver a
    /// new block to the consensus graph.
    pub fn on_new_block(
        &self, inner: &mut ConsensusGraphInner, hash: &H256, block: Arc<Block>,
    ) {
        let parent_hash = block.block_header.parent_hash();
        if !inner.indices.contains_key(&parent_hash) {
            self.process_outside_block(inner, block);
            return;
        }

        let me = self.insert_block_initial(inner, block.clone());
        let parent = inner.arena[me].parent;
        let era_height = inner.get_era_height(inner.arena[parent].height, 0);
        let mut fully_valid = true;
        let cur_pivot_era_block = if inner
            .pivot_index_to_height(inner.pivot_chain.len())
            > era_height
        {
            inner.get_pivot_block_index(era_height)
        } else {
            NULL
        };
        let era_block = inner.get_era_block_with_parent(parent, 0);

        // It's only correct to set tx stale after the block is considered
        // terminal for mining.
        // Note that we conservatively only mark those blocks inside the current
        // pivot era
        if era_block == cur_pivot_era_block {
            self.txpool.set_tx_packed(block.transactions.clone());
        }

        let pending = inner.ancestor_at(parent, inner.cur_era_stable_height)
            != inner.get_pivot_block_index(inner.cur_era_stable_height);

        let anticone_barrier = inner.compute_anticone(me);

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
                block.as_ref(),
                inner,
                adaptive,
                &anticone_barrier,
                weight_tuple.as_ref(),
            );

            inner.arena[me].stable = stable;
            if self.conf.bench_mode && fully_valid {
                inner.arena[me].adaptive = adaptive;
            }
        }
        self.data_man.insert_block_status_to_db(
            hash,
            if pending {
                BlockStatus::Pending
            } else if fully_valid {
                BlockStatus::Valid
            } else {
                BlockStatus::PartialInvalid
            },
        );

        if pending {
            inner.arena[me].data.pending = true;
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
            inner.aggregate_total_weight_in_past(my_weight);

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
                fork_at = inner.arena[lca].height + 1;
                let prev = inner.get_pivot_block_index(fork_at);
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
                        inner.reset_epoch_number_in_epoch(discarded_idx)
                    }
                    let mut u = new;
                    loop {
                        inner.pivot_chain.push(u);
                        inner.set_epoch_number_in_epoch(
                            u,
                            inner
                                .pivot_index_to_height(inner.pivot_chain.len())
                                - 1,
                        );
                        let mut heaviest = NULL;
                        let mut heaviest_weight = 0;
                        for index in &inner.arena[u].children {
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
                    // The previous subtree is still heavier, nothing is updated
                    debug!("Old pivot chain is heavier, pivot chain unchanged");
                    fork_at = inner.pivot_index_to_height(old_pivot_chain_len);
                }
            };
            debug!(
                "Forked at index {}",
                inner.get_pivot_block_index(fork_at - 1)
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
                let update_index = inner.height_to_pivot_index(update_at);
                for pivot_index in update_index..old_pivot_chain_len {
                    for x in &inner.pivot_chain_metadata[pivot_index]
                        .last_pivot_in_past_blocks
                    {
                        last_pivot_to_update.insert(*x);
                    }
                }
                self.recompute_metadata(inner, fork_at, last_pivot_to_update);
            } else {
                self.recompute_metadata(
                    inner,
                    inner.get_pivot_height(),
                    last_pivot_to_update,
                );
            }
        } else {
            let height = inner.arena[me].height;
            inner.arena[me].last_pivot_in_past = height;
            let p_index = inner.height_to_pivot_index(height);
            inner.pivot_chain_metadata[p_index]
                .last_pivot_in_past_blocks
                .insert(me);
        }

        // Now we can safely return
        if !fully_valid || pending {
            return;
        }

        let new_pivot_era_block = inner
            .get_era_block_with_parent(*inner.pivot_chain.last().unwrap(), 0);
        let new_era_height = inner.arena[new_pivot_era_block].height;
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
        if fork_at + DEFERRED_STATE_EPOCH_COUNT
            > inner.pivot_index_to_height(old_pivot_chain_len)
        {
            if inner.pivot_index_to_height(old_pivot_chain_len)
                > DEFERRED_STATE_EPOCH_COUNT
            {
                state_at = inner.pivot_index_to_height(old_pivot_chain_len)
                    - DEFERRED_STATE_EPOCH_COUNT
                    + 1;
            } else {
                state_at = 1;
            }
        }

        // Apply transactions in the determined total order
        while state_at < to_state_pos {
            let epoch_index = inner.get_pivot_block_index(state_at);
            let reward_execution_info =
                inner.get_reward_execution_info(&self.data_man, epoch_index);
            self.executor.enqueue_epoch(EpochExecutionTask::new(
                inner.arena[epoch_index].hash,
                inner.get_epoch_block_hashes(epoch_index),
                reward_execution_info,
                true,
                false,
            ));
            state_at += 1;
        }

        inner.adjust_difficulty(*inner.pivot_chain.last().expect("not empty"));

        self.update_confirmation_risks(inner, inner.get_total_weight_in_past());
        inner.optimistic_executed_height = if to_state_pos > 0 {
            Some(to_state_pos)
        } else {
            None
        };
        inner.persist_terminals();
        let new_checkpoint_era_genesis = self.should_form_checkpoint_at(inner);
        if new_checkpoint_era_genesis != inner.cur_era_genesis_block_index {
            info!(
                "Working on the checkpoint for block {} height {}",
                &inner.arena[inner.cur_era_genesis_block_index].hash,
                inner.cur_era_genesis_height
            );
            inner.checkpoint_at(new_checkpoint_era_genesis);
            info!(
                "New checkpoint formed at block {} height {}",
                &inner.arena[inner.cur_era_genesis_block_index].hash,
                inner.cur_era_genesis_height
            );
        }
        debug!("Finish processing block in ConsensusGraph: hash={:?}", hash);
    }
}
