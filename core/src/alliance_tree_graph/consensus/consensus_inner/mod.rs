// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod candidate_pivot_tree;
pub mod consensus_executor;
pub mod consensus_new_block_handler;

use crate::{
    block_data_manager::{BlockDataManager, BlockExecutionResultWithEpoch},
    parameters::consensus::*,
    pow::ProofOfWorkConfig,
};
use candidate_pivot_tree::CandidatePivotTree;
use cfx_types::H256;
use hibitset::BitSet;
use link_cut_tree::SizeMinLinkCutTree;
use parking_lot::Mutex;
use primitives::{
    receipt::Receipt, Block, BlockHeader, EpochId, TransactionAddress,
};
use slab::Slab;
use std::{
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    sync::Arc,
};

#[derive(Copy, Clone)]
pub struct ConsensusInnerConfig {
    // The number of epochs per era. Each era is a potential checkpoint
    // position. The parent_edge checking and adaptive checking are defined
    // relative to the era start blocks.
    pub era_epoch_count: u64,
    // FIXME: We should replace this to use confirmation risk instead
    pub era_checkpoint_gap: u64,
    pub enable_state_expose: bool,
}

#[derive(Default)]
pub struct ConsensusGraphPivotData {
    /// The indices set of the blocks in the epoch when the current
    /// block is as pivot chain block. This set does not contain
    /// the block itself.
    pub blockset_in_epoch: Vec<usize>,
    /// Ordered executable blocks in this epoch. This filters out blocks that
    /// are not in the same era of the epoch pivot block.
    ///
    /// For cur_era_genesis, this field should NOT be used because they contain
    /// out-of-era blocks not maintained in the memory.
    pub ordered_executable_epoch_blocks: Vec<usize>,
}

/// [Implementation details of Eras and Checkpoints]
///
/// Era in Conflux is defined based on the height of a block. Every
/// epoch_block_count height corresponds to one era. For example, if
/// era_block_count is 50000, then blocks at height 0 (the original genesis)
/// is the era genesis of the first era. The blocks at height 50000 are era
/// genesis blocks of the following era. Note that it is possible to have
/// multiple era genesis blocks for one era period. Eventually, only
/// one era genesis block and its subtree will become dominant and all other
/// genesis blocks together with their subtrees will be discarded.
///
/// The definition of Era enables Conflux to form checkpoints at the stabilized
/// era genesis blocks. To do that, we had the following modifications to the
/// original GHAST algorithm. First of all, full nodes will validate the parent
/// edge choice of each block but only *with in* its EraGenesis subtree. For
/// example, for a block at height 100100 (era_epoch_count = 50000), its
/// EraGenesis corresponds to its ancestor block at the height 100000 and
/// its LastEraGenesis corresponds to its ancestor block at the height 50000.

/// In ConsensusGraphInner, every block corresponds to a ConsensusGraphNode and
/// each node has an internal index. This enables fast internal implementation
/// to use integer index instead of H256 block hashes.
pub struct ConsensusGraphInner {
    /// This slab hold consensus graph node data and the array index is the
    /// internal index.
    pub arena: Slab<ConsensusGraphNode>,
    /// indices maps block hash to internal index.
    pub hash_to_arena_indices: HashMap<H256, usize>,
    /// The current pivot chain indexes.
    pub pivot_chain: Vec<usize>,
    pub pastset: BitSet,
    /// The metadata associated with each pivot chain block
    pub pivot_chain_metadata: Vec<ConsensusGraphPivotData>,
    /// The set of *graph* tips in the TreeGraph.
    terminal_hashes: HashSet<H256>,
    /// The ``current'' era_genesis block index. It will start being the
    /// original genesis. As time goes, it will move to future era genesis
    /// checkpoint.
    pub cur_era_genesis_block_arena_index: usize,
    /// The height of the ``current'' era_genesis block
    cur_era_genesis_height: u64,
    /// The height of the ``stable'' era block, unless from the start, it is
    /// always era_epoch_count higher than era_genesis_height
    cur_era_stable_height: u64,
    /// weight_tree maintains the subtree weight of each node in the TreeGraph
    inclusive_weight_tree: SizeMinLinkCutTree,
    pub pow_config: ProofOfWorkConfig,
    /// data_man is the handle to access raw block data
    data_man: Arc<BlockDataManager>,
    pub inner_conf: ConsensusInnerConfig,
    /// The cache to store Anticone information of each node. This could be
    /// very large so we periodically remove old ones in the cache.
    sequence_number_of_block_entrance: u64,
    //last_recycled_era_block: usize,
    /// Block set of each old era. It will garbage collected by sync graph
    pub old_era_block_set: Mutex<VecDeque<H256>>,
    pub candidate_pivot_tree: CandidatePivotTree,

    /// The lowest height of the epochs that have available states and
    /// commitments. For archive node, it equals `cur_era_stable_height`.
    /// For light node, it equals the height of remotely synchronized state at
    /// start, and equals `cur_era_stable_height` after making a new
    /// checkpoint.
    pub state_boundary_height: u64,
}

pub struct ConsensusGraphNode {
    pub hash: H256,
    pub height: u64,
    /// This is the number of epoch it belongs to.
    pub epoch_number: u64,
    /// The total block of its past set (exclude itself)
    past_num_blocks: u64,
    /// This is the parent edge of current block. It will be set during BFT
    /// commiting.
    pub parent: Option<usize>,
    pub sequence_number: u64,

    /// The genesis arena index of the era that `self` is in.
    ///
    /// It is `NULL` if `self` is not in the subtree of `cur_era_genesis`.
    pub era_block: usize,
    children: Vec<usize>,
    referrers: Vec<usize>,
    referees: Vec<usize>,
}

impl ConsensusGraphInner {
    pub fn with_era_genesis(
        pow_config: ProofOfWorkConfig, data_man: Arc<BlockDataManager>,
        inner_conf: ConsensusInnerConfig, cur_era_genesis_block_hash: &H256,
    ) -> Self
    {
        let genesis_block_header = data_man
            .block_header_by_hash(cur_era_genesis_block_hash)
            .expect("genesis block header should exist here");
        let cur_era_genesis_height = genesis_block_header.height();
        let cur_era_stable_height = if cur_era_genesis_height == 0 {
            0
        } else {
            cur_era_genesis_height + inner_conf.era_epoch_count
        };
        let mut inner = ConsensusGraphInner {
            arena: Slab::new(),
            hash_to_arena_indices: HashMap::new(),
            pivot_chain: Vec::new(),
            pivot_chain_metadata: Vec::new(),
            terminal_hashes: Default::default(),
            cur_era_genesis_block_arena_index: NULL,
            cur_era_genesis_height,
            cur_era_stable_height,
            inclusive_weight_tree: SizeMinLinkCutTree::new(),
            pastset: BitSet::new(),
            pow_config,
            data_man: data_man.clone(),
            inner_conf,
            sequence_number_of_block_entrance: 0,
            // TODO handle checkpoint in recovery
            // last_recycled_era_block: 0,
            old_era_block_set: Mutex::new(VecDeque::new()),
            state_boundary_height: cur_era_stable_height,
            candidate_pivot_tree: CandidatePivotTree::new(NULL),
        };

        // NOTE: Only genesis block will be first inserted into consensus graph
        // and then into synchronization graph. All the other blocks will be
        // inserted first into synchronization graph then consensus graph.
        let (genesis_arena_index, _, _) = inner.insert(&genesis_block_header);
        inner.cur_era_genesis_block_arena_index = genesis_arena_index;
        inner.inclusive_weight_tree.make_tree(genesis_arena_index);
        inner.arena[genesis_arena_index].epoch_number = cur_era_genesis_height;
        inner.arena[genesis_arena_index].past_num_blocks = inner
            .data_man
            .get_epoch_execution_context(cur_era_genesis_block_hash)
            .expect("ExecutionContext for cur_era_genesis exists")
            .start_block_number;
        inner.pivot_chain.push(genesis_arena_index);
        inner.pastset.add(genesis_arena_index as u32);
        inner.pivot_chain_metadata.push(ConsensusGraphPivotData {
            blockset_in_epoch: Vec::new(),
            ordered_executable_epoch_blocks: vec![genesis_arena_index],
        });

        inner
    }

    pub fn persist_epoch_set_hashes(&self, pivot_index: usize) {
        let height = self.pivot_index_to_height(pivot_index);
        let epoch_set_hashes = self.pivot_chain_metadata[pivot_index]
            .ordered_executable_epoch_blocks
            .iter()
            .map(|arena_index| self.arena[*arena_index].hash)
            .collect();
        self.data_man
            .insert_epoch_set_hashes_to_db(height, &epoch_set_hashes);
    }

    #[inline]
    /// The caller should ensure that `height` is within the current
    /// `self.pivot_chain` range. Otherwise the function may panic.
    pub fn get_pivot_block_arena_index(&self, height: u64) -> usize {
        let pivot_index = (height - self.cur_era_genesis_height) as usize;
        assert!(pivot_index < self.pivot_chain.len());
        self.pivot_chain[pivot_index]
    }

    #[inline]
    pub fn get_pivot_height(&self) -> u64 {
        self.cur_era_genesis_height + self.pivot_chain.len() as u64
    }

    #[inline]
    pub fn height_to_pivot_index(&self, height: u64) -> usize {
        (height - self.cur_era_genesis_height) as usize
    }

    #[inline]
    pub fn pivot_index_to_height(&self, pivot_index: usize) -> u64 {
        self.cur_era_genesis_height + pivot_index as u64
    }

    #[inline]
    fn get_next_sequence_number(&mut self) -> u64 {
        let sn = self.sequence_number_of_block_entrance;
        self.sequence_number_of_block_entrance += 1;
        sn
    }

    #[inline]
    pub fn set_initial_sequence_number(&mut self, initial_sn: u64) {
        self.arena[self.cur_era_genesis_block_arena_index].sequence_number =
            initial_sn;
        self.sequence_number_of_block_entrance = initial_sn + 1;
    }

    #[inline]
    pub fn ancestor_at(&self, me: usize, height: u64) -> usize {
        let height_index = self.height_to_pivot_index(height);
        self.inclusive_weight_tree.ancestor_at(me, height_index)
    }

    #[inline]
    /// for outside era block, consider the lca is NULL
    pub fn lca(&self, me: usize, v: usize) -> usize {
        if self.arena[v].era_block == NULL || self.arena[me].era_block == NULL {
            return NULL;
        }
        self.inclusive_weight_tree.lca(me, v)
    }

    #[inline]
    #[allow(dead_code)]
    fn get_era_genesis_height(&self, parent_height: u64, offset: u64) -> u64 {
        let era_genesis_height = if parent_height > offset {
            (parent_height - offset) / self.inner_conf.era_epoch_count
                * self.inner_conf.era_epoch_count
        } else {
            0
        };
        era_genesis_height
    }

    #[inline]
    pub fn get_cur_era_genesis_height(&self) -> u64 {
        self.cur_era_genesis_height
    }

    #[inline]
    #[allow(dead_code)]
    fn get_era_genesis_block_with_parent(
        &self, parent: usize, offset: u64,
    ) -> usize {
        if parent == NULL {
            return 0;
        }
        let height = self.arena[parent].height;
        let era_genesis_height = self.get_era_genesis_height(height, offset);
        trace!(
            "height={} era_height={} era_genesis_height={}",
            height,
            era_genesis_height,
            self.cur_era_genesis_height
        );
        self.ancestor_at(parent, era_genesis_height)
    }

    #[inline]
    fn get_epoch_block_hashes(&self, pivot_arena_index: usize) -> Vec<H256> {
        assert!(pivot_arena_index != self.cur_era_genesis_block_arena_index);
        let pivot_index =
            self.height_to_pivot_index(self.arena[pivot_arena_index].height);
        self.pivot_chain_metadata[pivot_index]
            .ordered_executable_epoch_blocks
            .iter()
            .map(|idx| self.arena[*idx].hash)
            .collect()
    }

    #[inline]
    fn get_epoch_start_block_number(&self, epoch_arena_index: usize) -> u64 {
        let parent =
            self.arena[epoch_arena_index].parent.expect("parent exists");

        return self.arena[parent].past_num_blocks + 1;
    }

    #[inline]
    #[allow(dead_code)]
    fn is_legacy_block(&self, index: usize) -> bool {
        self.arena[index].era_block == NULL
    }

    #[inline]
    fn is_same_era(&self, me: usize, pivot: usize) -> bool {
        self.arena[me].era_block == self.arena[pivot].era_block
    }

    fn collect_blockset_in_epoch(&mut self, pivot_index: usize) {
        assert!(pivot_index < self.pivot_chain.len());
        let pivot_arena_index = self.pivot_chain[pivot_index];

        let mut queue = VecDeque::new();
        queue.push_back(pivot_arena_index);
        self.pastset.add(pivot_arena_index as u32);
        while let Some(index) = queue.pop_front() {
            if index != pivot_arena_index {
                self.pivot_chain_metadata[pivot_index]
                    .blockset_in_epoch
                    .push(index);
            }
            for referee in &self.arena[index].referees {
                if !self.pastset.contains(*referee as u32) {
                    self.pastset.add(*referee as u32);
                    queue.push_back(*referee);
                }
            }
        }

        let filtered_blockset = self.pivot_chain_metadata[pivot_index]
            .blockset_in_epoch
            .iter()
            .filter(|idx| self.is_same_era(**idx, pivot_arena_index))
            .map(|idx| *idx)
            .collect();

        self.pivot_chain_metadata[pivot_index]
            .ordered_executable_epoch_blocks =
            self.topological_sort(&filtered_blockset);
        self.pivot_chain_metadata[pivot_index]
            .ordered_executable_epoch_blocks
            .push(pivot_arena_index);
    }

    fn insert_referee_if_not_duplicate(
        &self, referees: &mut Vec<usize>, me: usize,
    ) {
        // We do not insert current genesis
        if self.cur_era_genesis_block_arena_index == me {
            return;
        }
        // TODO: maybe consider a more vigorous mechanism
        let mut found = false;
        for i in 0..referees.len() {
            let x = referees[i];
            let lca = self.lca(x, me);
            if lca == me {
                found = true;
                break;
            } else if lca == x {
                found = true;
                referees[i] = me;
                break;
            }
        }
        if !found {
            referees.push(me);
        }
    }

    /// Insert a block into consensus, return `(arena_index, indices_len,
    /// sequence_number)`. If this block has no in memory referees, this block
    /// will be simply ignored.
    fn insert(&mut self, block_header: &BlockHeader) -> (usize, usize, u64) {
        let mut referees: Vec<usize> = Vec::new();
        for hash in block_header.referee_hashes().iter() {
            if let Some(x) = self.hash_to_arena_indices.get(hash) {
                self.insert_referee_if_not_duplicate(&mut referees, *x);
            }
        }

        let sn = self.get_next_sequence_number();
        let hash = block_header.hash();

        if referees.is_empty() {
            debug!("ignore isolated legacy block");
            return (NULL, self.hash_to_arena_indices.len(), sn);
        }

        for referee in &referees {
            self.terminal_hashes.remove(&self.arena[*referee].hash);
        }

        let index = self.arena.insert(ConsensusGraphNode {
            hash,
            height: NULLU64,
            past_num_blocks: 0,
            parent: None,
            era_block: NULL,
            children: Vec::new(),
            referees: referees.clone(),
            referrers: Vec::new(),
            epoch_number: NULLU64,
            sequence_number: sn,
        });
        self.hash_to_arena_indices.insert(hash, index);

        self.terminal_hashes.insert(hash);
        for referee in referees {
            self.arena[referee].referrers.push(index);
        }

        debug!(
            "Block {} inserted into Consensus with index={}",
            hash, index,
        );

        (index, self.hash_to_arena_indices.len(), sn)
    }

    /// Compute future set of `me`, excluding `me`.
    #[allow(dead_code)]
    fn compute_future_bitset(&self, me: usize) -> BitSet {
        let mut queue: VecDeque<usize> = VecDeque::new();
        let mut visited = BitSet::with_capacity(self.arena.len() as u32);
        queue.push_back(me);
        visited.add(me as u32);
        while let Some(index) = queue.pop_front() {
            for referrer in &self.arena[index].referrers {
                if !visited.contains(*referrer as u32) {
                    visited.add(*referrer as u32);
                    queue.push_back(*referrer);
                }
            }
        }
        visited.remove(me as u32);
        visited
    }

    /// Compute past set of `me`, including `me`.
    #[allow(dead_code)]
    fn compute_past_bitset(&self, me: usize) -> BitSet {
        let mut queue: VecDeque<usize> = VecDeque::new();
        let mut visited = BitSet::with_capacity(self.arena.len() as u32);
        queue.push_back(me);
        visited.add(me as u32);
        while let Some(index) = queue.pop_front() {
            for referee in &self.arena[index].referees {
                if !visited.contains(*referee as u32) {
                    visited.add(*referee as u32);
                    queue.push_back(*referee);
                }
            }
        }
        visited
    }

    fn topological_sort(&self, index_set: &HashSet<usize>) -> Vec<usize> {
        let mut num_incoming_edges = HashMap::new();

        for me in index_set {
            num_incoming_edges.entry(*me).or_insert(0);
            for referee in &self.arena[*me].referees {
                if index_set.contains(referee) {
                    *num_incoming_edges.entry(*referee).or_insert(0) += 1;
                }
            }
        }

        let mut candidates = BinaryHeap::new();
        let mut reversed_indices = Vec::new();

        for me in index_set {
            if num_incoming_edges[me] == 0 {
                candidates.push((self.arena[*me].hash, *me));
            }
        }
        while let Some((_, me)) = candidates.pop() {
            reversed_indices.push(me);

            for referee in &self.arena[me].referees {
                if index_set.contains(referee) {
                    num_incoming_edges.entry(*referee).and_modify(|e| *e -= 1);
                    if num_incoming_edges[referee] == 0 {
                        candidates.push((self.arena[*referee].hash, *referee));
                    }
                }
            }
        }
        reversed_indices.reverse();
        reversed_indices
    }

    pub fn get_executable_epoch_blocks(
        &self, pivot_arena_index: usize,
    ) -> Vec<Arc<Block>> {
        let pivot_index =
            self.height_to_pivot_index(self.arena[pivot_arena_index].height);
        self.pivot_chain_metadata[pivot_index]
            .ordered_executable_epoch_blocks
            .iter()
            .map(|x| {
                self.data_man
                    .block_by_hash(
                        &self.arena[*x].hash,
                        false, /* update_cache */
                    )
                    .expect("block exists")
            })
            .collect()
    }

    /// Return the last block hash in pivot chain
    pub fn best_block_hash(&self) -> H256 {
        self.arena[*self.pivot_chain.last().unwrap()].hash
    }

    /// Return the last epoch number in pivot chain
    pub fn best_epoch_number(&self) -> u64 {
        self.cur_era_genesis_height + self.pivot_chain.len() as u64 - 1
    }

    /// Return the arena index of the last block in pivot chain
    pub fn best_epoch_arena_index(&self) -> usize {
        *self.pivot_chain.last().unwrap()
    }

    /// Return the pivot block hash of current epoch.
    pub fn epoch_hash(&self, epoch_number: u64) -> Result<H256, String> {
        let height = epoch_number;
        if height >= self.cur_era_genesis_height {
            let pivot_index = self.height_to_pivot_index(height);
            self.pivot_chain
                .get(pivot_index)
                .map(|arena_index| self.arena[*arena_index].hash)
                .ok_or(
                    "Epoch number larger than the current pivot chain tip"
                        .into(),
                )
        } else {
            self.data_man
                .epoch_set_hashes_from_db(epoch_number)
                .ok_or(format!(
                    "epoch_hash: Epoch hash set not in db, epoch_number={}",
                    epoch_number
                ))
                .and_then(|epoch_hashes| {
                    epoch_hashes
                        .last()
                        .map(Clone::clone)
                        .ok_or("Epoch set is empty".into())
                })
        }
    }

    pub fn block_hashes_by_epoch(
        &self, epoch_number: u64,
    ) -> Result<Vec<H256>, String> {
        debug!(
            "block_hashes_by_epoch epoch_number={:?} pivot_chain.len={:?}",
            epoch_number,
            self.pivot_chain.len()
        );
        if epoch_number < self.cur_era_genesis_height {
            self.data_man
                .epoch_set_hashes_from_db(epoch_number)
                .ok_or(format!(
                    "Epoch set not in db epoch_number={}",
                    epoch_number
                ))
        } else {
            let pivot_index = self.height_to_pivot_index(epoch_number);
            match self.pivot_chain.get(pivot_index) {
                Some(pivot_arena_index) => {
                    if *pivot_arena_index
                        == self.cur_era_genesis_block_arena_index
                    {
                        self.data_man
                            .epoch_set_hashes_from_db(epoch_number)
                            .ok_or("Fail to load the epoch set for current era genesis in db".into())
                    } else {
                        Ok(self.pivot_chain_metadata[pivot_index]
                            .ordered_executable_epoch_blocks
                            .iter()
                            .map(|arena_index| self.arena[*arena_index].hash)
                            .collect())
                    }
                }
                None => {
                    Err("Epoch number larger than the current pivot chain tip"
                        .into())
                }
            }
        }
    }

    fn get_epoch_hash_for_block(&self, hash: &H256) -> Option<H256> {
        self.get_block_epoch_number(&hash)
            .and_then(|epoch_number| self.epoch_hash(epoch_number).ok())
    }

    pub fn terminal_hashes(&self) -> Vec<H256> {
        self.terminal_hashes
            .iter()
            .map(|hash| hash.clone())
            .collect()
    }

    pub fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        self.hash_to_arena_indices.get(hash).and_then(|index| {
            match self.arena[*index].epoch_number {
                NULLU64 => None,
                epoch => Some(epoch),
            }
        })
    }

    pub fn all_blocks_with_topo_order(&self) -> Vec<H256> {
        let epoch_number = self.best_epoch_number();
        let mut current_number = 0;
        let mut hashes = Vec::new();
        while current_number <= epoch_number {
            let epoch_hashes =
                self.block_hashes_by_epoch(current_number.into()).unwrap();
            for hash in epoch_hashes {
                hashes.push(hash);
            }
            current_number += 1;
        }
        hashes
    }

    /// Return the block receipts in the current pivot view and the epoch block
    /// hash.
    ///
    /// If `hash` is not maintained in the memory, we just return the receipts
    /// in the db without checking the pivot assumption.
    /// TODO Check if its receipts matches our current pivot view for this
    /// not-in-memory case.
    pub fn block_execution_results_by_hash(
        &self, hash: &H256, update_cache: bool,
    ) -> Option<BlockExecutionResultWithEpoch> {
        match self.get_epoch_hash_for_block(hash) {
            Some(epoch) => {
                trace!("Block {} is in epoch {}", hash, epoch);
                let execution_result =
                    self.data_man.block_execution_result_by_hash_with_epoch(
                        hash,
                        &epoch,
                        update_cache,
                    )?;
                Some(BlockExecutionResultWithEpoch(epoch, execution_result))
            }
            None => {
                debug!("Block {:?} not in mem, try to read from db", hash);
                self.data_man.block_execution_result_by_hash_from_db(hash)
            }
        }
    }

    pub fn get_transaction_receipt_with_address(
        &self, tx_hash: &H256,
    ) -> Option<(Receipt, TransactionAddress)> {
        trace!("Get receipt with tx_hash {}", tx_hash);
        let address = self.data_man.transaction_address_by_hash(
            tx_hash, false, /* update_cache */
        )?;
        // receipts should never be None if address is not None because
        let receipts = self
            .block_execution_results_by_hash(
                &address.block_hash,
                false, /* update_cache */
            )?
            .1
            .receipts;
        Some((
            receipts
                .get(address.index)
                .expect("Error: can't get receipt by tx_address ")
                .clone(),
            address,
        ))
    }

    pub fn check_block_pivot_assumption(
        &self, pivot_hash: &H256, epoch: u64,
    ) -> Result<(), String> {
        let last_number = self.best_epoch_number();
        let hash = self.epoch_hash(epoch)?;
        if epoch > last_number || hash != *pivot_hash {
            return Err("Error: pivot chain assumption failed".to_owned());
        }
        Ok(())
    }

    /// Compute metadata associated information on pivot chain extending.
    pub fn compute_metadata(&mut self, start_at: u64) {
        self.pivot_chain_metadata
            .resize_with(self.pivot_chain.len(), Default::default);
        let pivot_height = self.get_pivot_height();
        for height in start_at..pivot_height {
            let pivot_index = self.height_to_pivot_index(height);
            // TODO: determine parent of block in `blockset_in_epoch`.
            self.collect_blockset_in_epoch(pivot_index);
            self.set_epoch_number_in_epoch(pivot_index, height)
        }
    }

    /// This function force the pivot chain to follow our previous stable
    /// genesis choice. It assumes that the era_genesis_block should be the
    /// ancestor of stable_block, and the past of stable_block should have
    /// been inserted into consensus.
    pub fn set_pivot_to_stable(&mut self, stable: &H256) {
        let stable_index = *self
            .hash_to_arena_indices
            .get(stable)
            .expect("Era stable genesis inserted");
        self.pivot_chain.clear();
        self.pastset.clear();
        let mut pivot = stable_index;
        while pivot != NULL {
            self.pivot_chain.push(pivot);
            pivot = self.arena[pivot].parent.unwrap();
        }
        self.pivot_chain.reverse();
        debug!(
            "set_pivot_to_stable: stable={:?}, chain_len={}",
            stable,
            self.pivot_chain.len()
        );
        self.compute_metadata(self.cur_era_genesis_height);
    }

    pub fn total_processed_block_count(&self) -> u64 {
        self.sequence_number_of_block_entrance
    }

    /// Return the epoch that we are going to sync the state
    pub fn get_to_sync_epoch_id(&self) -> EpochId {
        let height_to_sync = self.latest_snapshot_height();
        // The height_to_sync is within the range of `self.pivit_chain`.
        let epoch_to_sync = self.arena
            [self.pivot_chain[self.height_to_pivot_index(height_to_sync)]]
        .hash;
        epoch_to_sync
    }

    /// FIXME Use snapshot-related information when we can sync snapshot states.
    /// Return the latest height that a snapshot should be available.
    fn latest_snapshot_height(&self) -> u64 { self.cur_era_stable_height }

    pub fn split_root(&mut self, me: usize) {
        let parent = self.arena[me].parent.expect("parent exists");
        assert!(parent != NULL);
        self.inclusive_weight_tree.split_root(parent, me);
        self.arena[me].parent = Some(NULL);
    }

    pub fn reset_epoch_number_in_epoch(&mut self, pivot_index: usize) {
        self.set_epoch_number_in_epoch(pivot_index, NULLU64);
    }

    pub fn set_epoch_number_in_epoch(
        &mut self, pivot_index: usize, epoch_number: u64,
    ) {
        for idx in &self.pivot_chain_metadata[pivot_index].blockset_in_epoch {
            self.arena[*idx].epoch_number = epoch_number;
        }
        let pivot_arena_index = self.pivot_chain[pivot_index];
        self.arena[pivot_arena_index].epoch_number = epoch_number;
    }

    /// Given a new `PivotBlockDecision` check whether it is valid. If it is
    /// valid this block will be added to `candidate_pivot_tree`.
    pub fn on_new_candidate_pivot(
        &mut self, _block_hash: &H256, _parent_hash: &H256, _height: u64,
    ) -> bool {
        true
    }

    pub fn on_new_pivot(&mut self, pivot_arena_index: usize) {
        // move to consensus_new_block_handler
        assert!(self.arena.contains(pivot_arena_index));
        let parent = self.arena[pivot_arena_index]
            .parent
            .expect("parent must set");
        assert!(parent == self.best_epoch_arena_index());
        self.pivot_chain.push(pivot_arena_index);
        self.pivot_chain_metadata.push(Default::default());
        self.compute_metadata(
            self.arena[pivot_arena_index].height - self.cur_era_genesis_height,
        );

        // TODO: recycle out era transactions
        // TODO: execution
    }

    /// TODO: move this function to `ConsensusNewBlockHandler` or
    /// `TreeGraphConsensus`
    pub fn commit(&mut self, committable_blocks: &Vec<H256>) {
        let mut last = *self.pivot_chain.last().unwrap();
        for block_hash in committable_blocks {
            let arena_index = self.hash_to_arena_indices[block_hash];
            self.arena[arena_index].parent = Some(last);
            self.arena[arena_index].height = self.arena[last].height + 1;
            self.data_man.insert_epoch_block_hash_to_db(
                self.arena[arena_index].height,
                block_hash,
            );
            self.data_man.insert_block_height_to_db(
                block_hash,
                self.arena[arena_index].height,
            );
            self.on_new_pivot(arena_index);
            last = arena_index;
        }
        self.candidate_pivot_tree =
            CandidatePivotTree::new(*self.pivot_chain.last().unwrap());
    }
}
