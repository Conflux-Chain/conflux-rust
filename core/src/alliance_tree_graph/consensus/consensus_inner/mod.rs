// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod candidate_pivot_tree;
pub mod consensus_executor;
pub mod consensus_new_block_handler;

use crate::{
    alliance_tree_graph::consensus::{
        error::ConsensusError, NewCandidatePivotCallbackType,
        NextSelectedPivotCallbackType, SetPivotChainCallbackType,
    },
    block_data_manager::{
        BlockDataManager, BlockExecutionResultWithEpoch, EpochExecutionContext,
    },
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
    mem,
    sync::Arc,
    time::Instant,
};

#[derive(Copy, Clone)]
pub struct ConsensusInnerConfig {
    // The number of epochs per era. Each era is a potential checkpoint
    // position. The parent_edge checking and adaptive checking are defined
    // relative to the era start blocks.
    pub era_epoch_count: u64,
    pub enable_state_expose: bool,
    pub candidate_pivot_waiting_timeout_ms: u64,
}

#[derive(Default, Debug)]
pub struct ConsensusGraphNodeData {
    /// The total block of its past set (exclude itself)
    pub past_num_blocks: u64,
    /// The indices set of the blocks in the epoch when the current
    /// block is as pivot chain block. This set does not contain
    /// the block itself.
    pub blockset_in_own_view_of_epoch: Vec<usize>,
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
    pub last_recycled_era_block: usize,
    /// Block set of each old era. It will garbage collected by sync graph
    pub old_era_block_set: Mutex<VecDeque<H256>>,
    pub candidate_pivot_tree: CandidatePivotTree,

    /// The lowest height of the epochs that have available states and
    /// commitments. For archive node, it equals `cur_era_stable_height`.
    /// For light node, it equals the height of remotely synchronized state at
    /// start, and equals `cur_era_stable_height` after making a new
    /// checkpoint.
    pub state_boundary_height: u64,
    pub next_selected_pivot_waiting_list:
        HashMap<H256, NextSelectedPivotCallbackType>,
    pub new_candidate_pivot_waiting_map:
        HashMap<H256, NewCandidatePivotCallbackType>,
    pub new_candidate_pivot_waiting_list: VecDeque<(H256, Instant)>,
    pub set_pivot_chain_callback: Option<(H256, SetPivotChainCallbackType)>,
}

#[derive(Debug)]
pub struct ConsensusGraphNode {
    pub hash: H256,
    pub height: u64,
    /// This is the number of epoch it belongs to.
    pub epoch_number: u64,
    /// This is the parent edge of current block.
    pub parent: usize,
    pub sequence_number: u64,

    /// The genesis arena index of the era that current block`self` is in.
    /// It is `NULL` if `self` is not in the subtree of `cur_era_genesis`.
    pub era_block: usize,
    children: Vec<usize>,
    referrers: Vec<usize>,
    referees: Vec<usize>,

    /// This maintains some data structures related with consensus graph node.
    pub data: Option<ConsensusGraphNodeData>,
    /// It indicates whether the states stored in header is correct or not.
    /// It's evaluated when needed, i.e., when we need to propose a new bft
    /// block or vote a bft block.
    pub state_valid: Option<bool>,
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
            last_recycled_era_block: 0,
            old_era_block_set: Mutex::new(VecDeque::new()),
            candidate_pivot_tree: CandidatePivotTree::new(NULL),
            state_boundary_height: cur_era_stable_height,
            next_selected_pivot_waiting_list: HashMap::new(),
            new_candidate_pivot_waiting_map: HashMap::new(),
            new_candidate_pivot_waiting_list: VecDeque::new(),
            set_pivot_chain_callback: None,
        };

        // NOTE: Only genesis block will be first inserted into consensus graph
        // and then into synchronization graph. All the other blocks will be
        // inserted first into synchronization graph then consensus graph.
        let (genesis_arena_index, _) = inner.insert(&genesis_block_header);
        inner.cur_era_genesis_block_arena_index = genesis_arena_index;
        inner.inclusive_weight_tree.make_tree(genesis_arena_index);
        inner.arena[genesis_arena_index].epoch_number = cur_era_genesis_height;
        inner.pivot_chain.push(genesis_arena_index);
        inner.arena[genesis_arena_index].data = Some(ConsensusGraphNodeData {
            past_num_blocks: inner
                .data_man
                .get_epoch_execution_context(cur_era_genesis_block_hash)
                .expect("ExecutionContext for cur_era_genesis exists")
                .start_block_number,
            blockset_in_own_view_of_epoch: Vec::new(),
            ordered_executable_epoch_blocks: vec![genesis_arena_index],
        });
        inner.pastset.add(genesis_arena_index as u32);

        inner.candidate_pivot_tree =
            CandidatePivotTree::new(genesis_arena_index);

        inner
    }

    pub fn persist_epoch_set_hashes(&self, pivot_index: usize) {
        let pivot_arena_index = self.pivot_chain[pivot_index];
        let height = self.pivot_index_to_height(pivot_index);
        let epoch_set_hashes = self.arena[pivot_arena_index]
            .data
            .as_ref()
            .expect("pivot data exists")
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
        self.arena[pivot_arena_index]
            .data
            .as_ref()
            .expect("pivot data computed")
            .ordered_executable_epoch_blocks
            .iter()
            .map(|idx| self.arena[*idx].hash)
            .collect()
    }

    #[inline]
    fn get_epoch_start_block_number(&self, pivot_arena_index: usize) -> u64 {
        let parent = self.arena[pivot_arena_index].parent;
        self.arena[parent]
            .data
            .as_ref()
            .expect("pivot data computed")
            .past_num_blocks
            + 1
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

    pub fn get_deferred_arena_index(&self, me: usize, offset: u64) -> usize {
        let mut idx = me;
        for _ in 0..offset {
            if idx == self.cur_era_genesis_block_arena_index {
                // If it is the original genesis, we just break
                if self.arena[idx].height == 0 {
                    break;
                } else {
                    panic!(
                        "parent is too old for computing the deferred state"
                    );
                }
            }
            idx = self.arena[idx].parent;
            if idx == NULL {
                panic!("parent is NULL, possibly out of era?");
            }
        }
        idx
    }

    /// Assume that
    ///   1. `arena_index` is not in pivot chain yet.
    ///   2. `arena_index` is in the subtree of last pivot block.
    ///   3. the blockset from parent of `arena_index` to last pivot block
    /// exist.
    fn collect_blockset_in_own_view_of_epoch(&mut self, arena_index: usize) {
        debug!(
            "collect_blockset_in_own_view_of_epoch for [{:?}] hash[{:?}]",
            arena_index, self.arena[arena_index].hash
        );
        let mut parent = self.arena[arena_index].parent;
        let last_pivot =
            *self.pivot_chain.last().expect("pivot chain not empty");
        assert!(parent != NULL);
        assert!(self.lca(parent, last_pivot) == last_pivot);

        let mut path_to_last_pivot = Vec::new();
        while parent != last_pivot {
            assert!(self.arena[parent].data.is_some());
            path_to_last_pivot.push(parent);
            parent = self.arena[parent].parent;
        }
        path_to_last_pivot.reverse();

        let mut visited = HashSet::new();
        for index in path_to_last_pivot {
            visited.insert(index);
            for block_arena_index in &self.arena[index]
                .data
                .as_ref()
                .unwrap()
                .blockset_in_own_view_of_epoch
            {
                visited.insert(*block_arena_index);
            }
        }

        let mut queue = VecDeque::new();
        queue.push_back(arena_index);
        visited.insert(arena_index);
        let mut blockset_in_own_view_of_epoch = Vec::new();
        while let Some(index) = queue.pop_front() {
            if index != arena_index {
                blockset_in_own_view_of_epoch.push(index);
            }
            let parent = self.arena[index].parent;
            if parent != NULL
                && !self.pastset.contains(parent as u32)
                && !visited.contains(&parent)
            {
                visited.insert(parent);
                queue.push_back(parent);
            }
            for referee in &self.arena[index].referees {
                if !self.pastset.contains(*referee as u32)
                    && !visited.contains(referee)
                {
                    visited.insert(*referee);
                    queue.push_back(*referee);
                }
            }
        }

        let filtered_blockset = blockset_in_own_view_of_epoch
            .iter()
            .filter(|idx| self.is_same_era(**idx, arena_index))
            .map(|idx| *idx)
            .collect();

        let mut ordered_executable_epoch_blocks =
            self.topological_sort(&filtered_blockset);
        ordered_executable_epoch_blocks.push(arena_index);

        parent = self.arena[arena_index].parent;
        let past_num_blocks =
            self.arena[parent].data.as_ref().unwrap().past_num_blocks
                + ordered_executable_epoch_blocks.len() as u64;

        self.data_man.insert_epoch_execution_context(
            self.arena[arena_index].hash,
            EpochExecutionContext {
                start_block_number: self
                    .get_epoch_start_block_number(arena_index),
            },
            true, /* persistent to db */
        );
        self.arena[arena_index].data = Some(ConsensusGraphNodeData {
            past_num_blocks,
            blockset_in_own_view_of_epoch,
            ordered_executable_epoch_blocks,
        });
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
    fn insert(&mut self, block_header: &BlockHeader) -> (usize, usize) {
        let mut referees: Vec<usize> = Vec::new();
        for hash in block_header.referee_hashes().iter() {
            if let Some(x) = self.hash_to_arena_indices.get(hash) {
                self.insert_referee_if_not_duplicate(&mut referees, *x);
            }
        }

        let sn = self.get_next_sequence_number();
        let hash = block_header.hash();

        let parent =
            if hash != self.data_man.get_cur_consensus_era_genesis_hash() {
                *self
                    .hash_to_arena_indices
                    .get(block_header.parent_hash())
                    .unwrap()
            } else {
                NULL
            };

        let index = self.arena.insert(ConsensusGraphNode {
            hash,
            height: block_header.height(),
            parent,
            era_block: self.get_era_genesis_block_with_parent(parent, 0),
            children: Vec::new(),
            referees: referees.clone(),
            referrers: Vec::new(),
            epoch_number: NULLU64,
            sequence_number: sn,
            data: None,
            state_valid: None,
        });
        self.hash_to_arena_indices.insert(hash, index);

        self.inclusive_weight_tree.make_tree(index);

        if parent != NULL {
            self.terminal_hashes.remove(&self.arena[parent].hash);
            self.arena[parent].children.push(index);
            self.inclusive_weight_tree.link(parent, index);
        }

        self.terminal_hashes.insert(hash);
        for referee in referees {
            self.arena[referee].referrers.push(index);
            self.terminal_hashes.remove(&self.arena[referee].hash);
        }

        debug!(
            "Block {} inserted into Consensus with index={}",
            hash, index,
        );

        (index, self.hash_to_arena_indices.len())
    }

    /// Try to insert an outside era block, return it's sequence number. If both
    /// it's parent and referees are empty, we will not insert it into
    /// `arena`.
    pub fn insert_out_era_block(&mut self, block_header: &BlockHeader) -> u64 {
        let sn = self.get_next_sequence_number();
        let hash = block_header.hash();
        // we make cur_era_genesis be it's parent if it doesn‘t has one.
        let parent = self
            .hash_to_arena_indices
            .get(block_header.parent_hash())
            .cloned()
            .unwrap_or(NULL);

        let mut referees: Vec<usize> = Vec::new();
        for hash in block_header.referee_hashes().iter() {
            if let Some(x) = self.hash_to_arena_indices.get(hash) {
                self.insert_referee_if_not_duplicate(&mut referees, *x);
            }
        }

        if parent == NULL && referees.is_empty() {
            self.old_era_block_set.lock().push_back(hash);
            return sn;
        }

        // actually, we only need these fields: `parent`, `referees`,
        // `children`, `referrers`, `era_block`
        let index = self.arena.insert(ConsensusGraphNode {
            hash,
            height: block_header.height(),
            parent,
            era_block: NULL,
            children: Vec::new(),
            referees,
            referrers: Vec::new(),
            epoch_number: NULLU64,
            sequence_number: sn,
            data: None,
            state_valid: None,
        });
        self.hash_to_arena_indices.insert(hash, index);

        let referees = self.arena[index].referees.clone();
        for referee in referees {
            self.arena[referee].referrers.push(index);
        }
        if parent != NULL {
            self.arena[parent].children.push(index);
        }

        self.inclusive_weight_tree.make_tree(index);

        sn
    }

    /// Compute future set of `me`, excluding `me`.
    fn compute_future_bitset(&self, me: usize) -> BitSet {
        let mut queue: VecDeque<usize> = VecDeque::new();
        let mut visited = BitSet::with_capacity(self.arena.len() as u32);
        queue.push_back(me);
        visited.add(me as u32);
        while let Some(index) = queue.pop_front() {
            for child in &self.arena[index].children {
                if !visited.contains(*child as u32) {
                    visited.add(*child as u32);
                    queue.push_back(*child);
                }
            }
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
    fn compute_past_bitset(&self, me: usize) -> BitSet {
        let mut queue: VecDeque<usize> = VecDeque::new();
        let mut visited = BitSet::with_capacity(self.arena.len() as u32);
        queue.push_back(me);
        visited.add(me as u32);
        while let Some(index) = queue.pop_front() {
            let parent = self.arena[index].parent;
            if parent != NULL && !visited.contains(parent as u32) {
                visited.add(parent as u32);
                queue.push_back(parent);
            }
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
            let parent = self.arena[*me].parent;
            if index_set.contains(&parent) {
                *num_incoming_edges.entry(parent).or_insert(0) += 1;
            }
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

            let parent = self.arena[me].parent;
            if index_set.contains(&parent) {
                num_incoming_edges.entry(parent).and_modify(|e| *e -= 1);
                if num_incoming_edges[&parent] == 0 {
                    candidates.push((self.arena[parent].hash, parent));
                }
            }

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
        self.arena[pivot_arena_index]
            .data
            .as_ref()
            .expect("pivot data exists")
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
                        Ok(self.arena[*pivot_arena_index]
                            .data
                            .as_ref()
                            .expect("pivot data exists")
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

    pub fn total_processed_block_count(&self) -> u64 {
        self.sequence_number_of_block_entrance
    }

    /// Return the epoch that we are going to sync the state
    pub fn get_to_sync_epoch_id(&self) -> EpochId {
        let height_to_sync = self.latest_snapshot_height();
        // The height_to_sync is within the range of `self.pivot_chain`.
        let epoch_to_sync = self.arena
            [self.pivot_chain[self.height_to_pivot_index(height_to_sync)]]
        .hash;
        epoch_to_sync
    }

    /// FIXME Use snapshot-related information when we can sync snapshot states.
    /// Return the latest height that a snapshot should be available.
    fn latest_snapshot_height(&self) -> u64 { self.cur_era_stable_height }

    pub fn split_root(&mut self, me: usize) {
        let parent = self.arena[me].parent;
        assert!(parent != NULL);
        self.inclusive_weight_tree.split_root(parent, me);
        self.arena[me].parent = NULL;
    }

    fn set_epoch_number_in_epoch(
        &mut self, pivot_arena_index: usize, epoch_number: u64,
    ) {
        let block_set = mem::replace(
            &mut self.arena[pivot_arena_index]
                .data
                .as_mut()
                .expect("pivot data exists")
                .blockset_in_own_view_of_epoch,
            Default::default(),
        );
        for idx in &block_set {
            self.arena[*idx].epoch_number = epoch_number;
        }
        self.arena[pivot_arena_index].epoch_number = epoch_number;
        mem::replace(
            &mut self.arena[pivot_arena_index]
                .data
                .as_mut()
                .expect("pivot data exists")
                .blockset_in_own_view_of_epoch,
            block_set,
        );
    }

    /// Given a new `PivotBlockDecision` check whether it is valid. If it is
    /// valid this block will be added to `candidate_pivot_tree`.
    /// Make sure `block_hash` is in `hash_to_arena_indices`.
    pub fn validate_and_add_candidate_pivot(
        &mut self, block_hash: &H256, parent_hash: &H256, height: u64,
    ) -> bool {
        assert!(self.hash_to_arena_indices.contains_key(block_hash));
        debug!("validate_and_add_candidate_pivot block={:?} parent={:?} height={:?}", block_hash, parent_hash, height);
        if !self.hash_to_arena_indices.contains_key(parent_hash) {
            debug!("Invalid pivot proposal: parent hash not exist");
            return false;
        }
        let parent_arena_index = self.hash_to_arena_indices[parent_hash];
        let arena_index = self.hash_to_arena_indices[block_hash];
        debug!(
            "arena_index={:?} parent_arena_index={:?}",
            arena_index, parent_arena_index
        );
        assert!(self.arena[arena_index].state_valid.is_some());
        if !self.arena[arena_index].state_valid.unwrap() {
            debug!("Invalid pivot proposal: states in header are wrong");
            return false;
        }
        if self.arena[arena_index].parent != parent_arena_index {
            debug!("Invalid pivot proposal: parent wrong");
            return false;
        }
        if !self.candidate_pivot_tree.contains(parent_arena_index) {
            debug!("Invalid pivot proposal: parent not exist in tree");
            return false;
        }

        self.candidate_pivot_tree
            .add_leaf(parent_arena_index, arena_index)
    }

    pub fn new_candidate_pivot(
        &mut self, block_hash: &H256, parent_hash: &H256, height: u64,
    ) -> bool {
        self.validate_and_add_candidate_pivot(block_hash, parent_hash, height)
    }

    pub fn new_pivot(&mut self, pivot_arena_index: usize, persist_epoch: bool) {
        assert!(self.arena.contains(pivot_arena_index));
        let parent = self.arena[pivot_arena_index].parent;
        assert!(parent == self.best_epoch_arena_index());

        if self.arena[pivot_arena_index].data.is_none() {
            self.collect_blockset_in_own_view_of_epoch(pivot_arena_index);
        }
        self.pivot_chain.push(pivot_arena_index);
        self.set_epoch_number_in_epoch(
            pivot_arena_index,
            self.arena[pivot_arena_index].height,
        );
        for index in &self.arena[pivot_arena_index]
            .data
            .as_ref()
            .expect("pivot data exists")
            .blockset_in_own_view_of_epoch
        {
            self.pastset.add(*index as u32);
        }
        self.pastset.add(pivot_arena_index as u32);
        if persist_epoch {
            self.persist_epoch_set_hashes(self.pivot_chain.len() - 1);
        }
    }

    pub fn commit(&mut self, block_hash: &H256) {
        assert!(self.hash_to_arena_indices.contains_key(block_hash));
        let arena_index = self.hash_to_arena_indices[block_hash];
        let parent_arena_index = self.arena[arena_index].parent;
        assert!(*self.pivot_chain.last().unwrap() == parent_arena_index);
        self.candidate_pivot_tree.make_root(arena_index);
        self.data_man.insert_epoch_block_hash_to_db(
            self.arena[arena_index].height,
            block_hash,
        );
        self.data_man.insert_block_height_to_db(
            block_hash,
            self.arena[arena_index].height,
        );
        self.new_pivot(arena_index, true /* persist_epoch */);
    }

    pub fn set_to_pivot(&mut self, block_hash: &H256) {
        let arena_index = *self
            .hash_to_arena_indices
            .get(block_hash)
            .expect("block_hash should inserted");

        let genesis_arena_index = self.cur_era_genesis_block_arena_index;
        let genesis_block_hash = self.arena[genesis_arena_index].hash;
        self.pivot_chain = vec![genesis_arena_index];
        self.pastset.clear();
        self.arena[genesis_arena_index].data = Some(ConsensusGraphNodeData {
            past_num_blocks: self
                .data_man
                .get_epoch_execution_context(&genesis_block_hash)
                .expect("ExecutionContext for cur_era_genesis exists")
                .start_block_number,
            blockset_in_own_view_of_epoch: Vec::new(),
            ordered_executable_epoch_blocks: vec![genesis_arena_index],
        });
        self.pastset.add(genesis_arena_index as u32);

        let mut pivot_chain = Vec::new();
        let mut pivot = arena_index;
        while pivot != genesis_arena_index {
            pivot_chain.push(pivot);
            pivot = self.arena[pivot].parent;
        }
        pivot_chain.reverse();

        for index in pivot_chain {
            self.new_pivot(index, false /* persist_epoch */);
        }

        self.candidate_pivot_tree = CandidatePivotTree::new(arena_index);
        debug!(
            "set pivot chain to block[{:?}], pivot_chain_len={:?}",
            block_hash,
            self.pivot_chain.len()
        );
    }

    pub fn remove_expired_bft_execution(&mut self) {
        while let Some((hash, timestamp)) =
            self.new_candidate_pivot_waiting_list.pop_front()
        {
            if !self.new_candidate_pivot_waiting_map.contains_key(&hash)
                || timestamp < Instant::now()
            {
                debug!(
                    "new_candidate_pivot_waiting timeout for block[{:?}]",
                    hash
                );
                if let Some(callback) =
                    self.new_candidate_pivot_waiting_map.remove(&hash)
                {
                    callback
                        .send(Err(ConsensusError::VerifyPivotTimeout.into()))
                        .expect("send new candidate pivot back should succeed");
                }
            } else {
                self.new_candidate_pivot_waiting_list
                    .push_front((hash, timestamp));
                break;
            }
        }
    }

    /// Compute `state_valid` for `me`.
    /// Assumption:
    ///   1. The execution_commitment for deferred block of `me` exist.
    ///   2. `me` is in stable era.
    fn compute_state_valid_for_block(&mut self, me: usize) {
        debug!(
            "compute_state_valid: block[{:?}] arena_index[{:?}] height[{:?}]",
            self.arena[me].hash, me, self.arena[me].height
        );
        let deferred_arena_index =
            self.get_deferred_arena_index(me, DEFERRED_STATE_EPOCH_COUNT);
        let deferred_exec_commitment = self
            .data_man
            .get_epoch_execution_commitment(
                &self.arena[deferred_arena_index].hash,
            )
            .expect("execution commitment of deferred block exists");
        let deferred_state_root = deferred_exec_commitment
            .state_root_with_aux_info
            .state_root
            .compute_state_root_hash();
        let deferred_receipts_root = deferred_exec_commitment.receipts_root;
        let deferred_logs_bloom_hash = deferred_exec_commitment.logs_bloom_hash;

        let block_header = self
            .data_man
            .block_header_by_hash(&self.arena[me].hash)
            .unwrap();

        let state_valid = *block_header.deferred_state_root()
            == deferred_state_root
            && *block_header.deferred_receipts_root() == deferred_receipts_root
            && *block_header.deferred_logs_bloom_hash()
                == deferred_logs_bloom_hash;

        if state_valid {
            debug!(
                "compute_state_valid_for_block(): Block {} state is valid.",
                self.arena[me].hash
            );
        } else {
            debug!(
                "compute_state_valid_for_block(): Block[{:?}] state is invalid! expected (state_root[{:?}], receipts_root[{:?}], logs_bloom_hash[{:?}]), but (state_root[{:?}], receipts_root[{:?}], logs_bloom_hash[{:?}]) found",
                self.arena[me].hash,
                deferred_state_root,
                deferred_receipts_root,
                deferred_logs_bloom_hash,
                block_header.deferred_state_root(),
                block_header.deferred_receipts_root(),
                block_header.deferred_logs_bloom_hash()
            );
        }

        self.arena[me].state_valid = Some(state_valid);
    }
}
