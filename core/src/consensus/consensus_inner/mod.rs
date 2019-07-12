pub mod consensus_executor;
pub mod consensus_new_block_handler;

use crate::{
    block_data_manager::BlockDataManager,
    consensus::{
        anticone_cache::AnticoneCache,
        consensus_inner::consensus_executor::{
            EpochExecutionTask, RewardExecutionInfo,
        },
        ANTICONE_PENALTY_RATIO, ANTICONE_PENALTY_UPPER_EPOCH_COUNT,
        DEFERRED_STATE_EPOCH_COUNT, REWARD_EPOCH_COUNT,
    },
    hash::KECCAK_EMPTY_LIST_RLP,
    pow::{target_difficulty, ProofOfWorkConfig},
    state::State,
    statedb::StateDb,
    storage::{state_manager::StateManagerTrait, SnapshotAndEpochIdRef},
};
use cfx_types::{
    into_i128, into_u256, H160, H256, KECCAK_EMPTY_BLOOM, U256, U512,
};
use hibitset::{BitSet, BitSetLike};
use link_cut_tree::MinLinkCutTree;
use primitives::{receipt::Receipt, Block, StateRoot, TransactionAddress};
use slab::Slab;
use std::{
    cmp::{max, min},
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    sync::Arc,
};

const NULL: usize = !0;
const NULLU64: u64 = !0;

#[derive(Copy, Clone)]
pub struct ConsensusInnerConfig {
    // num/den is the actual adaptive alpha parameter in GHAST. We use a
    // fraction to get around the floating point problem
    pub adaptive_weight_alpha_num: u64,
    pub adaptive_weight_alpha_den: u64,
    // Beta is the threshold in GHAST algorithm
    pub adaptive_weight_beta: u64,
    // The heavy block ratio (h) in GHAST algorithm
    pub heavy_block_difficulty_ratio: u64,
    // The number of epochs per era. Each era is a potential checkpoint
    // position. The parent_edge checking and adaptive checking are defined
    // relative to the era start blocks.
    pub era_epoch_count: u64,
    // Optimistic execution is the feature to execute ahead of the deferred
    // execution boundary. The goal is to pipeline the transaction
    // execution and the block packaging and verification.
    // optimistic_executed_height is the number of step to go ahead
    pub enable_optimistic_execution: bool,
}

pub struct ConsensusGraphNodeData {
    pub epoch_number: u64,
    partial_invalid: bool,
    pending: bool,
    /// The indices set of the blocks in the epoch when the current
    /// block is as pivot chain block. This set does not contain
    /// the block itself.
    blockset_in_own_view_of_epoch: HashSet<usize>,
    /// The number of blocks in the last two era. Only such blocks are counted
    /// during difficulty adjustment.
    num_epoch_blocks_in_2era: usize,
    /// Ordered executable blocks in this epoch. This filters out blocks that
    /// are not in the same era of the epoch pivot block.
    pub ordered_executable_epoch_blocks: Vec<usize>,
    /// The minimum/maximum epoch number of the block in the view of other
    /// blocks including itself.
    min_epoch_in_other_views: u64,
    max_epoch_in_other_views: u64,
    sequence_number: u64,
}

impl ConsensusGraphNodeData {
    fn new(epoch_number: u64, height: u64, sequence_number: u64) -> Self {
        ConsensusGraphNodeData {
            epoch_number,
            partial_invalid: false,
            pending: false,
            blockset_in_own_view_of_epoch: Default::default(),
            num_epoch_blocks_in_2era: 0,
            ordered_executable_epoch_blocks: Default::default(),
            min_epoch_in_other_views: height,
            max_epoch_in_other_views: height,
            sequence_number,
        }
    }
}

struct ConsensusGraphPivotData {
    /// The set of blocks whose last_pivot_in_past point to this pivot chain
    /// location
    last_pivot_in_past_blocks: HashSet<usize>,
}

impl Default for ConsensusGraphPivotData {
    fn default() -> Self {
        ConsensusGraphPivotData {
            last_pivot_in_past_blocks: HashSet::new(),
        }
    }
}

pub struct TotalWeightInPast {
    pub old: U256,
    pub cur: U256,
    pub delta: U256,
}

///
/// Implementation details of the GHAST algorithm
///
/// Conflux uses the Greedy Heaviest Adaptive SubTree (GHAST) algorithm to
/// select a chain from the genesis block to one of the leaf blocks as the pivot
/// chain. For each block b, GHAST algorithm computes two values: stable and
/// adaptive. Let's take stable as an example:
///
/// 1   B = Past(b)
/// 2   a = b.parent
/// 3   stable = True
/// 4   Let f(x) = PastW(b) - PastW(x.parent) - x.parent.weight
/// 5   Let g(x) = SubTW(B, x)
/// 6   while a.parent != Nil do
/// 7       if f(a) > beta and g(a) / f(a) < alpha then
/// 8           stable = False
/// 9       a = a.parent
///
/// To efficiently compute stable, we maintain a link-cut tree called
/// stable_tree.
///
/// Assume alpha = n / d, then g(a) / f(a) < n / d
///   => d * g(a) < n * f(a)
///   => d * SubTW(B, x) < n * (PastW(b) - PastW(x.parent) - x.parent.weight)
///   => d * SubTW(B, x) + n * PastW(x.parent) + n * x.parent.weight < n *
/// PastW(b)
///
/// Note that for a given block b, PastW(b) is a constant,
/// so in order to calculate stable, it is suffice to calculate
/// argmin{d * SubTW(B, x) + n * x.parent.weight + n * PastW(x.parent)}.
/// Therefore, in the stable_tree, the value for x is
/// d * SubTW(B, x) + n * x.parent.weight + n * PastW(x.parent).
///
/// adaptive could be computed in a similar manner:
///
/// 1   B = Past(b)
/// 2   a = b.parent
/// 3   Let f(x) = SubTW(B, x.parent)
/// 4   Let g(x) = SubStableTW(B, x)
/// 5   adaptive = False
/// 6   while a.parent != Nil do
/// 7       if f(a) > beta and g(a) / f(a) < alpha then
/// 8           adaptive = True
/// 9       a = a.parent
///
/// The only difference is that when maintaining g(x) * d - f(x) * n, we need to
/// do special caterpillar update in the Link-Cut-Tree, i.e., given a node X, we
/// need to update the values of all of those nodes A such that A is the child
/// of one of the node in the path from Genesis to X.
///
/// In ConsensusGraphInner, every block corresponds to a ConsensusGraphNode and
/// each node has an internal index. This enables fast internal implementation
/// to use integer index instead of H256 block hashes.
pub struct ConsensusGraphInner {
    // This slab hold consensus graph node data and the array index is the
    // internal index.
    pub arena: Slab<ConsensusGraphNode>,
    // indices maps block hash to internal index.
    pub hash_to_arena_indices: HashMap<H256, usize>,
    // The current pivot chain indexes.
    pub pivot_chain: Vec<usize>,
    // The metadata associated with each pivot chain block
    pivot_chain_metadata: Vec<ConsensusGraphPivotData>,
    // The set of *graph* tips in the TreeGraph.
    terminal_hashes: HashSet<H256>,
    // The map to connect reference edges of legacy node before the current
    // era. It maps the hash of a legacy node to a list of referred nodes
    // inside the current era.
    legacy_refs: HashMap<H256, Vec<usize>>,
    // The ``current'' era_genesis block index. It will start being the
    // original genesis. As time goes, it will move to future era genesis
    // checkpoint.
    pub cur_era_genesis_block_arena_index: usize,
    // The height of the ``current'' era_genesis block
    cur_era_genesis_height: u64,
    // The height of the ``stable'' era block, unless from the start, it is
    // always era_epoch_count higher than era_genesis_height
    cur_era_stable_height: u64,
    // The ``original'' genesis state root, receipts root, and logs bloom hash.
    genesis_block_state_root: StateRoot,
    genesis_block_receipts_root: H256,
    genesis_block_logs_bloom_hash: H256,
    // weight_tree maintains the subtree weight of each node in the TreeGraph
    weight_tree: MinLinkCutTree,
    inclusive_weight_tree: MinLinkCutTree,
    stable_weight_tree: MinLinkCutTree,
    // stable_tree maintains d * SubTW(B, x) + n * x.parent.weight + n *
    // PastW(x.parent)
    stable_tree: MinLinkCutTree,
    // adaptive_tree maintains d * SubStableTW(B, x) - n * SubTW(B, P(x))
    adaptive_tree: MinLinkCutTree,
    // inclusive_adaptive_tree maintains d * SubInclusiveTW(B, x) - n *
    // SubInclusiveTW(B, P(x))
    inclusive_adaptive_tree: MinLinkCutTree,
    pow_config: ProofOfWorkConfig,
    // It maintains the expected difficulty of the next local mined block.
    pub current_difficulty: U256,
    // data_man is the handle to access raw block data
    data_man: Arc<BlockDataManager>,
    // Optimistic execution is the feature to execute ahead of the deferred
    // execution boundary. The goal is to pipeline the transaction
    // execution and the block packaging and verification.
    // optimistic_executed_height is the number of step to go ahead
    optimistic_executed_height: Option<u64>,
    inner_conf: ConsensusInnerConfig,
    // The cache to store Anticone information of each node. This could be very
    // large so we periodically remove old ones in the cache.
    anticone_cache: AnticoneCache,
    sequence_number_of_block_entrance: u64,
    last_recycled_era_block: usize,
    total_weight_in_past_2d: TotalWeightInPast,
}

pub struct ConsensusGraphNode {
    pub hash: H256,
    pub height: u64,
    is_heavy: bool,
    difficulty: U256,
    /// The total weight of its past set (exclude itself)
    // FIXME: This field is not maintained during after the checkpoint.
    // We should review the finality computation and check whether we
    // still need this field!
    past_weight: i128,
    /// The total weight of its past set in its own era
    past_era_weight: i128,
    stable: bool,
    adaptive: bool,
    pub parent: usize,
    era_block: usize,
    last_pivot_in_past: u64,
    children: Vec<usize>,
    referrers: Vec<usize>,
    referees: Vec<usize>,
    pub data: ConsensusGraphNodeData,
}

impl ConsensusGraphInner {
    pub fn with_era_genesis_block(
        pow_config: ProofOfWorkConfig, data_man: Arc<BlockDataManager>,
        inner_conf: ConsensusInnerConfig, cur_era_genesis_block_hash: &H256,
        cur_era_stable_height: u64,
    ) -> Self
    {
        let genesis_block = data_man
            .block_by_hash(cur_era_genesis_block_hash, true)
            .unwrap();
        let cur_era_genesis_height = genesis_block.block_header.height();
        assert!(cur_era_stable_height >= cur_era_genesis_height);
        assert!(
            cur_era_stable_height == 0
                || cur_era_stable_height
                    == cur_era_genesis_height + inner_conf.era_epoch_count
        );
        let mut inner = ConsensusGraphInner {
            arena: Slab::new(),
            hash_to_arena_indices: HashMap::new(),
            pivot_chain: Vec::new(),
            pivot_chain_metadata: Vec::new(),
            optimistic_executed_height: None,
            terminal_hashes: Default::default(),
            legacy_refs: HashMap::new(),
            cur_era_genesis_block_arena_index: NULL,
            cur_era_genesis_height,
            cur_era_stable_height,
            genesis_block_state_root: data_man
                .genesis_block()
                .block_header
                .deferred_state_root()
                .clone(),
            genesis_block_receipts_root: data_man
                .genesis_block()
                .block_header
                .deferred_receipts_root()
                .clone(),
            genesis_block_logs_bloom_hash: data_man
                .genesis_block()
                .block_header
                .deferred_logs_bloom_hash()
                .clone(),
            weight_tree: MinLinkCutTree::new(),
            inclusive_weight_tree: MinLinkCutTree::new(),
            stable_weight_tree: MinLinkCutTree::new(),
            stable_tree: MinLinkCutTree::new(),
            adaptive_tree: MinLinkCutTree::new(),
            inclusive_adaptive_tree: MinLinkCutTree::new(),
            pow_config,
            current_difficulty: pow_config.initial_difficulty.into(),
            data_man: data_man.clone(),
            inner_conf,
            anticone_cache: AnticoneCache::new(),
            sequence_number_of_block_entrance: 0,
            // TODO handle checkpoint in recovery
            last_recycled_era_block: 0,
            total_weight_in_past_2d: TotalWeightInPast {
                old: U256::zero(),
                cur: U256::zero(),
                delta: U256::zero(),
            },
        };

        // NOTE: Only genesis block will be first inserted into consensus graph
        // and then into synchronization graph. All the other blocks will be
        // inserted first into synchronization graph then consensus graph.
        // For genesis block, its past weight is simply zero (default value).
        let (genesis_arena_index, _) = inner.insert(genesis_block.as_ref());
        inner.cur_era_genesis_block_arena_index = genesis_arena_index;
        inner
            .weight_tree
            .make_tree(inner.cur_era_genesis_block_arena_index);
        inner.weight_tree.path_apply(
            inner.cur_era_genesis_block_arena_index,
            into_i128(data_man.genesis_block().block_header.difficulty()),
        );
        inner
            .inclusive_weight_tree
            .make_tree(inner.cur_era_genesis_block_arena_index);
        inner.inclusive_weight_tree.path_apply(
            inner.cur_era_genesis_block_arena_index,
            into_i128(data_man.genesis_block().block_header.difficulty()),
        );
        inner
            .stable_weight_tree
            .make_tree(inner.cur_era_genesis_block_arena_index);
        inner.stable_weight_tree.path_apply(
            inner.cur_era_genesis_block_arena_index,
            into_i128(data_man.genesis_block().block_header.difficulty()),
        );
        inner
            .stable_tree
            .make_tree(inner.cur_era_genesis_block_arena_index);
        // The genesis node can be zero in stable_tree because it is never used!
        inner
            .stable_tree
            .set(inner.cur_era_genesis_block_arena_index, 0);
        inner
            .adaptive_tree
            .make_tree(inner.cur_era_genesis_block_arena_index);
        // The genesis node can be zero in adaptive_tree because it is never
        // used!
        inner
            .adaptive_tree
            .set(inner.cur_era_genesis_block_arena_index, 0);
        inner
            .inclusive_adaptive_tree
            .make_tree(inner.cur_era_genesis_block_arena_index);
        // The genesis node can be zero in adaptive_tree because it is never
        // used!
        inner
            .inclusive_adaptive_tree
            .set(inner.cur_era_genesis_block_arena_index, 0);
        inner.arena[inner.cur_era_genesis_block_arena_index]
            .data
            .epoch_number = 0;
        inner
            .pivot_chain
            .push(inner.cur_era_genesis_block_arena_index);
        let mut last_pivot_in_past_blocks = HashSet::new();
        last_pivot_in_past_blocks
            .insert(inner.cur_era_genesis_block_arena_index);
        inner.pivot_chain_metadata.push(ConsensusGraphPivotData {
            last_pivot_in_past_blocks,
        });
        assert!(inner.genesis_block_receipts_root == KECCAK_EMPTY_LIST_RLP);
        assert!(inner.genesis_block_logs_bloom_hash == KECCAK_EMPTY_BLOOM);

        inner
            .anticone_cache
            .update(inner.cur_era_genesis_block_arena_index, &BitSet::new());
        inner
    }

    #[inline]
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
    fn is_heavier(a: (i128, &H256), b: (i128, &H256)) -> bool {
        (a.0 > b.0) || ((a.0 == b.0) && (*a.1 > *b.1))
    }

    #[inline]
    pub fn ancestor_at(&self, me: usize, height: u64) -> usize {
        let height_index = self.height_to_pivot_index(height);
        self.inclusive_weight_tree.ancestor_at(me, height_index)
    }

    #[inline]
    pub fn lca(&self, me: usize, v: usize) -> usize {
        self.inclusive_weight_tree.lca(me, v)
    }

    #[inline]
    fn get_era_height(&self, parent_height: u64, offset: u64) -> u64 {
        let era_height = if parent_height > offset {
            (parent_height - offset) / self.inner_conf.era_epoch_count
                * self.inner_conf.era_epoch_count
        } else {
            0
        };
        era_height
    }

    #[inline]
    fn get_era_block_with_parent(&self, parent: usize, offset: u64) -> usize {
        if parent == NULL {
            return 0;
        }
        let height = self.arena[parent].height;
        let era_height = self.get_era_height(height, offset);
        self.ancestor_at(parent, era_height)
    }

    pub fn update_total_weight_in_past(&mut self) {
        let total_weight = &mut self.total_weight_in_past_2d;
        total_weight.delta = total_weight.cur - total_weight.old;
        total_weight.old = total_weight.cur;
    }

    fn aggregate_total_weight_in_past(&mut self, weight: i128) {
        let total_weight = &mut self.total_weight_in_past_2d;
        total_weight.cur += into_u256(weight);
    }

    fn get_total_weight_in_past(&self) -> i128 {
        let total_weight = &self.total_weight_in_past_2d;
        into_i128(&total_weight.delta)
    }

    fn get_optimistic_execution_task(
        &mut self, data_man: &BlockDataManager,
    ) -> Option<EpochExecutionTask> {
        if !self.inner_conf.enable_optimistic_execution {
            return None;
        }

        let opt_height = self.optimistic_executed_height?;
        let epoch_arena_index = self.get_pivot_block_arena_index(opt_height);

        // `on_local_pivot` is set to `true` because when we later skip its
        // execution on pivot chain, we will not notify tx pool, so we
        // will also notify in advance.
        let execution_task = EpochExecutionTask::new(
            self.arena[epoch_arena_index].hash,
            self.get_epoch_block_hashes(epoch_arena_index),
            self.get_reward_execution_info(data_man, epoch_arena_index),
            true,
            false,
        );
        let next_opt_height = opt_height + 1;
        if next_opt_height >= self.pivot_index_to_height(self.pivot_chain.len())
        {
            self.optimistic_executed_height = None;
        } else {
            self.optimistic_executed_height = Some(next_opt_height);
        }
        Some(execution_task)
    }

    #[inline]
    fn get_epoch_block_hashes(&self, epoch_arena_index: usize) -> Vec<H256> {
        self.arena[epoch_arena_index]
            .data
            .ordered_executable_epoch_blocks
            .iter()
            .map(|idx| self.arena[*idx].hash)
            .collect()
    }

    pub fn check_mining_adaptive_block(
        &mut self, parent_arena_index: usize, difficulty: U256,
    ) -> bool {
        let (_stable, adaptive) = self.adaptive_weight_impl(
            parent_arena_index,
            &BitSet::new(),
            None,
            into_i128(&difficulty),
        );
        adaptive
    }

    fn compute_subtree_weights(
        &self, me: usize, anticone_barrier: &BitSet,
    ) -> (Vec<i128>, Vec<i128>, Vec<i128>) {
        let mut subtree_weight = Vec::new();
        let mut subtree_inclusive_weight = Vec::new();
        let mut subtree_stable_weight = Vec::new();
        let n = self.arena.capacity();
        subtree_weight.resize_with(n, Default::default);
        subtree_inclusive_weight.resize_with(n, Default::default);
        subtree_stable_weight.resize_with(n, Default::default);
        let mut stack = Vec::new();
        stack.push((0, self.cur_era_genesis_block_arena_index));
        while let Some((stage, index)) = stack.pop() {
            if stage == 0 {
                stack.push((1, index));
                for child in &self.arena[index].children {
                    if !anticone_barrier.contains(*child as u32) && *child != me
                    {
                        stack.push((0, *child));
                    }
                }
            } else {
                for child in &self.arena[index].children {
                    subtree_weight[index] += subtree_weight[*child];
                    subtree_inclusive_weight[index] +=
                        subtree_inclusive_weight[*child];
                    subtree_stable_weight[index] +=
                        subtree_stable_weight[*child];
                }
                let weight = self.block_weight(index, false);
                subtree_weight[index] += weight;
                subtree_inclusive_weight[index] +=
                    self.block_weight(index, true);
                if self.arena[index].stable {
                    subtree_stable_weight[index] += weight;
                }
            }
        }
        (
            subtree_weight,
            subtree_inclusive_weight,
            subtree_stable_weight,
        )
    }

    fn adaptive_weight_impl_brutal(
        &self, parent_0: usize, subtree_weight: &Vec<i128>,
        subtree_inclusive_weight: &Vec<i128>,
        subtree_stable_weight: &Vec<i128>, difficulty: i128,
    ) -> (bool, bool)
    {
        let mut parent = parent_0;
        let mut stable = true;

        let height = self.arena[parent].height;
        let era_height = self.get_era_height(height, 0);
        let two_era_height =
            self.get_era_height(height, self.inner_conf.era_epoch_count);
        let era_genesis = self.ancestor_at(parent, era_height);

        let total_weight = subtree_weight[era_genesis];
        let adjusted_beta =
            (self.inner_conf.adaptive_weight_beta as i128) * difficulty;

        while self.arena[parent].height != era_height {
            let grandparent = self.arena[parent].parent;
            let past_era_weight = if grandparent == era_genesis {
                0
            } else {
                self.arena[grandparent].past_era_weight
            };
            let w = total_weight
                - past_era_weight
                - self.block_weight(grandparent, false);
            if w > adjusted_beta {
                let a = subtree_weight[parent];
                if self.inner_conf.adaptive_weight_alpha_den as i128 * a
                    - self.inner_conf.adaptive_weight_alpha_num as i128 * w
                    < 0
                {
                    stable = false;
                    break;
                }
            }
            parent = grandparent;
        }
        let mut adaptive = false;
        if !stable {
            parent = parent_0;
            while self.arena[parent].height != era_height {
                let grandparent = self.arena[parent].parent;
                let w = subtree_weight[grandparent];
                if w > adjusted_beta {
                    let a = subtree_stable_weight[parent];
                    if self.inner_conf.adaptive_weight_alpha_den as i128 * a
                        - self.inner_conf.adaptive_weight_alpha_num as i128 * w
                        < 0
                    {
                        adaptive = true;
                        break;
                    }
                }
                parent = grandparent;
            }
        }
        if !adaptive {
            while self.arena[parent].height != two_era_height {
                let grandparent = self.arena[parent].parent;
                let w = subtree_inclusive_weight[grandparent];
                if w > adjusted_beta {
                    let a = subtree_inclusive_weight[parent];
                    if self.inner_conf.adaptive_weight_alpha_den as i128 * a
                        - self.inner_conf.adaptive_weight_alpha_num as i128 * w
                        < 0
                    {
                        adaptive = true;
                        break;
                    }
                }
                parent = grandparent;
            }
        }

        (stable, adaptive)
    }

    fn adaptive_weight_impl(
        &mut self, parent_0: usize, anticone_barrier: &BitSet,
        weight_tuple: Option<&(Vec<i128>, Vec<i128>, Vec<i128>)>,
        difficulty: i128,
    ) -> (bool, bool)
    {
        if let Some((
            subtree_weight,
            subtree_inclusive_weight,
            subtree_stable_weight,
        )) = weight_tuple
        {
            return self.adaptive_weight_impl_brutal(
                parent_0,
                subtree_weight,
                subtree_inclusive_weight,
                subtree_stable_weight,
                difficulty,
            );
        }
        let mut parent = parent_0;

        let mut weight_delta = HashMap::new();
        let mut inclusive_weight_delta = HashMap::new();
        let mut stable_weight_delta = HashMap::new();

        for index in anticone_barrier.iter() {
            weight_delta
                .insert(index as usize, self.weight_tree.get(index as usize));
            inclusive_weight_delta.insert(
                index as usize,
                self.inclusive_weight_tree.get(index as usize),
            );
            stable_weight_delta.insert(
                index as usize,
                self.stable_weight_tree.get(index as usize),
            );
        }

        for (index, delta) in &weight_delta {
            self.weight_tree.path_apply(*index, -delta);
            self.stable_tree.path_apply(
                *index,
                -delta * (self.inner_conf.adaptive_weight_alpha_den as i128),
            );
            let parent = self.arena[*index].parent;
            self.adaptive_tree.catepillar_apply(
                parent,
                delta * (self.inner_conf.adaptive_weight_alpha_num as i128),
            );
        }
        for (index, delta) in &inclusive_weight_delta {
            let parent = self.arena[*index].parent;
            self.inclusive_weight_tree.path_apply(*index, -delta);
            self.inclusive_adaptive_tree.catepillar_apply(
                parent,
                delta * (self.inner_conf.adaptive_weight_alpha_num as i128),
            );
            self.inclusive_adaptive_tree.path_apply(
                *index,
                -delta * (self.inner_conf.adaptive_weight_alpha_den as i128),
            );
        }
        for (index, delta) in &stable_weight_delta {
            self.adaptive_tree.path_apply(
                *index,
                -delta * (self.inner_conf.adaptive_weight_alpha_den as i128),
            );
        }

        let era_height = self.get_era_height(self.arena[parent].height, 0);
        let two_era_height = self.get_era_height(
            self.arena[parent].height,
            self.inner_conf.era_epoch_count,
        );
        let era_genesis = self.ancestor_at(parent, era_height);
        let two_era_genesis = self.ancestor_at(parent, two_era_height);

        let total_weight = self.weight_tree.get(era_genesis);
        debug!("total_weight before insert: {}", total_weight);

        let adjusted_beta =
            (self.inner_conf.adaptive_weight_beta as i128) * difficulty;

        let mut high = self.arena[parent].height;
        let mut low = era_height + 1;
        // [low, high]
        let mut best = era_height;

        while low <= high {
            let mid = (low + high) / 2;
            let p = self.ancestor_at(parent, mid);
            let gp = self.arena[p].parent;
            let past_era_weight = if gp == era_genesis {
                0
            } else {
                self.arena[gp].past_era_weight
            };
            let w =
                total_weight - past_era_weight - self.block_weight(gp, false);
            if w > adjusted_beta {
                best = mid;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        let stable = if best != era_height {
            parent = self.ancestor_at(parent, best);

            let a = self.stable_tree.path_aggregate_chop(parent, era_genesis);
            let b = total_weight
                * (self.inner_conf.adaptive_weight_alpha_num as i128);
            if a < b {
                debug!("block is unstable: {:?} < {:?}!", a, b);
            } else {
                debug!("block is stable: {:?} >= {:?}!", a, b);
            }
            !(a < b)
        } else {
            debug!(
                "block is stable: too close to genesis, adjusted beta {:?}",
                adjusted_beta
            );
            true
        };
        let mut adaptive = false;

        if !stable {
            parent = parent_0;

            let mut high = self.arena[parent].height;
            let mut low = era_height + 1;
            let mut best = era_height;

            while low <= high {
                let mid = (low + high) / 2;
                let p = self.ancestor_at(parent, mid);
                let gp = self.arena[p].parent;
                let w = self.weight_tree.get(gp);
                if w > adjusted_beta {
                    best = mid;
                    low = mid + 1;
                } else {
                    high = mid - 1;
                }
            }

            if best != era_height {
                parent = self.ancestor_at(parent, best);
                let min_agg =
                    self.adaptive_tree.path_aggregate_chop(parent, era_genesis);
                if min_agg < 0 {
                    debug!("block is adaptive (intra-era): {:?}", min_agg);
                    adaptive = true;
                }
            }
        }

        if !adaptive {
            let mut high = era_height;
            let mut low = two_era_height + 1;
            let mut best = two_era_height;

            while low <= high {
                let mid = (low + high) / 2;
                let p = self.ancestor_at(parent, mid);
                let gp = self.arena[p].parent;
                let w = self.inclusive_weight_tree.get(gp);

                if w > adjusted_beta {
                    best = mid;
                    low = mid + 1;
                } else {
                    high = mid - 1;
                }
            }

            if best != two_era_height {
                parent = self.ancestor_at(parent, best);
                let min_agg = self
                    .inclusive_adaptive_tree
                    .path_aggregate_chop(parent, two_era_genesis);
                if min_agg < 0 {
                    debug!("block is adaptive (inter-era): {:?}", min_agg);
                    adaptive = true;
                }
            }
        }

        for (index, delta) in &weight_delta {
            self.weight_tree.path_apply(*index, *delta);
            self.stable_tree.path_apply(
                *index,
                delta * (self.inner_conf.adaptive_weight_alpha_den as i128),
            );
            let parent = self.arena[*index].parent;
            self.adaptive_tree.catepillar_apply(
                parent,
                -delta * (self.inner_conf.adaptive_weight_alpha_num as i128),
            );
        }
        for (index, delta) in &inclusive_weight_delta {
            let parent = self.arena[*index].parent;
            self.inclusive_weight_tree.path_apply(*index, *delta);
            self.inclusive_adaptive_tree.catepillar_apply(
                parent,
                -delta * (self.inner_conf.adaptive_weight_alpha_num as i128),
            );
            self.inclusive_adaptive_tree.path_apply(
                *index,
                delta * (self.inner_conf.adaptive_weight_alpha_den as i128),
            );
        }
        for (index, delta) in &stable_weight_delta {
            self.adaptive_tree.path_apply(
                *index,
                delta * (self.inner_conf.adaptive_weight_alpha_den as i128),
            );
        }

        (stable, adaptive)
    }

    /// Determine whether we should generate adaptive blocks or not. It is used
    /// both for block generations and for block validations.
    fn adaptive_weight(
        &mut self, me: usize, anticone_barrier: &BitSet,
        weight_tuple: Option<&(Vec<i128>, Vec<i128>, Vec<i128>)>,
    ) -> (bool, bool)
    {
        let parent = self.arena[me].parent;
        assert!(parent != NULL);

        let difficulty = into_i128(&self.arena[me].difficulty);

        self.adaptive_weight_impl(
            parent,
            anticone_barrier,
            weight_tuple,
            difficulty,
        )
    }

    #[inline]
    fn is_same_era(&self, me: usize, pivot: usize) -> bool {
        self.arena[me].era_block == self.arena[pivot].era_block
    }

    fn collect_blockset_in_own_view_of_epoch(&mut self, pivot: usize) {
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        for referee in &self.arena[pivot].referees {
            visited.insert(*referee);
            queue.push_back(*referee);
        }

        while let Some(index) = queue.pop_front() {
            let mut in_old_epoch = false;
            let mut parent = self.arena[pivot].parent;

            if self.arena[parent].height
                > self.arena[index].data.max_epoch_in_other_views
            {
                parent = self.ancestor_at(
                    parent,
                    self.arena[index].data.max_epoch_in_other_views,
                );
            }

            loop {
                assert!(parent != NULL);

                if self.arena[parent].height
                    < self.arena[index].data.min_epoch_in_other_views
                    || (self.arena[index].data.sequence_number
                        > self.arena[parent].data.sequence_number)
                {
                    break;
                }

                if parent == index
                    || self.arena[parent]
                        .data
                        .blockset_in_own_view_of_epoch
                        .contains(&index)
                {
                    in_old_epoch = true;
                    break;
                }

                parent = self.arena[parent].parent;
            }

            if !in_old_epoch {
                let parent = self.arena[index].parent;
                if !visited.contains(&parent) {
                    visited.insert(parent);
                    queue.push_back(parent);
                }
                for referee in &self.arena[index].referees {
                    if !visited.contains(referee) {
                        visited.insert(*referee);
                        queue.push_back(*referee);
                    }
                }
                self.arena[index].data.min_epoch_in_other_views = min(
                    self.arena[index].data.min_epoch_in_other_views,
                    self.arena[pivot].height,
                );
                self.arena[index].data.max_epoch_in_other_views = max(
                    self.arena[index].data.max_epoch_in_other_views,
                    self.arena[pivot].height,
                );
                self.arena[pivot]
                    .data
                    .blockset_in_own_view_of_epoch
                    .insert(index);
            }
        }
        let filtered_blockset = self.arena[pivot]
            .data
            .blockset_in_own_view_of_epoch
            .iter()
            .filter(|idx| self.is_same_era(**idx, pivot))
            .map(|idx| *idx)
            .collect();
        let two_era_block = self.get_era_block_with_parent(
            self.arena[pivot].parent,
            self.inner_conf.era_epoch_count,
        );
        self.arena[pivot].data.num_epoch_blocks_in_2era = self.arena[pivot]
            .data
            .blockset_in_own_view_of_epoch
            .iter()
            .filter(|idx| {
                let lca = self.lca(**idx, two_era_block);
                lca == two_era_block
            })
            .count();
        self.arena[pivot].data.ordered_executable_epoch_blocks =
            self.topological_sort(&filtered_blockset);
        self.arena[pivot]
            .data
            .ordered_executable_epoch_blocks
            .push(pivot);
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

    fn insert(&mut self, block: &Block) -> (usize, usize) {
        let hash = block.hash();

        let is_heavy = U512::from(block.block_header.pow_quality)
            >= U512::from(self.inner_conf.heavy_block_difficulty_ratio)
                * U512::from(block.block_header.difficulty());

        let parent = if *block.block_header.parent_hash() != H256::default() {
            self.hash_to_arena_indices
                .get(block.block_header.parent_hash())
                .cloned()
                .unwrap()
        } else {
            NULL
        };

        let mut referees: Vec<usize> = Vec::new();
        for hash in block.block_header.referee_hashes().iter() {
            if let Some(x) = self.hash_to_arena_indices.get(hash) {
                self.insert_referee_if_not_duplicate(&mut referees, *x);
            } else if let Some(r) = self.legacy_refs.get(hash) {
                for index in r {
                    self.insert_referee_if_not_duplicate(&mut referees, *index);
                }
            }
        }

        for referee in &referees {
            self.terminal_hashes.remove(&self.arena[*referee].hash);
        }
        let my_height = block.block_header.height();
        let sn = self.get_next_sequence_number();
        let index = self.arena.insert(ConsensusGraphNode {
            hash,
            height: my_height,
            is_heavy,
            difficulty: *block.block_header.difficulty(),
            past_weight: 0,     // will be updated later below
            past_era_weight: 0, // will be updated later below
            stable: true,
            // Block header contains an adaptive field, we will verify with our
            // own computation
            adaptive: block.block_header.adaptive(),
            parent,
            last_pivot_in_past: 0,
            era_block: self.get_era_block_with_parent(parent, 0),
            children: Vec::new(),
            referees,
            referrers: Vec::new(),
            data: ConsensusGraphNodeData::new(NULLU64, my_height, sn),
        });
        self.hash_to_arena_indices.insert(hash, index);

        if parent != NULL {
            self.terminal_hashes.remove(&self.arena[parent].hash);
            self.arena[parent].children.push(index);
        }
        self.terminal_hashes.insert(hash);
        let referees = self.arena[index].referees.clone();
        for referee in referees {
            self.arena[referee].referrers.push(index);
        }

        self.collect_blockset_in_own_view_of_epoch(index);

        if parent != NULL {
            let era_genesis = self.get_era_block_with_parent(parent, 0);

            let weight_in_my_epoch = self.total_weight_in_own_epoch(
                &self.arena[index].data.blockset_in_own_view_of_epoch,
                false,
                None,
            );
            let weight_era_in_my_epoch = self.total_weight_in_own_epoch(
                &self.arena[index].data.blockset_in_own_view_of_epoch,
                false,
                Some(era_genesis),
            );
            let past_weight = self.arena[parent].past_weight
                + self.block_weight(parent, false)
                + weight_in_my_epoch;
            let past_era_weight = if parent != era_genesis {
                self.arena[parent].past_era_weight
                    + self.block_weight(parent, false)
                    + weight_era_in_my_epoch
            } else {
                self.block_weight(parent, false) + weight_era_in_my_epoch
            };

            self.arena[index].past_weight = past_weight;
            self.arena[index].past_era_weight = past_era_weight;
        }

        debug!(
            "Block {} inserted into Consensus with index={} past_weight={}",
            hash, index, self.arena[index].past_weight
        );

        (index, self.hash_to_arena_indices.len())
    }

    fn compute_future_bitset(&self, me: usize) -> BitSet {
        // Compute future set of parent
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

    /// Return the consensus graph indexes of the pivot block where the rewards
    /// of its epoch should be computed The rewards are needed to compute
    /// the state of the epoch at height `state_at` of `chain`
    fn get_pivot_reward_index(
        &self, epoch_arena_index: usize,
    ) -> Option<(usize, usize)> {
        // We are going to exclude the original genesis block here!
        if self.arena[epoch_arena_index].height <= REWARD_EPOCH_COUNT {
            return None;
        }
        let parent_index = self.arena[epoch_arena_index].parent;
        // Recompute epoch.
        let anticone_cut_height =
            REWARD_EPOCH_COUNT - ANTICONE_PENALTY_UPPER_EPOCH_COUNT;
        let mut anticone_penalty_cutoff_epoch_block = parent_index;
        for _i in 1..anticone_cut_height {
            if anticone_penalty_cutoff_epoch_block == NULL {
                break;
            }
            anticone_penalty_cutoff_epoch_block =
                self.arena[anticone_penalty_cutoff_epoch_block].parent;
        }
        let mut reward_epoch_block = anticone_penalty_cutoff_epoch_block;
        for _i in 0..ANTICONE_PENALTY_UPPER_EPOCH_COUNT {
            if reward_epoch_block == NULL {
                break;
            }
            reward_epoch_block = self.arena[reward_epoch_block].parent;
        }
        if reward_epoch_block != NULL {
            // The anticone_penalty_cutoff respect the era bound!
            while !self.is_same_era(
                reward_epoch_block,
                anticone_penalty_cutoff_epoch_block,
            ) {
                anticone_penalty_cutoff_epoch_block =
                    self.arena[anticone_penalty_cutoff_epoch_block].parent;
            }
        }
        let reward_index = if reward_epoch_block == NULL {
            None
        } else {
            Some((reward_epoch_block, anticone_penalty_cutoff_epoch_block))
        };
        reward_index
    }

    pub fn get_executable_epoch_blocks(
        &self, data_man: &BlockDataManager, epoch_arena_index: usize,
    ) -> Vec<Arc<Block>> {
        let mut epoch_blocks = Vec::new();
        for idx in &self.arena[epoch_arena_index]
            .data
            .ordered_executable_epoch_blocks
        {
            let block = data_man
                .block_by_hash(&self.arena[*idx].hash, false)
                .expect("Exist");
            epoch_blocks.push(block);
        }
        epoch_blocks
    }

    fn recompute_anticone_weight(
        &self, me: usize, pivot_block_arena_index: usize,
    ) -> i128 {
        assert!(self.is_same_era(me, pivot_block_arena_index));
        // We need to compute the future size of me under the view of epoch
        // height pivot_index
        let mut visited = BitSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(pivot_block_arena_index);
        visited.add(pivot_block_arena_index as u32);
        let last_pivot = self.arena[me].last_pivot_in_past;
        while let Some(index) = queue.pop_front() {
            let parent = self.arena[index].parent;
            if self.arena[parent].data.epoch_number > last_pivot
                && !visited.contains(parent as u32)
            {
                queue.push_back(parent);
                visited.add(parent as u32);
            }
            for referee in &self.arena[index].referees {
                if self.arena[*referee].data.epoch_number > last_pivot
                    && !visited.contains(*referee as u32)
                {
                    queue.push_back(*referee);
                    visited.add(*referee as u32);
                }
            }
        }
        queue.push_back(me);
        let mut visited2 = BitSet::new();
        visited2.add(me as u32);
        while let Some(index) = queue.pop_front() {
            for child in &self.arena[index].children {
                if visited.contains(*child as u32)
                    && !visited2.contains(*child as u32)
                {
                    queue.push_back(*child);
                    visited2.add(*child as u32);
                }
            }
            for referrer in &self.arena[index].referrers {
                if visited.contains(*referrer as u32)
                    && !visited2.contains(*referrer as u32)
                {
                    queue.push_back(*referrer);
                    visited2.add(*referrer as u32);
                }
            }
        }
        let mut total_weight = self.arena[pivot_block_arena_index]
            .past_era_weight
            - self.arena[me].past_era_weight
            + self.block_weight(pivot_block_arena_index, false);
        for index in visited2.iter() {
            if self.is_same_era(index as usize, pivot_block_arena_index) {
                total_weight -= self.block_weight(index as usize, false);
            }
        }
        total_weight
    }

    fn get_reward_execution_info_from_index(
        &self, data_man: &BlockDataManager,
        reward_index: Option<(usize, usize)>,
    ) -> Option<RewardExecutionInfo>
    {
        reward_index.map(
            |(pivot_arena_index, anticone_penalty_cutoff_epoch_arena_index)| {
                let epoch_blocks = self
                    .get_executable_epoch_blocks(data_man, pivot_arena_index);

                let mut epoch_block_anticone_overlimited =
                    Vec::with_capacity(epoch_blocks.len());
                let mut epoch_block_anticone_difficulties =
                    Vec::with_capacity(epoch_blocks.len());

                let epoch_difficulty = self.arena[pivot_arena_index].difficulty;
                let anticone_cutoff_epoch_anticone_set_opt = self
                    .anticone_cache
                    .get(anticone_penalty_cutoff_epoch_arena_index);
                for index in &self.arena[pivot_arena_index]
                    .data
                    .ordered_executable_epoch_blocks
                {
                    let block_consensus_node = &self.arena[*index];

                    let mut anticone_overlimited =
                        block_consensus_node.data.partial_invalid;
                    // If a block is partial_invalid, it won't have reward and
                    // anticone_difficulty will not be used, so it's okay to set
                    // it to 0.
                    let mut anticone_difficulty: U512 = 0.into();
                    if !anticone_overlimited {
                        let block_consensus_node_anticone_opt =
                            self.anticone_cache.get(*index);
                        if block_consensus_node_anticone_opt.is_none()
                            || anticone_cutoff_epoch_anticone_set_opt.is_none()
                        {
                            anticone_difficulty = U512::from(into_u256(
                                self.recompute_anticone_weight(
                                    *index,
                                    anticone_penalty_cutoff_epoch_arena_index,
                                ),
                            ));
                        } else {
                            let block_consensus_node_anticone: HashSet<usize> =
                                block_consensus_node_anticone_opt
                                    .unwrap()
                                    .iter()
                                    .filter(|idx| {
                                        self.is_same_era(
                                            **idx,
                                            pivot_arena_index,
                                        )
                                    })
                                    .map(|idx| *idx)
                                    .collect();
                            let anticone_cutoff_epoch_anticone_set: HashSet<
                                usize,
                            > = anticone_cutoff_epoch_anticone_set_opt
                                .unwrap()
                                .iter()
                                .filter(|idx| {
                                    self.is_same_era(**idx, pivot_arena_index)
                                })
                                .map(|idx| *idx)
                                .collect();
                            let anticone_set = block_consensus_node_anticone
                                .difference(&anticone_cutoff_epoch_anticone_set)
                                .cloned()
                                .collect::<HashSet<_>>();
                            for a_index in anticone_set {
                                // TODO: Maybe consider to use base difficulty
                                // Check with the spec!
                                anticone_difficulty += U512::from(into_u256(
                                    self.block_weight(a_index, false),
                                ));
                            }
                        };

                        // TODO: check the clear definition of anticone penalty,
                        // normally and around the time of difficulty
                        // adjustment.
                        // LINT.IfChange(ANTICONE_PENALTY_1)
                        if anticone_difficulty / U512::from(epoch_difficulty)
                            >= U512::from(ANTICONE_PENALTY_RATIO)
                        {
                            anticone_overlimited = true;
                        }
                        // LINT.ThenChange(consensus/consensus_executor.
                        // rs#ANTICONE_PENALTY_2)
                    }
                    epoch_block_anticone_overlimited.push(anticone_overlimited);
                    epoch_block_anticone_difficulties.push(anticone_difficulty);
                }
                RewardExecutionInfo {
                    epoch_blocks,
                    epoch_block_anticone_overlimited,
                    epoch_block_anticone_difficulties,
                }
            },
        )
    }

    fn get_reward_execution_info(
        &self, data_man: &BlockDataManager, epoch_arena_index: usize,
    ) -> Option<RewardExecutionInfo> {
        self.get_reward_execution_info_from_index(
            data_man,
            self.get_pivot_reward_index(epoch_arena_index),
        )
    }

    pub fn expected_difficulty(&self, parent_hash: &H256) -> U256 {
        let parent_arena_index =
            *self.hash_to_arena_indices.get(parent_hash).unwrap();
        let parent_epoch = self.arena[parent_arena_index].height;
        if parent_epoch < self.pow_config.difficulty_adjustment_epoch_period {
            // Use initial difficulty for early epochs
            self.pow_config.initial_difficulty.into()
        } else {
            let last_period_upper = (parent_epoch
                / self.pow_config.difficulty_adjustment_epoch_period)
                * self.pow_config.difficulty_adjustment_epoch_period;
            if last_period_upper != parent_epoch {
                self.arena[parent_arena_index].difficulty
            } else {
                let mut cur = parent_arena_index;
                while self.arena[cur].height > last_period_upper {
                    cur = self.arena[cur].parent;
                }
                target_difficulty(
                    &self.data_man,
                    &self.pow_config,
                    &self.arena[cur].hash,
                    |h| {
                        let index = self.hash_to_arena_indices.get(h).unwrap();
                        self.arena[*index].data.num_epoch_blocks_in_2era
                    },
                )
            }
        }
    }

    fn adjust_difficulty(&mut self, new_best_arena_index: usize) {
        let new_best_hash = self.arena[new_best_arena_index].hash.clone();
        let new_best_difficulty = self.arena[new_best_arena_index].difficulty;
        let old_best_arena_index = *self.pivot_chain.last().expect("not empty");
        if old_best_arena_index == self.arena[new_best_arena_index].parent {
            // Pivot chain prolonged
            assert!(self.current_difficulty == new_best_difficulty);
        }

        let epoch = self.arena[new_best_arena_index].height;
        if epoch == 0 {
            // This may happen since the block at height 1 may have wrong
            // state root and do not update the pivot chain.
            self.current_difficulty = self.pow_config.initial_difficulty.into();
        } else if epoch
            == (epoch / self.pow_config.difficulty_adjustment_epoch_period)
                * self.pow_config.difficulty_adjustment_epoch_period
        {
            self.current_difficulty = target_difficulty(
                &self.data_man,
                &self.pow_config,
                &new_best_hash,
                |h| {
                    let index = self.hash_to_arena_indices.get(h).unwrap();
                    self.arena[*index].data.num_epoch_blocks_in_2era
                },
            );
        } else {
            self.current_difficulty = new_best_difficulty;
        }
    }

    pub fn best_block_hash(&self) -> H256 {
        self.arena[*self.pivot_chain.last().unwrap()].hash
    }

    pub fn best_state_epoch_number(&self) -> u64 {
        let pivot_height = self.pivot_index_to_height(self.pivot_chain.len());
        if pivot_height < DEFERRED_STATE_EPOCH_COUNT {
            0
        } else {
            pivot_height - DEFERRED_STATE_EPOCH_COUNT
        }
    }

    fn best_state_arena_index(&self) -> usize {
        self.get_pivot_block_arena_index(self.best_state_epoch_number())
    }

    pub fn best_state_block_hash(&self) -> H256 {
        self.arena[self.best_state_arena_index()].hash
    }

    /// Return None if the best state is not executed or the db returned error
    // TODO check if we can ignore the db error
    pub fn try_get_best_state<'a>(
        &self, data_man: &'a BlockDataManager,
    ) -> Option<State<'a>> {
        let best_state_hash = self.best_state_block_hash();
        if let Ok(state) = data_man.storage_manager.get_state_no_commit(
            SnapshotAndEpochIdRef::new(&best_state_hash, None),
        ) {
            state.map(|db| {
                State::new(StateDb::new(db), 0.into(), Default::default())
            })
        } else {
            warn!("try_get_best_state: Error for hash {}", best_state_hash);
            None
        }
    }

    pub fn best_epoch_number(&self) -> u64 {
        self.cur_era_genesis_height + self.pivot_chain.len() as u64 - 1
    }

    fn get_arena_index_from_epoch_number(
        &self, epoch_number: u64,
    ) -> Result<usize, String> {
        if epoch_number >= self.cur_era_genesis_height {
            Ok(self.get_pivot_block_arena_index(epoch_number))
        } else {
            Err("Invalid params: epoch number is too old and not maintained by consensus graph".to_owned())
        }
    }

    pub fn get_hash_from_epoch_number(
        &self, epoch_number: u64,
    ) -> Result<H256, String> {
        let height = epoch_number;
        if height >= self.cur_era_genesis_height {
            Ok(self.arena[self.get_pivot_block_arena_index(height)].hash)
        } else {
            let mut hash =
                self.arena[self.cur_era_genesis_block_arena_index].hash;
            let step = self.cur_era_genesis_height - height;
            for _ in 0..step {
                hash = self
                    .data_man
                    .block_header_by_hash(&hash)
                    .unwrap()
                    .parent_hash()
                    .clone();
            }
            Ok(hash)
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
        self.get_arena_index_from_epoch_number(epoch_number)
            .and_then(|index| {
                Ok(self.arena[index]
                    .data
                    .ordered_executable_epoch_blocks
                    .iter()
                    .map(|index| self.arena[*index].hash)
                    .collect())
            })
    }

    fn epoch_hash(&self, epoch_number: u64) -> Option<H256> {
        let pivot_index = self.height_to_pivot_index(epoch_number);
        self.pivot_chain
            .get(pivot_index)
            .map(|idx| self.arena[*idx].hash)
    }

    fn get_epoch_hash_for_block(&self, hash: &H256) -> Option<H256> {
        self.hash_to_arena_indices.get(hash).and_then(|index| {
            let epoch_number = self.arena[*index].data.epoch_number;
            self.epoch_hash(epoch_number)
        })
    }

    pub fn get_balance(
        &self, address: H160, epoch_number: u64,
    ) -> Result<U256, String> {
        let hash = self.get_hash_from_epoch_number(epoch_number)?;
        let maybe_state = self
            .data_man
            .storage_manager
            .get_state_no_commit(SnapshotAndEpochIdRef::new(&hash, None))
            .map_err(|e| format!("Error to get state, err={:?}", e))?;
        if let Some(state) = maybe_state {
            let state_db = StateDb::new(state);
            Ok(if let Ok(maybe_acc) = state_db.get_account(&address) {
                maybe_acc.map_or(U256::zero(), |acc| acc.balance).into()
            } else {
                0.into()
            })
        } else {
            Err(format!(
                "State for epoch (number={:?} hash={:?}) does not exist",
                epoch_number, hash
            )
            .into())
        }
    }

    pub fn terminal_hashes(&self) -> Vec<H256> {
        self.terminal_hashes
            .iter()
            .map(|hash| hash.clone())
            .collect()
    }

    pub fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        if let Some(idx) = self.hash_to_arena_indices.get(hash) {
            Some(self.arena[*idx].data.epoch_number)
        } else {
            None
        }
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

    pub fn block_receipts_by_hash(
        &self, hash: &H256, update_cache: bool,
    ) -> Option<Arc<Vec<Receipt>>> {
        self.get_epoch_hash_for_block(hash).and_then(|epoch| {
            trace!("Block {} is in epoch {}", hash, epoch);
            self.data_man
                .block_results_by_hash_with_epoch(hash, &epoch, update_cache)
                .map(|r| r.receipts)
        })
    }

    pub fn is_stable(&self, block_hash: &H256) -> Option<bool> {
        self.hash_to_arena_indices
            .get(block_hash)
            .and_then(|index| Some(self.arena[*index].stable))
    }

    pub fn is_adaptive(&self, block_hash: &H256) -> Option<bool> {
        self.hash_to_arena_indices
            .get(block_hash)
            .and_then(|index| Some(self.arena[*index].adaptive))
    }

    pub fn is_partial_invalid(&self, block_hash: &H256) -> Option<bool> {
        self.hash_to_arena_indices
            .get(block_hash)
            .and_then(|index| Some(self.arena[*index].data.partial_invalid))
    }

    pub fn is_pending(&self, block_hash: &H256) -> Option<bool> {
        self.hash_to_arena_indices
            .get(block_hash)
            .and_then(|index| Some(self.arena[*index].data.pending))
    }

    pub fn get_transaction_receipt_with_address(
        &self, tx_hash: &H256,
    ) -> Option<(Receipt, TransactionAddress)> {
        trace!("Get receipt with tx_hash {}", tx_hash);
        let address =
            self.data_man.transaction_address_by_hash(tx_hash, false)?;
        // receipts should never be None if address is not None because
        let receipts =
            self.block_receipts_by_hash(&address.block_hash, false)?;
        Some((
            receipts
                .get(address.index)
                .expect("Error: can't get receipt by tx_address ")
                .clone(),
            address,
        ))
    }

    pub fn transaction_count(
        &self, address: H160, epoch_number: u64,
    ) -> Result<U256, String> {
        let hash = self.get_hash_from_epoch_number(epoch_number)?;
        let state_db = StateDb::new(
            self.data_man
                .storage_manager
                .get_state_no_commit(SnapshotAndEpochIdRef::new(&hash, None))
                .unwrap()
                .unwrap(),
        );
        let state = State::new(state_db, 0.into(), Default::default());
        state
            .nonce(&address)
            .map_err(|err| format!("Get transaction count error: {:?}", err))
    }

    pub fn check_block_pivot_assumption(
        &self, pivot_hash: &H256, epoch: u64,
    ) -> Result<(), String> {
        let last_number = self.best_epoch_number();
        let hash = self.get_hash_from_epoch_number(epoch)?;
        if epoch > last_number || hash != *pivot_hash {
            return Err("Error: pivot chain assumption failed".to_owned());
        }
        Ok(())
    }

    /// Compute the block weight following the GHAST algorithm:
    /// For partially invalid block, the weight is always 0
    /// If a block is not adaptive, the weight is its difficulty
    /// If a block is adaptive, then for the heavy blocks, it equals to
    /// the heavy block ratio. Otherwise, it is zero.
    fn block_weight(&self, me: usize, inclusive: bool) -> i128 {
        if self.arena[me].data.partial_invalid && !inclusive {
            return 0 as i128;
        }
        let is_heavy = self.arena[me].is_heavy;
        let is_adaptive = self.arena[me].adaptive;
        if is_adaptive {
            if is_heavy {
                self.inner_conf.heavy_block_difficulty_ratio as i128
                    * into_i128(&self.arena[me].difficulty)
            } else {
                0 as i128
            }
        } else {
            into_i128(&self.arena[me].difficulty)
        }
    }

    /// Compute the total weight in the epoch represented by the block of
    /// my_hash.
    fn total_weight_in_own_epoch(
        &self, blockset_in_own_epoch: &HashSet<usize>, inclusive: bool,
        genesis_opt: Option<usize>,
    ) -> i128
    {
        let gen_arena_index = if let Some(x) = genesis_opt {
            x
        } else {
            self.cur_era_genesis_block_arena_index
        };
        let gen_height = self.arena[gen_arena_index].height;
        let mut total_weight = 0 as i128;
        for index in blockset_in_own_epoch.iter() {
            if gen_arena_index != self.cur_era_genesis_block_arena_index {
                let height = self.arena[*index].height;
                if height < gen_height {
                    continue;
                }
                let era_arena_index = self.ancestor_at(*index, gen_height);
                if gen_arena_index != era_arena_index {
                    continue;
                }
            }
            total_weight += self.block_weight(*index, inclusive);
        }
        total_weight
    }
}
