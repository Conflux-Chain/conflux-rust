// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod anticone_cache;
mod confirmation;
mod consensus_executor;
mod consensus_new_block_handler;
mod debug;

use super::consensus::{
    consensus_executor::ConsensusExecutor,
    consensus_new_block_handler::ConsensusNewBlockHandler,
};
use crate::{
    block_data_manager::BlockDataManager,
    consensus::{
        anticone_cache::AnticoneCache,
        confirmation::ConfirmationTrait,
        consensus_executor::{EpochExecutionTask, RewardExecutionInfo},
    },
    db::COL_MISC,
    hash::KECCAK_EMPTY_LIST_RLP,
    pow::ProofOfWorkConfig,
    state::State,
    statedb::StateDb,
    statistics::SharedStatistics,
    storage::{state_manager::SnapshotAndEpochIdRef, StorageManagerTrait},
    transaction_pool::SharedTransactionPool,
    vm_factory::VmFactory,
};
use cfx_types::{into_i128, into_u256, Bloom, H160, H256, U256, U512};
// use fenwick_tree::FenwickTree;
use crate::{pow::target_difficulty, storage::GuardedValue};
use hibitset::{BitSet, BitSetLike, DrainableBitSet};
use link_cut_tree::MinLinkCutTree;
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use primitives::{
    filter::{Filter, FilterError},
    log_entry::{LocalizedLogEntry, LogEntry},
    receipt::Receipt,
    Block, EpochNumber, SignedTransaction, StateRoot, StateRootWithAuxInfo,
    TransactionAddress,
};
use rayon::prelude::*;
use rlp::*;
use slab::Slab;
use std::{
    cmp::{max, min, Reverse},
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    mem,
    sync::Arc,
    thread::sleep,
    time::Duration,
};

const MIN_MAINTAINED_RISK: f64 = 0.000001;
const MAX_NUM_MAINTAINED_RISK: usize = 10;

pub const DEFERRED_STATE_EPOCH_COUNT: u64 = 5;

/// `REWARD_EPOCH_COUNT` needs to be larger than
/// `ANTICONE_PENALTY_UPPER_EPOCH_COUNT`. If we cannot cache receipts of recent
/// `REWARD_EPOCH_COUNT` epochs, the receipts will be loaded from db, which may
/// lead to performance downgrade
const REWARD_EPOCH_COUNT: u64 = 12;
const ANTICONE_PENALTY_UPPER_EPOCH_COUNT: u64 = 10;
const ANTICONE_PENALTY_RATIO: u64 = 100;
/// 900 Conflux tokens
const BASE_MINING_REWARD: u64 = 900;
/// The unit of one Conflux token: 10 ** 18
const CONFLUX_TOKEN: u64 = 1_000_000_000_000_000_000;
const GAS_PRICE_BLOCK_SAMPLE_SIZE: usize = 100;
const GAS_PRICE_TRANSACTION_SAMPLE_SIZE: usize = 10000;

pub const ADAPTIVE_WEIGHT_DEFAULT_ALPHA_NUM: u64 = 2;
pub const ADAPTIVE_WEIGHT_DEFAULT_ALPHA_DEN: u64 = 3;
pub const ADAPTIVE_WEIGHT_DEFAULT_BETA: u64 = 1000;
pub const HEAVY_BLOCK_DEFAULT_DIFFICULTY_RATIO: u64 = 240;

const NULL: usize = !0;
const NULLU64: u64 = !0;

// This is the cap of the size of the anticone barrier. If we have more than
// this number we will use the brute_force O(n) algorithm instead.
const ANTICONE_BARRIER_CAP: usize = 1000;
// The number of epochs per era. Each era is a potential checkpoint position.
// The parent_edge checking and adaptive checking are defined relative to the
// era start blocks.
pub const ERA_DEFAULT_EPOCH_COUNT: u64 = 50000;
// Here is the delay for us to recycle those orphaned blocks in the boundary of
// eras.
const ERA_RECYCLE_TRANSACTION_DELAY: u64 = 20;
// FIXME: We should use finality to determine the checkpoint moment instead.
const ERA_CHECKPOINT_GAP: u64 = 50000;

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

#[derive(Clone)]
pub struct ConsensusConfig {
    // If we hit invalid state root, we will dump the information into a
    // directory specified here. This is useful for testing.
    pub debug_dump_dir_invalid_state_root: String,
    // When bench_mode is true, the PoW solution verification will be skipped.
    // The transaction execution will also be skipped and only return the
    // pair of (KECCAK_NULL_RLP, KECCAK_EMPTY_LIST_RLP) This is for testing
    // only
    pub bench_mode: bool,
    // The configuration used by inner data
    pub inner_conf: ConsensusInnerConfig,
}

#[derive(Debug)]
pub struct ConsensusGraphStatistics {
    pub inserted_block_count: usize,
    pub processed_block_count: usize,
}

impl ConsensusGraphStatistics {
    pub fn new() -> ConsensusGraphStatistics {
        ConsensusGraphStatistics {
            inserted_block_count: 0,
            processed_block_count: 0,
        }
    }
}

struct ConsensusGraphNodeData {
    epoch_number: u64,
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
    ordered_executable_epoch_blocks: Vec<usize>,
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

pub struct BestInformation {
    pub best_block_hash: H256,
    pub best_epoch_number: u64,
    pub current_difficulty: U256,
    pub terminal_block_hashes: Vec<H256>,
    pub deferred_state_root: StateRootWithAuxInfo,
    pub deferred_receipts_root: H256,
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
    arena: Slab<ConsensusGraphNode>,
    // indices maps block hash to internal index.
    indices: HashMap<H256, usize>,
    // The current pivot chain indexes.
    pivot_chain: Vec<usize>,
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
    cur_era_genesis_block_index: usize,
    // The height of the ``current'' era_genesis block
    cur_era_genesis_height: u64,
    // The height of the ``stable'' era block, unless from the start, it is
    // always era_epoch_count higher than era_genesis_height
    cur_era_stable_height: u64,
    // The ``original'' genesis state root and receipts root.
    genesis_block_state_root: StateRoot,
    genesis_block_receipts_root: H256,
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
    current_difficulty: U256,
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

struct ConsensusGraphNode {
    hash: H256,
    height: u64,
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
    parent: usize,
    era_block: usize,
    last_pivot_in_past: u64,
    children: Vec<usize>,
    referrers: Vec<usize>,
    referees: Vec<usize>,
    data: ConsensusGraphNodeData,
}

impl ConsensusGraphInner {
    fn with_genesis_block(
        pow_config: ProofOfWorkConfig, data_man: Arc<BlockDataManager>,
        inner_conf: ConsensusInnerConfig,
    ) -> Self
    {
        let mut inner = ConsensusGraphInner {
            arena: Slab::new(),
            indices: HashMap::new(),
            pivot_chain: Vec::new(),
            pivot_chain_metadata: Vec::new(),
            optimistic_executed_height: None,
            terminal_hashes: Default::default(),
            legacy_refs: HashMap::new(),
            cur_era_genesis_block_index: NULL,
            cur_era_genesis_height: 0,
            cur_era_stable_height: 0,
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
        let (genesis_index, _) =
            inner.insert(data_man.genesis_block().as_ref());
        inner.cur_era_genesis_block_index = genesis_index;
        inner
            .weight_tree
            .make_tree(inner.cur_era_genesis_block_index);
        inner.weight_tree.path_apply(
            inner.cur_era_genesis_block_index,
            into_i128(data_man.genesis_block().block_header.difficulty()),
        );
        inner
            .inclusive_weight_tree
            .make_tree(inner.cur_era_genesis_block_index);
        inner.inclusive_weight_tree.path_apply(
            inner.cur_era_genesis_block_index,
            into_i128(data_man.genesis_block().block_header.difficulty()),
        );
        inner
            .stable_weight_tree
            .make_tree(inner.cur_era_genesis_block_index);
        inner.stable_weight_tree.path_apply(
            inner.cur_era_genesis_block_index,
            into_i128(data_man.genesis_block().block_header.difficulty()),
        );
        inner
            .stable_tree
            .make_tree(inner.cur_era_genesis_block_index);
        // The genesis node can be zero in stable_tree because it is never used!
        inner.stable_tree.set(inner.cur_era_genesis_block_index, 0);
        inner
            .adaptive_tree
            .make_tree(inner.cur_era_genesis_block_index);
        // The genesis node can be zero in adaptive_tree because it is never
        // used!
        inner
            .adaptive_tree
            .set(inner.cur_era_genesis_block_index, 0);
        inner
            .inclusive_adaptive_tree
            .make_tree(inner.cur_era_genesis_block_index);
        // The genesis node can be zero in adaptive_tree because it is never
        // used!
        inner
            .inclusive_adaptive_tree
            .set(inner.cur_era_genesis_block_index, 0);
        inner.arena[inner.cur_era_genesis_block_index]
            .data
            .epoch_number = 0;
        inner.pivot_chain.push(inner.cur_era_genesis_block_index);
        let mut last_pivot_in_past_blocks = HashSet::new();
        last_pivot_in_past_blocks.insert(inner.cur_era_genesis_block_index);
        inner.pivot_chain_metadata.push(ConsensusGraphPivotData {
            last_pivot_in_past_blocks,
        });
        assert!(inner.genesis_block_receipts_root == KECCAK_EMPTY_LIST_RLP);

        inner
            .anticone_cache
            .update(inner.cur_era_genesis_block_index, &BitSet::new());
        inner
    }

    #[inline]
    fn get_pivot_block_index(&self, height: u64) -> usize {
        let pivot_index = (height - self.cur_era_genesis_height) as usize;
        assert!(pivot_index < self.pivot_chain.len());
        self.pivot_chain[pivot_index]
    }

    #[inline]
    fn get_pivot_height(&self) -> u64 {
        self.cur_era_genesis_height + self.pivot_chain.len() as u64
    }

    #[inline]
    fn height_to_pivot_index(&self, height: u64) -> usize {
        (height - self.cur_era_genesis_height) as usize
    }

    #[inline]
    fn pivot_index_to_height(&self, pivot_index: usize) -> u64 {
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
    fn ancestor_at(&self, me: usize, height: u64) -> usize {
        let height_index = self.height_to_pivot_index(height);
        self.inclusive_weight_tree.ancestor_at(me, height_index)
    }

    #[inline]
    fn lca(&self, me: usize, v: usize) -> usize {
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

    fn update_total_weight_in_past(&mut self) {
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
        let epoch_index = self.get_pivot_block_index(opt_height);

        // `on_local_pivot` is set to `true` because when we later skip its
        // execution on pivot chain, we will not notify tx pool, so we
        // will also notify in advance.
        let execution_task = EpochExecutionTask::new(
            self.arena[epoch_index].hash,
            self.get_epoch_block_hashes(epoch_index),
            self.get_reward_execution_info(data_man, epoch_index),
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
    fn get_epoch_block_hashes(&self, epoch_index: usize) -> Vec<H256> {
        self.arena[epoch_index]
            .data
            .ordered_executable_epoch_blocks
            .iter()
            .map(|idx| self.arena[*idx].hash)
            .collect()
    }

    fn check_mining_adaptive_block(
        &mut self, parent_index: usize, difficulty: U256,
    ) -> bool {
        let (_stable, adaptive) = self.adaptive_weight_impl(
            parent_index,
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
        stack.push((0, self.cur_era_genesis_block_index));
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
        if self.cur_era_genesis_block_index == me {
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
            self.indices
                .get(block.block_header.parent_hash())
                .cloned()
                .unwrap()
        } else {
            NULL
        };

        let mut referees: Vec<usize> = Vec::new();
        for hash in block.block_header.referee_hashes().iter() {
            if let Some(x) = self.indices.get(hash) {
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
        self.indices.insert(hash, index);

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

        (index, self.indices.len())
    }

    fn check_correct_parent_brutal(
        &mut self, me: usize, subtree_weight: &Vec<i128>,
    ) -> bool {
        let mut valid = true;
        let parent = self.arena[me].parent;
        let parent_height = self.arena[parent].height;
        let era_height = self.get_era_height(parent_height, 0);

        // Check the pivot selection decision.
        for consensus_index_in_epoch in
            self.arena[me].data.blockset_in_own_view_of_epoch.iter()
        {
            if self.arena[*consensus_index_in_epoch].data.partial_invalid {
                continue;
            }

            let lca = self.lca(*consensus_index_in_epoch, parent);
            assert!(lca != *consensus_index_in_epoch);
            // If it is outside current era, we will skip!
            if self.arena[lca].height < era_height {
                continue;
            }
            if lca == parent {
                valid = false;
                break;
            }

            let fork = self.ancestor_at(
                *consensus_index_in_epoch,
                self.arena[lca].height + 1,
            );
            let pivot = self.ancestor_at(parent, self.arena[lca].height + 1);

            let fork_subtree_weight = subtree_weight[fork];
            let pivot_subtree_weight = subtree_weight[pivot];

            if ConsensusGraphInner::is_heavier(
                (fork_subtree_weight, &self.arena[fork].hash),
                (pivot_subtree_weight, &self.arena[pivot].hash),
            ) {
                valid = false;
                break;
            }
        }

        valid
    }

    fn check_correct_parent(
        &mut self, me: usize, anticone_barrier: &BitSet,
        weight_tuple: Option<&(Vec<i128>, Vec<i128>, Vec<i128>)>,
    ) -> bool
    {
        if let Some((subtree_weight, _, _)) = weight_tuple {
            return self.check_correct_parent_brutal(me, subtree_weight);
        }
        let mut valid = true;
        let parent = self.arena[me].parent;
        let parent_height = self.arena[parent].height;
        let era_height = self.get_era_height(parent_height, 0);

        let mut weight_delta = HashMap::new();

        for index in anticone_barrier {
            weight_delta
                .insert(index as usize, self.weight_tree.get(index as usize));
        }

        // Remove weight contribution of anticone
        for (index, delta) in &weight_delta {
            self.weight_tree.path_apply(*index, -delta);
        }

        // Check the pivot selection decision.
        for consensus_index_in_epoch in
            self.arena[me].data.blockset_in_own_view_of_epoch.iter()
        {
            if self.arena[*consensus_index_in_epoch].data.partial_invalid {
                continue;
            }

            let lca = self.lca(*consensus_index_in_epoch, parent);
            assert!(lca != *consensus_index_in_epoch);
            // If it is outside the era, we will skip!
            if self.arena[lca].height < era_height {
                continue;
            }
            if lca == parent {
                valid = false;
                break;
            }

            let fork = self.ancestor_at(
                *consensus_index_in_epoch,
                self.arena[lca].height + 1,
            );
            let pivot = self.ancestor_at(parent, self.arena[lca].height + 1);

            let fork_subtree_weight = self.weight_tree.get(fork);
            let pivot_subtree_weight = self.weight_tree.get(pivot);

            if ConsensusGraphInner::is_heavier(
                (fork_subtree_weight, &self.arena[fork].hash),
                (pivot_subtree_weight, &self.arena[pivot].hash),
            ) {
                valid = false;
                break;
            }
        }

        for (index, delta) in &weight_delta {
            self.weight_tree.path_apply(*index, *delta);
        }

        valid
    }

    fn compute_anticone_bruteforce(&self, me: usize) -> BitSet {
        let parent = self.arena[me].parent;
        if parent == NULL {
            // This is genesis, so the anticone should be empty
            return BitSet::new();
        }
        let mut last_in_pivot = self.arena[parent].last_pivot_in_past;
        for referee in &self.arena[me].referees {
            last_in_pivot =
                max(last_in_pivot, self.arena[*referee].last_pivot_in_past);
        }
        let mut visited = BitSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(me);
        visited.add(me as u32);
        while let Some(index) = queue.pop_front() {
            let parent = self.arena[index].parent;
            if self.arena[parent].data.epoch_number > last_in_pivot
                && !visited.contains(parent as u32)
            {
                visited.add(parent as u32);
                queue.push_back(parent);
            }
            for referee in &self.arena[index].referees {
                if self.arena[*referee].data.epoch_number > last_in_pivot
                    && !visited.contains(*referee as u32)
                {
                    visited.add(*referee as u32);
                    queue.push_back(*referee);
                }
            }
        }
        let mut anticone = BitSet::with_capacity(self.arena.len() as u32);
        for (i, node) in self.arena.iter() {
            if node.data.epoch_number > last_in_pivot
                && !visited.contains(i as u32)
            {
                anticone.add(i as u32);
            }
        }
        anticone
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

    fn compute_anticone(&mut self, me: usize) -> BitSet {
        let parent = self.arena[me].parent;
        debug_assert!(parent != NULL);
        debug_assert!(self.arena[me].children.is_empty());
        debug_assert!(self.arena[me].referrers.is_empty());

        // If we do not have the anticone of its parent, we compute it with
        // brute force!
        let parent_anticone_opt = self.anticone_cache.get(parent);
        let mut anticone;
        if parent_anticone_opt.is_none() {
            anticone = self.compute_anticone_bruteforce(me);
        } else {
            // Compute future set of parent
            let mut parent_futures = self.compute_future_bitset(parent);
            parent_futures.remove(me as u32);

            anticone = {
                let parent_anticone = parent_anticone_opt.unwrap();
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

                    let idx_parent = self.arena[index].parent;
                    debug_assert!(idx_parent != NULL);
                    if parent_anticone.contains(&idx_parent)
                        || parent_futures.contains(idx_parent as u32)
                    {
                        queue.push_back(idx_parent);
                    }

                    for referee in &self.arena[index].referees {
                        if parent_anticone.contains(referee)
                            || parent_futures.contains(*referee as u32)
                        {
                            queue.push_back(*referee);
                        }
                    }
                }
                for index in parent_anticone {
                    parent_futures.add(*index as u32);
                }
                for index in my_past.drain() {
                    parent_futures.remove(index);
                }
                parent_futures
            };
        }

        self.anticone_cache.update(me, &anticone);

        let mut anticone_barrier = BitSet::new();
        for index in anticone.clone().iter() {
            let parent = self.arena[index as usize].parent as u32;
            if !anticone.contains(parent) {
                anticone_barrier.add(index);
            }
        }

        debug!(
            "Block {} anticone size {}",
            self.arena[me].hash,
            anticone.len()
        );

        anticone_barrier
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
        &self, epoch_index: usize,
    ) -> Option<(usize, usize)> {
        // We are going to exclude the original genesis block here!
        if self.arena[epoch_index].height <= REWARD_EPOCH_COUNT {
            return None;
        }
        let parent_index = self.arena[epoch_index].parent;
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

    fn get_executable_epoch_blocks(
        &self, data_man: &BlockDataManager, epoch_index: usize,
    ) -> Vec<Arc<Block>> {
        let mut epoch_blocks = Vec::new();
        for idx in &self.arena[epoch_index].data.ordered_executable_epoch_blocks
        {
            let block = data_man
                .block_by_hash(&self.arena[*idx].hash, false)
                .expect("Exist");
            epoch_blocks.push(block);
        }
        epoch_blocks
    }

    fn recompute_anticone_weight(
        &self, me: usize, pivot_block_index: usize,
    ) -> i128 {
        assert!(self.is_same_era(me, pivot_block_index));
        // We need to compute the future size of me under the view of epoch
        // height pivot_index
        let mut visited = BitSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(pivot_block_index);
        visited.add(pivot_block_index as u32);
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
        let mut total_weight = self.arena[pivot_block_index].past_era_weight
            - self.arena[me].past_era_weight
            + self.block_weight(pivot_block_index, false);
        for index in visited2.iter() {
            if self.is_same_era(index as usize, pivot_block_index) {
                total_weight -= self.block_weight(index as usize, false);
            }
        }
        total_weight
    }

    // TODO: consider moving the logic to background when consensus locks are
    // broken down.
    fn get_reward_execution_info_from_index(
        &self, data_man: &BlockDataManager,
        reward_index: Option<(usize, usize)>,
    ) -> Option<RewardExecutionInfo>
    {
        reward_index.map(
            |(pivot_index, anticone_penalty_cutoff_epoch_index)| {
                let epoch_blocks =
                    self.get_executable_epoch_blocks(data_man, pivot_index);

                let mut epoch_block_anticone_overlimited =
                    Vec::with_capacity(epoch_blocks.len());
                let mut epoch_block_anticone_difficulties =
                    Vec::with_capacity(epoch_blocks.len());

                let epoch_difficulty = self.arena[pivot_index].difficulty;
                let anticone_cutoff_epoch_anticone_set_opt = self
                    .anticone_cache
                    .get(anticone_penalty_cutoff_epoch_index);
                for index in &self.arena[pivot_index]
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
                                    anticone_penalty_cutoff_epoch_index,
                                ),
                            ));
                        } else {
                            let block_consensus_node_anticone: HashSet<usize> =
                                block_consensus_node_anticone_opt
                                    .unwrap()
                                    .iter()
                                    .filter(|idx| {
                                        self.is_same_era(**idx, pivot_index)
                                    })
                                    .map(|idx| *idx)
                                    .collect();
                            let anticone_cutoff_epoch_anticone_set: HashSet<
                                usize,
                            > = anticone_cutoff_epoch_anticone_set_opt
                                .unwrap()
                                .iter()
                                .filter(|idx| {
                                    self.is_same_era(**idx, pivot_index)
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
        &self, data_man: &BlockDataManager, epoch_index: usize,
    ) -> Option<RewardExecutionInfo> {
        self.get_reward_execution_info_from_index(
            data_man,
            self.get_pivot_reward_index(epoch_index),
        )
    }

    fn expected_difficulty(&self, parent_hash: &H256) -> U256 {
        let parent_index = *self.indices.get(parent_hash).unwrap();
        let parent_epoch = self.arena[parent_index].height;
        if parent_epoch < self.pow_config.difficulty_adjustment_epoch_period {
            // Use initial difficulty for early epochs
            self.pow_config.initial_difficulty.into()
        } else {
            let last_period_upper = (parent_epoch
                / self.pow_config.difficulty_adjustment_epoch_period)
                * self.pow_config.difficulty_adjustment_epoch_period;
            if last_period_upper != parent_epoch {
                self.arena[parent_index].difficulty
            } else {
                let mut cur = parent_index;
                while self.arena[cur].height > last_period_upper {
                    cur = self.arena[cur].parent;
                }
                target_difficulty(
                    &self.data_man,
                    &self.pow_config,
                    &self.arena[cur].hash,
                    |h| {
                        let index = self.indices.get(h).unwrap();
                        self.arena[*index].data.num_epoch_blocks_in_2era
                    },
                )
            }
        }
    }

    fn adjust_difficulty(&mut self, new_best_index: usize) {
        let new_best_hash = self.arena[new_best_index].hash.clone();
        let new_best_difficulty = self.arena[new_best_index].difficulty;
        let old_best_index = *self.pivot_chain.last().expect("not empty");
        if old_best_index == self.arena[new_best_index].parent {
            // Pivot chain prolonged
            assert!(self.current_difficulty == new_best_difficulty);
        }

        let epoch = self.arena[new_best_index].height;
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
                    let index = self.indices.get(h).unwrap();
                    self.arena[*index].data.num_epoch_blocks_in_2era
                },
            );
        } else {
            self.current_difficulty = new_best_difficulty;
        }
    }

    fn best_block_hash(&self) -> H256 {
        self.arena[*self.pivot_chain.last().unwrap()].hash
    }

    fn best_state_epoch_number(&self) -> u64 {
        let pivot_height = self.pivot_index_to_height(self.pivot_chain.len());
        if pivot_height < DEFERRED_STATE_EPOCH_COUNT {
            0
        } else {
            pivot_height - DEFERRED_STATE_EPOCH_COUNT
        }
    }

    fn best_state_index(&self) -> usize {
        self.get_pivot_block_index(self.best_state_epoch_number())
    }

    fn best_state_block_hash(&self) -> H256 {
        self.arena[self.best_state_index()].hash
    }

    /// Return None if the best state is not executed or the db returned error
    // TODO check if we can ignore the db error
    fn try_get_best_state<'a>(
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

    fn best_epoch_number(&self) -> u64 {
        self.cur_era_genesis_height + self.pivot_chain.len() as u64 - 1
    }

    fn get_height_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<u64, String> {
        Ok(match epoch_number {
            EpochNumber::Earliest => 0,
            EpochNumber::LatestMined => self.best_epoch_number(),
            EpochNumber::LatestState => self.best_state_epoch_number(),
            EpochNumber::Number(num) => {
                let epoch_num = num;
                if epoch_num > self.best_epoch_number() {
                    return Err("Invalid params: expected a numbers with less than largest epoch number.".to_owned());
                }
                epoch_num
            }
        })
    }

    fn get_index_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<usize, String> {
        self.get_height_from_epoch_number(epoch_number)
            .and_then(|height| {
                if height >= self.cur_era_genesis_height {
                    Ok(self.get_pivot_block_index(height))
                } else {
                    Err("Invalid params: epoch number is too old and not maintained by consensus graph".to_owned())
                }
            })
    }

    pub fn get_hash_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<H256, String> {
        let height = self.get_height_from_epoch_number(epoch_number)?;
        if height >= self.cur_era_genesis_height {
            Ok(self.arena[self.get_pivot_block_index(height)].hash)
        } else {
            let mut hash = self.arena[self.cur_era_genesis_block_index].hash;
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

    fn block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String> {
        debug!(
            "block_hashes_by_epoch epoch_number={:?} pivot_chain.len={:?}",
            epoch_number,
            self.pivot_chain.len()
        );
        self.get_index_from_epoch_number(epoch_number)
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
        self.indices.get(hash).and_then(|block_index| {
            let epoch_number = self.arena[*block_index].data.epoch_number;
            self.epoch_hash(epoch_number)
        })
    }

    fn get_balance(
        &self, address: H160, epoch_number: EpochNumber,
    ) -> Result<U256, String> {
        let hash = self.get_hash_from_epoch_number(epoch_number.clone())?;
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

    fn terminal_hashes(&self) -> Vec<H256> {
        self.terminal_hashes
            .iter()
            .map(|hash| hash.clone())
            .collect()
    }

    pub fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        if let Some(idx) = self.indices.get(hash) {
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
            let epoch_hashes = self
                .block_hashes_by_epoch(EpochNumber::Number(
                    current_number.into(),
                ))
                .unwrap();
            for hash in epoch_hashes {
                hashes.push(hash);
            }
            current_number += 1;
        }
        hashes
    }

    fn validate_stated_epoch(
        &self, epoch_number: &EpochNumber,
    ) -> Result<(), String> {
        match epoch_number {
            EpochNumber::LatestMined => {
                return Err("Latest mined epoch is not executed".into());
            }
            EpochNumber::Number(num) => {
                let latest_state_epoch = self.best_state_epoch_number();
                if *num > latest_state_epoch {
                    return Err(format!("Specified epoch {} is not executed, the latest state epoch is {}", num, latest_state_epoch));
                }
            }
            _ => {}
        }

        Ok(())
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
        self.indices
            .get(block_hash)
            .and_then(|block_index| Some(self.arena[*block_index].stable))
    }

    pub fn is_adaptive(&self, block_hash: &H256) -> Option<bool> {
        self.indices
            .get(block_hash)
            .and_then(|block_index| Some(self.arena[*block_index].adaptive))
    }

    pub fn is_partial_invalid(&self, block_hash: &H256) -> Option<bool> {
        self.indices.get(block_hash).and_then(|block_index| {
            Some(self.arena[*block_index].data.partial_invalid)
        })
    }

    pub fn is_pending(&self, block_hash: &H256) -> Option<bool> {
        self.indices
            .get(block_hash)
            .and_then(|block_index| Some(self.arena[*block_index].data.pending))
    }

    fn get_transaction_receipt_with_address(
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

    fn transaction_count(
        &self, address: H160, epoch_number: EpochNumber,
    ) -> Result<U256, String> {
        self.validate_stated_epoch(&epoch_number)?;

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

    fn get_balance_validated(
        &self, address: H160, epoch_number: EpochNumber,
    ) -> Result<U256, String> {
        self.validate_stated_epoch(&epoch_number)?;
        self.get_balance(address, epoch_number)
    }

    pub fn check_block_pivot_assumption(
        &self, pivot_hash: &H256, epoch: u64,
    ) -> Result<(), String> {
        let last_number = self
            .get_height_from_epoch_number(EpochNumber::LatestMined)
            .unwrap();
        let hash =
            self.get_hash_from_epoch_number(EpochNumber::Number(epoch.into()))?;
        if epoch > last_number || hash != *pivot_hash {
            return Err("Error: pivot chain assumption failed".to_owned());
        }
        Ok(())
    }

    fn persist_terminals(&self) {
        let mut terminals = Vec::with_capacity(self.terminal_hashes.len());
        for h in &self.terminal_hashes {
            terminals.push(h);
        }
        let mut rlp_stream = RlpStream::new();
        rlp_stream.begin_list(terminals.len());
        for hash in terminals {
            rlp_stream.append(hash);
        }
        let mut dbops = self.data_man.db.key_value().transaction();
        dbops.put(COL_MISC, b"terminals", &rlp_stream.drain());
        self.data_man.db.key_value().write(dbops).expect("db error");
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
        let gen_index = if let Some(x) = genesis_opt {
            x
        } else {
            self.cur_era_genesis_block_index
        };
        let gen_height = self.arena[gen_index].height;
        let mut total_weight = 0 as i128;
        for index in blockset_in_own_epoch.iter() {
            if gen_index != self.cur_era_genesis_block_index {
                let height = self.arena[*index].height;
                if height < gen_height {
                    continue;
                }
                let era_index = self.ancestor_at(*index, gen_height);
                if gen_index != era_index {
                    continue;
                }
            }
            total_weight += self.block_weight(*index, inclusive);
        }
        total_weight
    }

    /// Binary search to find the starting point so we can execute to the end of
    /// the chain.
    /// Return the first index that is not executed,
    /// or return `chain.len()` if they are all executed (impossible for now).
    ///
    /// NOTE: If a state for an block exists, all the blocks on its pivot chain
    /// must have been executed and state committed. The receipts for these
    /// past blocks may not exist because the receipts on forks will be
    /// garbage-collected, but when we need them, we will recompute these
    /// missing receipts in `process_rewards_and_fees`. This 'recompute' is safe
    /// because the parent state exists. Thus, it's okay that here we do not
    /// check existence of the receipts that will be needed for reward
    /// computation during epoch execution.
    fn find_start_index(&self, chain: &Vec<usize>) -> usize {
        let mut base = 0;
        let mut size = chain.len();
        while size > 1 {
            let half = size / 2;
            let mid = base + half;
            let epoch_hash = self.arena[chain[mid]].hash;
            base = if self.data_man.epoch_executed(&epoch_hash) {
                mid
            } else {
                base
            };
            size -= half;
        }
        let epoch_hash = self.arena[chain[base]].hash;
        if self.data_man.epoch_executed(&epoch_hash) {
            base + 1
        } else {
            base
        }
    }

    fn reset_epoch_number_in_epoch(&mut self, pivot_index: usize) {
        self.set_epoch_number_in_epoch(pivot_index, NULLU64);
    }

    fn set_epoch_number_in_epoch(
        &mut self, pivot_index: usize, epoch_number: u64,
    ) {
        let block_set = mem::replace(
            &mut self.arena[pivot_index].data.blockset_in_own_view_of_epoch,
            Default::default(),
        );
        for idx in &block_set {
            self.arena[*idx].data.epoch_number = epoch_number
        }
        self.arena[pivot_index].data.epoch_number = epoch_number;
        mem::replace(
            &mut self.arena[pivot_index].data.blockset_in_own_view_of_epoch,
            block_set,
        );
    }

    fn process_referees(
        &self, old_referees: &Vec<usize>, era_blockset: &HashSet<usize>,
        legacy_refs: &HashMap<H256, Vec<usize>>,
    ) -> Vec<usize>
    {
        let mut referees = Vec::new();
        for referee in old_referees {
            let hash = self.arena[*referee].hash;
            if era_blockset.contains(referee) {
                self.insert_referee_if_not_duplicate(&mut referees, *referee);
            } else if let Some(r) = legacy_refs.get(&hash) {
                for r_index in r {
                    self.insert_referee_if_not_duplicate(
                        &mut referees,
                        *r_index,
                    );
                }
            }
        }
        referees
    }

    fn checkpoint_at(&mut self, new_era_block_index: usize) {
        // We first compute the set of blocks inside the new era
        let mut new_era_blockset = HashSet::new();
        new_era_blockset.clear();
        let mut queue = VecDeque::new();
        queue.push_back(new_era_block_index);
        new_era_blockset.insert(new_era_block_index);
        while let Some(x) = queue.pop_front() {
            for child in self.arena[x].children.iter() {
                queue.push_back(*child);
                new_era_blockset.insert(*child);
            }
        }

        // Now we topologically sort the blocks outside the era
        let mut outside_blocks = HashSet::new();
        for (index, _) in self.arena.iter() {
            if !new_era_blockset.contains(&index) {
                outside_blocks.insert(index);
            }
        }
        let sorted_outside_blocks = self.topological_sort(&outside_blocks);
        // Next we are going to compute the new legacy_refs map based on current
        // graph information
        let mut new_legacy_refs = HashMap::new();
        for index in sorted_outside_blocks.iter() {
            let referees = self.process_referees(
                &self.arena[*index].referees,
                &new_era_blockset,
                &new_legacy_refs,
            );
            if !referees.is_empty() {
                new_legacy_refs.insert(self.arena[*index].hash, referees);
            }
        }
        // Now we append all existing legacy_refs into the new_legacy_refs
        for (hash, old_referees) in self.legacy_refs.iter() {
            let referees = self.process_referees(
                &old_referees,
                &new_era_blockset,
                &new_legacy_refs,
            );
            if !referees.is_empty() {
                new_legacy_refs.insert(*hash, referees);
            }
        }
        // Next we are going to recompute all referee and referrer information
        // in arena
        let era_parent = self.arena[new_era_block_index].parent;
        let new_era_height = self.arena[new_era_block_index].height;
        let new_era_pivot_index = self.height_to_pivot_index(new_era_height);
        for v in new_era_blockset.iter() {
            self.arena[*v].referrers = Vec::new();
        }
        for v in new_era_blockset.iter() {
            let me = *v;
            let new_referees = self.process_referees(
                &self.arena[me].referees,
                &new_era_blockset,
                &new_legacy_refs,
            );
            for u in new_referees.iter() {
                self.arena[*u].referrers.push(me);
            }
            self.arena[me].referees = new_referees;
            // We no longer need to consider blocks outside our era when
            // computing blockset_in_epoch
            self.arena[me].data.min_epoch_in_other_views = max(
                self.arena[me].data.min_epoch_in_other_views,
                new_era_height + 1,
            );
            assert!(
                self.arena[me].data.max_epoch_in_other_views >= new_era_height
            );
            self.arena[me]
                .data
                .blockset_in_own_view_of_epoch
                .retain(|v| new_era_blockset.contains(v));
        }
        // Now we are ready to cleanup outside blocks in inner data structures
        self.legacy_refs = new_legacy_refs;
        self.arena[new_era_block_index].parent = NULL;
        for index in outside_blocks {
            let hash = self.arena[index].hash;
            self.indices.remove(&hash);
            self.terminal_hashes.remove(&hash);
            self.arena.remove(index);
        }
        assert!(new_era_pivot_index < self.pivot_chain.len());
        self.pivot_chain = self.pivot_chain.split_off(new_era_pivot_index);
        self.pivot_chain_metadata =
            self.pivot_chain_metadata.split_off(new_era_pivot_index);
        for d in self.pivot_chain_metadata.iter_mut() {
            d.last_pivot_in_past_blocks
                .retain(|v| new_era_blockset.contains(v));
        }
        self.anticone_cache.intersect_update(&new_era_blockset);

        // Chop off all link-cut-trees in the inner data structure
        self.weight_tree.split_root(era_parent, new_era_block_index);
        self.inclusive_weight_tree
            .split_root(era_parent, new_era_block_index);
        self.stable_weight_tree
            .split_root(era_parent, new_era_block_index);
        self.stable_tree.split_root(era_parent, new_era_block_index);
        self.adaptive_tree
            .split_root(era_parent, new_era_block_index);
        self.inclusive_adaptive_tree
            .split_root(era_parent, new_era_block_index);

        self.cur_era_genesis_block_index = new_era_block_index;
        self.cur_era_genesis_height = new_era_height;
        self.cur_era_stable_height =
            new_era_height + self.inner_conf.era_epoch_count;

        self.data_man.set_cur_consensus_era_genesis_hash(
            &self.arena[new_era_block_index].hash,
        );
    }
}

pub struct TotalWeightInPast {
    pub old: U256,
    pub cur: U256,
    pub delta: U256,
}

/// ConsensusGraph is a layer on top of SynchronizationGraph. A SyncGraph
/// collect all blocks that the client has received so far, but a block can only
/// be delivered to the ConsensusGraph if 1) the whole block content is
/// available and 2) all of its past blocks are also in the ConsensusGraph.
///
/// ConsensusGraph maintains the TreeGraph structure of the client and
/// implements *GHAST*/*Conflux* algorithm to determine the block total order.
/// It dispatches transactions in epochs to ConsensusExecutor to process. To
/// avoid executing too many execution reroll caused by transaction order
/// oscillation. It defers the transaction execution for a few epochs.
pub struct ConsensusGraph {
    pub inner: Arc<RwLock<ConsensusGraphInner>>,
    pub txpool: SharedTransactionPool,
    pub data_man: Arc<BlockDataManager>,
    executor: Arc<ConsensusExecutor>,
    pub statistics: SharedStatistics,
    pub new_block_handler: ConsensusNewBlockHandler,
}

pub type SharedConsensusGraph = Arc<ConsensusGraph>;

impl ConfirmationTrait for ConsensusGraph {
    fn confirmation_risk_by_hash(&self, hash: H256) -> Option<f64> {
        let inner = self.inner.read();
        self.new_block_handler
            .confirmation_risk_by_hash(&*inner, hash)
    }
}

impl ConsensusGraph {
    /// Build the ConsensusGraph with a genesis block and various other
    /// components The execution will be skipped if bench_mode sets to true.
    pub fn with_genesis_block(
        conf: ConsensusConfig, vm: VmFactory, txpool: SharedTransactionPool,
        statistics: SharedStatistics, data_man: Arc<BlockDataManager>,
        pow_config: ProofOfWorkConfig,
    ) -> Self
    {
        let inner =
            Arc::new(RwLock::new(ConsensusGraphInner::with_genesis_block(
                pow_config,
                data_man.clone(),
                conf.inner_conf.clone(),
            )));
        let executor = Arc::new(ConsensusExecutor::start(
            txpool.clone(),
            data_man.clone(),
            vm,
            inner.clone(),
            conf.bench_mode,
        ));

        ConsensusGraph {
            inner,
            txpool: txpool.clone(),
            data_man: data_man.clone(),
            executor: executor.clone(),
            statistics: statistics.clone(),
            new_block_handler: ConsensusNewBlockHandler::new(
                conf, txpool, data_man, executor, statistics,
            ),
        }
    }

    pub fn expected_difficulty(&self, parent_hash: &H256) -> U256 {
        let inner = self.inner.read();
        inner.expected_difficulty(parent_hash)
    }

    pub fn update_total_weight_in_past(&self) {
        self.inner.write().update_total_weight_in_past();
    }

    pub fn get_to_propagate_trans(
        &self,
    ) -> HashMap<H256, Arc<SignedTransaction>> {
        self.txpool.get_to_propagate_trans()
    }

    pub fn set_to_propagate_trans(
        &self, transactions: HashMap<H256, Arc<SignedTransaction>>,
    ) {
        self.txpool.set_to_propagate_trans(transactions);
    }

    /// Wait for the generation and the execution completion of a block in the
    /// consensus graph. This API is used mainly for testing purpose
    pub fn wait_for_generation(&self, hash: &H256) {
        while !self.inner.read().indices.contains_key(hash) {
            sleep(Duration::from_millis(1));
        }
        let best_state_block = self.inner.read().best_state_block_hash();
        self.executor.wait_for_result(best_state_block);
    }

    /// Determine whether the next mined block should have adaptive weight or
    /// not
    pub fn check_mining_adaptive_block(
        &self, inner: &mut ConsensusGraphInner, parent_hash: &H256,
        difficulty: &U256,
    ) -> bool
    {
        let parent_index = *inner.indices.get(parent_hash).unwrap();
        inner.check_mining_adaptive_block(parent_index, *difficulty)
    }

    pub fn get_height_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<u64, String> {
        self.inner.read().get_height_from_epoch_number(epoch_number)
    }

    pub fn best_epoch_number(&self) -> u64 {
        self.inner.read().best_epoch_number()
    }

    pub fn get_block_total_weight(&self, hash: &H256) -> Option<i128> {
        let w = self.inner.write();
        if let Some(idx) = w.indices.get(hash).cloned() {
            Some(w.weight_tree.get(idx))
        } else {
            None
        }
    }

    pub fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        self.inner.read().get_block_epoch_number(hash)
    }

    pub fn get_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String> {
        self.inner.read().block_hashes_by_epoch(epoch_number)
    }

    pub fn gas_price(&self) -> Option<U256> {
        let inner = self.inner.read();
        let mut last_epoch_number = inner.best_epoch_number();
        let mut number_of_blocks_to_sample = GAS_PRICE_BLOCK_SAMPLE_SIZE;
        let mut tx_hashes = HashSet::new();
        let mut prices = Vec::new();

        loop {
            if number_of_blocks_to_sample == 0 || last_epoch_number == 0 {
                break;
            }
            if prices.len() == GAS_PRICE_TRANSACTION_SAMPLE_SIZE {
                break;
            }
            let mut hashes = inner
                .block_hashes_by_epoch(EpochNumber::Number(
                    last_epoch_number.into(),
                ))
                .unwrap();
            hashes.reverse();
            last_epoch_number -= 1;

            for hash in hashes {
                let block = self.data_man.block_by_hash(&hash, false).unwrap();
                for tx in block.transactions.iter() {
                    if tx_hashes.insert(tx.hash()) {
                        prices.push(tx.gas_price().clone());
                        if prices.len() == GAS_PRICE_TRANSACTION_SAMPLE_SIZE {
                            break;
                        }
                    }
                }
                number_of_blocks_to_sample -= 1;
                if number_of_blocks_to_sample == 0 {
                    break;
                }
            }
        }

        prices.sort();
        if prices.is_empty() {
            None
        } else {
            Some(prices[prices.len() / 2])
        }
    }

    pub fn get_balance(
        &self, address: H160, epoch_number: EpochNumber,
    ) -> Result<U256, String> {
        self.inner
            .read()
            .get_balance_validated(address, epoch_number)
    }

    pub fn get_epoch_blocks(
        &self, inner: &ConsensusGraphInner, epoch_index: usize,
    ) -> Vec<Arc<Block>> {
        inner.get_executable_epoch_blocks(&self.data_man, epoch_index)
    }

    // TODO Merge logic.
    /// This is a very expensive call to force the engine to recompute the state
    /// root of a given block
    pub fn compute_state_for_block(
        &self, block_hash: &H256, inner: &mut ConsensusGraphInner,
    ) -> Result<(StateRootWithAuxInfo, H256), String> {
        self.new_block_handler
            .compute_state_for_block(block_hash, inner)
    }

    /// Force the engine to recompute the deferred state root for a particular
    /// block given a delay.
    pub fn compute_deferred_state_for_block(
        &self, block_hash: &H256, delay: usize,
    ) -> Result<(StateRootWithAuxInfo, H256), String> {
        let inner = &mut *self.inner.write();

        let idx_opt = inner.indices.get(block_hash);
        if idx_opt == None {
            return Err(
                "Parent hash is too old for computing the deferred state"
                    .to_owned(),
            );
        }
        let mut idx = *idx_opt.unwrap();
        for _i in 0..delay {
            if idx == inner.cur_era_genesis_block_index {
                // If it is the original genesis, we just break
                if inner.arena[inner.cur_era_genesis_block_index].height == 0 {
                    break;
                } else {
                    return Err("Parent hash is too old for computing the deferred state".to_owned());
                }
            }
            idx = inner.arena[idx].parent;
        }
        let hash = inner.arena[idx].hash;
        self.compute_state_for_block(&hash, inner)
    }

    /// construct_pivot() should be used after on_new_block_construction_only()
    /// calls. It builds the pivot chain and ists state at once, avoiding
    /// intermediate redundant computation triggered by on_new_block().
    /// FIXME: Checkpoint will require a new way to catch up
    pub fn construct_pivot(&self) {
        {
            let inner = &mut *self.inner.write();
            self.new_block_handler.construct_pivot_info(inner);
        }
        {
            let inner = &*self.inner.read();
            self.new_block_handler.construct_state_info(inner);
        }
    }

    pub fn on_new_block_construction_only(&self, hash: &H256) {
        let block = self.data_man.block_by_hash(hash, true).unwrap();

        debug!(
            "insert new block into consensus: block_header={:?} tx_count={}, block_size={}",
            block.block_header,
            block.transactions.len(),
            block.size(),
        );

        self.statistics.inc_consensus_graph_processed_block_count();
        let inner = &mut *self.inner.write();
        self.new_block_handler
            .on_new_block_construction_only(inner, hash, block);
    }

    pub fn on_new_block(&self, hash: &H256) {
        let block = self.data_man.block_by_hash(hash, true).unwrap();

        debug!(
            "insert new block into consensus: block_header={:?} tx_count={}, block_size={}",
            block.block_header,
            block.transactions.len(),
            block.size(),
        );

        self.statistics.inc_consensus_graph_processed_block_count();
        let inner = &mut *self.inner.write();
        self.new_block_handler.on_new_block(inner, hash, block);
    }

    pub fn best_block_hash(&self) -> H256 {
        self.inner.read().best_block_hash()
    }

    pub fn best_state_epoch_number(&self) -> u64 {
        self.inner.read().best_state_epoch_number()
    }

    pub fn get_hash_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<H256, String> {
        self.inner.read().get_hash_from_epoch_number(epoch_number)
    }

    pub fn get_transaction_info_by_hash(
        &self, hash: &H256,
    ) -> Option<(SignedTransaction, Receipt, TransactionAddress)> {
        // We need to hold the inner lock to ensure that tx_address and receipts
        // are consistent
        let inner = self.inner.read();
        if let Some((receipt, address)) =
            inner.get_transaction_receipt_with_address(hash)
        {
            let block =
                self.data_man.block_by_hash(&address.block_hash, false)?;
            let transaction = (*block.transactions[address.index]).clone();
            Some((transaction, receipt, address))
        } else {
            None
        }
    }

    pub fn transaction_count(
        &self, address: H160, epoch_number: EpochNumber,
    ) -> Result<U256, String> {
        self.inner.read().transaction_count(address, epoch_number)
    }

    pub fn get_ancestor(&self, hash: &H256, height: u64) -> H256 {
        let inner = self.inner.write();
        let me = *inner.indices.get(hash).unwrap();
        let idx = inner.ancestor_at(me, height);
        inner.arena[idx].hash.clone()
    }

    pub fn try_get_best_state(&self) -> Option<State> {
        self.inner.read().try_get_best_state(&self.data_man)
    }

    /// Wait until the best state has been executed, and return the state
    pub fn get_best_state(&self) -> State {
        let inner = self.inner.read();
        self.wait_for_block_state(&inner.best_state_block_hash());
        inner
            .try_get_best_state(&self.data_man)
            .expect("Best state has been executed")
    }

    /// Returns the total number of blocks in consensus graph
    pub fn block_count(&self) -> usize { self.inner.read().indices.len() }

    pub fn estimate_gas(&self, tx: &SignedTransaction) -> Result<U256, String> {
        self.call_virtual(tx, EpochNumber::LatestState)
            .map(|(_, gas_used)| gas_used)
    }

    pub fn logs(
        &self, filter: Filter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        let block_hashes = if filter.block_hashes.is_none() {
            if filter.from_epoch >= filter.to_epoch {
                return Err(FilterError::InvalidEpochNumber {
                    from_epoch: filter.from_epoch,
                    to_epoch: filter.to_epoch,
                });
            }

            let inner = self.inner.read();

            if filter.from_epoch
                >= inner.pivot_index_to_height(inner.pivot_chain.len())
            {
                return Ok(Vec::new());
            }

            let from_epoch = filter.from_epoch;
            let to_epoch = min(
                filter.to_epoch,
                inner.pivot_index_to_height(inner.pivot_chain.len()),
            );

            let blooms = filter.bloom_possibilities();
            let bloom_match = |block_log_bloom: &Bloom| {
                blooms
                    .iter()
                    .any(|bloom| block_log_bloom.contains_bloom(bloom))
            };

            let mut blocks = Vec::new();
            for epoch_number in from_epoch..to_epoch {
                let epoch_hash =
                    inner.arena[inner.get_pivot_block_index(epoch_number)].hash;
                for index in &inner.arena
                    [inner.get_pivot_block_index(epoch_number)]
                .data
                .ordered_executable_epoch_blocks
                {
                    let hash = inner.arena[*index].hash;
                    if let Some(block_log_bloom) = self
                        .data_man
                        .block_results_by_hash_with_epoch(
                            &hash,
                            &epoch_hash,
                            false,
                        )
                        .map(|r| r.bloom)
                    {
                        if !bloom_match(&block_log_bloom) {
                            continue;
                        }
                    }
                    blocks.push(hash);
                }
            }

            blocks
        } else {
            filter.block_hashes.as_ref().unwrap().clone()
        };

        Ok(self.logs_from_blocks(
            block_hashes,
            |entry| filter.matches(entry),
            filter.limit,
        ))
    }

    /// Returns logs matching given filter. The order of logs returned will be
    /// the same as the order of the blocks provided. And it's the callers
    /// responsibility to sort blocks provided in advance.
    pub fn logs_from_blocks<F>(
        &self, mut blocks: Vec<H256>, matches: F, limit: Option<usize>,
    ) -> Vec<LocalizedLogEntry>
    where
        F: Fn(&LogEntry) -> bool + Send + Sync,
        Self: Sized,
    {
        // sort in reverse order
        blocks.reverse();

        let mut logs = blocks
            .chunks(128)
            .flat_map(move |blocks_chunk| {
                blocks_chunk.into_par_iter()
                    .filter_map(|hash|
                        self.inner.read().block_receipts_by_hash(&hash, false).map(|r| (hash, (*r).clone()))
                    )
                    .filter_map(|(hash, receipts)| self.data_man.block_by_hash(&hash, false).map(|b| (hash, receipts, b.transaction_hashes())))
                    .flat_map(|(hash, mut receipts, mut hashes)| {
                        if receipts.len() != hashes.len() {
                            warn!("Block ({}) has different number of receipts ({}) to transactions ({}). Database corrupt?", hash, receipts.len(), hashes.len());
                            assert!(false);
                        }
                        let mut log_index = receipts.iter().fold(0, |sum, receipt| sum + receipt.logs.len());

                        let receipts_len = receipts.len();
                        hashes.reverse();
                        receipts.reverse();
                        receipts.into_iter()
                            .map(|receipt| receipt.logs)
                            .zip(hashes)
                            .enumerate()
                            .flat_map(move |(index, (mut logs, tx_hash))| {
                                let current_log_index = log_index;
                                let no_of_logs = logs.len();
                                log_index -= no_of_logs;

                                logs.reverse();
                                logs.into_iter()
                                    .enumerate()
                                    .map(move |(i, log)| LocalizedLogEntry {
                                        entry: log,
                                        block_hash: *hash,
                                        // TODO
                                        block_number: 0,
                                        transaction_hash: tx_hash,
                                        // iterating in reverse order
                                        transaction_index: receipts_len - index - 1,
                                        transaction_log_index: no_of_logs - i - 1,
                                        log_index: current_log_index - i - 1,
                                    })
                            })
                            .filter(|log_entry| matches(&log_entry.entry))
                            .take(limit.unwrap_or(::std::usize::MAX))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .take(limit.unwrap_or(::std::usize::MAX))
            .collect::<Vec<LocalizedLogEntry>>();
        logs.reverse();
        logs
    }

    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch: EpochNumber,
    ) -> Result<(Vec<u8>, U256), String> {
        // only allow to call against stated epoch
        self.inner.read().validate_stated_epoch(&epoch)?;
        let epoch_id = self.get_hash_from_epoch_number(epoch)?;
        self.executor.call_virtual(tx, &epoch_id)
    }

    /// Wait for a block's epoch is computed.
    /// Return the state_root and receipts_root
    pub fn wait_for_block_state(
        &self, block_hash: &H256,
    ) -> (StateRootWithAuxInfo, H256) {
        self.executor.wait_for_result(*block_hash)
    }

    /// Return the current era genesis block (checkpoint block) in the consesus
    /// graph. This API is used by the SynchronizationLayer to trim data
    /// before the checkpoint.
    pub fn current_era_genesis_hash(&self) -> H256 {
        let inner = self.inner.read();
        inner.arena[inner.cur_era_genesis_block_index].hash.clone()
    }

    /// Get the number of processed blocks (i.e., the number of calls to
    /// on_new_block() and on_new_block_construction_only())
    pub fn get_processed_block_count(&self) -> usize {
        self.statistics.get_consensus_graph_processed_block_count()
    }

    /// This function is called when preparing a new block for generation. It
    /// propagate the ReadGuard up to make the read-lock live longer so that
    /// the whole block packing process can be atomic.
    pub fn get_best_info(
        &self, referee_bound_opt: Option<usize>,
    ) -> GuardedValue<
        RwLockUpgradableReadGuard<ConsensusGraphInner>,
        BestInformation,
    > {
        let consensus_inner = self.inner.upgradable_read();
        let (deferred_state_root, deferred_receipts_root) =
            self.wait_for_block_state(&consensus_inner.best_state_block_hash());
        let mut bounded_terminal_hashes = consensus_inner.terminal_hashes();
        if let Some(referee_bound) = referee_bound_opt {
            if bounded_terminal_hashes.len() > referee_bound {
                let mut tmp = Vec::new();
                let best_idx = consensus_inner.pivot_chain.last().unwrap();
                for hash in bounded_terminal_hashes {
                    let a_idx = consensus_inner.indices.get(&hash).unwrap();
                    let a_lca = consensus_inner.lca(*a_idx, *best_idx);
                    tmp.push((consensus_inner.arena[a_lca].height, hash));
                }
                tmp.sort_by(|a, b| Reverse(a.0).cmp(&Reverse(b.0)));
                bounded_terminal_hashes = tmp
                    .split_off(referee_bound)
                    .iter()
                    .map(|(_, b)| b.clone())
                    .collect()
            }
        }
        let value = BestInformation {
            best_block_hash: consensus_inner.best_block_hash(),
            best_epoch_number: consensus_inner.best_epoch_number(),
            current_difficulty: consensus_inner.current_difficulty,
            terminal_block_hashes: bounded_terminal_hashes,
            deferred_state_root,
            deferred_receipts_root,
        };
        GuardedValue::new(consensus_inner, value)
    }

    pub fn block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String> {
        self.inner
            .read_recursive()
            .block_hashes_by_epoch(epoch_number)
    }
}

impl Drop for ConsensusGraph {
    fn drop(&mut self) { self.executor.stop(); }
}
