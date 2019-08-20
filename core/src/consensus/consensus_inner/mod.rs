// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod confirmation_meter;
pub mod consensus_executor;
pub mod consensus_new_block_handler;

use crate::{
    block_data_manager::{
        BlockDataManager, ConsensusGraphExecutionInfo, EpochExecutionContext,
    },
    consensus::{anticone_cache::AnticoneCache, pastset_cache::PastSetCache},
    parameters::{consensus::*, consensus_internal::*},
    pow::{target_difficulty, ProofOfWorkConfig},
    state::State,
    statedb::StateDb,
    storage::{state_manager::StateManagerTrait, SnapshotAndEpochIdRef},
};
use cfx_types::{into_i128, H160, H256, U256, U512};
use hibitset::{BitSet, BitSetLike};
use link_cut_tree::{
    CaterpillarMinLinkCutTree, DefaultMinLinkCutTree, SizeMinLinkCutTree,
};
use primitives::{
    receipt::Receipt, Block, BlockHeader, BlockHeaderBuilder,
    StateRootWithAuxInfo, TransactionAddress,
};
use slab::Slab;
use std::{
    cmp::max,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    sync::Arc,
};

const NULL: usize = !0;
const NULLU64: u64 = !0;

#[allow(dead_code)]
const MAX_BLAME_RATIO_FOR_TRUST: f64 = 0.4;

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
    // FIXME: We should replace this to use confirmation risk instead
    pub era_checkpoint_gap: u64,
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
    blockset_in_own_view_of_epoch: Vec<usize>,
    /// The number of blocks in the last two era. Only such blocks are counted
    /// during difficulty adjustment.
    num_epoch_blocks_in_2era: usize,
    /// Ordered executable blocks in this epoch. This filters out blocks that
    /// are not in the same era of the epoch pivot block.
    pub ordered_executable_epoch_blocks: Vec<usize>,
    /// It indicates whether `blockset_in_own_view_of_epoch` is cleared due to
    /// its size.
    pub blockset_cleared: bool,
    pub sequence_number: u64,
    /// exec_info_lca_height indicates the fork_at height that the vote_valid
    /// field corresponds to.
    exec_info_lca_height: u64,
    /// It indicates whether the blame voting information of this block is
    /// correct or not.
    vote_valid: bool,
}

impl ConsensusGraphNodeData {
    fn new(epoch_number: u64, sequence_number: u64) -> Self {
        ConsensusGraphNodeData {
            epoch_number,
            partial_invalid: false,
            pending: false,
            blockset_in_own_view_of_epoch: Default::default(),
            num_epoch_blocks_in_2era: 0,
            ordered_executable_epoch_blocks: Default::default(),
            blockset_cleared: false,
            sequence_number,
            exec_info_lca_height: NULLU64,
            vote_valid: true,
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
/// The anticone cut point for reward calculation will also stay within one era.
/// Also the adaptive rule in GHAST is modified as well (described below) to
/// reflect the era boundary.
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
/// 6   while a != EraGenesis do
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
/// so in order to calculate stable, it is sufficient to calculate
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
/// 6   while a != EraGenesis do
/// 7       if f(a) > beta and g(a) / f(a) < alpha then
/// 8           adaptive = True
/// 9       a = a.parent
///10   let f1(x) = InclusiveSubTW(B, x.parent)
///11   let g1(x) = InclusiveSubTW(B, x)
///12   while a != LastEraGenesis do
///13       if f1(a) > beta and g1(a) / f1(a) < alpha then
///14           adaptive = True
///15       a = a.parent
///
/// The only difference is that when maintaining g(x) * d - f(x) * n, we need to
/// do special caterpillar update in the Link-Cut-Tree, i.e., given a node X, we
/// need to update the values of all of those nodes A such that A is the child
/// of one of the node in the path from Genesis to X.
///
/// Note that when computing stable we only consider the view under the single
/// current era, while when computing adaptive we consider both the current and
/// the last eras. The reason is as follows. Here we are going to handle split
/// attack and balance attack. The split attack requires stable detection since
/// it requires information about non-past. And it also requires attacker to
/// keep creating unstable situations along with graph growing, therefore it
/// can be detected in the current latest era. In contrast, balance attack may
/// only require subtree information, so it mainly needs to detect adaptive. And
/// balance attack may incurs adaptive case only once, which could be just
/// before the beginning of the latest current era, to generate two balanced era
/// subtrees, while these two era trees themselves can look healthy. Therefore,
/// to handle balance attack, we also need to consider adaptive situation in the
/// last/previous era.

/// [Introduction of blaming mechanism]
///
/// Blaming is used to provide proof for state root of a specific pivot block.
/// The rationale behind is as follows. Verifying state roots of blocks off
/// pivot chain is very costly. It is preferred to avoid this verification if
/// possible. Normally, Conflux only needs to store correct state root in
/// header of pivot block to provide proof for light node. However, the pivot
/// chain may oscillate at the place close to ledger tail, which means that
/// a block that is off pivot at some point may become pivot block in the
/// future. If we do not verify the state root in the header of that block, when
/// it becomes a pivot block later, we cannot guarantee the correctness of the
/// state root in its header. Therefore, if we do not verify the state root in
/// off-pivot block, we cannot guarantee the correctness of state root in pivot
/// block. Of course, one may argue that you can switch pivot chain when
/// incorrect state root in pivot block is observed. However, this makes the
/// check for the correct parent selection rely on state root checking, which in
/// turn will require state root verification on any blocks including off-pivot
/// ones. This violates the original goal to save cost of verification of state
/// root in off-pivot blocks.
///
/// We therefore allow incorrect state root in pivot block header, and use the
/// blaming mechanism to enable the proof generation of the correct state root.
/// A full/archive node verifies the deferred state root and the blaming
/// information stored in the header of each pivot block. It blames the blocks
/// with incorrect information and stores the blaming result in the header of
/// the newly mined block. The blaming result is simply a count which represents
/// the distance (in the number of blocks) between the last correct block on the
/// pivot chain and the newly mined block. For example, consider the blocks
/// Bi-1, Bi, Bi+1, Bi+2, Bi+3. Assume the blaming count in Bi+3 is 2.
/// This means when Bi+3 was mined, the node thinks Bi's information is correct,
/// while the information in Bi+1 and Bi+2 are wrong. Therefore, the node
/// recovers the true deferred state roots (DSR) of Bi+1, Bi+2, and Bi+3 by
/// computing locally, and then computes the keccak hash of [DSRi+3, DSRi+2,
/// DSRi+1] and stores the hash into the header of Bi+3 as its final deferred
/// state root. A special case is if the blaming count is 0, the final deferred
/// state root of the block is simply the original deferred state root, i.e.,
/// DSRi+3 for block Bi+3 in the above case.
///
/// To provide proof of state root to light node (or a full node when it tries
/// to recover from a checkpoint), the protocol goes through the following
/// steps. Let's assume the verifier has a subtree of block headers which
/// includes the block whose state root is to be verified.
/// 1. The verifier node gets a merkle path whose merkle root corresponds
/// to the state root after executing block Bi. Let's call it the path root
/// which is to be verified.
///
/// 2. Assume deferred count is 2, the verifier node gets block header Bi+2
/// whose deferred state root should be the state root of Bi.
///
/// 3. The verifier node locally searches for the first block whose information
/// in header is correct, starting from block Bi+2 along with the pivot
/// chain. The correctness of header information of a block is decided based
/// on the ratio of the number of blamers in the subtree of the block. If the
/// ratio is small enough, the information is correct. Assume the first such
/// block is block Bj.
///
/// 4. The verifier then searches backward along the pivot chain from Bj for
/// the block whose blaming count is larger than or equal to the distance
/// between block Bi+2 and it. Let's call this block as Bk.
///
/// 5. The verifier asks the prover which is a full or archive node to get the
/// deferred state root of block Bk and its DSR vector, i.e., [..., DSRi+2,
/// ...].
///
/// 6. The verifier verifies the keccak hash of [..., DSRi+2, ...] equals
/// to deferred state root of Bk, and then verifies that DSRi+2 equals to the
/// path root of Bi.

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
    genesis_block_state_root: H256,
    genesis_block_receipts_root: H256,
    genesis_block_logs_bloom_hash: H256,
    // weight_tree maintains the subtree weight of each node in the TreeGraph
    weight_tree: DefaultMinLinkCutTree,
    inclusive_weight_tree: SizeMinLinkCutTree,
    stable_weight_tree: DefaultMinLinkCutTree,
    // stable_tree maintains d * SubTW(B, x) + n * x.parent.weight + n *
    // PastW(x.parent)
    stable_tree: DefaultMinLinkCutTree,
    // adaptive_tree maintains d * SubStableTW(B, x) - n * SubTW(B, P(x))
    adaptive_tree: CaterpillarMinLinkCutTree,
    // inclusive_adaptive_tree maintains d * SubInclusiveTW(B, x) - n *
    // SubInclusiveTW(B, P(x))
    inclusive_adaptive_tree: CaterpillarMinLinkCutTree,
    pub pow_config: ProofOfWorkConfig,
    // It maintains the expected difficulty of the next local mined block.
    pub current_difficulty: U256,
    // data_man is the handle to access raw block data
    data_man: Arc<BlockDataManager>,
    // Optimistic execution is the feature to execute ahead of the deferred
    // execution boundary. The goal is to pipeline the transaction
    // execution and the block packaging and verification.
    // optimistic_executed_height is the number of step to go ahead
    optimistic_executed_height: Option<u64>,
    pub inner_conf: ConsensusInnerConfig,
    // The cache to store Anticone information of each node. This could be very
    // large so we periodically remove old ones in the cache.
    anticone_cache: AnticoneCache,
    pastset_cache: PastSetCache,
    // The cache to store execution information of nodes in the consensus graph
    pub execution_info_cache: HashMap<usize, ConsensusGraphExecutionInfo>,
    sequence_number_of_block_entrance: u64,
    last_recycled_era_block: usize,
    // Block set of each old era. It will garbage collected by sync graph
    pub old_era_block_sets: VecDeque<Vec<H256>>,
}

pub struct ConsensusGraphNode {
    pub hash: H256,
    pub height: u64,
    is_heavy: bool,
    difficulty: U256,
    /// The total weight of its past set (exclude itself)
    past_weight: i128,
    past_num_blocks: u64,
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
    ) -> Self
    {
        let genesis_block = data_man
            .block_by_hash(cur_era_genesis_block_hash, true)
            .unwrap();
        let cur_era_genesis_height = genesis_block.block_header.height();
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
            weight_tree: DefaultMinLinkCutTree::new(),
            inclusive_weight_tree: SizeMinLinkCutTree::new(),
            stable_weight_tree: DefaultMinLinkCutTree::new(),
            stable_tree: DefaultMinLinkCutTree::new(),
            adaptive_tree: CaterpillarMinLinkCutTree::new(),
            inclusive_adaptive_tree: CaterpillarMinLinkCutTree::new(),
            pow_config,
            current_difficulty: pow_config.initial_difficulty.into(),
            data_man: data_man.clone(),
            inner_conf,
            anticone_cache: AnticoneCache::new(),
            pastset_cache: Default::default(),
            execution_info_cache: HashMap::new(),
            sequence_number_of_block_entrance: 0,
            // TODO handle checkpoint in recovery
            last_recycled_era_block: 0,
            old_era_block_sets: VecDeque::new(),
        };
        // The last vector is the current maintained set
        inner.old_era_block_sets.push_back(Vec::new());

        // NOTE: Only genesis block will be first inserted into consensus graph
        // and then into synchronization graph. All the other blocks will be
        // inserted first into synchronization graph then consensus graph.
        // For genesis block, its past weight is simply zero (default value).
        let (genesis_arena_index, _) =
            inner.insert(&genesis_block.block_header);
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
        inner.arena[inner.cur_era_genesis_block_arena_index]
            .last_pivot_in_past = genesis_block.block_header.height();
        inner
            .pivot_chain
            .push(inner.cur_era_genesis_block_arena_index);
        let mut last_pivot_in_past_blocks = HashSet::new();
        last_pivot_in_past_blocks
            .insert(inner.cur_era_genesis_block_arena_index);
        inner.pivot_chain_metadata.push(ConsensusGraphPivotData {
            last_pivot_in_past_blocks,
        });

        inner.data_man.insert_epoch_execution_context(
            data_man.genesis_block().hash(),
            EpochExecutionContext {
                start_block_number: 0,
            },
        );

        inner
            .anticone_cache
            .update(inner.cur_era_genesis_block_arena_index, &BitSet::new());
        if let Some(exe_info) = inner
            .data_man
            .consensus_graph_execution_info_from_db(cur_era_genesis_block_hash)
        {
            inner
                .execution_info_cache
                .insert(genesis_arena_index, exe_info);
        } else {
            error!("No execution info for cur_era_genesis in db!");
        }
        inner
    }

    pub fn persist_epoch_set_hashes(&self, pivot_index: usize) {
        let height = self.pivot_index_to_height(pivot_index);
        let arena_index = self.pivot_chain[pivot_index];
        let epoch_set_hashes = self.arena[arena_index]
            .data
            .ordered_executable_epoch_blocks
            .iter()
            .map(|arena_index| self.arena[*arena_index].hash)
            .collect();
        self.data_man
            .insert_epoch_set_hashes_to_db(height, &epoch_set_hashes);
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
    pub fn set_initial_sequence_number(&mut self, initial_sn: u64) {
        self.arena[self.cur_era_genesis_block_arena_index]
            .data
            .sequence_number = initial_sn;
        self.sequence_number_of_block_entrance = initial_sn + 1;
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
        debug!(
            "height={} era_height={} era_genesis_height={}",
            height, era_genesis_height, self.cur_era_genesis_height
        );
        self.ancestor_at(parent, era_genesis_height)
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

    #[inline]
    fn get_epoch_start_block_number(&self, epoch_arena_index: usize) -> u64 {
        let parent = self.arena[epoch_arena_index].parent;

        return self.arena[parent].past_num_blocks + 1;
    }

    fn get_blame(&self, arena_index: usize) -> u32 {
        let block_header = self
            .data_man
            .block_header_by_hash(&self.arena[arena_index].hash)
            .unwrap();
        block_header.blame()
    }

    fn get_blame_with_pivot_index(&self, pivot_index: usize) -> u32 {
        let arena_index = self.pivot_chain[pivot_index];
        self.get_blame(arena_index)
    }

    pub fn find_first_index_with_correct_state_of(
        &self, pivot_index: usize,
    ) -> Option<usize> {
        // this is the earliest block we need to consider; blocks before `from`
        // cannot have any information about the state root of `pivot_index`
        let from = pivot_index + DEFERRED_STATE_EPOCH_COUNT as usize;

        // get pivot index of first trusted block based on the blame fields
        let mut trusted_index =
            match self.find_first_with_trusted_blame_starting_from(from) {
                None => return None,
                Some(index) => index,
            };

        // iteratively search for the smallest trusted index greater than
        // or equal to `from`
        while trusted_index != from {
            let blame = self.get_blame_with_pivot_index(trusted_index);
            let prev_trusted = trusted_index - blame as usize - 1;

            if prev_trusted < from {
                break;
            }

            trusted_index = prev_trusted;
        }

        Some(trusted_index)
    }

    fn find_first_with_trusted_blame_starting_from(
        &self, pivot_index: usize,
    ) -> Option<usize> {
        let mut cur_pivot_index = pivot_index;
        while cur_pivot_index < self.pivot_chain.len() {
            let arena_index = self.pivot_chain[cur_pivot_index];
            let blame_ratio = self.compute_blame_ratio(arena_index);
            if blame_ratio < MAX_BLAME_RATIO_FOR_TRUST {
                return Some(cur_pivot_index);
            }
            cur_pivot_index += 1;
        }

        None
    }

    // Compute the ratio of blames that the block gets
    fn compute_blame_ratio(&self, arena_index: usize) -> f64 {
        let mut total_blame_count = 0 as u64;
        let mut queue = VecDeque::new();
        let mut votes = HashMap::new();
        queue.push_back((arena_index, 0 as u32));
        while let Some((index, step)) = queue.pop_front() {
            if index == arena_index {
                votes.insert(index, true);
            } else {
                let mut my_blame = self.get_blame(index);
                let mut parent = index;
                loop {
                    parent = self.arena[parent].parent;
                    if my_blame == 0 {
                        let parent_vote = *votes.get(&parent).unwrap();
                        votes.insert(index, parent_vote);
                        if !parent_vote {
                            total_blame_count += 1;
                        }
                        break;
                    } else if parent == arena_index {
                        votes.insert(index, false);
                        total_blame_count += 1;
                        break;
                    }
                    my_blame -= 1;
                }
            }

            let next_step = step + 1;
            for child in &self.arena[index].children {
                queue.push_back((*child, next_step));
            }
        }

        let total_vote_count = votes.len();

        total_blame_count as f64 / total_vote_count as f64
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
        let era_genesis_height = self.get_era_genesis_height(height, 0);
        let two_era_genesis_height = self
            .get_era_genesis_height(height, self.inner_conf.era_epoch_count);
        let era_genesis = self.ancestor_at(parent, era_genesis_height);

        let total_weight = subtree_weight[era_genesis];
        let adjusted_beta =
            (self.inner_conf.adaptive_weight_beta as i128) * difficulty;

        while self.arena[parent].height != era_genesis_height {
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
            while self.arena[parent].height != era_genesis_height {
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
            while self.arena[parent].height != two_era_genesis_height {
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
            self.adaptive_tree.caterpillar_apply(
                parent,
                delta * (self.inner_conf.adaptive_weight_alpha_num as i128),
            );
        }
        for (index, delta) in &inclusive_weight_delta {
            let parent = self.arena[*index].parent;
            self.inclusive_weight_tree.path_apply(*index, -delta);
            self.inclusive_adaptive_tree.caterpillar_apply(
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

        let era_genesis_height =
            self.get_era_genesis_height(self.arena[parent].height, 0);
        let two_era_genesis_height = self.get_era_genesis_height(
            self.arena[parent].height,
            self.inner_conf.era_epoch_count,
        );
        let era_genesis = self.ancestor_at(parent, era_genesis_height);
        let two_era_genesis = self.ancestor_at(parent, two_era_genesis_height);

        let total_weight = self.weight_tree.get(era_genesis);
        debug!("total_weight before insert: {}", total_weight);

        let adjusted_beta =
            (self.inner_conf.adaptive_weight_beta as i128) * difficulty;

        let mut high = self.arena[parent].height;
        let mut low = era_genesis_height + 1;
        // [low, high]
        let mut best = era_genesis_height;

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

        let stable = if best != era_genesis_height {
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
            let mut low = era_genesis_height + 1;
            let mut best = era_genesis_height;

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

            if best != era_genesis_height {
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
            let mut high = era_genesis_height;
            let mut low = two_era_genesis_height + 1;
            let mut best = two_era_genesis_height;

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

            if best != two_era_genesis_height {
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
            self.adaptive_tree.caterpillar_apply(
                parent,
                -delta * (self.inner_conf.adaptive_weight_alpha_num as i128),
            );
        }
        for (index, delta) in &inclusive_weight_delta {
            let parent = self.arena[*index].parent;
            self.inclusive_weight_tree.path_apply(*index, *delta);
            self.inclusive_adaptive_tree.caterpillar_apply(
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

    fn collect_blockset_in_own_view_of_epoch_brutal(
        &mut self, lca: usize, pivot: usize,
    ) {
        let pastset = self.pastset_cache.get(lca, false).unwrap();
        let mut path_to_lca = Vec::new();
        let mut cur = pivot;
        while cur != lca {
            path_to_lca.push(cur);
            cur = self.arena[cur].parent;
        }
        path_to_lca.reverse();
        let mut visited = HashSet::new();
        for ancestor_arena_index in path_to_lca {
            visited.insert(ancestor_arena_index);
            if ancestor_arena_index == pivot
                || self.arena[ancestor_arena_index].data.blockset_cleared
            {
                let mut queue = VecDeque::new();
                for referee in &self.arena[ancestor_arena_index].referees {
                    if !pastset.contains(*referee as u32)
                        && !visited.contains(referee)
                    {
                        visited.insert(*referee);
                        queue.push_back(*referee);
                    }
                }
                while let Some(index) = queue.pop_front() {
                    if ancestor_arena_index == pivot {
                        self.arena[pivot]
                            .data
                            .blockset_in_own_view_of_epoch
                            .push(index);
                    }
                    let parent = self.arena[index].parent;
                    if parent != NULL
                        && !pastset.contains(parent as u32)
                        && !visited.contains(&parent)
                    {
                        visited.insert(parent);
                        queue.push_back(parent);
                    }
                    for referee in &self.arena[index].referees {
                        if !pastset.contains(*referee as u32)
                            && !visited.contains(referee)
                        {
                            visited.insert(*referee);
                            queue.push_back(*referee);
                        }
                    }
                }
            } else {
                for index in &self.arena[ancestor_arena_index]
                    .data
                    .blockset_in_own_view_of_epoch
                {
                    visited.insert(*index);
                }
            }
        }
    }

    fn compute_pastset_brutal(&mut self, me: usize) -> BitSet {
        let mut path = Vec::new();
        let mut cur = me;
        while cur != NULL && self.pastset_cache.get(cur, false).is_none() {
            path.push(cur);
            cur = self.arena[cur].parent;
        }
        path.reverse();
        let mut result = self
            .pastset_cache
            .get(cur, false)
            .unwrap_or(&BitSet::new())
            .clone();
        for ancestor_arena_index in path {
            result.add(ancestor_arena_index as u32);
            if self.arena[ancestor_arena_index].data.blockset_cleared {
                let mut queue = VecDeque::new();
                queue.push_back(ancestor_arena_index);
                while let Some(index) = queue.pop_front() {
                    let parent = self.arena[index].parent;
                    if parent != NULL && !result.contains(parent as u32) {
                        result.add(parent as u32);
                        queue.push_back(parent);
                    }
                    for referee in &self.arena[index].referees {
                        if !result.contains(*referee as u32) {
                            result.add(*referee as u32);
                            queue.push_back(*referee);
                        }
                    }
                }
            } else {
                for index in &self.arena[ancestor_arena_index]
                    .data
                    .blockset_in_own_view_of_epoch
                {
                    result.add(*index as u32);
                }
            }
        }
        result
    }

    fn collect_blockset_in_own_view_of_epoch(&mut self, pivot: usize) {
        // TODO: consider the speed for recovery from db
        let parent = self.arena[pivot].parent;
        // This indicates `pivot` is partial_invalid and for partial invalid
        // block we don't need to calculate and store the blockset
        if parent != NULL && self.arena[parent].data.partial_invalid {
            return;
        }
        if parent != NULL {
            let last = *self.pivot_chain.last().unwrap();
            let lca = self.lca(last, parent);
            assert!(lca != NULL);
            if self.pastset_cache.get(lca, true).is_none() {
                let pastset = self.compute_pastset_brutal(lca);
                self.pastset_cache.update(lca, pastset);
            }
            self.collect_blockset_in_own_view_of_epoch_brutal(lca, pivot);
        }

        let filtered_blockset = self.arena[pivot]
            .data
            .blockset_in_own_view_of_epoch
            .iter()
            .filter(|idx| self.is_same_era(**idx, pivot))
            .map(|idx| *idx)
            .collect();
        // FIXME Double check if it's okay to use cur_era_genesis instead of
        // two_era_block        let two_era_block =
        // self.get_era_genesis_block_with_parent(
        // self.arena[pivot].parent,
        // self.inner_conf.era_epoch_count,        );

        // Here `num_epoch_blocks_in_2era` might be incorrect for pending blocks
        // (either really pending because it's past stable block or just
        // pending because it's being inserted during recovery.
        let two_era_block = self.cur_era_genesis_block_arena_index;
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
        self.arena[pivot].data.blockset_cleared = false;
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

    fn insert(&mut self, block_header: &BlockHeader) -> (usize, usize) {
        let hash = block_header.hash();

        let is_heavy = U512::from(block_header.pow_quality)
            >= U512::from(self.inner_conf.heavy_block_difficulty_ratio)
                * U512::from(block_header.difficulty());

        let parent = if hash != self.data_man.genesis_block().hash() {
            self.hash_to_arena_indices
                .get(block_header.parent_hash())
                .cloned()
                .unwrap()
        } else {
            NULL
        };

        let mut referees: Vec<usize> = Vec::new();
        for hash in block_header.referee_hashes().iter() {
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
        let my_height = block_header.height();
        let sn = self.get_next_sequence_number();
        let index = self.arena.insert(ConsensusGraphNode {
            hash,
            height: my_height,
            is_heavy,
            difficulty: *block_header.difficulty(),
            past_weight: 0, // will be updated later below
            past_num_blocks: 0,
            past_era_weight: 0, // will be updated later below
            stable: true,
            // Block header contains an adaptive field, we will verify with our
            // own computation
            adaptive: block_header.adaptive(),
            parent,
            last_pivot_in_past: 0,
            era_block: self.get_era_genesis_block_with_parent(parent, 0),
            children: Vec::new(),
            referees,
            referrers: Vec::new(),
            data: ConsensusGraphNodeData::new(NULLU64, sn),
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
            let era_genesis = self.get_era_genesis_block_with_parent(parent, 0);
            let graph_era_stable_genesis =
                self.ancestor_at(parent, self.cur_era_stable_height);

            let weight_in_my_epoch = self.total_weight_in_own_epoch(
                &self.arena[index].data.blockset_in_own_view_of_epoch,
                false,
                graph_era_stable_genesis,
            );
            let weight_era_in_my_epoch = self.total_weight_in_own_epoch(
                &self.arena[index].data.blockset_in_own_view_of_epoch,
                false,
                era_genesis,
            );
            let past_weight = self.arena[parent].past_weight
                + self.block_weight(parent, false)
                + weight_in_my_epoch;
            let past_num_blocks = self.arena[parent].past_num_blocks
                + self.arena[index].data.ordered_executable_epoch_blocks.len()
                    as u64;
            let past_era_weight = if parent != era_genesis {
                self.arena[parent].past_era_weight
                    + self.block_weight(parent, false)
                    + weight_era_in_my_epoch
            } else {
                self.block_weight(parent, false) + weight_era_in_my_epoch
            };

            self.data_man.insert_epoch_execution_context(
                hash.clone(),
                EpochExecutionContext {
                    start_block_number: self
                        .get_epoch_start_block_number(index),
                },
            );

            self.arena[index].past_weight = past_weight;
            self.arena[index].past_num_blocks = past_num_blocks;
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

    /// Return the latest epoch number with executed state.
    ///
    /// The state is ensured to exist.
    pub fn executed_best_state_epoch_number(&self) -> u64 {
        let pivot_len = self.pivot_chain.len() as u64;
        let mut best_state_pivot_index =
            if pivot_len < DEFERRED_STATE_EPOCH_COUNT {
                0
            } else {
                pivot_len - DEFERRED_STATE_EPOCH_COUNT
            };
        while best_state_pivot_index > 0 {
            if self.data_man.epoch_executed(
                &self.arena[self.pivot_chain[best_state_pivot_index as usize]]
                    .hash,
            ) {
                break;
            } else {
                best_state_pivot_index -= 1;
            }
        }
        self.pivot_index_to_height(best_state_pivot_index as usize)
    }

    /// Return the latest epoch number whose state has been enqueued.
    ///
    /// The state may not exist, so the caller should wait for the result if its
    /// state will be used.
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

    pub fn get_state_block_with_delay(
        &self, block_hash: &H256, delay: usize,
    ) -> Result<&H256, String> {
        let idx_opt = self.hash_to_arena_indices.get(block_hash);
        if idx_opt == None {
            return Err(
                "Parent hash is too old for computing the deferred state"
                    .to_owned(),
            );
        }
        let mut idx = *idx_opt.unwrap();
        for _i in 0..delay {
            trace!("get_state_block_with_delay: idx={}", idx);
            if idx == self.cur_era_genesis_block_arena_index {
                // If it is the original genesis, we just break
                if self.arena[self.cur_era_genesis_block_arena_index].height
                    == 0
                {
                    break;
                } else {
                    return Err(
                        "Parent is too old for computing the deferred state"
                            .to_owned(),
                    );
                }
            }
            idx = self.arena[idx].parent;
        }
        Ok(&self.arena[idx].hash)
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
            self.data_man.epoch_set_hashes_from_db(epoch_number).ok_or(
                format!("get_hash_from_epoch_number: Epoch hash set not in db, epoch_number={}", epoch_number).into()
            ).and_then(|epoch_hashes|
                epoch_hashes.last().map(Clone::clone).ok_or("Epoch set is empty".into())
            )
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
        match self.get_arena_index_from_epoch_number(epoch_number) {
            Ok(pivot_arena_index) => Ok(self.arena[pivot_arena_index]
                .data
                .ordered_executable_epoch_blocks
                .iter()
                .map(|index| self.arena[*index].hash)
                .collect()),
            Err(e) => {
                self.data_man.epoch_set_hashes_from_db(epoch_number).ok_or(
                    format!(
                    "Epoch hash set not in db epoch_number={}, in mem err={:?}",
                    epoch_number, e
                )
                    .into(),
                )
            }
        }
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

    /// Return the block receipts in the current pivot view.
    ///
    /// If `hash` is not maintained in the memory, we just return the receipts
    /// in the db without checking the pivot assumption.
    /// TODO Check if its receipts matches our current pivot view for this
    /// not-in-memory case.
    pub fn block_receipts_by_hash(
        &self, hash: &H256, update_cache: bool,
    ) -> Option<Arc<Vec<Receipt>>> {
        match self.get_epoch_hash_for_block(hash) {
            Some(epoch) => {
                trace!("Block {} is in epoch {}", hash, epoch);
                self.data_man
                    .block_results_by_hash_with_epoch(
                        hash,
                        &epoch,
                        update_cache,
                    )
                    .map(|r| r.receipts)
            }
            None => {
                debug!("Block {:?} not in mem, try to read from db", hash);
                self.data_man
                    .block_results_by_hash_from_db(hash)
                    .map(|r| r.1.receipts)
            }
        }
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

    fn compute_blame_and_state_with_execution_result(
        &self, parent: usize, exec_result: (StateRootWithAuxInfo, H256, H256),
    ) -> Result<(u32, StateRootWithAuxInfo, H256, H256, H256), String> {
        let mut cur = parent;
        let mut blame: u32 = 0;
        let mut state_blame_vec = Vec::new();
        let mut receipt_blame_vec = Vec::new();
        let mut bloom_blame_vec = Vec::new();
        state_blame_vec
            .push(exec_result.0.state_root.compute_state_root_hash());
        receipt_blame_vec.push(exec_result.1.clone());
        bloom_blame_vec.push(exec_result.2.clone());
        loop {
            let exec_info_opt = self.execution_info_cache.get(&cur);
            if exec_info_opt.is_none() {
                return Err("Failed to compute blame and state due to stale consensus graph state".to_owned());
            }
            let exec_info = exec_info_opt.unwrap();
            if exec_info.state_valid {
                break;
            }
            blame += 1;
            if cur == self.cur_era_genesis_block_arena_index {
                return Err(
                    "Failed to compute blame and state due to out of era"
                        .to_owned(),
                );
            }
            state_blame_vec
                .push(exec_info.original_deferred_state_root.clone());
            receipt_blame_vec
                .push(exec_info.original_deferred_receipt_root.clone());
            bloom_blame_vec
                .push(exec_info.original_deferred_logs_bloom_hash.clone());
            cur = self.arena[cur].parent;
        }
        if blame > 0 {
            Ok((
                blame,
                exec_result.0,
                BlockHeaderBuilder::compute_blame_state_root_vec_root(
                    state_blame_vec,
                ),
                BlockHeaderBuilder::compute_blame_state_root_vec_root(
                    receipt_blame_vec,
                ),
                BlockHeaderBuilder::compute_blame_state_root_vec_root(
                    bloom_blame_vec,
                ),
            ))
        } else {
            Ok((
                0,
                exec_result.0,
                state_blame_vec.pop().unwrap(),
                receipt_blame_vec.pop().unwrap(),
                bloom_blame_vec.pop().unwrap(),
            ))
        }
    }

    fn compute_execution_info_with_result(
        &mut self, me: usize, exec_result: (StateRootWithAuxInfo, H256, H256),
    ) -> Result<(), String> {
        // For the original genesis, it is always correct
        if self.arena[me].height == 0 {
            let exec_info = ConsensusGraphExecutionInfo {
                state_valid: true,
                original_deferred_state_root: self.genesis_block_state_root,
                original_deferred_receipt_root: self
                    .genesis_block_receipts_root,
                original_deferred_logs_bloom_hash: self
                    .genesis_block_logs_bloom_hash,
            };
            self.data_man.insert_consensus_graph_execution_info_to_db(
                &self.arena[me].hash,
                &exec_info,
            );
            self.execution_info_cache.insert(me, exec_info);
            return Ok(());
        }
        let parent = self.arena[me].parent;
        let original_deferred_state_root =
            exec_result.0.state_root.compute_state_root_hash();
        let original_deferred_receipt_root = exec_result.1.clone();
        let original_deferred_logs_bloom_hash = exec_result.2.clone();
        let (
            blame,
            _,
            deferred_state_root,
            deferred_receipt_root,
            deferred_logs_bloom_hash,
        ) = self.compute_blame_and_state_with_execution_result(
            parent,
            exec_result,
        )?;
        let block_header = self
            .data_man
            .block_header_by_hash(&self.arena[me].hash)
            .unwrap();
        let state_valid = block_header.blame() == blame
            && *block_header.deferred_state_root() == deferred_state_root
            && *block_header.deferred_receipts_root() == deferred_receipt_root
            && *block_header.deferred_logs_bloom_hash()
                == deferred_logs_bloom_hash;

        if state_valid {
            debug!("compute_execution_info_with_result(): Block {} state/blame is valid.", self.arena[me].hash);
        } else {
            debug!("compute_execution_info_with_result(): Block {} state/blame is invalid! header blame {}, our blame {}, header state_root {}, our state root {}, header receipt_root {}, our receipt root {}, header logs_bloom_hash {}, our logs_bloom_hash {}.", self.arena[me].hash, block_header.blame(), blame, block_header.deferred_state_root(), deferred_state_root, block_header.deferred_receipts_root(), deferred_receipt_root, block_header.deferred_logs_bloom_hash(), deferred_logs_bloom_hash);
        }

        let exec_info = ConsensusGraphExecutionInfo {
            state_valid,
            original_deferred_state_root,
            original_deferred_receipt_root,
            original_deferred_logs_bloom_hash,
        };
        self.data_man.insert_consensus_graph_execution_info_to_db(
            &self.arena[me].hash,
            &exec_info,
        );
        self.execution_info_cache.insert(me, exec_info);

        Ok(())
    }

    fn compute_vote_valid_for_pivot_block(
        &mut self, data_man: &BlockDataManager, me: usize,
        pivot_arena_index: usize,
    ) -> bool
    {
        let lca = self.lca(me, pivot_arena_index);
        let lca_height = self.arena[lca].height;
        debug!(
            "compute_vote_valid_for_pivot_block: lca={}, lca_height={}",
            lca, lca_height
        );
        let mut stack = Vec::new();
        stack.push((0, me, 0));
        while !stack.is_empty() {
            let (stage, index, a) = stack.pop().unwrap();
            if stage == 0 {
                if self.arena[index].data.exec_info_lca_height != lca_height {
                    let header = data_man
                        .block_header_by_hash(&self.arena[index].hash)
                        .unwrap();
                    let blame = header.blame();
                    if self.arena[index].height > lca_height + 1 + blame as u64
                    {
                        let ancestor = self.ancestor_at(
                            index,
                            self.arena[index].height - blame as u64 - 1,
                        );
                        stack.push((1, index, ancestor));
                        stack.push((0, ancestor, 0));
                    } else {
                        // We need to make sure the ancestor at height
                        // self.arena[index].height - blame - 1 is state valid,
                        // and the remainings are not
                        let start_height =
                            self.arena[index].height - blame as u64 - 1;
                        let mut cur_height = lca_height;
                        let mut cur = lca;
                        let mut vote_valid = true;
                        while cur_height > start_height {
                            if self
                                .execution_info_cache
                                .get(&cur)
                                .unwrap()
                                .state_valid
                            {
                                vote_valid = false;
                                break;
                            }
                            cur_height -= 1;
                            cur = self.arena[cur].parent;
                        }
                        if vote_valid
                            && !self
                                .execution_info_cache
                                .get(&cur)
                                .unwrap()
                                .state_valid
                        {
                            vote_valid = false;
                        }
                        self.arena[index].data.exec_info_lca_height =
                            lca_height;
                        self.arena[index].data.vote_valid = vote_valid;
                    }
                }
            } else {
                self.arena[index].data.exec_info_lca_height = lca_height;
                self.arena[index].data.vote_valid =
                    self.arena[a].data.vote_valid;
            }
        }
        self.arena[me].data.vote_valid
    }

    /// Compute the total weight in the epoch represented by the block of
    /// my_hash.
    fn total_weight_in_own_epoch(
        &self, blockset_in_own_epoch: &Vec<usize>, inclusive: bool,
        genesis: usize,
    ) -> i128
    {
        let gen_arena_index = if genesis != NULL {
            genesis
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

    /// Recompute metadata associated information on pivot chain changes
    pub fn recompute_metadata(
        &mut self, start_at: u64, mut to_update: HashSet<usize>,
    ) {
        self.pivot_chain_metadata
            .resize_with(self.pivot_chain.len(), Default::default);
        let pivot_height = self.get_pivot_height();
        for i in start_at..pivot_height {
            let me = self.get_pivot_block_arena_index(i);
            self.arena[me].last_pivot_in_past = i;
            let i_pivot_index = self.height_to_pivot_index(i);
            self.pivot_chain_metadata[i_pivot_index]
                .last_pivot_in_past_blocks
                .clear();
            self.pivot_chain_metadata[i_pivot_index]
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
            let parent = self.arena[me].parent;
            if stage == 0 {
                if to_update.contains(&me) {
                    to_update.remove(&me);
                    stack.push((1, me));
                    stack.push((0, parent));
                    for referee in &self.arena[me].referees {
                        stack.push((0, *referee));
                    }
                }
            } else if stage == 1 && me != self.cur_era_genesis_block_arena_index
            {
                let mut last_pivot = self.arena[parent].last_pivot_in_past;
                for referee in &self.arena[me].referees {
                    let x = self.arena[*referee].last_pivot_in_past;
                    last_pivot = max(last_pivot, x);
                }
                self.arena[me].last_pivot_in_past = last_pivot;
                let last_pivot_index = self.height_to_pivot_index(last_pivot);
                self.pivot_chain_metadata[last_pivot_index]
                    .last_pivot_in_past_blocks
                    .insert(me);
            }
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
        let mut new_pivot_chain = Vec::new();
        let mut to_update = HashSet::new();
        let mut pivot = stable_index;
        while pivot != NULL {
            new_pivot_chain.push(pivot);
            to_update.insert(pivot);
            pivot = self.arena[pivot].parent;
        }
        new_pivot_chain.reverse();
        self.pivot_chain.clear();
        for index in &new_pivot_chain {
            self.pivot_chain.push(*index);
            if self.arena[*index].data.blockset_cleared {
                self.collect_blockset_in_own_view_of_epoch(*index);
            }
        }
        debug!(
            "set_pivot_to_stable: stable={:?}, chain_len={}",
            stable,
            self.pivot_chain.len()
        );
        // TODO Double check if this is needed
        self.recompute_metadata(self.cur_era_genesis_height, to_update);
    }

    pub fn total_processed_block_count(&self) -> u64 {
        self.sequence_number_of_block_entrance
    }
}
