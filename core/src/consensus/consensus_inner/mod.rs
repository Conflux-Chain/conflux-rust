// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod confirmation_meter;
pub mod consensus_executor;
pub mod consensus_new_block_handler;

use crate::{
    block_data_manager::{
        BlockDataManager, BlockExecutionResultWithEpoch, EpochExecutionContext,
    },
    consensus::{anticone_cache::AnticoneCache, pastset_cache::PastSetCache},
    parameters::{consensus::*, consensus_internal::*},
    pow::{target_difficulty, ProofOfWorkConfig},
    state_exposer::{ConsensusGraphBlockExecutionState, STATE_EXPOSER},
};
use cfx_types::{H256, U256, U512};
use hashbrown::HashMap as FastHashMap;
use hibitset::{BitSet, BitSetLike, DrainableBitSet};
use link_cut_tree::{CaterpillarMinLinkCutTree, SizeMinLinkCutTree};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use parking_lot::Mutex;
use primitives::{
    receipt::Receipt, Block, BlockHeader, BlockHeaderBuilder, EpochId,
    SignedTransaction, TransactionIndex,
};
use slab::Slab;
use std::{
    cmp::max,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    convert::TryFrom,
    mem,
    sync::Arc,
};

#[derive(Copy, Clone)]
pub struct ConsensusInnerConfig {
    /// Beta is the threshold in GHAST algorithm
    pub adaptive_weight_beta: u64,
    /// The heavy block ratio (h) in GHAST algorithm
    pub heavy_block_difficulty_ratio: u64,
    /// The timer block ratio in timer chain algorithm
    pub timer_chain_block_difficulty_ratio: u64,
    /// The timer chain beta ratio
    pub timer_chain_beta: u64,
    /// The number of epochs per era. Each era is a potential checkpoint
    /// position. The parent_edge checking and adaptive checking are defined
    /// relative to the era start blocks.
    pub era_epoch_count: u64,
    /// Optimistic execution is the feature to execute ahead of the deferred
    /// execution boundary. The goal is to pipeline the transaction
    /// execution and the block packaging and verification.
    /// optimistic_executed_height is the number of step to go ahead
    pub enable_optimistic_execution: bool,
    /// Control whether we enable the state exposer for the testing purpose.
    pub enable_state_expose: bool,
}

#[derive(Copy, Clone, DeriveMallocSizeOf)]
pub struct StateBlameInfo {
    pub blame: u32,
    pub state_vec_root: H256,
    pub receipts_vec_root: H256,
    pub logs_boom_vec_root: H256,
}

/// ConsensusGraphNodeData contains all extra information of a block that will
/// change as the consensus graph state evolves (e.g., pivot chain changes).
/// Unlike the ConsensusGraphNode fields, fields in ConsensusGraphNodeData will
/// only be available after the block is *preactivated* (after calling
/// preactivate_block().
#[derive(DeriveMallocSizeOf)]
pub struct ConsensusGraphNodeData {
    /// It indicates the epoch number of the block, i.e., the height of the
    /// corresponding pivot chain block of this one
    pub epoch_number: u64,
    /// It indicates whether the block is partial invalid or not. A block
    /// is partial invalid if it selects an incorrect parent or filling an
    /// incorrect adaptive field.
    partial_invalid: bool,
    /// It indicates whether the block is pending or not. A block is pending if
    /// the consensus engine determines that it is not necessary to determine
    /// its partial invalid status.
    pending: bool,
    /// This is a special counter marking whether the block is active or not.
    /// A block is active only if the counter is zero
    /// A partial invalid block will get a NULL counter
    /// A normal block which referenced directly or indirectly will have a
    /// positive counter
    active_cnt: usize,
    /// This is an implementation flag indicate whether the node is active or
    /// not. Because multiple blocks may have their `active_cnt` turning
    /// zero in the same time, we need this flag to process them correctly
    /// one by one.
    activated: bool,
    /// This records the force confirm point in the past view of this block.
    force_confirm: usize,
    /// The indices set of the blocks in the epoch when the current
    /// block is as pivot chain block. This set does not contain
    /// the block itself.
    blockset_in_own_view_of_epoch: Vec<usize>,
    /// Ordered executable blocks in this epoch. This filters out blocks that
    /// are not in the same era of the epoch pivot block.
    ///
    /// For cur_era_genesis, this field should NOT be used because they contain
    /// out-of-era blocks not maintained in the memory.
    ordered_executable_epoch_blocks: Vec<usize>,
    /// If an epoch has more than ``EPOCH_EXECUTED_BLOCK_BOUND''. We will only
    /// execute the last ``EPOCH_EXECUTED_BLOCK_BOUND'' and skip the
    /// remaining. The `skipped_epoch_blocks` also contain those blocks that
    /// are not in the same era of the pivot block.
    skipped_epoch_blocks: Vec<usize>,
    /// It indicates whether `blockset_in_own_view_of_epoch` and
    /// `skipped_epoch_blocks` are cleared due to its size.
    blockset_cleared: bool,
    /// The sequence number is used to identify the order of each block
    /// entering the consensus. The sequence number of the genesis is used
    /// by the syncronization layer to determine whether a block exists in
    /// the consensus or not.
    sequence_number: u64,
    /// The longest chain of all timer blocks.
    past_view_timer_longest_difficulty: i128,
    /// The last timer block index in the chain.
    past_view_last_timer_block_arena_index: usize,
    /// The height of the closest timer block in the longest timer chain.
    /// Note that this only considers the current longest timer chain and
    /// ingores the remaining timer blocks.
    ledger_view_timer_chain_height: u64,
    /// vote_valid_lca_height indicates the fork_at height that the vote_valid
    /// field corresponds to.
    vote_valid_lca_height: u64,
    /// It indicates whether the blame voting information of this block is
    /// correct or not.
    vote_valid: bool,
    /// It denotes the height of the last pivot chain in the past set of this
    /// block.
    last_pivot_in_past: u64,
    /// It indicates whether the states stored in header is correct or not.
    /// It's evaluated when needed, i.e., when we need the blame information to
    /// generate a new block or to compute rewards.
    pub state_valid: Option<bool>,
    /// It stores the correct blame info for the block if its state is invalid.
    /// It's evaluated when needed and acts as a cache.
    blame_info: Option<StateBlameInfo>,
}

impl ConsensusGraphNodeData {
    fn new(epoch_number: u64, sequence_number: u64, active_cnt: usize) -> Self {
        ConsensusGraphNodeData {
            epoch_number,
            partial_invalid: false,
            pending: false,
            active_cnt,
            activated: false,
            force_confirm: NULL,
            blockset_in_own_view_of_epoch: Default::default(),
            ordered_executable_epoch_blocks: Default::default(),
            skipped_epoch_blocks: Default::default(),
            blockset_cleared: true,
            sequence_number,
            past_view_timer_longest_difficulty: 0,
            past_view_last_timer_block_arena_index: NULL,
            ledger_view_timer_chain_height: 0,
            vote_valid_lca_height: NULLU64,
            vote_valid: true,
            last_pivot_in_past: 0,
            state_valid: None,
            blame_info: None,
        }
    }
}

#[derive(DeriveMallocSizeOf)]
struct ConsensusGraphPivotData {
    /// The set of blocks whose last_pivot_in_past point to this pivot chain
    /// location
    last_pivot_in_past_blocks: HashSet<usize>,
    /// The total weight of the past set of the pivot block. This value
    /// is used by the confirmation meter.
    past_weight: i128,
}

impl Default for ConsensusGraphPivotData {
    fn default() -> Self {
        ConsensusGraphPivotData {
            last_pivot_in_past_blocks: HashSet::new(),
            past_weight: 0,
        }
    }
}

/// # Implementation details of Eras, Timer chain and Checkpoints
///
/// Era in Conflux is defined based on the height of a block. Every
/// epoch_block_count height corresponds to one era. For example, if
/// era_block_count is 50000, then blocks at height 0 (the original genesis)
/// is the era genesis of the first era. The blocks at height 50000 are era
/// genesis blocks of the following era. Note that it is possible to have
/// multiple era genesis blocks for one era period. Eventually, only
/// one era genesis block and its subtree will become dominant and all other
/// genesis blocks together with their subtrees will be discarded. The
/// definition of Era enables Conflux to form checkpoints at the stabilized
/// era genesis blocks.
///
/// # Implementation details of the Timer chain
///
/// Timer chain contains special blocks whose PoW qualities are significantly
/// higher than normal blocks. The goal of timer chain is to enable a slowly
/// growing longest chain to indicate the time elapsed between two blocks.
/// Timer chain also provides a force confirmation rule which will enable us
/// to safely form the checkpoint.
///
/// Any block whose PoW quality is timer_chain_block_difficulty_ratio times
/// higher than its supposed difficulty is *timer block*. The longest chain of
/// timer blocks (counting both parent edges and reference edges) is the timer
/// chain. When timer_chain_beta is large enough, malicious attackers can
/// neither control the timer chain nor stop its growth. We use Timer(G) to
/// denote the number of timer chain blocks in G. We use TimerDis(b_1, b_2) to
/// denote Timer(Past(B_1)) - Timer(Past(B_2)). In case that b_2 \in
/// Future(b_1), TimerDis(b_1, b_2) is a good indicator about how long it has
/// past between the generation of the two blocks.
///
/// A block b in G is considered force-confirm if 1) there are *consecutively*
/// timer_chain_beta timer chain blocks under the subtree of b and 2) there are
/// at least timer_chain_beta blocks after these blocks (not necessarily in the
/// subtree of b). Force-confirm rule overrides any GHAST weight rule, i.e.,
/// new blocks will always be generated under b.
///
///
/// # Implementation details of the GHAST algorithm
///
/// Conflux uses the Greedy Heaviest Adaptive SubTree (GHAST) algorithm to
/// select a chain from the genesis block to one of the leaf blocks as the pivot
/// chain. For each block b, GHAST algorithm computes it is adaptive
///
/// ```python
/// B = Past(b)
/// f is the force confirm point of b in the view of Past(b)
/// a = b.parent
/// adaptive = False
/// Let f(x) = 2 * SubTW(B, x) - SubTW(B, x.parent) + x.parent.weight
/// Let g(x) = adaptive_weight_beta * b.diff
/// while a != force_confirm do
///     if TimerDis(a, b) >= timer_chain_beta and f(a) < g(a) then
///         adaptive = True
///     a = a.parent
/// ```
///
/// To efficiently compute adaptive, we maintain a link-cut tree called
/// adaptive_weight_tree. The value for x in the link-cut-tree is
/// 2 * SubTW(B, x) + x.parent.weight - SubTW(B, x.parent). Note that we need to
/// do special caterpillar update in the Link-Cut-Tree, i.e., given a node X, we
/// need to update the values of all of those nodes A such that A is the child
/// of one of the node in the path from Genesis to X.
///
/// For an adaptive block, its weights will be calculated in a special way. If
/// its PoW quality is adaptive_heavy_weight_ratio times higher than the normal
/// difficulty, its weight will be adaptive_heavy_weight_ratio instead of one.
/// Otherwise, the weight will be zero. The goal of adaptive weight is to deal
/// with potential liveness attacks that balance two subtrees. Note that when
/// computing adaptive we only consider the nodes after force_confirm.
///
/// # Implementation details of partial invalid blocks
///
/// One block may become partial invalid because 1) it chooses incorrect parent
/// or 2) it generates an adaptive block when it should not. In normal
/// situations, we should verify every block we receive and determine whether it
/// is partial invalid or not. For a partial invalid block b, it will not
/// receive any reward. Normal nodes will also refrain from *directly or
/// indirectly* referencing b until TimerDis(*b*, new_block) is greater than or
/// equal to timer_dis_delta. Normal nodes essentially ignores partial invalid
/// blocks for a while. We implement this via our active_cnt field. Last but not
/// least, we exclude *partial invalid* blocks from the timer chain
/// consideration. They are not timer blocks!
///
/// # Implementation details of checkpoints
///
/// Our consensus engine will form a checkpoint pair (a, b) given a DAG state G
/// if:
///
/// 1) b is force confirmed in G
/// 2) a is force confirmed in Past(b)
///
/// Now we are safe to remove all blocks that are not in Future(a). For those
/// blocks that are in the Future(a) but not in Subtree(a), we can also redirect
/// a as their parents. We call *a* the cur_era_genesis_block and *b* the
/// cur_era_stable_block.
///
/// We no longer need to check the partial invalid block which does not
/// referencing b (directly and indirectly), because such block would never go
/// into the timer chain. Our assumption is that the timer chain will not reorg
/// on a length greater than timer_chain_beta. For those blocks which
/// referencing *b* but also not under the subtree of a, they are by default
/// partial invalid. We can ignore them as well. Therefore *a* can be treated as
/// a new genesis block. We are going to check the possibility of making
/// checkpoints only at the era boundary.
///
/// Note that we have the assumption that the force confirmation point will
/// always move along parental edges, i.e., it is not possible for the point
/// to move to a sibling tree. This assumption is true if the timer_chain_beta
/// and the timer_chain_difficulty_ratio are set to large enough values.
///
/// # Introduction of blaming mechanism
///
/// Blaming is used to provide proof for state root of a specific pivot block.
/// The rationale behind is as follows. Verifying state roots of blocks off
/// pivot chain is very costly and sometimes impractical, e.g., when the block
/// refers to another block that is not in the current era. It is preferred to
/// avoid this verification if possible. Normally, Conflux only needs to store
/// correct state root in header of pivot block to provide proof for light node.
/// However, the pivot chain may oscillate at the place close to ledger tail,
/// which means that a block that is off pivot at some point may become pivot
/// block in the future. If we do not verify the state root in the header of
/// that block, when it becomes a pivot block later, we cannot guarantee the
/// correctness of the state root in its header. Therefore, if we do not verify
/// the state root in off-pivot block, we cannot guarantee the correctness of
/// state root in pivot block. Of course, one may argue that you can switch
/// pivot chain when incorrect state root in pivot block is observed. However,
/// this makes the check for the correct parent selection rely on state root
/// checking. Then, since Conflux is an inclusive protocol which adopts
/// off-pivot blocks in its final ledger, it needs to verify the correctness of
/// parent selection of off-pivot blocks and this relies on the state
/// verification on all the parent candidates of the off-pivot blocks.
/// Therefore, this eventually will lead to state root verification on any
/// blocks including off-pivot ones. This violates the original goal of saving
/// cost of the state root verification in off-pivot blocks.
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
/// Computing the reward for a block relies on correct blaming behavior of
/// the block. If the block is a pivot block when computing its reward,
/// it is required that:
///
/// 1. the block correctly chooses its parent;
/// 2. the block contains the correct deferred state root;
/// 3. the block correctly blames all its previous blocks following parent
///    edges.
///
/// If the block is an off-pivot block when computing its reward,
/// it is required that:
/// 1. the block correctly chooses its parent;
/// 2. the block correctly blames the blocks in the intersection of pivot chain
///    blocks and all its previous blocks following parent edges. (This is to
///    encourage the node generating the off-pivot block to keep verifying
///    pivot chain blocks.)
///
/// To provide proof of state root to light node (or a full node when it tries
/// to recover from a checkpoint), the protocol goes through the following
/// steps. Let's assume the verifier has a subtree of block headers which
/// includes the block whose state root is to be verified.
///
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
///
/// In ConsensusGraphInner, every block corresponds to a ConsensusGraphNode and
/// each node has an internal index. This enables fast internal implementation
/// to use integer index instead of H256 block hashes.
pub struct ConsensusGraphInner {
    /// This slab hold consensus graph node data and the array index is the
    /// internal index.
    pub arena: Slab<ConsensusGraphNode>,
    /// indices maps block hash to internal index.
    pub hash_to_arena_indices: FastHashMap<H256, usize>,
    /// The current pivot chain indexes.
    pivot_chain: Vec<usize>,
    /// The metadata associated with each pivot chain block
    pivot_chain_metadata: Vec<ConsensusGraphPivotData>,
    /// The longest timer chain block indexes
    timer_chain: Vec<usize>,
    /// The accumulative LCA of timer_chain for consecutive
    timer_chain_accumulative_lca: Vec<usize>,
    /// The set of *graph* tips in the TreeGraph for mining.
    /// Note that this set does not include non-active partial invalid blocks
    terminal_hashes: HashSet<H256>,
    /// The ``current'' era_genesis block index. It will start being the
    /// original genesis. As time goes, it will move to future era genesis
    /// checkpoint.
    cur_era_genesis_block_arena_index: usize,
    /// The height of the ``current'' era_genesis block
    cur_era_genesis_height: u64,
    /// The height of the ``stable'' era block, unless from the start, it is
    /// always era_epoch_count higher than era_genesis_height
    cur_era_stable_height: u64,
    /// If this value is not none, then we are still expecting the initial
    /// stable block to come. This value would equal to the expected hash of
    /// the block.
    cur_era_stable_block_hash: H256,
    /// If this value is not none, then we are manually maintain the future set
    /// of the expected stable block. We have to do this because during the
    /// initial stage it may not be always on the pivot chain.
    initial_stable_future: Option<BitSet>,
    /// The timer chain height of the ``current'' era_genesis block
    cur_era_genesis_timer_chain_height: u64,
    /// The best timer chain difficulty and hash in the current graph
    best_timer_chain_difficulty: i128,
    best_timer_chain_hash: H256,
    /// weight_tree maintains the subtree weight of each node in the TreeGraph
    weight_tree: SizeMinLinkCutTree,
    /// adaptive_tree maintains 2 * SubStableTW(B, x) - SubTW(B, P(x)) +
    /// Weight(P(x))
    adaptive_tree: CaterpillarMinLinkCutTree,
    /// A priority that holds for every non-active partial invalid block, the
    /// timer chain stamp that will become valid
    invalid_block_queue: BinaryHeap<(i128, usize)>,
    /// This cache is to store all passed block body parameters of non-active
    /// blocks
    block_body_caches: HashMap<usize, Option<Vec<Arc<SignedTransaction>>>>,
    pub pow_config: ProofOfWorkConfig,
    /// It maintains the expected difficulty of the next local mined block.
    pub current_difficulty: U256,
    /// data_man is the handle to access raw block data
    data_man: Arc<BlockDataManager>,
    pub inner_conf: ConsensusInnerConfig,
    /// The cache to store Anticone information of each node. This could be
    /// very large so we periodically remove old ones in the cache.
    anticone_cache: AnticoneCache,
    pastset_cache: PastSetCache,
    sequence_number_of_block_entrance: u64,
    /// Block set of each old era. It will garbage collected by sync graph via
    /// `pop_old_era_block_set()`. This is a helper for full nodes to determine
    /// which blocks it can safely remove
    old_era_block_set: Mutex<VecDeque<H256>>,

    /// This is a cache map to speed up the lca computation of terminals in the
    /// best terminals call. The basic idea is that if no major
    /// reorganization happens, then it could use the last results
    /// instead of calling it again.
    best_terminals_lca_height_cache: FastHashMap<usize, u64>,
    /// This is to record the pivot chain reorganization height since the last
    /// invocation of best_terminals()
    best_terminals_reorg_height: u64,
    /// This is a cache to record history of checking whether a block has timer
    /// block in its anticone.
    has_timer_block_in_anticone_cache: HashSet<usize>,
}

impl MallocSizeOf for ConsensusGraphInner {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.arena.size_of(ops)
            + self.hash_to_arena_indices.size_of(ops)
            + self.pivot_chain.size_of(ops)
            + self.pivot_chain_metadata.size_of(ops)
            + self.timer_chain.size_of(ops)
            + self.timer_chain_accumulative_lca.size_of(ops)
            + self.terminal_hashes.size_of(ops)
            + self.initial_stable_future.size_of(ops)
            + self.weight_tree.size_of(ops)
            + self.adaptive_tree.size_of(ops)
            + self.invalid_block_queue.size_of(ops)
            + self.block_body_caches.size_of(ops)
            + self.pow_config.size_of(ops)
            + self.data_man.size_of(ops)
            + self.anticone_cache.size_of(ops)
            + self.pastset_cache.size_of(ops)
            + self.old_era_block_set.lock().size_of(ops)
            + self.best_terminals_lca_height_cache.size_of(ops)
            + self.best_terminals_reorg_height.size_of(ops)
    }
}

#[derive(DeriveMallocSizeOf)]
pub struct ConsensusGraphNode {
    pub hash: H256,
    pub height: u64,
    pub parent: usize,
    difficulty: U256,
    is_heavy: bool,
    is_timer: bool,
    /// The total number of *executed* blocks in its past (not including self)
    past_num_blocks: u64,
    adaptive: bool,

    /// The genesis arena index of the era that `self` is in.
    ///
    /// It is `NULL` if `self` is not in the subtree of `cur_era_genesis`.
    era_block: usize,
    children: Vec<usize>,
    referrers: Vec<usize>,
    referees: Vec<usize>,
    /// data contains all extra information of a block that will change as the
    /// consensus graph state evolves (e.g., pivot chain changes). Unlike the
    /// above fields, this information will only be available after the
    /// block is *preactivated* (after calling preactivate_block().
    pub data: ConsensusGraphNodeData,
}

impl ConsensusGraphNode {
    pub fn past_num_blocks(&self) -> u64 { self.past_num_blocks }

    pub fn adaptive(&self) -> bool { self.adaptive }

    pub fn pending(&self) -> bool { self.data.pending }

    pub fn partial_invalid(&self) -> bool { self.data.partial_invalid }

    pub fn era_block(&self) -> usize { self.era_block }
}

impl ConsensusGraphInner {
    pub fn with_era_genesis(
        pow_config: ProofOfWorkConfig, data_man: Arc<BlockDataManager>,
        inner_conf: ConsensusInnerConfig, cur_era_genesis_block_hash: &H256,
        cur_era_stable_block_hash: &H256,
    ) -> Self
    {
        let genesis_block_header = data_man
            .block_header_by_hash(cur_era_genesis_block_hash)
            .expect("genesis block header should exist here");
        let cur_era_genesis_height = genesis_block_header.height();
        let stable_block_header = data_man
            .block_header_by_hash(cur_era_stable_block_hash)
            .expect("stable genesis block header should exist here");
        let cur_era_stable_height = stable_block_header.height();
        let initial_difficulty = pow_config.initial_difficulty;
        let mut inner = ConsensusGraphInner {
            arena: Slab::new(),
            hash_to_arena_indices: FastHashMap::new(),
            pivot_chain: Vec::new(),
            pivot_chain_metadata: Vec::new(),
            timer_chain: Vec::new(),
            timer_chain_accumulative_lca: Vec::new(),
            terminal_hashes: Default::default(),
            cur_era_genesis_block_arena_index: NULL,
            cur_era_genesis_height,
            cur_era_stable_height,
            // Timer chain height is an internal number. We always start from
            // zero.
            cur_era_stable_block_hash: cur_era_stable_block_hash.clone(),
            initial_stable_future: Some(BitSet::new()),
            cur_era_genesis_timer_chain_height: 0,
            best_timer_chain_difficulty: 0,
            best_timer_chain_hash: Default::default(),
            weight_tree: SizeMinLinkCutTree::new(),
            adaptive_tree: CaterpillarMinLinkCutTree::new(),
            invalid_block_queue: BinaryHeap::new(),
            block_body_caches: HashMap::new(),
            pow_config,
            current_difficulty: initial_difficulty.into(),
            data_man: data_man.clone(),
            inner_conf,
            anticone_cache: AnticoneCache::new(),
            pastset_cache: Default::default(),
            sequence_number_of_block_entrance: 0,
            old_era_block_set: Mutex::new(VecDeque::new()),
            best_terminals_lca_height_cache: Default::default(),
            best_terminals_reorg_height: NULLU64,
            has_timer_block_in_anticone_cache: Default::default(),
        };

        // NOTE: Only genesis block will be first inserted into consensus graph
        // and then into synchronization graph. All the other blocks will be
        // inserted first into synchronization graph then consensus graph.
        // For genesis block, its past weight is simply zero (default value).
        let (genesis_arena_index, _) = inner.insert(&genesis_block_header);
        if cur_era_genesis_block_hash == cur_era_stable_block_hash {
            inner
                .initial_stable_future
                .as_mut()
                .unwrap()
                .add(genesis_arena_index as u32);
        }
        inner.arena[genesis_arena_index].data.blockset_cleared = false;
        if genesis_block_header.height() == 0 {
            inner.arena[genesis_arena_index].data.state_valid = Some(true);
        }
        inner.cur_era_genesis_block_arena_index = genesis_arena_index;
        inner.arena[genesis_arena_index].data.activated = true;
        let genesis_block_weight = genesis_block_header.difficulty().low_u128();
        inner
            .weight_tree
            .make_tree(inner.cur_era_genesis_block_arena_index);
        inner.weight_tree.path_apply(
            inner.cur_era_genesis_block_arena_index,
            genesis_block_weight as i128,
        );
        inner
            .adaptive_tree
            .make_tree(inner.cur_era_genesis_block_arena_index);
        // The genesis node can be zero in adaptive_tree because it is never
        // used!
        inner
            .adaptive_tree
            .set(inner.cur_era_genesis_block_arena_index, 0);
        inner.arena[inner.cur_era_genesis_block_arena_index]
            .data
            .epoch_number = cur_era_genesis_height;
        let genesis_epoch_size = inner
            .data_man
            .executed_epoch_set_hashes_from_db(cur_era_genesis_height)
            .expect("Genesis epoch set should be in data manager.")
            .len();
        inner.arena[inner.cur_era_genesis_block_arena_index].past_num_blocks =
            inner
                .data_man
                .get_epoch_execution_context(cur_era_genesis_block_hash)
                .expect("ExecutionContext for cur_era_genesis exists")
                .start_block_number
                + genesis_epoch_size as u64
                - 1;
        inner.arena[inner.cur_era_genesis_block_arena_index]
            .data
            .last_pivot_in_past = cur_era_genesis_height;
        inner
            .pivot_chain
            .push(inner.cur_era_genesis_block_arena_index);
        let mut last_pivot_in_past_blocks = HashSet::new();
        last_pivot_in_past_blocks
            .insert(inner.cur_era_genesis_block_arena_index);
        inner.pivot_chain_metadata.push(ConsensusGraphPivotData {
            last_pivot_in_past_blocks,
            past_weight: genesis_block_weight as i128,
        });
        if inner.arena[inner.cur_era_genesis_block_arena_index].is_timer {
            inner
                .timer_chain
                .push(inner.cur_era_genesis_block_arena_index);
        }
        inner.arena[inner.cur_era_genesis_block_arena_index]
            .data
            .ledger_view_timer_chain_height = 0;
        inner.best_timer_chain_difficulty =
            inner.get_timer_difficulty(inner.cur_era_genesis_block_arena_index);

        inner
            .anticone_cache
            .update(inner.cur_era_genesis_block_arena_index, &BitSet::new());

        inner
    }

    fn persist_epoch_set_hashes(&mut self, pivot_index: usize) {
        let height = self.pivot_index_to_height(pivot_index);
        let arena_index = self.pivot_chain[pivot_index];
        let epoch_set_hashes = self
            .get_ordered_executable_epoch_blocks(arena_index)
            .iter()
            .map(|arena_index| self.arena[*arena_index].hash)
            .collect();
        let skipped_set_hashes = self
            .get_or_compute_skipped_epoch_blocks(arena_index)
            .clone()
            .iter()
            .map(|arena_index| self.arena[*arena_index].hash)
            .collect();
        self.data_man
            .insert_executed_epoch_set_hashes_to_db(height, &epoch_set_hashes);
        self.data_man
            .insert_skipped_epoch_set_hashes_to_db(height, &skipped_set_hashes);
    }

    #[inline]
    pub fn current_era_genesis_seq_num(&self) -> u64 {
        self.arena[self.cur_era_genesis_block_arena_index]
            .data
            .sequence_number
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
    fn ancestor_at(&self, me: usize, height: u64) -> usize {
        let height_index = self.height_to_pivot_index(height);
        self.weight_tree.ancestor_at(me, height_index)
    }

    #[inline]
    /// for outside era block, consider the lca is NULL
    fn lca(&self, me: usize, v: usize) -> usize {
        if self.arena[v].era_block == NULL || self.arena[me].era_block == NULL {
            return NULL;
        }
        self.weight_tree.lca(me, v)
    }

    #[inline]
    fn get_era_genesis_height(&self, parent_height: u64) -> u64 {
        parent_height / self.inner_conf.era_epoch_count
            * self.inner_conf.era_epoch_count
    }

    #[inline]
    pub fn get_cur_era_genesis_height(&self) -> u64 {
        self.cur_era_genesis_height
    }

    #[inline]
    fn get_era_genesis_block_with_parent(&self, parent: usize) -> usize {
        if parent == NULL {
            return 0;
        }
        let height = self.arena[parent].height;
        let era_genesis_height = self.get_era_genesis_height(height);
        trace!(
            "height={} era_height={} era_genesis_height={}",
            height,
            era_genesis_height,
            self.cur_era_genesis_height
        );
        self.ancestor_at(parent, era_genesis_height)
    }

    #[inline]
    fn get_epoch_block_hashes(&self, epoch_arena_index: usize) -> Vec<H256> {
        self.get_ordered_executable_epoch_blocks(epoch_arena_index)
            .iter()
            .map(|idx| self.arena[*idx].hash)
            .collect()
    }

    #[inline]
    fn get_epoch_start_block_number(&self, epoch_arena_index: usize) -> u64 {
        let parent = self.arena[epoch_arena_index].parent;

        return self.arena[parent].past_num_blocks + 1;
    }

    #[inline]
    fn is_legacy_block(&self, index: usize) -> bool {
        self.arena[index].era_block == NULL
    }

    fn compute_blockset_in_own_view_of_epoch_impl(
        &mut self, lca: usize, pivot: usize,
    ) {
        let pastset = self.pastset_cache.get(lca).unwrap();
        let mut path_to_lca = Vec::new();
        let mut cur = pivot;
        while cur != lca {
            path_to_lca.push(cur);
            cur = self.arena[cur].parent;
        }
        path_to_lca.reverse();
        let mut visited = BitSet::new();
        for ancestor_arena_index in path_to_lca {
            visited.add(ancestor_arena_index as u32);
            if ancestor_arena_index == pivot
                || self.arena[ancestor_arena_index].data.blockset_cleared
            {
                let mut queue = VecDeque::new();
                for referee in &self.arena[ancestor_arena_index].referees {
                    if !pastset.contains(*referee as u32)
                        && !visited.contains(*referee as u32)
                    {
                        visited.add(*referee as u32);
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
                        && !visited.contains(parent as u32)
                    {
                        visited.add(parent as u32);
                        queue.push_back(parent);
                    }
                    for referee in &self.arena[index].referees {
                        if !pastset.contains(*referee as u32)
                            && !visited.contains(*referee as u32)
                        {
                            visited.add(*referee as u32);
                            queue.push_back(*referee);
                        }
                    }
                }
            } else {
                for index in &self.arena[ancestor_arena_index]
                    .data
                    .blockset_in_own_view_of_epoch
                {
                    visited.add(*index as u32);
                }
            }
        }
    }

    fn compute_blockset_in_own_view_of_epoch(&mut self, pivot: usize) {
        if !self.arena[pivot].data.blockset_cleared {
            return;
        }
        // TODO: consider the speed for recovery from db
        let parent = self.arena[pivot].parent;
        if parent != NULL {
            let last = *self.pivot_chain.last().unwrap();
            let lca = self.lca(last, parent);
            assert!(lca != NULL);
            if self.pastset_cache.get_and_update_cache(lca).is_none() {
                let pastset = self.compute_pastset_brutal(lca);
                self.pastset_cache.update(lca, pastset);
            }
            self.compute_blockset_in_own_view_of_epoch_impl(lca, pivot);
        }

        let mut filtered_blockset = HashSet::new();
        let mut different_era_blocks = Vec::new();
        for idx in &self.arena[pivot].data.blockset_in_own_view_of_epoch {
            if self.is_same_era(*idx, pivot) {
                filtered_blockset.insert(*idx);
            } else {
                different_era_blocks.push(*idx);
            }
        }

        self.arena[pivot].data.ordered_executable_epoch_blocks =
            self.topological_sort(&filtered_blockset);
        self.arena[pivot]
            .data
            .ordered_executable_epoch_blocks
            .push(pivot);
        if self.arena[pivot].data.ordered_executable_epoch_blocks.len()
            > EPOCH_EXECUTED_BLOCK_BOUND
        {
            let cut_off =
                self.arena[pivot].data.ordered_executable_epoch_blocks.len()
                    - EPOCH_EXECUTED_BLOCK_BOUND;
            self.arena[pivot].data.skipped_epoch_blocks = mem::replace(
                &mut self.arena[pivot].data.ordered_executable_epoch_blocks,
                Default::default(),
            );
            self.arena[pivot].data.ordered_executable_epoch_blocks = self.arena
                [pivot]
                .data
                .skipped_epoch_blocks
                .split_off(cut_off);
        } else {
            self.arena[pivot].data.skipped_epoch_blocks = Default::default();
        }
        self.arena[pivot]
            .data
            .skipped_epoch_blocks
            .append(&mut different_era_blocks);
        self.arena[pivot].data.blockset_cleared = false;
    }

    #[inline]
    fn exchange_or_compute_blockset_in_own_view_of_epoch(
        &mut self, index: usize, blockset_opt: Option<Vec<usize>>,
    ) -> Vec<usize> {
        if let Some(blockset) = blockset_opt {
            mem::replace(
                &mut self.arena[index].data.blockset_in_own_view_of_epoch,
                blockset,
            )
        } else {
            if self.arena[index].data.blockset_cleared {
                self.compute_blockset_in_own_view_of_epoch(index);
            }
            mem::replace(
                &mut self.arena[index].data.blockset_in_own_view_of_epoch,
                Default::default(),
            )
        }
    }

    #[inline]
    pub fn get_ordered_executable_epoch_blocks(
        &self, index: usize,
    ) -> &Vec<usize> {
        &self.arena[index].data.ordered_executable_epoch_blocks
    }

    #[inline]
    pub fn get_or_compute_skipped_epoch_blocks(
        &mut self, index: usize,
    ) -> &Vec<usize> {
        if self.arena[index].data.blockset_cleared {
            self.compute_blockset_in_own_view_of_epoch(index);
        }
        &self.arena[index].data.skipped_epoch_blocks
    }

    #[inline]
    pub fn get_skipped_epoch_blocks(
        &self, index: usize,
    ) -> Option<&Vec<usize>> {
        if self.arena[index].data.blockset_cleared {
            None
        } else {
            Some(&self.arena[index].data.skipped_epoch_blocks)
        }
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
        &self, pivot_index: usize, blame_bound: Option<u32>,
    ) -> Option<usize> {
        // this is the earliest block we need to consider; blocks before `from`
        // cannot have any information about the state root of `pivot_index`
        let from = pivot_index + DEFERRED_STATE_EPOCH_COUNT as usize;

        self.find_first_trusted_starting_from(from, blame_bound)
    }

    pub fn find_first_trusted_starting_from(
        &self, from: usize, blame_bound: Option<u32>,
    ) -> Option<usize> {
        let mut trusted_index = match self
            .find_first_with_trusted_blame_starting_from(from, blame_bound)
        {
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
        &self, pivot_index: usize, blame_bound: Option<u32>,
    ) -> Option<usize> {
        trace!(
            "find_first_with_trusted_blame_starting_from pivot_index={:?}",
            pivot_index
        );
        let mut cur_pivot_index = pivot_index;
        while cur_pivot_index < self.pivot_chain.len() {
            let arena_index = self.pivot_chain[cur_pivot_index];
            let blame_ratio =
                self.compute_blame_ratio(arena_index, blame_bound);
            trace!(
                "blame_ratio for {:?} is {}",
                self.arena[arena_index].hash,
                blame_ratio
            );
            if blame_ratio < MAX_BLAME_RATIO_FOR_TRUST {
                return Some(cur_pivot_index);
            }
            cur_pivot_index += 1;
        }

        None
    }

    // Compute the ratio of blames that the block gets
    fn compute_blame_ratio(
        &self, arena_index: usize, blame_bound: Option<u32>,
    ) -> f64 {
        let blame_bound = if let Some(bound) = blame_bound {
            bound
        } else {
            u32::max_value()
        };
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

            if step == blame_bound {
                continue;
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
        &mut self, parent_arena_index: usize, referee_indices: Vec<usize>,
        difficulty: U256,
    ) -> bool
    {
        // We first compute anticone barrier for newly mined block
        let parent_anticone_opt = self.anticone_cache.get(parent_arena_index);
        let mut anticone;
        if parent_anticone_opt.is_none() {
            anticone = consensus_new_block_handler::ConsensusNewBlockHandler::compute_anticone_bruteforce(
                self, parent_arena_index,
            );
            anticone |= &self.compute_future_bitset(parent_arena_index);
        } else {
            anticone = self.compute_future_bitset(parent_arena_index);
            for index in parent_anticone_opt.unwrap() {
                anticone.add(*index as u32);
            }
        }
        let mut my_past = BitSet::new();
        let mut queue: VecDeque<usize> = VecDeque::new();
        for index in &referee_indices {
            queue.push_back(*index);
        }
        while let Some(index) = queue.pop_front() {
            if my_past.contains(index as u32) {
                continue;
            }
            my_past.add(index as u32);
            let idx_parent = self.arena[index].parent;
            if anticone.contains(idx_parent as u32)
                || self.arena[idx_parent].era_block == NULL
            {
                queue.push_back(idx_parent);
            }
            for referee in &self.arena[index].referees {
                if anticone.contains(*referee as u32)
                    || self.arena[idx_parent].era_block == NULL
                {
                    queue.push_back(*referee);
                }
            }
        }
        for index in my_past.drain() {
            anticone.remove(index);
        }

        let mut anticone_barrier = BitSet::new();
        for index in (&anticone).iter() {
            let parent = self.arena[index as usize].parent as u32;
            if self.arena[index as usize].era_block != NULL
                && !anticone.contains(parent)
            {
                anticone_barrier.add(index);
            }
        }

        let timer_chain_tuple = self.compute_timer_chain_tuple(
            parent_arena_index,
            &referee_indices,
            Some(&anticone),
        );

        self.adaptive_weight_impl(
            parent_arena_index,
            &anticone_barrier,
            None,
            Some(&timer_chain_tuple),
            i128::try_from(difficulty.low_u128()).unwrap(),
        )
    }

    fn compute_subtree_weights(
        &self, me: usize, anticone_barrier: &BitSet,
    ) -> Vec<i128> {
        let mut subtree_weight = Vec::new();
        let n = self.arena.capacity();
        subtree_weight.resize_with(n, Default::default);
        let mut stack = Vec::new();
        stack.push((0, self.cur_era_genesis_block_arena_index));
        while let Some((stage, index)) = stack.pop() {
            if stage == 0 {
                stack.push((1, index));
                subtree_weight[index] = 0;
                for child in &self.arena[index].children {
                    if !anticone_barrier.contains(*child as u32) && *child != me
                    {
                        stack.push((0, *child));
                    }
                }
            } else {
                let weight = self.block_weight(index);
                subtree_weight[index] += weight;
                let parent = self.arena[index].parent;
                if parent != NULL {
                    subtree_weight[parent] += subtree_weight[index];
                }
            }
        }
        subtree_weight
    }

    fn get_best_timer_tick(
        &self,
        timer_chain_tuple: Option<&(
            u64,
            HashMap<usize, u64>,
            Vec<usize>,
            Vec<usize>,
        )>,
    ) -> u64
    {
        if let Some((fork_at, _, _, c)) = timer_chain_tuple {
            *fork_at + c.len() as u64
        } else {
            self.cur_era_genesis_timer_chain_height
                + self.timer_chain.len() as u64
        }
    }

    fn get_timer_tick(
        &self, me: usize,
        timer_chain_tuple: Option<&(
            u64,
            HashMap<usize, u64>,
            Vec<usize>,
            Vec<usize>,
        )>,
    ) -> u64
    {
        if let Some((fork_at, m, _, _)) = timer_chain_tuple {
            if let Some(t) = m.get(&me) {
                return *t;
            } else {
                assert!(
                    self.arena[me].data.ledger_view_timer_chain_height
                        <= *fork_at
                );
            }
        }
        return self.arena[me].data.ledger_view_timer_chain_height;
    }

    fn adaptive_weight_impl_brutal(
        &self, parent_0: usize, subtree_weight: &Vec<i128>,
        timer_chain_tuple: Option<&(
            u64,
            HashMap<usize, u64>,
            Vec<usize>,
            Vec<usize>,
        )>,
        force_confirm: usize, difficulty: i128,
    ) -> bool
    {
        let mut parent = parent_0;

        let force_confirm_height = self.arena[force_confirm].height;
        let timer_me = self.get_best_timer_tick(timer_chain_tuple);

        let adjusted_beta =
            (self.inner_conf.adaptive_weight_beta as i128) * difficulty;

        let mut adaptive = false;
        while self.arena[parent].height != force_confirm_height {
            let grandparent = self.arena[parent].parent;
            let timer_parent = self.get_timer_tick(parent, timer_chain_tuple);
            assert!(timer_me >= timer_parent);
            if timer_me - timer_parent >= self.inner_conf.timer_chain_beta {
                let w = 2 * subtree_weight[parent]
                    - subtree_weight[grandparent]
                    + self.block_weight(grandparent);
                if w < adjusted_beta {
                    adaptive = true;
                    break;
                }
            }
            parent = grandparent;
        }

        adaptive
    }

    fn adaptive_weight_impl(
        &mut self, parent_0: usize, anticone_barrier: &BitSet,
        weight_tuple: Option<&Vec<i128>>,
        timer_chain_tuple: Option<&(
            u64,
            HashMap<usize, u64>,
            Vec<usize>,
            Vec<usize>,
        )>,
        difficulty: i128,
    ) -> bool
    {
        let mut parent = parent_0;
        let force_confirm = self.compute_force_confirm(timer_chain_tuple);
        let force_confirm_height = self.arena[force_confirm].height;
        // This may happen if we are forced to generate at a position choosing
        // incorrect parent. We should return false here.
        if self.arena[parent].height < force_confirm_height
            || self.ancestor_at(parent, force_confirm_height) != force_confirm
        {
            return false;
        }
        if let Some(subtree_weight) = weight_tuple {
            return self.adaptive_weight_impl_brutal(
                parent_0,
                subtree_weight,
                timer_chain_tuple,
                force_confirm,
                difficulty,
            );
        }

        let mut weight_delta = HashMap::new();

        for index in anticone_barrier.iter() {
            assert!(!self.is_legacy_block(index as usize));
            weight_delta
                .insert(index as usize, self.weight_tree.get(index as usize));
        }

        for (index, delta) in &weight_delta {
            self.weight_tree.path_apply(*index, -*delta);
            let parent = self.arena[*index].parent;
            assert!(parent != NULL);
            self.adaptive_tree.caterpillar_apply(parent, *delta);
            self.adaptive_tree.path_apply(*index, -*delta * 2);
        }

        let timer_me = self.get_best_timer_tick(timer_chain_tuple);
        let adjusted_beta = self.inner_conf.timer_chain_beta;

        let mut high = self.arena[parent].height;
        let mut low = force_confirm_height + 1;
        // [low, high]
        let mut best = force_confirm_height;

        while low <= high {
            let mid = (low + high) / 2;
            let p = self.ancestor_at(parent, mid);
            let timer_mid = self.get_timer_tick(p, timer_chain_tuple);
            assert!(timer_me >= timer_mid);
            if timer_me - timer_mid >= adjusted_beta {
                best = mid;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }

        let adaptive = if best != force_confirm_height {
            parent = self.ancestor_at(parent, best);

            let a = self
                .adaptive_tree
                .path_aggregate_chop(parent, force_confirm);
            let b = self.inner_conf.adaptive_weight_beta as i128 * difficulty;

            if a < b {
                debug!("block is adaptive: {:?} < {:?}!", a, b);
            } else {
                debug!("block is not adaptive: {:?} >= {:?}!", a, b);
            }
            a < b
        } else {
            debug!(
                "block is not adaptive: too close to genesis, timer tick {:?}",
                timer_me
            );
            false
        };

        for (index, delta) in &weight_delta {
            self.weight_tree.path_apply(*index, *delta);
            let parent = self.arena[*index].parent;
            self.adaptive_tree.caterpillar_apply(parent, -*delta);
            self.adaptive_tree.path_apply(*index, *delta * 2)
        }

        adaptive
    }

    /// Determine whether we should generate adaptive blocks or not. It is used
    /// both for block generations and for block validations.
    fn adaptive_weight(
        &mut self, me: usize, anticone_barrier: &BitSet,
        weight_tuple: Option<&Vec<i128>>,
        timer_chain_tuple: &(u64, HashMap<usize, u64>, Vec<usize>, Vec<usize>),
    ) -> bool
    {
        let parent = self.arena[me].parent;
        assert!(parent != NULL);

        let difficulty =
            i128::try_from(self.arena[me].difficulty.low_u128()).unwrap();

        self.adaptive_weight_impl(
            parent,
            anticone_barrier,
            weight_tuple,
            Some(timer_chain_tuple),
            difficulty,
        )
    }

    #[inline]
    fn is_same_era(&self, me: usize, pivot: usize) -> bool {
        self.arena[me].era_block == self.arena[pivot].era_block
    }

    fn compute_pastset_brutal(&mut self, me: usize) -> BitSet {
        let mut path = Vec::new();
        let mut cur = me;
        while cur != NULL && self.pastset_cache.get(cur).is_none() {
            path.push(cur);
            cur = self.arena[cur].parent;
        }
        path.reverse();
        let mut result = self
            .pastset_cache
            .get(cur)
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
                let blockset = self
                    .exchange_or_compute_blockset_in_own_view_of_epoch(
                        ancestor_arena_index,
                        None,
                    );
                for index in &blockset {
                    result.add(*index as u32);
                }
                self.exchange_or_compute_blockset_in_own_view_of_epoch(
                    ancestor_arena_index,
                    Some(blockset),
                );
            }
        }
        result
    }

    fn insert_referee_if_not_duplicate(
        &self, referees: &mut Vec<usize>, me: usize,
    ) {
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

    /// Try to insert an outside era block, return it's sequence number. If both
    /// it's parent and referees are empty, we will not insert it into
    /// `arena`.
    pub fn insert_out_era_block(
        &mut self, block_header: &BlockHeader, partial_invalid: bool,
    ) -> (u64, usize) {
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
            return (sn, NULL);
        }

        let mut active_cnt = 0;
        for referee in &referees {
            if !self.arena[*referee].data.activated {
                active_cnt += 1;
            }
        }

        // actually, we only need these fields: `parent`, `referees`,
        // `children`, `referrers`, `era_block`
        let index = self.arena.insert(ConsensusGraphNode {
            hash,
            height: block_header.height(),
            is_heavy: true,
            difficulty: *block_header.difficulty(),
            past_num_blocks: 0,
            is_timer: false,
            // Block header contains an adaptive field, we will verify with our
            // own computation
            adaptive: block_header.adaptive(),
            parent,
            era_block: NULL,
            children: Vec::new(),
            referees,
            referrers: Vec::new(),
            data: ConsensusGraphNodeData::new(NULLU64, sn, active_cnt),
        });
        self.arena[index].data.pending = true;
        self.arena[index].data.activated = false;
        self.arena[index].data.partial_invalid = partial_invalid;
        self.hash_to_arena_indices.insert(hash, index);

        let referees = self.arena[index].referees.clone();
        for referee in referees {
            self.arena[referee].referrers.push(index);
        }
        if parent != NULL {
            self.arena[parent].children.push(index);
        }

        self.weight_tree.make_tree(index);
        self.adaptive_tree.make_tree(index);

        (sn, index)
    }

    fn get_timer_difficulty(&self, me: usize) -> i128 {
        if self.arena[me].is_timer && !self.arena[me].data.partial_invalid {
            i128::try_from(self.arena[me].difficulty.low_u128()).unwrap()
        } else {
            0
        }
    }

    fn compute_force_confirm(
        &self,
        timer_chain_tuple_opt: Option<&(
            u64,
            HashMap<usize, u64>,
            Vec<usize>,
            Vec<usize>,
        )>,
    ) -> usize
    {
        if let Some((fork_at, _, extra_lca, tmp_chain)) = timer_chain_tuple_opt
        {
            let fork_end_index =
                (*fork_at - self.cur_era_genesis_timer_chain_height) as usize
                    + tmp_chain.len();
            let acc_lca_ref = extra_lca;
            if let Some(x) = acc_lca_ref.last() {
                *x
            } else if fork_end_index > self.inner_conf.timer_chain_beta as usize
            {
                self.timer_chain_accumulative_lca[fork_end_index
                    - self.inner_conf.timer_chain_beta as usize
                    - 1]
            } else {
                self.cur_era_genesis_block_arena_index
            }
        } else {
            if let Some(x) = self.timer_chain_accumulative_lca.last() {
                *x
            } else {
                self.cur_era_genesis_block_arena_index
            }
        }
    }

    fn insert(&mut self, block_header: &BlockHeader) -> (usize, usize) {
        let hash = block_header.hash();

        let is_heavy = U512::from(block_header.pow_quality)
            >= U512::from(self.inner_conf.heavy_block_difficulty_ratio)
                * U512::from(block_header.difficulty());
        let is_timer = U512::from(block_header.pow_quality)
            >= U512::from(self.inner_conf.timer_chain_block_difficulty_ratio)
                * U512::from(block_header.difficulty());

        let parent =
            if hash != self.data_man.get_cur_consensus_era_genesis_hash() {
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
            }
        }

        let mut active_cnt =
            if parent != NULL && !self.arena[parent].data.activated {
                1
            } else {
                0
            };
        for referee in &referees {
            if !self.arena[*referee].data.activated {
                active_cnt += 1;
            }
        }

        let my_height = block_header.height();
        let sn = self.get_next_sequence_number();
        let index = self.arena.insert(ConsensusGraphNode {
            hash,
            height: my_height,
            is_heavy,
            difficulty: *block_header.difficulty(),
            past_num_blocks: 0,
            is_timer,
            // Block header contains an adaptive field, we will verify with our
            // own computation
            adaptive: block_header.adaptive(),
            parent,
            era_block: self.get_era_genesis_block_with_parent(parent),
            children: Vec::new(),
            referees,
            referrers: Vec::new(),
            data: ConsensusGraphNodeData::new(NULLU64, sn, active_cnt),
        });
        self.hash_to_arena_indices.insert(hash, index);

        if parent != NULL {
            self.arena[parent].children.push(index);
        }
        let referees = self.arena[index].referees.clone();
        for referee in referees {
            self.arena[referee].referrers.push(index);
        }

        self.compute_blockset_in_own_view_of_epoch(index);
        let executed_epoch_len =
            self.get_ordered_executable_epoch_blocks(index).len();

        if parent != NULL {
            let past_num_blocks =
                self.arena[parent].past_num_blocks + executed_epoch_len as u64;

            self.data_man.insert_epoch_execution_context(
                hash.clone(),
                EpochExecutionContext {
                    start_block_number: self
                        .get_epoch_start_block_number(index),
                },
                true, /* persistent to db */
            );

            self.arena[index].past_num_blocks = past_num_blocks;
        }

        debug!(
            "Block {} inserted into Consensus with index={}",
            hash, index
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
                if !visited.contains(*child as u32)
                    && (self.arena[*child].data.activated
                        || self.arena[*child].data.active_cnt == NULL)
                /* We include all preactivated blocks */
                {
                    visited.add(*child as u32);
                    queue.push_back(*child);
                }
            }
            for referrer in &self.arena[index].referrers {
                if !visited.contains(*referrer as u32)
                    && (self.arena[*referrer].data.activated
                        || self.arena[*referrer].data.active_cnt == NULL)
                /* We include all preactivated blocks */
                {
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
    /// of its epoch should be computed.
    ///
    ///   epoch to                         Block holding
    ///   compute reward                   the reward state
    ///                         Block epoch                  Block with
    ///   | [Bi1]   |           for cared                    [Bj]'s state
    ///   |     \   |           anticone                     as deferred root
    /// --|----[Bi]-|--------------[Ba]---------[Bj]----------[Bt]
    ///   |    /    |
    ///   | [Bi2]   |
    ///
    /// Let i([Bi]) is the arena index of [Bi].
    /// Let h([Bi]) is the height of [Bi].
    ///
    /// Params:
    ///   epoch_arena_index: the arena index of [Bj]
    /// Return:
    ///   Option<(i([Bi]), i([Ba]))>
    ///
    /// The gap between [Bj] and [Bi], i.e., h([Bj])-h([Bi]),
    /// is REWARD_EPOCH_COUNT.
    /// Let D is the gap between the parent of the genesis of next era and [Bi].
    /// The gap between [Ba] and [Bi] is
    ///     min(ANTICONE_PENALTY_UPPER_EPOCH_COUNT, D).
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

    fn get_executable_epoch_blocks(
        &self, epoch_arena_index: usize,
    ) -> Vec<Arc<Block>> {
        let mut epoch_blocks = Vec::new();
        for idx in self.get_ordered_executable_epoch_blocks(epoch_arena_index) {
            let block = self
                .data_man
                .block_by_hash(
                    &self.arena[*idx].hash,
                    false, /* update_cache */
                )
                .expect("Exist");
            epoch_blocks.push(block);
        }
        epoch_blocks
    }

    /// Compute the expected difficulty of a new block given its parent.
    /// Assume the difficulty adjustment period being p.
    /// The period boundary is [i*p+1, (i+1)*p].
    /// Genesis block does not belong to any period, and the first
    /// period is [1, p]. Then, if parent height is less than p, the
    /// current block belongs to the first period, and its difficulty
    /// should be the initial difficulty. Otherwise, we need to consider
    /// 2 cases:
    ///
    /// 1. The parent height is at the period boundary, i.e., the height
    /// is exactly divisible by p. In this case, the new block and its
    /// parent do not belong to the same period. The expected difficulty
    /// of the new block should be computed based on the situation of
    /// parent's period.
    ///
    /// 2. The parent height is not at the period boundary. In this case,
    /// the new block and its parent belong to the same period, and hence,
    /// its difficulty should be same as its parent's.
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
                target_difficulty(
                    &self.data_man,
                    &self.pow_config,
                    &self.arena[parent_arena_index].hash,
                    |h| {
                        let index = self.hash_to_arena_indices.get(h).unwrap();
                        let parent = self.arena[*index].parent;
                        (self.arena[*index].past_num_blocks
                            - self.arena[parent].past_num_blocks)
                            as usize
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
                    let parent = self.arena[*index].parent;
                    (self.arena[*index].past_num_blocks
                        - self.arena[parent].past_num_blocks)
                        as usize
                },
            );
        } else {
            self.current_difficulty = new_best_difficulty;
        }
    }

    pub fn best_block_hash(&self) -> H256 {
        self.arena[*self.pivot_chain.last().unwrap()].hash
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
            trace!(
                "get_state_block_with_delay: idx={}, height={}",
                idx,
                self.arena[idx].height
            );
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

    pub fn best_epoch_number(&self) -> u64 {
        self.cur_era_genesis_height + self.pivot_chain.len() as u64 - 1
    }

    pub fn best_timer_chain_height(&self) -> u64 {
        self.cur_era_genesis_timer_chain_height + self.timer_chain.len() as u64
            - 1
    }

    fn get_arena_index_from_epoch_number(
        &self, epoch_number: u64,
    ) -> Result<usize, String> {
        if epoch_number >= self.cur_era_genesis_height {
            let pivot_index =
                (epoch_number - self.cur_era_genesis_height) as usize;
            if pivot_index >= self.pivot_chain.len() {
                Err("Epoch number larger than the current pivot chain tip"
                    .into())
            } else {
                Ok(self.get_pivot_block_arena_index(epoch_number))
            }
        } else {
            Err("Invalid params: epoch number is too old and not maintained by consensus graph".to_owned())
        }
    }

    /// Get the pivot hash from an epoch number. This function will try to query
    /// the data manager if it is not available in the ConsensusGraph due to
    /// out of the current era.
    pub fn get_pivot_hash_from_epoch_number(
        &self, epoch_number: u64,
    ) -> Result<H256, String> {
        let height = epoch_number;
        if height >= self.cur_era_genesis_height {
            let pivot_index = (height - self.cur_era_genesis_height) as usize;
            if pivot_index >= self.pivot_chain.len() {
                Err("Epoch number larger than the current pivot chain tip"
                    .into())
            } else {
                Ok(self.arena[self.get_pivot_block_arena_index(height)].hash)
            }
        } else {
            self.data_man.executed_epoch_set_hashes_from_db(epoch_number).ok_or(
                format!("get_hash_from_epoch_number: Epoch hash set not in db, epoch_number={}", epoch_number).into()
            ).and_then(|epoch_hashes|
                epoch_hashes.last().map(Clone::clone).ok_or("Epoch set is empty".into())
            )
        }
    }

    /// This function differs from `get_pivot_hash_from_epoch_number` in that it
    /// only returns the hash if it is in the current consensus graph.
    fn epoch_hash(&self, epoch_number: u64) -> Option<H256> {
        let pivot_index = self.height_to_pivot_index(epoch_number);
        self.pivot_chain
            .get(pivot_index)
            .map(|idx| self.arena[*idx].hash)
    }

    pub fn block_hashes_by_epoch(
        &self, epoch_number: u64,
    ) -> Result<Vec<H256>, String> {
        debug!(
            "block_hashes_by_epoch epoch_number={:?} pivot_chain.len={:?}",
            epoch_number,
            self.pivot_chain.len()
        );

        let e;
        // We first try to get it from the consensus. Note that we cannot use
        // the info for the genesis because it may contain out-of-era
        // blocks that is not maintained anymore.
        match self.get_arena_index_from_epoch_number(epoch_number) {
            Ok(pivot_arena_index) => {
                if pivot_arena_index != self.cur_era_genesis_block_arena_index {
                    return Ok(self
                        .get_ordered_executable_epoch_blocks(pivot_arena_index)
                        .iter()
                        .map(|index| self.arena[*index].hash)
                        .collect());
                }
                e = "Epoch set of the current genesis is not maintained".into();
            }
            Err(err) => e = err,
        }

        self.data_man
            .executed_epoch_set_hashes_from_db(epoch_number)
            .ok_or(
                format!(
                    "Epoch set not in db epoch_number={}, in mem err={:?}",
                    epoch_number, e
                )
                .into(),
            )
    }

    pub fn skipped_block_hashes_by_epoch(
        &self, epoch_number: u64,
    ) -> Result<Vec<H256>, String> {
        debug!(
            "skipped_block_hashes_by_epoch epoch_number={:?} pivot_chain.len={:?}",
            epoch_number,
            self.pivot_chain.len()
        );

        let e;
        // We first try to get it from the consensus. Note that we cannot use
        // the info for the genesis because it may contain out-of-era
        // blocks that is not maintained anymore.
        match self.get_arena_index_from_epoch_number(epoch_number) {
            Ok(pivot_arena_index) => {
                if pivot_arena_index != self.cur_era_genesis_block_arena_index {
                    if let Some(skipped_block_set) =
                        self.get_skipped_epoch_blocks(pivot_arena_index)
                    {
                        return Ok(skipped_block_set
                            .iter()
                            .map(|index| self.arena[*index].hash)
                            .collect());
                    }
                }
                e = "Skipped epoch set of the current genesis is not maintained".into();
            }
            Err(err) => e = err,
        }

        self.data_man
            .skipped_epoch_set_hashes_from_db(epoch_number)
            .ok_or(
                format!(
                "Skipped epoch set not in db epoch_number={}, in mem err={:?}",
                epoch_number, e
            )
                .into(),
            )
    }

    fn get_epoch_hash_for_block(&self, hash: &H256) -> Option<H256> {
        self.get_block_epoch_number(&hash)
            .and_then(|epoch_number| self.epoch_hash(epoch_number))
    }

    pub fn terminal_hashes(&self) -> Vec<H256> {
        self.terminal_hashes
            .iter()
            .map(|hash| hash.clone())
            .collect()
    }

    pub fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        self.hash_to_arena_indices.get(hash).and_then(|index| {
            match self.arena[*index].data.epoch_number {
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
    /// hash. If `hash` is not executed in the current view, return None.
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
                        false, /* update_pivot_assumption */
                        update_cache,
                    )?;
                Some(BlockExecutionResultWithEpoch(epoch, execution_result))
            }
            None => {
                debug!("Block {:?} not in mem, try to read from db", hash);

                // result in db might be outdated
                // (after chain reorg but before re-execution)
                let res = match self
                    .data_man
                    .block_execution_result_by_hash_from_db(hash)
                {
                    None => return None,
                    Some(res) => res,
                };

                let execution_pivot_hash = res.0;
                let epoch_number = self
                    .data_man
                    .block_header_by_hash(&execution_pivot_hash)?
                    .height();

                match self.get_pivot_hash_from_epoch_number(epoch_number) {
                    // pivot chain has not changed, result should be correct
                    Ok(h) if h == execution_pivot_hash => Some(res),

                    // pivot chain has changed, block is not re-executed yet
                    _ => None,
                }
            }
        }
    }

    pub fn is_timer_block(&self, block_hash: &H256) -> Option<bool> {
        self.hash_to_arena_indices
            .get(block_hash)
            .and_then(|index| Some(self.arena[*index].is_timer))
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
    ) -> Option<(Receipt, TransactionIndex, U256)> {
        trace!("Get receipt with tx_hash {}", tx_hash);
        let tx_index = self.data_man.transaction_index_by_hash(
            tx_hash, false, /* update_cache */
        )?;
        // receipts should never be None if transaction index isn't none.
        let block_receipts = self
            .block_execution_results_by_hash(
                &tx_index.block_hash,
                false, /* update_cache */
            )?
            .1
            .block_receipts;

        let prior_gas_used = if tx_index.index == 0 {
            U256::zero()
        } else {
            block_receipts.receipts[tx_index.index - 1].accumulated_gas_used
        };

        Some((
            block_receipts
                .receipts
                .get(tx_index.index)
                .expect("Error: can't get receipt by tx_index ")
                .clone(),
            tx_index,
            prior_gas_used,
        ))
    }

    pub fn check_block_pivot_assumption(
        &self, pivot_hash: &H256, epoch: u64,
    ) -> Result<(), String> {
        let last_number = self.best_epoch_number();
        let hash = self.get_pivot_hash_from_epoch_number(epoch)?;
        if epoch > last_number || hash != *pivot_hash {
            return Err("Error: pivot chain assumption failed".to_owned());
        }
        Ok(())
    }

    /// Compute the block weight following the GHAST algorithm:
    /// If a block is not adaptive, the weight is its difficulty
    /// If a block is adaptive, then for the heavy blocks, it equals to
    /// the heavy block ratio times the difficulty. Otherwise, it is zero.
    fn block_weight(&self, me: usize) -> i128 {
        if !self.arena[me].data.activated || self.arena[me].era_block == NULL {
            return 0 as i128;
        }
        let is_heavy = self.arena[me].is_heavy;
        let is_adaptive = self.arena[me].adaptive;
        if is_adaptive {
            if is_heavy {
                self.inner_conf.heavy_block_difficulty_ratio as i128
                    * i128::try_from(self.arena[me].difficulty.low_u128())
                        .unwrap()
            } else {
                0 as i128
            }
        } else {
            i128::try_from(self.arena[me].difficulty.low_u128()).unwrap()
        }
    }

    ////////////////////////////////////////////////////////////////////
    ///                   _________ 5 __________
    ///                   |                    |
    ///  state_valid:           t    f    f    f
    /// <----------------[Bl]-[Bk]-[Bj]-[Bi]-[Bp]-[Bm]----
    ///   [Dj]-[Di]-[Dp]-[Dm]
    ///
    /// [Bp] is the parent of [Bm]
    /// [Dm] is the deferred state root of [Bm]. This is a rough definition
    /// representing deferred state/receipt/blame root
    /// i([Bm]) is the arena index of [Bm]
    /// e([Bm]) is the execution commitment of [Bm]
    /// [Dm] can be generated from e([Bl])
    ///
    /// Param:
    ///   i([Bp]),
    ///   e([Bl]),
    /// Return:
    ///   The blame and the deferred blame roots information that should be
    ///   contained in header of [Bm].
    ///   (blame,
    ///    deferred_blame_state_root,
    ///    deferred_blame_receipt_root,
    ///    deferred_blame_bloom_root)
    ///
    /// Assumption:
    ///   * [Bm] is a pivot block on current pivot chain.
    ///   This assumption is derived from the following cases:
    ///   1. This function may be triggered when evaluating the reward for the
    ///      blocks in epoch of [Bm]. This relies on the state_valid value of
    ///      [Bm]. In other words, in this case, this function is triggered
    ///      when computing the state_valid value of [Bm].
    ///   2. This function may be triggered when mining [Bm].
    ///
    ///   * The execution commitments of blocks needed do exist.
    ///
    ///   * [Bm] is in stable era.
    ///   This assumption is derived from the following cases:
    ///   1. In normal run, before updating stable era genesis, we always
    ///      make state_valid of all the pivot blocks before the new
    ///      stable era genesis computed.
    ///   2. The recover phase (including both archive and full node)
    ///      prepares the graph state to the normal run state before
    ///      calling this function.
    ///
    /// This function searches backward for all the blocks whose
    /// state_valid are false, starting from [Bp]. The number of found
    /// blocks is the 'blame' of [Bm]. if 'blame' == 0, the deferred blame
    /// root information of [Bm] is simply [Dm], otherwise, it is computed
    /// from the vector of deferred state roots of these found blocks
    /// together with [Bm], e.g., in the above example, 'blame'==3, and
    /// the vector of deferred roots of these blocks is
    /// ([Dm], [Dp], [Di], [Dj]), therefore, the deferred blame root of
    /// [Bm] is keccak([Dm], [Dp], [Di], [Dj]).
    fn compute_blame_and_state_with_execution_result(
        &mut self, parent: usize, state_root_hash: H256,
        receipts_root_hash: H256, logs_bloom_hash: H256,
    ) -> Result<StateBlameInfo, String>
    {
        let mut cur = parent;
        let mut blame_cnt: u32 = 0;
        let mut state_blame_vec = Vec::new();
        let mut receipt_blame_vec = Vec::new();
        let mut bloom_blame_vec = Vec::new();
        let mut blame_info_to_fill = Vec::new();
        state_blame_vec.push(state_root_hash);
        receipt_blame_vec.push(receipts_root_hash);
        bloom_blame_vec.push(logs_bloom_hash);
        loop {
            if self.arena[cur]
                .data
                .state_valid
                .expect("computed by the caller")
            {
                // The state_valid for this block and blocks before have been
                // computed. In this case, we need to fill the last one with
                // blame 0.
                if let Some(last_blame_info) = blame_info_to_fill.pop() {
                    self.arena[last_blame_info].data.blame_info =
                        Some(StateBlameInfo {
                            blame: 0,
                            state_vec_root: state_blame_vec
                                .last()
                                .unwrap()
                                .clone(),
                            receipts_vec_root: receipt_blame_vec
                                .last()
                                .unwrap()
                                .clone(),
                            logs_boom_vec_root: bloom_blame_vec
                                .last()
                                .unwrap()
                                .clone(),
                        });
                    blame_cnt = 1;
                }
                break;
            }

            debug!("compute_blame_and_state_with_execution_result: cur={} height={}", cur, self.arena[cur].height);
            // Note that this function should never return errors for pivot
            // chain blocks, because our assumption is that stable
            // blocks will always already have `state_valid` and
            // `blame_info` computed.
            let deferred_arena_index =
                self.get_deferred_state_arena_index(cur)?;
            let deferred_block_commitment = self
                .data_man
                .get_epoch_execution_commitment(
                    &self.arena[deferred_arena_index].hash,
                )
                .ok_or("State block commitment missing")?;
            // We can retrieve the already filled info and maybe stop here
            if let Some(blame_info) = self.arena[cur].data.blame_info {
                blame_cnt = blame_info.blame + 1;
                state_blame_vec.push(blame_info.state_vec_root);
                receipt_blame_vec.push(blame_info.receipts_vec_root);
                bloom_blame_vec.push(blame_info.logs_boom_vec_root);
                break;
            }
            blame_info_to_fill.push(cur);
            if self.arena[cur].height == self.cur_era_genesis_height {
                // Note that this should never happen for pivot chain blocks,
                // because we guarantee that the blame vector at
                // the stable genesis will not stretch beyond the checkpoint
                // genesis. So the blame vector should stop at
                // some point unless the stable genesis is reverted.
                return Err(
                    "Failed to compute blame and state due to out of era. The blockchain data is probably corrupted."
                        .to_owned(),
                );
            }
            state_blame_vec.push(
                deferred_block_commitment
                    .state_root_with_aux_info
                    .aux_info
                    .state_root_hash,
            );
            receipt_blame_vec
                .push(deferred_block_commitment.receipts_root.clone());
            bloom_blame_vec
                .push(deferred_block_commitment.logs_bloom_hash.clone());
            cur = self.arena[cur].parent;
        }
        let blame = blame_cnt + blame_info_to_fill.len() as u32;
        if blame > 0 {
            let mut accumulated_state_root =
                state_blame_vec.last().unwrap().clone();
            let mut accumulated_receipts_root =
                receipt_blame_vec.last().unwrap().clone();
            let mut accumulated_logs_boom_root =
                bloom_blame_vec.last().unwrap().clone();
            for i in (0..blame_info_to_fill.len()).rev() {
                accumulated_state_root =
                    BlockHeaderBuilder::compute_blame_state_root_incremental(
                        state_blame_vec[i + 1],
                        accumulated_state_root,
                    );
                accumulated_receipts_root =
                    BlockHeaderBuilder::compute_blame_state_root_incremental(
                        receipt_blame_vec[i + 1],
                        accumulated_receipts_root,
                    );
                accumulated_logs_boom_root =
                    BlockHeaderBuilder::compute_blame_state_root_incremental(
                        bloom_blame_vec[i + 1],
                        accumulated_logs_boom_root,
                    );
                self.arena[blame_info_to_fill[i]].data.blame_info =
                    Some(StateBlameInfo {
                        blame: blame_cnt,
                        state_vec_root: accumulated_state_root,
                        receipts_vec_root: accumulated_receipts_root,
                        logs_boom_vec_root: accumulated_logs_boom_root,
                    });
                blame_cnt += 1;
            }
            let state_vec_root =
                BlockHeaderBuilder::compute_blame_state_root_incremental(
                    state_blame_vec[0],
                    accumulated_state_root,
                );
            let receipts_vec_root =
                BlockHeaderBuilder::compute_blame_state_root_incremental(
                    receipt_blame_vec[0],
                    accumulated_receipts_root,
                );
            let logs_boom_vec_root =
                BlockHeaderBuilder::compute_blame_state_root_incremental(
                    bloom_blame_vec[0],
                    accumulated_logs_boom_root,
                );
            Ok(StateBlameInfo {
                blame,
                state_vec_root,
                receipts_vec_root,
                logs_boom_vec_root,
            })
        } else {
            Ok(StateBlameInfo {
                blame: 0,
                state_vec_root: state_blame_vec.pop().unwrap(),
                receipts_vec_root: receipt_blame_vec.pop().unwrap(),
                logs_boom_vec_root: bloom_blame_vec.pop().unwrap(),
            })
        }
    }

    /// Compute `state_valid` and `blame_info` for `me`.
    /// Assumption:
    ///   1. The precedents of `me` have computed state_valid
    ///   2. The execution_commitment for deferred state block of `me` exist.
    ///   3. `me` is in stable era.
    fn compute_state_valid_and_blame_info_for_block(
        &mut self, me: usize,
    ) -> Result<(), String> {
        debug!(
            "compute_state_valid: me={} height={}",
            me, self.arena[me].height
        );
        let deferred_state_arena_index =
            self.get_deferred_state_arena_index(me)?;
        let exec_commitment = self
            .data_man
            .get_epoch_execution_commitment(
                &self.arena[deferred_state_arena_index].hash,
            )
            .expect("Commitment exist");
        let parent = self.arena[me].parent;
        let original_deferred_state_root = exec_commitment
            .state_root_with_aux_info
            .aux_info
            .state_root_hash;
        let original_deferred_receipt_root =
            exec_commitment.receipts_root.clone();
        let original_deferred_logs_bloom_hash =
            exec_commitment.logs_bloom_hash.clone();

        let state_blame_info = self
            .compute_blame_and_state_with_execution_result(
                parent,
                original_deferred_state_root.clone(),
                original_deferred_receipt_root.clone(),
                original_deferred_logs_bloom_hash.clone(),
            )?;
        let block_header = self
            .data_man
            .block_header_by_hash(&self.arena[me].hash)
            .unwrap();
        let state_valid = block_header.blame() == state_blame_info.blame
            && *block_header.deferred_state_root()
                == state_blame_info.state_vec_root
            && *block_header.deferred_receipts_root()
                == state_blame_info.receipts_vec_root
            && *block_header.deferred_logs_bloom_hash()
                == state_blame_info.logs_boom_vec_root;

        if state_valid {
            debug!("compute_state_valid_for_block(): Block {} state/blame is valid.", self.arena[me].hash);
        } else {
            debug!("compute_state_valid_for_block(): Block {} state/blame is invalid! header blame {}, our blame {}, header state_root {}, our state root {}, header receipt_root {}, our receipt root {}, header logs_bloom_hash {}, our logs_bloom_hash {}.",
                   self.arena[me].hash, block_header.blame(), state_blame_info.blame, block_header.deferred_state_root(),
                   state_blame_info.state_vec_root, block_header.deferred_receipts_root(),
                   state_blame_info.receipts_vec_root, block_header.deferred_logs_bloom_hash(),
                   state_blame_info.logs_boom_vec_root);
        }

        self.arena[me].data.state_valid = Some(state_valid);
        if !state_valid {
            self.arena[me].data.blame_info = Some(state_blame_info);
        }

        if self.inner_conf.enable_state_expose {
            STATE_EXPOSER
                .consensus_graph
                .lock()
                .block_execution_state_vec
                .push(ConsensusGraphBlockExecutionState {
                    block_hash: self.arena[me].hash,
                    deferred_state_root: original_deferred_state_root,
                    deferred_receipt_root: original_deferred_receipt_root,
                    deferred_logs_bloom_hash: original_deferred_logs_bloom_hash,
                    state_valid: self.arena[me]
                        .data
                        .state_valid
                        .unwrap_or(true),
                })
        }

        Ok(())
    }

    fn compute_vote_valid_for_pivot_block(
        &mut self, me: usize, pivot_arena_index: usize,
    ) -> bool {
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
                if self.arena[index].data.vote_valid_lca_height != lca_height {
                    let header = self
                        .data_man
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
                            if self.arena[cur].data.state_valid
                                .expect("state_valid for me has been computed in \
                                wait_and_compute_state_valid_locked by the caller, \
                                so the precedents should have state_valid") {
                                vote_valid = false;
                                break;
                            }
                            cur_height -= 1;
                            cur = self.arena[cur].parent;
                        }
                        if vote_valid && !self.arena[cur].data.state_valid
                            .expect("state_valid for me has been computed in \
                            wait_and_compute_state_valid_locked by the caller, \
                            so the precedents should have state_valid") {
                            vote_valid = false;
                        }
                        self.arena[index].data.vote_valid_lca_height =
                            lca_height;
                        self.arena[index].data.vote_valid = vote_valid;
                    }
                }
            } else {
                self.arena[index].data.vote_valid_lca_height = lca_height;
                self.arena[index].data.vote_valid =
                    self.arena[a].data.vote_valid;
            }
        }
        self.arena[me].data.vote_valid
    }

    /// Compute the total weight in the epoch represented by the block of
    /// my_hash.
    fn total_weight_in_own_epoch(
        &self, blockset_in_own_epoch: &Vec<usize>, genesis: usize,
    ) -> i128 {
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
            total_weight += self.block_weight(*index);
        }
        total_weight
    }

    /// Recompute metadata associated information on pivot chain changes
    fn recompute_metadata(
        &mut self, start_at: u64, mut to_update: HashSet<usize>,
    ) {
        self.pivot_chain_metadata
            .resize_with(self.pivot_chain.len(), Default::default);
        let pivot_height = self.get_pivot_height();
        for i in start_at..pivot_height {
            let me = self.get_pivot_block_arena_index(i);
            self.arena[me].data.last_pivot_in_past = i;
            let i_pivot_index = self.height_to_pivot_index(i);
            self.pivot_chain_metadata[i_pivot_index]
                .last_pivot_in_past_blocks
                .clear();
            self.pivot_chain_metadata[i_pivot_index]
                .last_pivot_in_past_blocks
                .insert(me);
            self.pivot_chain_metadata[i_pivot_index].past_weight =
                if i_pivot_index > 0 {
                    let blockset = self
                        .exchange_or_compute_blockset_in_own_view_of_epoch(
                            me, None,
                        );
                    let blockset_weight = self.total_weight_in_own_epoch(
                        &blockset,
                        self.cur_era_genesis_block_arena_index,
                    );
                    self.exchange_or_compute_blockset_in_own_view_of_epoch(
                        me,
                        Some(blockset),
                    );
                    self.pivot_chain_metadata[i_pivot_index - 1].past_weight
                        + blockset_weight
                        + self.block_weight(me)
                } else {
                    self.block_weight(me)
                };
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
                let mut last_pivot = if parent == NULL {
                    0
                } else {
                    self.arena[parent].data.last_pivot_in_past
                };
                for referee in &self.arena[me].referees {
                    let x = self.arena[*referee].data.last_pivot_in_past;
                    last_pivot = max(last_pivot, x);
                }
                self.arena[me].data.last_pivot_in_past = last_pivot;
                let last_pivot_index = self.height_to_pivot_index(last_pivot);
                self.pivot_chain_metadata[last_pivot_index]
                    .last_pivot_in_past_blocks
                    .insert(me);
            }
        }
    }

    fn get_timer_chain_index(&self, me: usize) -> usize {
        if !self.arena[me].is_timer || self.arena[me].data.partial_invalid {
            return NULL;
        }
        let timer_chain_index =
            (self.arena[me].data.ledger_view_timer_chain_height
                - self.cur_era_genesis_timer_chain_height) as usize;
        if self.timer_chain.len() > timer_chain_index
            && self.timer_chain[timer_chain_index] == me
        {
            timer_chain_index
        } else {
            NULL
        }
    }

    fn compute_timer_chain_past_view_info(
        &self, parent: usize, referees: &Vec<usize>,
    ) -> (i128, usize) {
        let mut timer_longest_difficulty = 0;
        let mut longest_referee = parent;
        if parent != NULL {
            timer_longest_difficulty =
                self.arena[parent].data.past_view_timer_longest_difficulty
                    + self.get_timer_difficulty(parent);
        }
        for referee in referees {
            let timer_difficulty =
                self.arena[*referee].data.past_view_timer_longest_difficulty
                    + self.get_timer_difficulty(*referee);
            if longest_referee == NULL
                || ConsensusGraphInner::is_heavier(
                    (timer_difficulty, &self.arena[*referee].hash),
                    (
                        timer_longest_difficulty,
                        &self.arena[longest_referee].hash,
                    ),
                )
            {
                timer_longest_difficulty = timer_difficulty;
                longest_referee = *referee;
            }
        }
        let last_timer_block_arena_index = if longest_referee == NULL
            || self.arena[longest_referee].is_timer
                && !self.arena[longest_referee].data.partial_invalid
        {
            longest_referee
        } else {
            self.arena[longest_referee]
                .data
                .past_view_last_timer_block_arena_index
        };
        (timer_longest_difficulty, last_timer_block_arena_index)
    }

    fn compute_timer_chain_tuple(
        &self, parent: usize, referees: &Vec<usize>,
        anticone_opt: Option<&BitSet>,
    ) -> (u64, HashMap<usize, u64>, Vec<usize>, Vec<usize>)
    {
        let empty_set = BitSet::new();
        let anticone = if let Some(a) = anticone_opt {
            a
        } else {
            &empty_set
        };
        let mut tmp_chain = Vec::new();
        let mut tmp_chain_set = HashSet::new();
        let (_, past_view_last_timer_block_arena_index) =
            self.compute_timer_chain_past_view_info(parent, referees);
        let mut i = past_view_last_timer_block_arena_index;
        while i != NULL && self.get_timer_chain_index(i) == NULL {
            tmp_chain.push(i);
            tmp_chain_set.insert(i);
            i = self.arena[i].data.past_view_last_timer_block_arena_index;
        }
        tmp_chain.reverse();
        let fork_at;
        let fork_at_index;
        if i != NULL {
            fork_at = self.arena[i].data.ledger_view_timer_chain_height + 1;
            assert!(fork_at >= self.cur_era_genesis_timer_chain_height);
            fork_at_index =
                (fork_at - self.cur_era_genesis_timer_chain_height) as usize;
        } else {
            fork_at = self.cur_era_genesis_timer_chain_height;
            fork_at_index = 0;
        }

        let mut res = HashMap::new();
        if fork_at_index < self.timer_chain.len() {
            debug!("New block parent = {} referees = {:?} not extending timer chain (len = {}), fork at timer chain height {}, timer chain index {}", parent, referees, self.timer_chain.len(), fork_at, fork_at_index);
            // Now we need to update the timer_chain_height field of the
            // remaining blocks with topological sort
            let mut queue = VecDeque::new();
            let mut visited = BitSet::new();
            if i == NULL {
                queue.push_back(self.cur_era_genesis_block_arena_index);
                visited.add(self.cur_era_genesis_block_arena_index as u32);
            } else {
                queue.push_back(self.timer_chain[fork_at_index - 1]);
                visited.add(self.timer_chain[fork_at_index - 1] as u32);
            }
            while let Some(x) = queue.pop_front() {
                for succ in self.arena[x]
                    .children
                    .iter()
                    .chain(self.arena[x].referrers.iter())
                {
                    if anticone.contains(*succ as u32) {
                        continue;
                    }
                    if !visited.contains(*succ as u32) {
                        queue.push_back(*succ);
                        visited.add(*succ as u32);
                    }
                }
            }
            let mut counter = HashMap::new();
            for x in &visited {
                let mut cnt = 0;
                if self.arena[x as usize].parent != NULL {
                    if visited.contains(self.arena[x as usize].parent as u32) {
                        cnt = 1;
                    }
                }
                for referee in &self.arena[x as usize].referees {
                    if visited.contains(*referee as u32) {
                        cnt += 1;
                    }
                }
                counter.insert(x as usize, cnt);
            }
            if i == NULL {
                queue.push_back(self.cur_era_genesis_block_arena_index);
            } else {
                queue.push_back(self.timer_chain[fork_at_index - 1]);
            }
            while let Some(x) = queue.pop_front() {
                let mut timer_chain_height = 0;
                let mut preds = self.arena[x].referees.clone();
                if self.arena[x].parent != NULL {
                    preds.push(self.arena[x].parent);
                }
                for pred in &preds {
                    let mut height = if let Some(v) = res.get(pred) {
                        *v
                    } else {
                        self.arena[*pred].data.ledger_view_timer_chain_height
                    };
                    if tmp_chain_set.contains(pred)
                        || self.get_timer_chain_index(*pred) < fork_at_index
                    {
                        height += 1;
                    }
                    if height > timer_chain_height {
                        timer_chain_height = height;
                    }
                }
                res.insert(x, timer_chain_height);
                for succ in self.arena[x]
                    .children
                    .iter()
                    .chain(self.arena[x].referrers.iter())
                {
                    if !visited.contains(*succ as u32) {
                        continue;
                    }
                    let cnt = counter.get(succ).unwrap() - 1;
                    if cnt == 0 {
                        queue.push_back(*succ);
                    }
                    counter.insert(*succ, cnt);
                }
            }
        }

        // We compute the accumulative lca list after this
        let mut tmp_lca = Vec::new();
        if tmp_chain.len() > self.inner_conf.timer_chain_beta as usize {
            let mut last_lca = if fork_at_index == 0 {
                self.cur_era_genesis_block_arena_index
            } else {
                // This is guaranteed to be inside the bound because: 1) fork_at
                // + tmp_chain.len() cannot be longer than the current
                // maintained longest timer chain. 2) tmp_chain.len() is greater
                // than timer_chain_beta.
                self.timer_chain_accumulative_lca[fork_at_index - 1]
            };
            for i in 0..(tmp_chain.len()
                - (self.inner_conf.timer_chain_beta as usize))
            {
                if fork_at_index + i + 1
                    < self.inner_conf.timer_chain_beta as usize
                {
                    tmp_lca.push(self.cur_era_genesis_block_arena_index)
                } else {
                    let mut lca = tmp_chain[i];
                    // We only go over timer_chain_beta elements to compute lca
                    let s = if i < self.inner_conf.timer_chain_beta as usize - 1
                    {
                        0
                    } else {
                        i + 1 - self.inner_conf.timer_chain_beta as usize
                    };
                    for j in s..i {
                        // Note that we may have timer_chain blocks that are
                        // outside the genesis tree temporarily.
                        // Therefore we have to deal with the case that lca
                        // becomes NULL
                        if lca == NULL {
                            break;
                        }
                        lca = self.lca(lca, tmp_chain[j]);
                    }
                    for j in (fork_at_index + i + 1
                        - self.inner_conf.timer_chain_beta as usize)
                        ..fork_at_index
                    {
                        // Note that we may have timer_chain blocks that are
                        // outside the genesis tree temporarily.
                        // Therefore we have to deal with the case that lca
                        // becomes NULL
                        if lca == NULL {
                            break;
                        }
                        lca = self.lca(lca, self.timer_chain[j]);
                    }
                    // Note that we have the assumption that the force
                    // confirmation point will always move
                    // along parental edges, i.e., it is not possible for the
                    // point to move to a sibling tree. This
                    // assumption is true if the timer_chain_beta
                    // and the timer_chain_difficulty_ratio are set to large
                    // enough values.
                    //
                    // It is therefore safe here to use the height to compare.
                    if lca != NULL
                        && self.arena[last_lca].height < self.arena[lca].height
                    {
                        last_lca = lca;
                    }
                    tmp_lca.push(last_lca);
                }
            }
        } else if tmp_chain.len() > self.timer_chain.len() - fork_at_index {
            let mut last_lca = match self.timer_chain_accumulative_lca.last() {
                Some(last_lca) => *last_lca,
                None => self.cur_era_genesis_block_arena_index,
            };
            for i in self.timer_chain.len()..(fork_at_index + tmp_chain.len()) {
                // `end` is the timer chain index of the end of
                // `timer_chain_beta` consecutive blocks which
                // we will compute accumulative lca.
                let end = i - self.inner_conf.timer_chain_beta as usize;
                if end < self.inner_conf.timer_chain_beta as usize {
                    tmp_lca.push(self.cur_era_genesis_block_arena_index);
                    continue;
                }
                let mut lca = self.timer_chain[end];
                for j in
                    (end - self.inner_conf.timer_chain_beta as usize + 1)..end
                {
                    // Note that we may have timer_chain blocks that are
                    // outside the genesis tree temporarily.
                    // Therefore we have to deal with the case that lca
                    // becomes NULL
                    if lca == NULL {
                        break;
                    }
                    lca = self.lca(lca, self.timer_chain[j]);
                }
                // Note that we have the assumption that the force
                // confirmation point will always move
                // along parental edges, i.e., it is not possible for the
                // point to move to a sibling tree. This
                // assumption is true if the timer_chain_beta
                // and the timer_chain_difficulty_ratio are set to large
                // enough values.
                //
                // It is therefore safe here to use the height to compare.
                if lca != NULL
                    && self.arena[last_lca].height < self.arena[lca].height
                {
                    last_lca = lca;
                }
                tmp_lca.push(last_lca);
            }
        }

        (fork_at, res, tmp_lca, tmp_chain)
    }

    fn update_timer_chain(&mut self, me: usize) {
        let (fork_at, res, extra_lca, tmp_chain) = self
            .compute_timer_chain_tuple(
                self.arena[me].parent,
                &self.arena[me].referees,
                None,
            );

        let fork_at_index =
            (fork_at - self.cur_era_genesis_timer_chain_height) as usize;
        self.timer_chain.resize(fork_at_index + tmp_chain.len(), 0);
        let new_chain_lca_size = if self.timer_chain.len()
            > self.inner_conf.timer_chain_beta as usize
        {
            self.timer_chain.len() - self.inner_conf.timer_chain_beta as usize
        } else {
            0
        };
        self.timer_chain_accumulative_lca
            .resize(new_chain_lca_size, 0);
        for i in 0..tmp_chain.len() {
            self.timer_chain[fork_at_index + i] = tmp_chain[i];
        }
        for i in 0..extra_lca.len() {
            self.timer_chain_accumulative_lca
                [new_chain_lca_size - extra_lca.len() + i] = extra_lca[i];
        }
        // In case of extending the key chain, me may not be inside the result
        // map and we will set it to the end of the timer chain.
        if !res.contains_key(&me) {
            assert!(
                self.cur_era_genesis_timer_chain_height
                    + self.timer_chain.len() as u64
                    == fork_at
            );
            self.arena[me].data.ledger_view_timer_chain_height = fork_at;
        }
        for (k, v) in res {
            self.arena[k].data.ledger_view_timer_chain_height = v;
        }
        if self.arena[me].is_timer && !self.arena[me].data.partial_invalid {
            self.timer_chain.push(me);
            if self.timer_chain.len()
                >= 2 * self.inner_conf.timer_chain_beta as usize
            {
                let s = self.timer_chain.len()
                    - 2 * self.inner_conf.timer_chain_beta as usize;
                let e = self.timer_chain.len()
                    - self.inner_conf.timer_chain_beta as usize;
                let mut lca = self.timer_chain[e - 1];
                for i in s..(e - 1) {
                    // Note that we may have timer_chain blocks that are outside
                    // the genesis tree temporarily.
                    // Therefore we have to deal with the case that lca becomes
                    // NULL
                    if lca == NULL {
                        break;
                    }
                    lca = self.lca(lca, self.timer_chain[i]);
                }
                let last_lca =
                    if let Some(x) = self.timer_chain_accumulative_lca.last() {
                        *x
                    } else {
                        self.cur_era_genesis_block_arena_index
                    };
                // Note that we have the assumption that the force confirmation
                // point will always move along parental edges,
                // i.e., it is not possible for the point
                // to move to a sibling tree. This assumption is true if the
                // timer_chain_beta
                // and the timer_chain_difficulty_ratio are set to large enough
                // values.
                //
                // It is therefore safe here to use the height to compare.
                if lca != NULL
                    && self.arena[last_lca].height < self.arena[lca].height
                {
                    self.timer_chain_accumulative_lca.push(lca);
                } else {
                    self.timer_chain_accumulative_lca.push(last_lca);
                }
                assert_eq!(
                    self.timer_chain_accumulative_lca.len(),
                    self.timer_chain.len()
                        - self.inner_conf.timer_chain_beta as usize
                );
            } else if self.timer_chain.len()
                > self.inner_conf.timer_chain_beta as usize
            {
                self.timer_chain_accumulative_lca
                    .push(self.cur_era_genesis_block_arena_index);
            }
        }
        debug!(
            "Timer chain updated to {:?} accumulated lca {:?}",
            self.timer_chain, self.timer_chain_accumulative_lca
        );
    }

    pub fn total_processed_block_count(&self) -> u64 {
        self.sequence_number_of_block_entrance
    }

    pub fn get_trusted_blame_block(
        &self, checkpoint_hash: &H256, plus_depth: usize,
    ) -> Option<H256> {
        let arena_index_opt = self.hash_to_arena_indices.get(checkpoint_hash);
        // checkpoint has changed, wait for next checkpoint
        if arena_index_opt.is_none() {
            debug!(
                "get_trusted_blame_block: block {:?} not in consensus",
                checkpoint_hash
            );
            return None;
        }
        let arena_index = *arena_index_opt.unwrap();
        let pivot_index =
            self.height_to_pivot_index(self.arena[arena_index].height);
        // the given checkpoint hash is invalid
        if pivot_index >= self.pivot_chain.len()
            || self.pivot_chain[pivot_index] != arena_index
        {
            debug!(
                "get_trusted_blame_block: block {:?} not on pivot chain",
                checkpoint_hash
            );
            return None;
        }
        self.find_first_index_with_correct_state_of(
            pivot_index + plus_depth,
            None, /* blame_bound */
        )
        .and_then(|index| Some(self.arena[self.pivot_chain[index]].hash))
    }

    /// Find a trusted blame block for snapshot full sync
    pub fn get_trusted_blame_block_for_snapshot(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Option<H256> {
        self.get_trusted_blame_block(
            snapshot_epoch_id,
            self.data_man.get_snapshot_blame_plus_depth(),
        )
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

    fn collect_defer_blocks_missing_execution_commitments(
        &self, me: usize,
    ) -> Result<Vec<H256>, String> {
        let mut cur = self.get_deferred_state_arena_index(me)?;
        let mut waiting_blocks = Vec::new();
        debug!(
            "collect_blocks_missing_execution_commitments: me={}, height={}",
            me, self.arena[me].height
        );
        // FIXME: Same here. Be explicit about whether a checkpoint or a synced
        // FIXME: snapshot is requested, and distinguish two cases.
        let state_boundary_height =
            self.data_man.state_availability_boundary.read().lower_bound;
        loop {
            let deferred_block_hash = self.arena[cur].hash;

            if self
                .data_man
                .get_epoch_execution_commitment(&deferred_block_hash)
                .is_some()
                || self.arena[cur].height <= state_boundary_height
            {
                // This block and the blocks before have been executed or will
                // not be executed
                break;
            }
            waiting_blocks.push(deferred_block_hash);
            cur = self.arena[cur].parent;
        }
        waiting_blocks.reverse();
        Ok(waiting_blocks)
    }

    /// Compute missing `state_valid` for `me` and all the precedents.
    fn compute_state_valid_and_blame_info(
        &mut self, me: usize,
    ) -> Result<(), String> {
        // Collect all precedents whose state_valid is empty, and evaluate them
        // in order
        let mut blocks_to_compute = Vec::new();
        let mut cur = me;
        // FIXME: Same here. Be explicit about whether a checkpoint or a synced
        // FIXME: snapshot is requested, and distinguish two cases.
        let state_boundary_height =
            self.data_man.state_availability_boundary.read().lower_bound;
        loop {
            if self.arena[cur].data.state_valid.is_some() {
                break;
            }
            // See comments on compute_blame_and_state_with_execution_result()
            // for explanation of this assumption.
            assert!(self.arena[cur].height >= state_boundary_height);
            blocks_to_compute.push(cur);
            cur = self.arena[cur].parent;
        }
        blocks_to_compute.reverse();

        for index in blocks_to_compute {
            self.compute_state_valid_and_blame_info_for_block(index)?;
        }
        Ok(())
    }

    fn split_root(&mut self, me: usize) {
        let parent = self.arena[me].parent;
        assert!(parent != NULL);
        self.weight_tree.split_root(parent, me);
        self.adaptive_tree.split_root(parent, me);
        self.arena[me].parent = NULL;
    }

    pub fn reset_epoch_number_in_epoch(&mut self, pivot_arena_index: usize) {
        self.set_epoch_number_in_epoch(pivot_arena_index, NULLU64);
    }

    fn set_epoch_number_in_epoch(
        &mut self, pivot_arena_index: usize, epoch_number: u64,
    ) {
        assert!(!self.arena[pivot_arena_index].data.blockset_cleared);
        let block_set = self.exchange_or_compute_blockset_in_own_view_of_epoch(
            pivot_arena_index,
            None,
        );
        for idx in &block_set {
            self.arena[*idx].data.epoch_number = epoch_number
        }
        self.exchange_or_compute_blockset_in_own_view_of_epoch(
            pivot_arena_index,
            Some(block_set),
        );
        self.arena[pivot_arena_index].data.epoch_number = epoch_number;
    }

    fn get_deferred_state_arena_index(
        &self, me: usize,
    ) -> Result<usize, String> {
        let height = self.arena[me].height;
        // We are in the very early of the blockchain, here we can just
        // return cur_era_genesis_block_arena_index and it will be the true
        // genesis.
        if height <= DEFERRED_STATE_EPOCH_COUNT {
            return Ok(self.cur_era_genesis_block_arena_index);
        }
        // This is the case we cannot handle, the block is no longer maintained.
        if self.cur_era_genesis_height + DEFERRED_STATE_EPOCH_COUNT > height {
            return Err(
                "Parent is too old for computing the deferred state".to_owned()
            );
        }
        let target_height = height - DEFERRED_STATE_EPOCH_COUNT;
        let pivot_idx = self.height_to_pivot_index(height);
        // If it is on the pivot chain already, we can avoid O(log n) lca query
        if pivot_idx < self.pivot_chain.len()
            && self.pivot_chain[pivot_idx] == me
        {
            return Ok(
                self.pivot_chain[self.height_to_pivot_index(target_height)]
            );
        } else {
            return Ok(self.ancestor_at(me, target_height));
        }
    }

    /// Find the first state valid block on the pivot chain after
    /// `state_boundary_height` and set `state_valid` of it and its blamed
    /// blocks. This block is found according to blame_ratio.
    pub fn recover_state_valid(&mut self) {
        // FIXME: Same here. Be explicit about whether a checkpoint or a synced
        // FIXME: snapshot is requested, and distinguish two cases.
        let start_pivot_index =
            (self.data_man.state_availability_boundary.read().lower_bound
                - self.cur_era_genesis_height) as usize;
        if start_pivot_index >= self.pivot_chain.len() {
            // It seems that if this case happens, it is a full node and
            // stated was synced from peers. So, `state_valid` will be recovered
            // by `pivot_block_state_valid_map`.
            // TODO: We may need to go through the whole logic.
            return;
        }
        let start_epoch_hash =
            self.arena[self.pivot_chain[start_pivot_index]].hash;
        // We will get the first
        // pivot block whose `state_valid` is `true` after `start_epoch_hash`
        // (include `start_epoch_hash` itself).
        let maybe_trusted_blame_block =
            self.get_trusted_blame_block(&start_epoch_hash, 0);
        debug!("recover_state_valid: checkpoint={:?}, maybe_trusted_blame_block={:?}", start_epoch_hash, maybe_trusted_blame_block);

        // Set `state_valid` of `trusted_blame_block` to true,
        // and set that of the blocks blamed by it to false
        if let Some(trusted_blame_block) = maybe_trusted_blame_block {
            let mut cur = *self
                .hash_to_arena_indices
                .get(&trusted_blame_block)
                .unwrap();
            while cur != NULL {
                let blame = self
                    .data_man
                    .block_header_by_hash(&self.arena[cur].hash)
                    .unwrap()
                    .blame();
                for i in 0..blame + 1 {
                    self.arena[cur].data.state_valid = Some(i == 0);
                    trace!(
                        "recover_state_valid: index={} hash={} state_valid={}",
                        cur,
                        self.arena[cur].hash,
                        i == 0
                    );
                    cur = self.arena[cur].parent;
                    if cur == NULL {
                        break;
                    }
                }
            }
        } else {
            error!("Fail to recover state_valid");
        }
    }

    pub fn block_node(&self, block_hash: &H256) -> Option<&ConsensusGraphNode> {
        self.hash_to_arena_indices
            .get(block_hash)
            .and_then(|arena_index| self.arena.get(*arena_index))
    }

    /// Return the list of best terminals when respecting a bound (for
    /// referencing edges). We sort the terminals based on its lca so that
    /// it will not change the parent selection results if we exclude last
    /// few terminals in the sorted order.
    pub fn best_terminals(
        &mut self, best_index: usize, ref_bound: usize,
    ) -> Vec<H256> {
        let pastset_tmp;
        let pastset = if let Some(s) = self.pastset_cache.get(best_index) {
            s
        } else {
            pastset_tmp = self.compute_pastset_brutal(best_index);
            &pastset_tmp
        };

        let lca_height_cache = mem::replace(
            &mut self.best_terminals_lca_height_cache,
            Default::default(),
        );

        // We prepare a counter_map to denote the number of erased incoming
        // edges for each block.
        let mut counter_map = FastHashMap::new();
        let mut queue = BinaryHeap::new();
        for hash in self.terminal_hashes.iter() {
            let a_idx = self.hash_to_arena_indices.get(hash).unwrap();
            let mut a_lca_height = NULLU64;
            if let Some(h) = lca_height_cache.get(a_idx) {
                if *h < self.best_terminals_reorg_height {
                    a_lca_height = *h;
                }
            }
            if a_lca_height == NULLU64 {
                let a_lca = self.lca(*a_idx, best_index);
                a_lca_height = self.arena[a_lca].height;
            }
            self.best_terminals_lca_height_cache
                .insert(*a_idx, a_lca_height);
            queue.push((-(a_lca_height as i128), *a_idx));
        }

        // The basic idea is to have a loop go over the refs in the priority
        // queue. We remove tips that have the smallest lca height. When
        // we remove a tip, we add those blocks the tip references back
        // to the queue. Eventually, we will get a set of referees
        // that is 1) within the ref_bound and 2) still holding best_index as
        // their parent.
        //
        // Note that we ignore the case where the force confirm mechanism will
        // influence the result here. The idea is that in normal
        // scenarios with good parameter setting. Force confirmation will
        // happen only when a block is already very stable.
        while queue.len() > ref_bound
            || queue
                .peek()
                .map_or(false, |(v, _)| *v == -(NULLU64 as i128))
        {
            let (_, idx) = queue.pop().unwrap();
            let parent = self.arena[idx].parent;
            if parent != NULL {
                if let Some(p) = counter_map.get_mut(&parent) {
                    *p = *p + 1;
                } else if !pastset.contains(parent as u32) {
                    counter_map.insert(parent, 1);
                }
                if let Some(p) = counter_map.get(&parent) {
                    if *p
                        == self.arena[parent].children.len()
                            + self.arena[parent].referrers.len()
                    {
                        // Note that although original terminal_hashes do not
                        // have out-of-era blocks,
                        // we can now get out-of-era blocks. We need to handle
                        // them.
                        if self.arena[parent].era_block == NULL {
                            queue.push((-(NULLU64 as i128), parent));
                        } else {
                            let mut a_lca_height = NULLU64;
                            if let Some(h) = lca_height_cache.get(&parent) {
                                if *h < self.best_terminals_reorg_height {
                                    a_lca_height = *h;
                                }
                            }
                            if a_lca_height == NULLU64 {
                                let a_lca = self.lca(parent, best_index);
                                a_lca_height = self.arena[a_lca].height;
                            }
                            self.best_terminals_lca_height_cache
                                .insert(parent, a_lca_height);
                            queue.push((-(a_lca_height as i128), parent));
                        }
                    }
                }
            }
            for referee in &self.arena[idx].referees {
                if let Some(p) = counter_map.get_mut(referee) {
                    *p = *p + 1;
                } else if !pastset.contains(*referee as u32) {
                    counter_map.insert(*referee, 1);
                }
                if let Some(p) = counter_map.get(referee) {
                    if *p
                        == self.arena[*referee].children.len()
                            + self.arena[*referee].referrers.len()
                    {
                        // Note that although original terminal_hashes do not
                        // have out-of-era blocks,
                        // we can now get out-of-era blocks. We need to handle
                        // them.
                        if self.arena[*referee].era_block == NULL {
                            queue.push((-(NULLU64 as i128), *referee));
                        } else {
                            let mut a_lca_height = NULLU64;
                            if let Some(h) = lca_height_cache.get(referee) {
                                if *h < self.best_terminals_reorg_height {
                                    a_lca_height = *h;
                                }
                            }
                            if a_lca_height == NULLU64 {
                                let a_lca = self.lca(*referee, best_index);
                                a_lca_height = self.arena[a_lca].height;
                            }
                            self.best_terminals_lca_height_cache
                                .insert(*referee, a_lca_height);
                            queue.push((-(a_lca_height as i128), *referee));
                        }
                    }
                }
            }
        }
        self.best_terminals_reorg_height = NULLU64;
        let bounded_hashes =
            queue.iter().map(|(_, b)| self.arena[*b].hash).collect();
        bounded_hashes
    }

    /// This function is used by the synchronization layer to garbege collect
    /// `old_era_block_set`. The set contains all the blocks that should be
    /// eliminated by full nodes
    pub fn pop_old_era_block_set(&self) -> Option<H256> {
        self.old_era_block_set.lock().pop_front()
    }

    /// Finish block recovery and prepare for normal block processing.
    ///
    /// During block recovery, blocks are inserted without block body. If a
    /// block is still inactive after recovery, its state will not be
    /// available after `construct_pivot_state`. We need to fill its body
    /// here so that it will be executed when it's activated.
    pub fn finish_block_recovery(&mut self) {
        let data_man = self.data_man.clone();
        for (_, arena_index) in &self.invalid_block_queue {
            let block_hash = self.arena[*arena_index].hash;
            self.block_body_caches.entry(*arena_index).or_insert_with(
                || data_man
                    .block_by_hash(&block_hash, true)
                    .map(|block| block.transactions.clone())
                    .or_else(|| {
                        error!("Block {:?} in ConsensusInner is missing from db",
                               block_hash);
                        None
                    })
            );
        }
    }
}
