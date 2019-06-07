// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod consensus_executor;
mod debug;

use self::debug::*;
use super::consensus::consensus_executor::ConsensusExecutor;
use crate::{
    block_data_manager::BlockDataManager,
    cache_manager::{CacheId, CacheManager},
    consensus::consensus_executor::{EpochExecutionTask, RewardExecutionInfo},
    db::COL_MISC,
    ext_db::SystemDB,
    hash::KECCAK_EMPTY_LIST_RLP,
    pow::ProofOfWorkConfig,
    state::State,
    statedb::StateDb,
    statistics::SharedStatistics,
    storage::{state::StateTrait, StorageManager, StorageManagerTrait},
    sync::SynchronizationGraphInner,
    transaction_pool::SharedTransactionPool,
    vm_factory::VmFactory,
};
use cfx_types::{Bloom, H160, H256, U256, U512};
use link_cut_tree::{MinLinkCutTree, SignedBigNum};
use parking_lot::{Mutex, RwLock};
use primitives::{
    filter::{Filter, FilterError},
    log_entry::{LocalizedLogEntry, LogEntry},
    receipt::Receipt,
    transaction::Action,
    Block, BlockHeaderBuilder, EpochNumber, SignedTransaction,
    TransactionAddress,
};
use rayon::prelude::*;
use rlp::*;
use slab::Slab;
use std::{
    cell::RefCell,
    cmp::min,
    collections::{HashMap, HashSet, VecDeque},
    io::Write,
    iter::FromIterator,
    sync::Arc,
    thread::sleep,
    time::Duration,
};

const HEAVY_BLOCK_THRESHOLD: usize = 2000;
pub const HEAVY_BLOCK_DIFFICULTY_RATIO: usize = 240;

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

const NULL: usize = !0;
const EPOCH_LIMIT_OF_RELATED_TRANSACTIONS: usize = 100;

#[derive(Copy, Clone)]
pub struct ConsensusInnerConfig {
    // num/den is the actual adaptive alpha parameter in GHAST. We use a
    // fraction to get around the floating point problem
    pub adaptive_weight_alpha_num: u64,
    pub adaptive_weight_alpha_den: u64,
    // Beta is the threshold in GHAST algorithm
    pub adaptive_weight_beta: u64,
    // Optimistic execution is the feature to execute ahead of the deferred
    // execution boundary. The goal is to pipeline the transaction
    // execution and the block packaging and verification.
    // optimistic_executed_height is the number of step to go ahead
    pub enable_optimistic_execution: bool,
}

pub struct ConsensusConfig {
    // If we hit invalid state root, we will dump the information into a
    // directory specified here. This is useful for testing.
    pub debug_dump_dir_invalid_state_root: String,
    pub record_tx_address: bool,
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
}

impl ConsensusGraphStatistics {
    pub fn new() -> ConsensusGraphStatistics {
        ConsensusGraphStatistics {
            inserted_block_count: 0,
        }
    }
}

pub struct ConsensusGraphNodeData {
    pub epoch_number: RefCell<usize>,
    pub partial_invalid: bool,
    pub anticone: HashSet<usize>,
}

unsafe impl Sync for ConsensusGraphNodeData {}

impl ConsensusGraphNodeData {
    pub fn new(epoch_number: usize) -> Self {
        ConsensusGraphNodeData {
            epoch_number: RefCell::new(epoch_number),
            partial_invalid: false,
            anticone: HashSet::new(),
        }
    }
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
/// adaptive could be computed in a similar manner.

impl ConsensusGraphNode {
    pub fn light_difficulty(&self) -> U256 {
        if self.is_heavy {
            self.difficulty / U256::from(HEAVY_BLOCK_DIFFICULTY_RATIO)
        } else {
            self.difficulty
        }
    }
}

/// In ConsensusGraphInner, every block corresponds to a ConsensusGraphNode and
/// each node has an internal index. This enables fast internal implementation
/// to use integer index instead of H256 block hashes.
pub struct ConsensusGraphInner {
    // This slab hold consensus graph node data and the array index is the
    // internal index.
    pub arena: Slab<ConsensusGraphNode>,
    // indices maps block hash to internal index.
    pub indices: HashMap<H256, usize>,
    // The current pivot chain indexes.
    pub pivot_chain: Vec<usize>,
    // The set of *graph* tips in the TreeGraph.
    pub terminal_hashes: HashSet<H256>,
    genesis_block_index: usize,
    genesis_block_state_root: H256,
    genesis_block_receipts_root: H256,
    // It maps internal index of a block to the set of internal indexes of
    // blocks, when treat the block as the pivot chain block.
    indices_in_epochs: HashMap<usize, Vec<usize>>,
    // weight_tree maintains the subtree weight of each node in the TreeGraph
    weight_tree: MinLinkCutTree,
    // stable_tree maintains d * SubTW(B, x) + n * x.parent.weight + n *
    // PastW(x.parent)
    stable_tree: MinLinkCutTree,
    // adaptive_tree maintains d * SubStableTW(B, x) - n * SubTW(B, P(x))
    adaptive_tree: MinLinkCutTree,
    pow_config: ProofOfWorkConfig,
    // It maintains the expected difficulty of the next local mined block.
    pub current_difficulty: U256,
    // data_man is the handle to access raw block data
    data_man: Arc<BlockDataManager>,
    // Optimistic execution is the feature to execute ahead of the deferred
    // execution boundary. The goal is to pipeline the transaction
    // execution and the block packaging and verification.
    // optimistic_executed_height is the number of step to go ahead
    optimistic_executed_height: Option<usize>,
    inner_conf: ConsensusInnerConfig,
}

pub struct ConsensusGraphNode {
    pub hash: H256,
    pub height: u64,
    pub is_heavy: bool,
    pub difficulty: U256,
    /// The total difficulty of its past set (exclude itself)
    pub past_difficulty: U256,
    pub pow_quality: U256,
    pub stable: bool,
    pub adaptive: bool,
    pub parent: usize,
    pub children: Vec<usize>,
    pub referrers: Vec<usize>,
    pub referees: Vec<usize>,
    pub data: ConsensusGraphNodeData,
}

impl ConsensusGraphInner {
    pub fn with_genesis_block(
        pow_config: ProofOfWorkConfig, data_man: Arc<BlockDataManager>,
        inner_conf: ConsensusInnerConfig,
    ) -> Self
    {
        let mut inner = ConsensusGraphInner {
            arena: Slab::new(),
            indices: HashMap::new(),
            pivot_chain: Vec::new(),
            optimistic_executed_height: None,
            terminal_hashes: Default::default(),
            genesis_block_index: NULL,
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
            indices_in_epochs: HashMap::new(),
            weight_tree: MinLinkCutTree::new(),
            stable_tree: MinLinkCutTree::new(),
            adaptive_tree: MinLinkCutTree::new(),
            pow_config,
            current_difficulty: pow_config.initial_difficulty.into(),
            data_man: data_man.clone(),
            inner_conf,
        };

        // NOTE: Only genesis block will be first inserted into consensus graph
        // and then into synchronization graph. All the other blocks will be
        // inserted first into synchronization graph then consensus graph.
        // At current point, genesis block is not in synchronization graph,
        // so we cannot compute its past_difficulty from
        // sync_graph.total_difficulty_in_own_epoch().
        // For genesis block, its past_difficulty is simply zero.
        let (genesis_index, _) = inner.insert(
            data_man.genesis_block().as_ref(),
            U256::zero(),
            false,
        );
        inner.genesis_block_index = genesis_index;
        inner.weight_tree.make_tree(inner.genesis_block_index);
        inner.weight_tree.path_apply(
            inner.genesis_block_index,
            &SignedBigNum::pos(
                *data_man.genesis_block().block_header.difficulty(),
            ),
        );
        inner.stable_tree.make_tree(inner.genesis_block_index);
        inner
            .stable_tree
            .set(inner.genesis_block_index, &SignedBigNum::zero());
        inner.adaptive_tree.make_tree(inner.genesis_block_index);
        inner
            .adaptive_tree
            .set(inner.genesis_block_index, &SignedBigNum::zero());
        *inner.arena[inner.genesis_block_index]
            .data
            .epoch_number
            .borrow_mut() = 0;
        inner.pivot_chain.push(inner.genesis_block_index);
        assert!(inner.genesis_block_receipts_root == KECCAK_EMPTY_LIST_RLP);
        inner
            .indices_in_epochs
            .insert(0, vec![inner.genesis_block_index]);

        inner
    }

    pub fn is_heavier(
        a: (&SignedBigNum, &H256), b: (&SignedBigNum, &H256),
    ) -> bool {
        (*a.0 > *b.0) || ((*a.0 == *b.0) && (*a.1 > *b.1))
    }

    pub fn get_optimistic_execution_task(
        &mut self, data_man: &BlockDataManager,
    ) -> Option<EpochExecutionTask> {
        if !self.inner_conf.enable_optimistic_execution {
            return None;
        }

        let opt_height = self.optimistic_executed_height?;
        let epoch_index = self.pivot_chain[opt_height];

        // `on_local_pivot` is set to `true` because when we later skip its
        // execution on pivot chain, we will not notify tx pool, so we
        // will also notify in advance.
        let execution_task = EpochExecutionTask::new(
            self.arena[epoch_index].hash,
            self.get_epoch_block_hashes(epoch_index),
            self.get_reward_execution_info(
                data_man,
                opt_height,
                &self.pivot_chain,
            ),
            true,
            false,
        );
        let next_opt_height = opt_height + 1;
        if next_opt_height >= self.pivot_chain.len() {
            self.optimistic_executed_height = None;
        } else {
            self.optimistic_executed_height = Some(next_opt_height);
        }
        Some(execution_task)
    }

    pub fn get_epoch_block_hashes(&self, epoch_index: usize) -> Vec<H256> {
        let reversed_indices =
            self.indices_in_epochs.get(&epoch_index).unwrap();

        let mut epoch_blocks = Vec::new();
        {
            for idx in reversed_indices {
                epoch_blocks.push(self.arena[*idx].hash);
            }
        }
        epoch_blocks
    }

    pub fn check_mining_heavy_block(
        &mut self, parent_index: usize, light_difficulty: U256,
    ) -> bool {
        let mut index = parent_index;
        let mut parent = self.arena[index].parent;
        let total_difficulty =
            U256::from(self.weight_tree.get(self.genesis_block_index));

        while index != self.genesis_block_index {
            debug_assert!(parent != NULL);
            let m = total_difficulty - self.arena[parent].past_difficulty;
            let n = U256::from(self.weight_tree.get(index));
            if ((U512::from(2) * U512::from(m - n)) > U512::from(n))
                && (U512::from(m)
                    > (U512::from(HEAVY_BLOCK_THRESHOLD)
                        * U512::from(light_difficulty)))
            {
                debug!(
                    "Should mine heavy block m={} n={} parent={:?}",
                    m, n, self.arena[parent].hash
                );
                return true;
            }
            index = parent;
            parent = self.arena[index].parent;
        }

        false
    }

    pub fn adaptive_weight(&mut self, me: usize) -> (bool, bool) {
        let mut parent = self.arena[me].parent;
        assert!(parent != NULL);

        let anticone = &self.arena[me].data.anticone;

        for index in anticone {
            if self.arena[*index].data.partial_invalid {
                continue;
            }
            let difficulty = self.arena[*index].difficulty;
            self.weight_tree
                .path_apply(*index, &SignedBigNum::neg(difficulty));
            self.stable_tree.path_apply(
                *index,
                &SignedBigNum::neg(
                    difficulty
                        * U256::from(self.inner_conf.adaptive_weight_alpha_den),
                ),
            );
            //            if self.arena[*index].stable {
            //                self.adaptive_tree.path_apply(
            //                    *index,
            //                    &SignedBigNum::neg(difficulty + difficulty),
            //                );
            //            }
            //            self.adaptive_tree
            //                .path_apply(parent,
            // &SignedBigNum::pos(difficulty));
        }

        let total_difficulty =
            U256::from(self.weight_tree.get(self.genesis_block_index));
        debug!("total_difficulty before insert: {}", total_difficulty);

        let adjusted_beta = U256::from(self.inner_conf.adaptive_weight_beta)
            * self.current_difficulty;

        while parent != self.genesis_block_index {
            let grandparent = self.arena[parent].parent;
            let w = total_difficulty
                - self.arena[grandparent].past_difficulty
                - self.arena[grandparent].difficulty;
            if w > adjusted_beta {
                break;
            }
            parent = grandparent;
        }

        let a = U256::from(self.stable_tree.path_aggregate(parent));
        let b = total_difficulty
            * U256::from(self.inner_conf.adaptive_weight_alpha_num);

        let stable = if parent != self.genesis_block_index {
            !(a < b)
        } else {
            true
        };
        let adaptive = false;

        if !stable {
            debug!("block is unstable: {:?} < {:?}!", a, b);
            parent = self.arena[me].parent;

            while parent != self.genesis_block_index {
                let grandparent = self.arena[parent].parent;
                let w = U256::from(self.weight_tree.get(grandparent));
                if w > adjusted_beta {
                    break;
                }
                parent = grandparent;
            }

            if parent != self.genesis_block_index {
                //                if self.adaptive_tree.path_aggregate(parent)
                //                    < SignedBigNum::zero()
                //                {
                //                    adaptive = true;
                //                }
            }
        } else {
            if parent != self.genesis_block_index {
                debug!("block is stable: {:?} >= {:?}", a, b);
            } else {
                debug!(
                    "block is stable: too close to genesis, adjusted beta {:?}",
                    adjusted_beta
                );
            }
        }

        for index in anticone {
            if self.arena[*index].data.partial_invalid {
                continue;
            }
            let difficulty = self.arena[*index].difficulty;
            self.weight_tree
                .path_apply(*index, &SignedBigNum::pos(difficulty));
            self.stable_tree.path_apply(
                *index,
                &SignedBigNum::pos(
                    difficulty
                        * U256::from(self.inner_conf.adaptive_weight_alpha_den),
                ),
            );
            //            if self.arena[*index].stable {
            //                self.adaptive_tree.path_apply(
            //                    *index,
            //                    &SignedBigNum::pos(difficulty + difficulty),
            //                );
            //            }
            //            self.adaptive_tree
            //                .path_apply(parent,
            // &SignedBigNum::neg(difficulty));
        }

        (stable, adaptive)
    }

    // Note that, at current point, the difficulty of "me" has not been applied
    // to affect weights in parental tree.
    pub fn check_heavy_block(&mut self, me: usize) -> bool {
        let mut difficulties_to_minus: HashMap<u64, U256> = HashMap::new();
        let parent_index = self.arena[me].parent;
        assert!(parent_index != NULL);
        let anticone = &self.arena[me].data.anticone;

        for index in anticone {
            if self.arena[*index].data.partial_invalid {
                continue;
            }
            let difficulty_to_minus = self.arena[*index].difficulty;
            let lca = self.weight_tree.lca(*index, parent_index);
            assert!(*index != lca);
            let lca_height = self.arena[lca].height;
            let entry = difficulties_to_minus
                .entry(lca_height)
                .or_insert(U256::from(0));
            *entry = *entry + difficulty_to_minus;
        }

        let mut difficulty_to_minus = U256::from(0);
        let light_difficulty = self.arena[me].difficulty
            / U256::from(HEAVY_BLOCK_DIFFICULTY_RATIO);

        let mut index = parent_index;
        let mut parent = self.arena[index].parent;
        let total_difficulty = {
            let total_difficulty_to_minus = difficulties_to_minus
                .iter()
                .fold(U256::from(0), |acc, (_, difficulty)| acc + difficulty);
            U256::from(self.weight_tree.get(self.genesis_block_index))
                - total_difficulty_to_minus
        };

        while index != self.genesis_block_index {
            debug_assert!(parent != NULL);
            let index_height = self.arena[index].height;
            if let Some(difficulty) = difficulties_to_minus.get(&index_height) {
                difficulty_to_minus = difficulty_to_minus + difficulty;
            }

            let m = total_difficulty - self.arena[parent].past_difficulty;
            let mut n = U256::from(self.weight_tree.get(index));
            assert!(n > difficulty_to_minus);
            n = n - difficulty_to_minus;
            if ((U512::from(2) * U512::from(m - n)) > U512::from(n))
                && (U512::from(m)
                    > (U512::from(HEAVY_BLOCK_THRESHOLD)
                        * U512::from(light_difficulty)))
            {
                return true;
            }
            index = parent;
            parent = self.arena[index].parent;
        }

        false
    }

    pub fn insert(
        &mut self, block: &Block, past_difficulty: U256, is_heavy: bool,
    ) -> (usize, usize) {
        let hash = block.hash();

        let parent = if *block.block_header.parent_hash() != H256::default() {
            self.indices
                .get(block.block_header.parent_hash())
                .cloned()
                .unwrap()
        } else {
            NULL
        };
        let referees: Vec<usize> = block
            .block_header
            .referee_hashes()
            .iter()
            .map(|hash| self.indices.get(hash).cloned().unwrap())
            .collect();
        for referee in &referees {
            self.terminal_hashes.remove(&self.arena[*referee].hash);
        }
        let index = self.arena.insert(ConsensusGraphNode {
            hash,
            height: block.block_header.height(),
            is_heavy,
            difficulty: *block.block_header.difficulty(),
            past_difficulty,
            pow_quality: block.block_header.pow_quality,
            stable: true,
            adaptive: false,
            parent,
            children: Vec::new(),
            referees,
            referrers: Vec::new(),
            data: ConsensusGraphNodeData::new(NULL),
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
        debug!(
            "Block {} inserted into Consensus with index={} past_difficulty={}",
            hash, index, past_difficulty
        );

        (index, self.indices.len())
    }

    fn check_correct_parent(
        &mut self, me_in_consensus: usize,
        sync_graph: &SynchronizationGraphInner,
    ) -> bool
    {
        let me_in_sync = *sync_graph
            .indices
            .get(&self.arena[me_in_consensus].hash)
            .unwrap();

        let anticone = &self.arena[me_in_consensus].data.anticone;

        let mut valid = true;
        let parent = self.arena[me_in_consensus].parent;

        // Remove difficulty contribution of anticone
        for index in anticone {
            if self.arena[*index].data.partial_invalid {
                continue;
            }
            let difficulty = self.arena[*index].difficulty;
            self.weight_tree
                .path_apply(*index, &SignedBigNum::neg(difficulty));
        }

        // Check the pivot selection decision.
        for sync_index_in_epoch in
            &sync_graph.arena[me_in_sync].blockset_in_own_view_of_epoch
        {
            let consensus_index_in_epoch = *self
                .indices
                .get(
                    &sync_graph.arena[*sync_index_in_epoch].block_header.hash(),
                )
                .expect("In consensus graph");

            if self.arena[consensus_index_in_epoch].data.partial_invalid {
                continue;
            }

            let lca = self.weight_tree.lca(consensus_index_in_epoch, parent);
            assert!(lca != consensus_index_in_epoch);
            if lca == parent {
                valid = false;
                break;
            }

            let fork = self.weight_tree.ancestor_at(
                consensus_index_in_epoch,
                self.arena[lca].height as usize + 1,
            );
            let pivot = self
                .weight_tree
                .ancestor_at(parent, self.arena[lca].height as usize + 1);

            let fork_subtree_weight = self.weight_tree.get(fork);
            let pivot_subtree_weight = self.weight_tree.get(pivot);

            if ConsensusGraphInner::is_heavier(
                (&fork_subtree_weight, &self.arena[fork].hash),
                (&pivot_subtree_weight, &self.arena[pivot].hash),
            ) {
                valid = false;
                break;
            }
        }

        // Add back difficulty contribution of anticone
        for index in anticone {
            if self.arena[*index].data.partial_invalid {
                continue;
            }
            let difficulty = self.arena[*index].difficulty;
            self.weight_tree
                .path_apply(*index, &SignedBigNum::pos(difficulty));
        }

        valid
    }

    pub fn compute_anticone(&mut self, me: usize) {
        let parent = self.arena[me].parent;
        debug_assert!(parent != NULL);
        debug_assert!(self.arena[me].children.is_empty());
        debug_assert!(self.arena[me].referrers.is_empty());

        // Compute future set of parent
        let mut parent_futures: HashSet<usize> = HashSet::new();
        let mut queue: VecDeque<usize> = VecDeque::new();
        let mut visited: HashSet<usize> = HashSet::new();
        queue.push_back(parent);
        while let Some(index) = queue.pop_front() {
            if visited.contains(&index) {
                continue;
            }
            if index != parent && index != me {
                parent_futures.insert(index);
            }

            visited.insert(index);
            for child in &self.arena[index].children {
                queue.push_back(*child);
            }
            for referrer in &self.arena[index].referrers {
                queue.push_back(*referrer);
            }
        }

        let anticone = {
            let parent_anticone = &self.arena[parent].data.anticone;
            let mut my_past: HashSet<usize> = HashSet::new();
            debug_assert!(queue.is_empty());
            queue.push_back(me);
            while let Some(index) = queue.pop_front() {
                if my_past.contains(&index) {
                    continue;
                }

                debug_assert!(index != parent);
                if index != me {
                    my_past.insert(index);
                }

                let idx_parent = self.arena[index].parent;
                debug_assert!(idx_parent != NULL);
                if parent_anticone.contains(&idx_parent)
                    || parent_futures.contains(&idx_parent)
                {
                    queue.push_back(idx_parent);
                }

                for referee in &self.arena[index].referees {
                    if parent_anticone.contains(referee)
                        || parent_futures.contains(referee)
                    {
                        queue.push_back(*referee);
                    }
                }
            }
            parent_futures
                .union(parent_anticone)
                .cloned()
                .collect::<HashSet<_>>()
                .difference(&my_past)
                .cloned()
                .collect::<HashSet<_>>()
        };

        for index in &anticone {
            self.arena[*index].data.anticone.insert(me);
        }

        debug!(
            "Block {} anticone size {}",
            self.arena[me].hash,
            anticone.len()
        );
        self.arena[me].data.anticone = anticone;
    }

    fn topological_sort(&self, queue: &Vec<usize>) -> Vec<usize> {
        let index_set: HashSet<usize> =
            HashSet::from_iter(queue.iter().cloned());
        let mut num_incoming_edges = HashMap::new();

        for me in queue {
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

        let mut candidates = HashSet::new();
        let mut reversed_indices = Vec::new();

        for me in queue {
            if num_incoming_edges[me] == 0 {
                candidates.insert(*me);
            }
        }
        while !candidates.is_empty() {
            let me = candidates
                .iter()
                .max_by_key(|index| self.arena[**index].hash)
                .cloned()
                .unwrap();
            candidates.remove(&me);
            reversed_indices.push(me);

            let parent = self.arena[me].parent;
            if index_set.contains(&parent) {
                num_incoming_edges.entry(parent).and_modify(|e| *e -= 1);
                if num_incoming_edges[&parent] == 0 {
                    candidates.insert(parent);
                }
            }
            for referee in &self.arena[me].referees {
                if index_set.contains(referee) {
                    num_incoming_edges.entry(*referee).and_modify(|e| *e -= 1);
                    if num_incoming_edges[referee] == 0 {
                        candidates.insert(*referee);
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
        &self, state_at: usize, chain: &Vec<usize>,
    ) -> Option<(usize, usize)> {
        if state_at > REWARD_EPOCH_COUNT as usize {
            let epoch_num = state_at - REWARD_EPOCH_COUNT as usize;
            let anticone_penalty_cutoff_epoch_index =
                epoch_num + ANTICONE_PENALTY_UPPER_EPOCH_COUNT as usize;
            let pivot_index = chain[epoch_num];
            debug_assert!(epoch_num == self.arena[pivot_index].height as usize);
            debug_assert!(
                epoch_num
                    == *self.arena[pivot_index].data.epoch_number.borrow()
            );
            Some((pivot_index, chain[anticone_penalty_cutoff_epoch_index]))
        } else {
            None
        }
    }

    pub fn get_epoch_blocks(
        &self, data_man: &BlockDataManager, epoch_index: usize,
    ) -> Vec<Arc<Block>> {
        let mut epoch_blocks = Vec::new();
        let reversed_indices =
            self.indices_in_epochs.get(&epoch_index).unwrap();
        {
            for idx in reversed_indices {
                let block = data_man
                    .block_by_hash(&self.arena[*idx].hash, false)
                    .expect("Exist");
                epoch_blocks.push(block);
            }
        }
        epoch_blocks
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
                let epoch_blocks = self.get_epoch_blocks(data_man, pivot_index);

                let mut epoch_block_light_difficulties =
                    Vec::with_capacity(epoch_blocks.len());
                let mut epoch_block_is_heavy =
                    Vec::with_capacity(epoch_blocks.len());
                let mut epoch_block_anticone_overlimited =
                    Vec::with_capacity(epoch_blocks.len());
                let mut epoch_block_anticone_set_sizes =
                    Vec::with_capacity(epoch_blocks.len());
                let mut epoch_block_anticone_difficulties =
                    Vec::with_capacity(epoch_blocks.len());

                let epoch_light_difficulty =
                    self.arena[pivot_index].light_difficulty();
                let anticone_cutoff_epoch_anticone_set = &self.arena
                    [anticone_penalty_cutoff_epoch_index]
                    .data
                    .anticone;
                for index in self.indices_in_epochs.get(&pivot_index).unwrap() {
                    let block_consensus_node = &self.arena[*index];

                    epoch_block_light_difficulties
                        .push(block_consensus_node.light_difficulty());
                    epoch_block_is_heavy.push(block_consensus_node.is_heavy);

                    // TODO: partial invalidity is with respect to a certain
                    // TODO: pivot chain block. When pivot chain is reverted
                    // TODO: before the block, anticone should be recomputed.
                    let mut anticone_overlimited =
                        block_consensus_node.data.partial_invalid;
                    let mut anticone_difficulty: U512 = 0.into();
                    // If a block is partial_invalid, it won't have reward and
                    // anticone_difficulty will not be used, so it's okay to set
                    // it to 0.
                    let anticone_set_size;
                    if !anticone_overlimited {
                        let anticone_set = block_consensus_node
                            .data
                            .anticone
                            .difference(anticone_cutoff_epoch_anticone_set)
                            .cloned()
                            .collect::<HashSet<_>>();
                        anticone_set_size = anticone_set.len();

                        for a_index in anticone_set {
                            // TODO: Use base difficulty.
                            anticone_difficulty +=
                                U512::from(self.arena[a_index].difficulty);
                        }

                        // TODO: check the clear definition of anticone penalty,
                        // normally and around the time of difficulty
                        // adjustment.
                        // LINT.IfChange(ANTICONE_PENALTY_1)
                        if anticone_difficulty
                            / U512::from(epoch_light_difficulty)
                            >= U512::from(ANTICONE_PENALTY_RATIO)
                        {
                            anticone_overlimited = true;
                        }
                    // LINT.ThenChange(consensus/consensus_executor.
                    // rs#ANTICONE_PENALTY_2)
                    } else {
                        anticone_set_size = 0;
                    }
                    epoch_block_anticone_set_sizes.push(anticone_set_size);
                    epoch_block_anticone_overlimited.push(anticone_overlimited);
                    epoch_block_anticone_difficulties.push(anticone_difficulty);
                }
                RewardExecutionInfo {
                    epoch_blocks,
                    epoch_block_light_difficulties,
                    epoch_block_is_heavy,
                    epoch_block_anticone_overlimited,
                    epoch_block_anticone_set_sizes,
                    epoch_block_anticone_difficulties,
                }
            },
        )
    }

    fn get_reward_execution_info(
        &self, data_man: &BlockDataManager, state_at: usize, chain: &Vec<usize>,
    ) -> Option<RewardExecutionInfo> {
        self.get_reward_execution_info_from_index(
            data_man,
            self.get_pivot_reward_index(state_at, chain),
        )
    }

    pub fn adjust_difficulty(
        &mut self, new_best_index: usize,
        sync_inner: &SynchronizationGraphInner,
    )
    {
        let new_best_hash = self.arena[new_best_index].hash.clone();
        let new_best_light_difficulty =
            self.arena[new_best_index].light_difficulty();
        let old_best_index = *self.pivot_chain.last().expect("not empty");
        if old_best_index == self.arena[new_best_index].parent {
            // Pivot chain prolonged
            assert!(self.current_difficulty == new_best_light_difficulty);
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
            self.current_difficulty =
                sync_inner.target_difficulty(&new_best_hash);
        } else {
            self.current_difficulty = new_best_light_difficulty;
        }
    }

    pub fn best_block_hash(&self) -> H256 {
        self.arena[*self.pivot_chain.last().unwrap()].hash
    }

    pub fn best_state_epoch_number(&self) -> usize {
        let pivot_len = self.pivot_chain.len();
        if pivot_len < DEFERRED_STATE_EPOCH_COUNT as usize {
            0
        } else {
            pivot_len - DEFERRED_STATE_EPOCH_COUNT as usize
        }
    }

    pub fn best_state_index(&self) -> usize {
        self.pivot_chain[self.best_state_epoch_number()]
    }

    pub fn best_state_block_hash(&self) -> H256 {
        self.arena[self.best_state_index()].hash
    }

    pub fn best_epoch_number(&self) -> usize { self.pivot_chain.len() - 1 }

    pub fn get_height_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<usize, String> {
        Ok(match epoch_number {
            EpochNumber::Earliest => 0,
            EpochNumber::LatestMined => self.best_epoch_number(),
            EpochNumber::LatestState => self.best_state_epoch_number(),
            EpochNumber::Number(num) => {
                let epoch_num: usize = num.as_usize();
                if epoch_num > self.best_epoch_number() {
                    return Err("Invalid params: expected a numbers with less than largest epoch number.".to_owned());
                }
                epoch_num
            }
        })
    }

    pub fn get_index_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<usize, String> {
        self.get_height_from_epoch_number(epoch_number)
            .and_then(|height| Ok(self.pivot_chain[height]))
    }

    pub fn get_hash_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<H256, String> {
        self.get_index_from_epoch_number(epoch_number)
            .and_then(|index| Ok(self.arena[index].hash))
    }

    pub fn block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String> {
        debug!(
            "block_hashes_by_epoch epoch_number={:?} pivot_chain.len={:?}",
            epoch_number,
            self.pivot_chain.len()
        );
        self.get_index_from_epoch_number(epoch_number)
            .and_then(|index| {
                Ok(self
                    .indices_in_epochs
                    .get(&index)
                    .unwrap()
                    .into_iter()
                    .map(|index| self.arena[*index].hash)
                    .collect())
            })
    }

    pub fn epoch_hash(&self, epoch_number: usize) -> Option<H256> {
        self.pivot_chain
            .get(epoch_number)
            .map(|idx| self.arena[*idx].hash)
    }

    pub fn get_epoch_hash_for_block(&self, hash: &H256) -> Option<H256> {
        self.indices.get(hash).and_then(|block_index| {
            let epoch_number =
                self.arena[*block_index].data.epoch_number.borrow().clone();
            self.epoch_hash(epoch_number)
        })
    }

    pub fn get_balance(
        &self, address: H160, epoch_number: EpochNumber,
    ) -> Result<U256, String> {
        let hash = self.get_hash_from_epoch_number(epoch_number)?;
        let state_db = StateDb::new(
            self.data_man.storage_manager.get_state_at(hash).unwrap(),
        );
        Ok(
            if let Ok(maybe_acc) = state_db.get_account(&address, false) {
                maybe_acc.map_or(U256::zero(), |acc| acc.balance).into()
            } else {
                0.into()
            },
        )
    }

    pub fn terminal_hashes(&self) -> Vec<H256> {
        self.terminal_hashes
            .iter()
            .map(|hash| hash.clone())
            .collect()
    }

    pub fn get_block_epoch_number(&self, hash: &H256) -> Option<usize> {
        if let Some(idx) = self.indices.get(hash) {
            Some(self.arena[*idx].data.epoch_number.borrow().clone())
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
                if num.as_usize() > latest_state_epoch {
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
        &self, address: H160, epoch_number: EpochNumber,
    ) -> Result<U256, String> {
        self.validate_stated_epoch(&epoch_number)?;

        let hash = self.get_hash_from_epoch_number(epoch_number)?;
        let state_db = StateDb::new(
            self.data_man.storage_manager.get_state_at(hash).unwrap(),
        );
        let state = State::new(state_db, 0.into(), Default::default());
        state
            .nonce(&address)
            .map_err(|err| format!("Get transaction count error: {:?}", err))
    }

    pub fn get_balance_validated(
        &self, address: H160, epoch_number: EpochNumber,
    ) -> Result<U256, String> {
        self.validate_stated_epoch(&epoch_number)?;
        self.get_balance(address, epoch_number)
    }

    pub fn check_block_pivot_assumption(
        &self, pivot_hash: &H256, epoch: usize,
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

    pub fn persist_terminals(&self) {
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

    /// Compute the total difficulty in the epoch represented by the block of
    /// my_hash The input `my_hash` must have been inserted to sync_graph,
    /// otherwise it'll panic.
    pub fn total_difficulty_in_own_epoch(
        &self, sync: &SynchronizationGraphInner, my_hash: &H256,
    ) -> U256 {
        let my_sync_index = *sync.indices.get(my_hash).expect("exist");
        let mut total_difficulty = U256::zero();
        for index_in_sync in sync.arena[my_sync_index]
            .blockset_in_own_view_of_epoch
            .iter()
        {
            let hash = sync.arena[*index_in_sync].block_header.hash();
            let index_in_consensus = self.indices.get(&hash).unwrap();
            if self.arena[*index_in_consensus].data.partial_invalid {
                continue;
            }
            total_difficulty +=
                sync.arena[*index_in_sync].block_header.difficulty().clone();
        }
        total_difficulty
    }
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
    pub conf: ConsensusConfig,
    pub inner: Arc<RwLock<ConsensusGraphInner>>,
    pub txpool: SharedTransactionPool,
    pub data_man: Arc<BlockDataManager>,
    pub invalid_blocks: RwLock<HashSet<H256>>,
    executor: Arc<ConsensusExecutor>,
    pub statistics: SharedStatistics,
}

pub type SharedConsensusGraph = Arc<ConsensusGraph>;

impl ConsensusGraph {
    /// Build the ConsensusGraph with a genesis block and various other
    /// components The execution will be skipped if bench_mode sets to true.
    pub fn with_genesis_block(
        conf: ConsensusConfig, genesis_block: Block,
        storage_manager: Arc<StorageManager>, vm: VmFactory,
        txpool: SharedTransactionPool, statistics: SharedStatistics,
        db: Arc<SystemDB>, cache_man: Arc<Mutex<CacheManager<CacheId>>>,
        pow_config: ProofOfWorkConfig,
    ) -> Self
    {
        let data_man = Arc::new(BlockDataManager::new(
            Arc::new(genesis_block),
            txpool.clone(),
            db,
            storage_manager,
            cache_man,
            conf.record_tx_address,
        ));
        let inner =
            Arc::new(RwLock::new(ConsensusGraphInner::with_genesis_block(
                pow_config,
                data_man.clone(),
                conf.inner_conf.clone(),
            )));
        let executor = Arc::new(ConsensusExecutor::start(
            data_man.clone(),
            vm,
            inner.clone(),
            conf.bench_mode,
        ));

        ConsensusGraph {
            conf,
            inner,
            txpool,
            data_man: data_man.clone(),
            invalid_blocks: RwLock::new(HashSet::new()),
            executor,
            statistics,
        }
    }

    /// Wait for the generation and the execution completion of a block in the
    /// consensus graph. This API is used mainly for testing purpose
    pub fn wait_for_generation(&self, hash: &H256) {
        while !self.inner.read().indices.contains_key(hash) {
            sleep(Duration::from_millis(100));
        }
        let best_state_block = self.inner.read().best_state_block_hash();
        self.executor.wait_for_result(best_state_block);
    }

    pub fn check_mining_heavy_block(
        &self, inner: &mut ConsensusGraphInner, parent_hash: &H256,
        light_difficulty: &U256,
    ) -> bool
    {
        let parent_index = *inner.indices.get(parent_hash).unwrap();
        inner.check_mining_heavy_block(parent_index, *light_difficulty)
    }

    pub fn get_height_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<usize, String> {
        self.inner.read().get_height_from_epoch_number(epoch_number)
    }

    pub fn best_epoch_number(&self) -> usize {
        self.inner.read().best_epoch_number()
    }

    pub fn verified_invalid(&self, hash: &H256) -> bool {
        self.invalid_blocks.read().contains(hash)
    }

    pub fn invalidate_block(&self, hash: &H256) {
        self.invalid_blocks.write().insert(hash.clone());
    }

    pub fn get_block_total_difficulty(&self, hash: &H256) -> Option<U256> {
        let mut w = self.inner.write();
        if let Some(idx) = w.indices.get(hash).cloned() {
            Some(U256::from(w.weight_tree.get(idx)))
        } else {
            None
        }
    }

    pub fn get_block_epoch_number(&self, hash: &H256) -> Option<usize> {
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

    pub fn get_related_transactions(
        &self, address: H160, num_txs: usize, epoch_number: EpochNumber,
    ) -> Result<Vec<Arc<SignedTransaction>>, String> {
        let inner = self.inner.read();
        inner.get_height_from_epoch_number(epoch_number).and_then(
            |best_epoch_number| {
                let mut transactions = Vec::new();
                if num_txs == 0 {
                    return Ok(transactions);
                }
                let earlist_epoch_number = if best_epoch_number
                    < EPOCH_LIMIT_OF_RELATED_TRANSACTIONS
                {
                    0
                } else {
                    best_epoch_number - EPOCH_LIMIT_OF_RELATED_TRANSACTIONS + 1
                };
                let mut current_epoch_number = best_epoch_number;
                let mut include_hashes = HashSet::new();

                loop {
                    let hashes = inner
                        .block_hashes_by_epoch(EpochNumber::Number(
                            current_epoch_number.into(),
                        ))
                        .unwrap();
                    for hash in hashes {
                        let block = self
                            .data_man
                            .block_by_hash(&hash, false)
                            .expect("Error: Cannot get block by hash.");
                        for tx in block.transactions.iter() {
                            if include_hashes.contains(&tx.hash()) {
                                continue;
                            }
                            let mut is_valid = false;
                            if tx.sender() == address {
                                is_valid = true;
                            } else if let Action::Call(receiver_address) =
                                tx.action
                            {
                                if receiver_address == address {
                                    is_valid = true;
                                }
                            }
                            if is_valid {
                                transactions.push(tx.clone());
                                include_hashes.insert(tx.hash());
                                if transactions.len() == num_txs {
                                    return Ok(transactions);
                                }
                            }
                        }
                    }
                    if current_epoch_number == earlist_epoch_number {
                        break;
                    }
                    current_epoch_number -= 1;
                }

                Ok(transactions)
            },
        )
    }

    pub fn get_account(
        &self, address: H160, num_txs: usize, epoch_number: EpochNumber,
    ) -> Result<(U256, Vec<Arc<SignedTransaction>>), String> {
        let inner = self.inner.read();
        inner
            .get_balance_validated(address, epoch_number.clone())
            .and_then(|balance| {
                self.get_related_transactions(address, num_txs, epoch_number)
                    .and_then(|transactions| Ok((balance, transactions)))
            })
    }

    pub fn get_epoch_blocks(
        &self, inner: &ConsensusGraphInner, epoch_index: usize,
    ) -> Vec<Arc<Block>> {
        inner.get_epoch_blocks(&self.data_man, epoch_index)
    }

    // TODO Merge logic.
    /// This is a very expensive call to force the engine to recompute the state
    /// root of a given block
    pub fn compute_state_for_block(
        &self, block_hash: &H256, inner: &mut ConsensusGraphInner,
    ) -> (H256, H256) {
        // If we already computed the state of the block before, we should not
        // do it again FIXME: propagate the error up
        info!("compute_state_for_block {:?}", block_hash);
        {
            let cached_state = self
                .data_man
                .storage_manager
                .get_state_at(block_hash.clone())
                .unwrap();
            if cached_state.does_exist() {
                if let Some(receipts_root) =
                    self.data_man.get_receipts_root(&block_hash)
                {
                    return (
                        cached_state.get_state_root().unwrap().unwrap(),
                        receipts_root,
                    );
                }
            }
        }
        // FIXME: propagate the error up
        let me: usize = inner.indices.get(block_hash).unwrap().clone();
        let block_height = inner.arena[me].height as usize;
        let mut fork_height = block_height;
        let mut chain: Vec<usize> = Vec::new();
        let mut idx = me;
        while fork_height > 0
            && (fork_height >= inner.pivot_chain.len()
                || inner.pivot_chain[fork_height] != idx)
        {
            chain.push(idx);
            fork_height -= 1;
            idx = inner.arena[idx].parent;
        }
        // Because we have genesis at height 0, this should always be true
        debug_assert!(inner.pivot_chain[fork_height] == idx);
        debug!("Forked at index {} height {}", idx, fork_height);
        chain.push(idx);
        chain.reverse();
        let mut epoch_number_map: HashMap<usize, usize> = HashMap::new();

        // Construct epochs
        for fork_at in 1..chain.len() {
            // First, identify all the blocks in the current epoch of the
            // hypothetical pivot chain
            let mut queue = Vec::new();
            {
                let new_epoch_number = fork_at + fork_height;
                let enqueue_if_new =
                    |queue: &mut Vec<usize>,
                     epoch_number_map: &mut HashMap<usize, usize>,
                     index| {
                        let epoch_number =
                            inner.arena[index].data.epoch_number.borrow();
                        if (*epoch_number == NULL
                            || *epoch_number > fork_height)
                            && !epoch_number_map.contains_key(&index)
                        {
                            epoch_number_map.insert(index, new_epoch_number);
                            queue.push(index);
                        }
                    };

                let mut at = 0;
                enqueue_if_new(
                    &mut queue,
                    &mut epoch_number_map,
                    chain[fork_at],
                );
                while at < queue.len() {
                    let me = queue[at];
                    for referee in &inner.arena[me].referees {
                        enqueue_if_new(
                            &mut queue,
                            &mut epoch_number_map,
                            *referee,
                        );
                    }
                    enqueue_if_new(
                        &mut queue,
                        &mut epoch_number_map,
                        inner.arena[me].parent,
                    );
                    at += 1;
                }
            }

            // Second, sort all the blocks based on their topological order
            // and break ties with block hash
            let reversed_indices = inner.topological_sort(&queue);

            debug!(
                "Construct epoch_id={}, block_count={}",
                inner.arena[chain[fork_at]].hash,
                reversed_indices.len()
            );

            inner
                .indices_in_epochs
                .insert(chain[fork_at], reversed_indices);
        }

        let mut last_state_height =
            if inner.pivot_chain.len() > DEFERRED_STATE_EPOCH_COUNT as usize {
                inner.pivot_chain.len() - DEFERRED_STATE_EPOCH_COUNT as usize
            } else {
                0
            };

        last_state_height += 1;
        while last_state_height <= fork_height {
            let epoch_index = inner.pivot_chain[last_state_height];
            let reward_execution_info = inner.get_reward_execution_info(
                &self.data_man,
                last_state_height,
                &inner.pivot_chain,
            );
            self.executor.enqueue_epoch(EpochExecutionTask::new(
                inner.arena[epoch_index].hash,
                inner.get_epoch_block_hashes(epoch_index),
                reward_execution_info,
                false,
                false,
            ));
            last_state_height += 1;
        }

        for fork_at in 1..chain.len() {
            let epoch_index = chain[fork_at];
            let reward_index = if fork_height + fork_at
                > REWARD_EPOCH_COUNT as usize
            {
                let epoch_num =
                    fork_height + fork_at - REWARD_EPOCH_COUNT as usize;
                let anticone_penalty_cutoff_epoch_num =
                    epoch_num + ANTICONE_PENALTY_UPPER_EPOCH_COUNT as usize;
                let pivot_block_upper =
                    if anticone_penalty_cutoff_epoch_num > fork_height {
                        chain[anticone_penalty_cutoff_epoch_num - fork_height]
                    } else {
                        inner.pivot_chain[anticone_penalty_cutoff_epoch_num]
                    };
                let pivot_index = if epoch_num > fork_height {
                    chain[epoch_num - fork_height]
                } else {
                    inner.pivot_chain[epoch_num]
                };
                Some((pivot_index, pivot_block_upper))
            } else {
                None
            };
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

        // FIXME: Propagate errors upward
        let (state_root, receipts_root) =
            self.executor.wait_for_result(*block_hash);
        debug!(
            "Epoch {:?} has state_root={:?} receipts_root={:?}",
            inner.arena[me].hash, state_root, receipts_root
        );

        (state_root, receipts_root)
    }

    pub fn compute_deferred_state_for_block(
        &self, block_hash: &H256, delay: usize,
    ) -> (H256, H256) {
        let inner = &mut *self.inner.write();

        // FIXME: Propagate errors upward
        let mut idx = inner.indices.get(block_hash).unwrap().clone();
        for _i in 0..delay {
            if idx == inner.genesis_block_index {
                break;
            }
            idx = inner.arena[idx].parent;
        }
        let hash = inner.arena[idx].hash;
        self.compute_state_for_block(&hash, inner)
    }

    fn log_debug_epoch_computation(
        &self, epoch_index: usize, inner: &ConsensusGraphInner,
    ) -> ComputeEpochDebugRecord {
        let epoch_block_hash = inner.arena[epoch_index].hash;

        let epoch_block_hashes = {
            let epoch_blocks =
                inner.indices_in_epochs.get(&epoch_index).unwrap();

            epoch_blocks
                .iter()
                .map(|index| inner.arena[*index].hash)
                .collect::<Vec<_>>()
        };

        // Parent state root.
        let parent_index = inner.arena[epoch_index].parent;
        let parent_block_hash = inner.arena[parent_index].hash;
        let parent_state_root = inner
            .data_man
            .storage_manager
            .get_state_at(parent_block_hash)
            .unwrap()
            .get_state_root()
            .unwrap()
            .unwrap();

        // Recompute epoch.
        let anticone_cut_height =
            REWARD_EPOCH_COUNT - ANTICONE_PENALTY_UPPER_EPOCH_COUNT;
        let mut anticone_penalty_cutoff_epoch_block = parent_index;
        for _i in 1..anticone_cut_height {
            if anticone_penalty_cutoff_epoch_block == NULL {
                break;
            }
            anticone_penalty_cutoff_epoch_block =
                inner.arena[anticone_penalty_cutoff_epoch_block].parent;
        }
        let mut reward_epoch_block = anticone_penalty_cutoff_epoch_block;
        for _i in 0..ANTICONE_PENALTY_UPPER_EPOCH_COUNT {
            if reward_epoch_block == NULL {
                break;
            }
            reward_epoch_block = inner.arena[reward_epoch_block].parent;
        }
        let reward_index = if reward_epoch_block == NULL {
            None
        } else {
            Some((reward_epoch_block, anticone_penalty_cutoff_epoch_block))
        };

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
            debug_record.reward_epoch_hash = if reward_epoch_block != NULL {
                Some(inner.arena[reward_epoch_block].hash)
            } else {
                None
            };
            debug_record.anticone_penalty_cutoff_epoch_hash =
                if anticone_penalty_cutoff_epoch_block != NULL {
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
        &self, expected_state_root: &H256, got_state_root: &H256,
        deferred: usize, inner: &ConsensusGraphInner,
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
        sync_graph: &SynchronizationGraphInner,
    ) -> bool
    {
        if inner.arena[inner.arena[new].parent].data.partial_invalid {
            warn!(
                "Partially invalid due to partially invalid parent. {:?}",
                block.block_header.clone()
            );
            return false;
        }

        // Check whether the new block select the correct parent block
        if !inner.check_correct_parent(new, sync_graph) {
            warn!(
                "Partially invalid due to picking incorrect parent. {:?}",
                block.block_header.clone()
            );
            return false;
        }

        // Check heavy block
        if inner.arena[new].is_heavy {
            if !inner.check_heavy_block(new) {
                warn!(
                    "Partially invalid due to invalid heavy block. {:?}",
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
                .contains_state(inner.arena[deferred].hash)
                && correct_receipts_root.is_some()
            {
                let mut valid = true;
                let correct_state_root = self
                    .data_man
                    .storage_manager
                    .get_state_at(inner.arena[deferred].hash)
                    .unwrap()
                    .get_state_root()
                    .unwrap()
                    .unwrap();
                if *block.block_header.deferred_state_root()
                    != correct_state_root
                {
                    self.log_invalid_state_root(
                        &correct_state_root,
                        &block.block_header.deferred_state_root(),
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
                let (state_root, receipts_root) =
                    self.compute_state_for_block(&deferred_hash, inner);

                if state_root != *block.block_header.deferred_state_root() {
                    self.log_invalid_state_root(
                        &state_root,
                        block.block_header.deferred_state_root(),
                        deferred,
                        inner,
                    )
                    .ok();
                }

                *block.block_header.deferred_state_root() == state_root
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

    pub fn construct_pivot(
        &self, sync_inner_lock: &RwLock<SynchronizationGraphInner>,
    ) {
        {
            let sync_inner = &*sync_inner_lock.read();
            let mut inner = &mut *self.inner.write();

            assert_eq!(inner.pivot_chain.len(), 1);
            assert_eq!(inner.pivot_chain[0], inner.genesis_block_index);

            let mut new_pivot_chain = Vec::new();
            let mut u = inner.genesis_block_index;
            loop {
                new_pivot_chain.push(u);
                let mut heaviest = NULL;
                let mut heaviest_weight = SignedBigNum::zero();
                for index in &inner.arena[u].children {
                    let weight = inner.weight_tree.get(*index);
                    if heaviest == NULL
                        || ConsensusGraphInner::is_heavier(
                            (&weight, &inner.arena[*index].hash),
                            (&heaviest_weight, &inner.arena[heaviest].hash),
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
            let mut height = 1;
            while height < new_pivot_chain.len() {
                // First, identify all the blocks in the current epoch
                let mut queue = Vec::new();
                {
                    let copy_of_fork_at = height;
                    let enqueue_if_new = |queue: &mut Vec<usize>, index| {
                        let mut epoch_number =
                            inner.arena[index].data.epoch_number.borrow_mut();
                        if *epoch_number == NULL {
                            *epoch_number = copy_of_fork_at;
                            queue.push(index);
                        }
                    };

                    let mut at = 0;
                    enqueue_if_new(&mut queue, new_pivot_chain[height]);
                    while at < queue.len() {
                        let me = queue[at];
                        for referee in &inner.arena[me].referees {
                            enqueue_if_new(&mut queue, *referee);
                        }
                        enqueue_if_new(&mut queue, inner.arena[me].parent);
                        at += 1;
                    }
                }

                // Second, sort all the blocks based on their topological order
                // and break ties with block hash
                let reversed_indices = inner.topological_sort(&queue);
                debug!(
                    "Construct epoch_id={}, block_count={}",
                    inner.arena[new_pivot_chain[height]].hash,
                    reversed_indices.len()
                );
                inner
                    .indices_in_epochs
                    .insert(new_pivot_chain[height], reversed_indices);

                // Construct in-memory receipts root
                if new_pivot_chain.len() >= DEFERRED_STATE_EPOCH_COUNT as usize
                    && height
                        < new_pivot_chain.len()
                            - DEFERRED_STATE_EPOCH_COUNT as usize
                {
                    // This block's deferred block is pivot_index, so the
                    // deferred_receipts_root in its header is the
                    // receipts_root of pivot_index
                    let future_block_hash = inner.arena[new_pivot_chain
                        [height + DEFERRED_STATE_EPOCH_COUNT as usize]]
                        .hash
                        .clone();
                    self.data_man.insert_receipts_root(
                        inner.arena[new_pivot_chain[height]].hash,
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
            inner.adjust_difficulty(
                *new_pivot_chain.last().expect("not empty"),
                sync_inner,
            );
            inner.pivot_chain = new_pivot_chain;
        }
        {
            let inner = &*self.inner.read();
            // Compute receipts root for the deferred block of the mining block,
            // which is not in the db
            if inner.pivot_chain.len() > DEFERRED_STATE_EPOCH_COUNT as usize {
                let state_height = inner.pivot_chain.len()
                    - DEFERRED_STATE_EPOCH_COUNT as usize;
                let pivot_index = inner.pivot_chain[state_height];
                let pivot_hash = inner.arena[pivot_index].hash.clone();
                let epoch_indexes =
                    inner.indices_in_epochs.get(&pivot_index).unwrap().clone();
                let mut epoch_receipts =
                    Vec::with_capacity(epoch_indexes.len());

                let mut receipts_correct = true;
                for i in epoch_indexes {
                    if let Some(r) =
                        self.data_man.block_results_by_hash_with_epoch(
                            &inner.arena[i].hash,
                            &pivot_hash,
                            true,
                        )
                    {
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
                    let reward_execution_info = inner
                        .get_reward_execution_info(
                            &self.data_man,
                            state_height,
                            &inner.pivot_chain,
                        );
                    let epoch_block_hashes = inner.get_epoch_block_hashes(
                        inner.pivot_chain[state_height],
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
    }

    /// This is the function to insert a new block into the consensus graph
    /// during construction. We by pass many verifications because those
    /// blocks are from our own database so we trust them.
    pub fn on_new_block_construction_only(
        &self, hash: &H256, sync_inner: &SynchronizationGraphInner,
    ) {
        let block = self.data_man.block_by_hash(hash, false).unwrap();

        let inner = &mut *self.inner.write();
        let difficulty_in_my_epoch;
        let is_heavy;
        {
            difficulty_in_my_epoch =
                inner.total_difficulty_in_own_epoch(sync_inner, hash);
            is_heavy = sync_inner.arena[*sync_inner.indices.get(hash).unwrap()]
                .is_heavy;
        }
        let parent_idx =
            *inner.indices.get(block.block_header.parent_hash()).unwrap();
        let past_difficulty = inner.arena[parent_idx].past_difficulty
            + inner.arena[parent_idx].difficulty
            + difficulty_in_my_epoch;

        let (me, indices_len) =
            inner.insert(block.as_ref(), past_difficulty, is_heavy);
        self.statistics
            .set_consensus_graph_inserted_block_count(indices_len);

        let parent = inner.arena[me].parent;

        inner.weight_tree.make_tree(me);
        inner.weight_tree.link(parent, me);

        inner.stable_tree.make_tree(me);
        inner.stable_tree.link(parent, me);
        inner.stable_tree.set(
            me,
            &SignedBigNum::pos(
                U256::from(inner.inner_conf.adaptive_weight_alpha_num)
                    * U256::from(
                        inner.arena[parent].difficulty
                            + inner.arena[parent].past_difficulty,
                    ),
            ),
        );

        inner.compute_anticone(me);
        let fully_valid = if let Some(partial_invalid) =
            self.data_man.block_status_from_db(hash)
        {
            !partial_invalid
        } else {
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
            debug!("Assume block {} is valid", hash);
            true
        };
        if !fully_valid {
            inner.arena[me].data.partial_invalid = true;
            return;
        }

        let (stable, adaptive) = inner.adaptive_weight(me);
        inner.arena[me].stable = stable;
        inner.arena[me].adaptive = adaptive;

        inner.weight_tree.path_apply(
            me,
            &SignedBigNum::pos(*block.block_header.difficulty()),
        );

        inner.stable_tree.path_apply(
            me,
            &SignedBigNum::pos(
                U256::from(inner.inner_conf.adaptive_weight_alpha_den)
                    * U256::from(*block.block_header.difficulty()),
            ),
        );
    }

    /// This is the main function that SynchronizationGraph calls to deliver a
    /// new block to the consensus graph.
    pub fn on_new_block(
        &self, hash: &H256, sync_inner_lock: &RwLock<SynchronizationGraphInner>,
    ) {
        let block = self.data_man.block_by_hash(hash, true).unwrap();

        debug!(
            "insert new block into consensus: block_header={:?} tx_count={}, block_size={}",
            block.block_header,
            block.transactions.len(),
            block.size(),
        );

        {
            // When a tx is executed successfully, it will be removed from
            // `unexecuted_transaction_addresses` If a tx is
            // executed with failure(InvalidNonce), or the block packing it is
            // never refered and executed, only the corresponding tx address
            // will be removed. After a tx is removed from
            // `unexecuted_transaction_addresses` because of
            // successful execution, its new nonce will be available in state
            // and it will not be inserted to tx pool again.
            let mut unexecuted_transaction_addresses =
                self.txpool.unexecuted_transaction_addresses.lock();
            let mut cache_man = self.data_man.cache_man.lock();
            for (idx, tx) in block.transactions.iter().enumerate() {
                // If an executed tx
                let tx_hash = tx.hash();
                if let Some(addr_set) =
                    unexecuted_transaction_addresses.get_mut(&tx_hash)
                {
                    addr_set.insert(TransactionAddress {
                        block_hash: hash.clone(),
                        index: idx,
                    });
                } else {
                    let mut addr_set = HashSet::new();
                    addr_set.insert(TransactionAddress {
                        block_hash: hash.clone(),
                        index: idx,
                    });
                    unexecuted_transaction_addresses.insert(tx_hash, addr_set);
                    cache_man.note_used(CacheId::UnexecutedTransactionAddress(
                        tx_hash,
                    ));
                }
            }
        }

        let mut inner = &mut *self.inner.write();

        let is_heavy;
        let difficulty_in_my_epoch;
        {
            let sync_inner = sync_inner_lock.read();
            is_heavy = sync_inner.arena[*sync_inner.indices.get(hash).unwrap()]
                .is_heavy;
            difficulty_in_my_epoch =
                inner.total_difficulty_in_own_epoch(&*sync_inner, hash);
        }

        let parent_idx =
            *inner.indices.get(block.block_header.parent_hash()).unwrap();
        let past_difficulty = inner.arena[parent_idx].past_difficulty
            + inner.arena[parent_idx].difficulty
            + difficulty_in_my_epoch;

        let (me, indices_len) =
            inner.insert(block.as_ref(), past_difficulty, is_heavy);
        self.statistics
            .set_consensus_graph_inserted_block_count(indices_len);

        // It's only correct to set tx stale after the block is considered
        // terminal for mining.
        for tx in block.transactions.iter() {
            self.txpool.remove_pending(&*tx);
            self.txpool.remove_ready(tx.clone());
        }

        inner.compute_anticone(me);

        let fully_valid = self.check_block_full_validity(
            me,
            block.as_ref(),
            inner,
            &*sync_inner_lock.read(),
        );
        self.data_man.insert_block_status_to_db(hash, !fully_valid);

        let parent = inner.arena[me].parent;

        inner.weight_tree.make_tree(me);
        inner.weight_tree.link(parent, me);

        inner.stable_tree.make_tree(me);
        inner.stable_tree.link(parent, me);
        inner.stable_tree.set(
            me,
            &SignedBigNum::pos(
                U256::from(inner.inner_conf.adaptive_weight_alpha_num)
                    * U256::from(
                        inner.arena[parent].difficulty
                            + inner.arena[parent].past_difficulty,
                    ),
            ),
        );

        if !fully_valid {
            inner.arena[me].data.partial_invalid = true;
            return;
        }
        debug!(
            "Block {} (hash = {}) is fully valid",
            me, inner.arena[me].hash
        );

        let (stable, adaptive) = inner.adaptive_weight(me);
        inner.arena[me].stable = stable;
        inner.arena[me].adaptive = adaptive;

        inner.weight_tree.path_apply(
            me,
            &SignedBigNum::pos(*block.block_header.difficulty()),
        );
        inner.stable_tree.path_apply(
            me,
            &SignedBigNum::pos(
                U256::from(inner.inner_conf.adaptive_weight_alpha_den)
                    * U256::from(*block.block_header.difficulty()),
            ),
        );

        let last = inner.pivot_chain.last().cloned().unwrap();
        // TODO: constructing new_pivot_chain without cloning!
        let mut new_pivot_chain = inner.pivot_chain.clone();
        let fork_at = if inner.arena[me].parent == last {
            new_pivot_chain.push(me);
            inner.pivot_chain.len()
        } else {
            let lca = inner.weight_tree.lca(last, me);

            let fork_at = inner.arena[lca].height as usize + 1;
            let prev = inner.pivot_chain[fork_at];
            let prev_weight = inner.weight_tree.get(prev);
            let new = inner.weight_tree.ancestor_at(me, fork_at as usize);
            let new_weight = inner.weight_tree.get(new);

            if ConsensusGraphInner::is_heavier(
                (&new_weight, &inner.arena[new].hash),
                (&prev_weight, &inner.arena[prev].hash),
            ) {
                // The new subtree is heavier, update pivot chain
                new_pivot_chain.truncate(fork_at);
                let mut u = new;
                loop {
                    new_pivot_chain.push(u);
                    let mut heaviest = NULL;
                    let mut heaviest_weight = SignedBigNum::zero();
                    for index in &inner.arena[u].children {
                        let weight = inner.weight_tree.get(*index);
                        if heaviest == NULL
                            || ConsensusGraphInner::is_heavier(
                                (&weight, &inner.arena[*index].hash),
                                (&heaviest_weight, &inner.arena[heaviest].hash),
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
                fork_at
            } else {
                // The previous subtree is still heavier, nothing is updated
                debug!("Finish Consensus.on_new_block() with pivot chain unchanged");
                inner.pivot_chain.len()
            }
        };
        debug!("Forked at index {}", new_pivot_chain[fork_at - 1]);

        if fork_at < inner.pivot_chain.len() {
            let enqueue_if_obsolete = |queue: &mut VecDeque<usize>, index| {
                let mut epoch_number =
                    inner.arena[index].data.epoch_number.borrow_mut();
                if *epoch_number != NULL && *epoch_number >= fork_at {
                    *epoch_number = NULL;
                    queue.push_back(index);
                }
            };

            let mut queue = VecDeque::new();
            enqueue_if_obsolete(&mut queue, last);
            while let Some(me) = queue.pop_front() {
                for referee in inner.arena[me].referees.clone() {
                    enqueue_if_obsolete(&mut queue, referee);
                }
                enqueue_if_obsolete(&mut queue, inner.arena[me].parent);
            }
        }

        assert_ne!(fork_at, 0);

        // Construct epochs
        let mut pivot_index = fork_at;
        while pivot_index < new_pivot_chain.len() {
            // First, identify all the blocks in the current epoch
            let mut queue = Vec::new();
            {
                let copy_of_fork_at = pivot_index;
                let enqueue_if_new = |queue: &mut Vec<usize>, index| {
                    let mut epoch_number =
                        inner.arena[index].data.epoch_number.borrow_mut();
                    if *epoch_number == NULL {
                        *epoch_number = copy_of_fork_at;
                        queue.push(index);
                    }
                };

                let mut at = 0;
                enqueue_if_new(&mut queue, new_pivot_chain[pivot_index]);
                while at < queue.len() {
                    let me = queue[at];
                    for referee in &inner.arena[me].referees {
                        enqueue_if_new(&mut queue, *referee);
                    }
                    enqueue_if_new(&mut queue, inner.arena[me].parent);
                    at += 1;
                }
            }

            // Second, sort all the blocks based on their topological order
            // and break ties with block hash
            let reversed_indices = inner.topological_sort(&queue);

            debug!(
                "Construct epoch_id={}, block_count={}",
                inner.arena[new_pivot_chain[pivot_index]].hash,
                reversed_indices.len()
            );

            inner
                .indices_in_epochs
                .insert(new_pivot_chain[pivot_index], reversed_indices);

            pivot_index += 1;
        }

        let to_state_pos =
            if new_pivot_chain.len() < DEFERRED_STATE_EPOCH_COUNT as usize {
                0 as usize
            } else {
                new_pivot_chain.len() - DEFERRED_STATE_EPOCH_COUNT as usize + 1
            };

        let mut state_at = fork_at;
        if fork_at + DEFERRED_STATE_EPOCH_COUNT as usize
            > inner.pivot_chain.len()
        {
            if inner.pivot_chain.len() > DEFERRED_STATE_EPOCH_COUNT as usize {
                state_at = inner.pivot_chain.len()
                    - DEFERRED_STATE_EPOCH_COUNT as usize
                    + 1;
            } else {
                state_at = 1;
            }
        }

        // Apply transactions in the determined total order
        while state_at < to_state_pos {
            let epoch_index = new_pivot_chain[state_at];
            let reward_execution_info = inner.get_reward_execution_info(
                &self.data_man,
                state_at,
                &new_pivot_chain,
            );
            self.executor.enqueue_epoch(EpochExecutionTask::new(
                inner.arena[epoch_index].hash,
                inner.get_epoch_block_hashes(epoch_index),
                reward_execution_info,
                true,
                false,
            ));
            state_at += 1;
        }

        inner.adjust_difficulty(
            *new_pivot_chain.last().expect("not empty"),
            &*sync_inner_lock.read(),
        );
        inner.pivot_chain = new_pivot_chain;
        inner.optimistic_executed_height = if to_state_pos > 0 {
            Some(to_state_pos)
        } else {
            None
        };
        inner.persist_terminals();
        debug!("Finish processing block in ConsensusGraph: hash={:?}", hash);
    }

    pub fn best_block_hash(&self) -> H256 {
        self.inner.read().best_block_hash()
    }

    pub fn best_state_epoch_number(&self) -> usize {
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

    pub fn best_state_block_hash(&self) -> H256 {
        self.inner.read().best_state_block_hash()
    }

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

            if filter.from_epoch >= inner.pivot_chain.len() {
                return Ok(Vec::new());
            }

            let from_epoch = filter.from_epoch;
            let to_epoch = min(filter.to_epoch, inner.pivot_chain.len());

            let blooms = filter.bloom_possibilities();
            let bloom_match = |block_log_bloom: &Bloom| {
                blooms
                    .iter()
                    .any(|bloom| block_log_bloom.contains_bloom(bloom))
            };

            let mut blocks = Vec::new();
            for epoch_idx in from_epoch..to_epoch {
                let epoch_hash = inner.arena[epoch_idx].hash;
                for index in inner
                    .indices_in_epochs
                    .get(&inner.pivot_chain[epoch_idx])
                    .unwrap()
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
    pub fn wait_for_block_state(&self, block_hash: &H256) -> (H256, H256) {
        self.executor.wait_for_result(*block_hash)
    }
}

impl Drop for ConsensusGraph {
    fn drop(&mut self) { self.executor.stop(); }
}
