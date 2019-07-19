// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockDataManager,
    consensus::{ConsensusGraphInner, SharedConsensusGraph},
    error::{BlockError, Error, ErrorKind},
    machine::new_machine,
    pow::ProofOfWorkConfig,
    statistics::SharedStatistics,
    verification::*,
};
use cfx_types::{H256, U256};
use metrics::{register_meter_with_group, Meter, MeterTimer};
use parking_lot::{Mutex, RwLock};
use primitives::{
    transaction::SignedTransaction, Block, BlockHeader, EpochNumber,
};
use slab::Slab;
use std::{
    cmp::max,
    collections::{HashMap, HashSet, VecDeque},
    mem,
    sync::{
        mpsc::{self, Sender},
        Arc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use unexpected::{Mismatch, OutOfBounds};

lazy_static! {
    static ref SYNC_INSERT_HEADER: Arc<Meter> =
        register_meter_with_group("timer", "sync::insert_block_header");
    static ref SYNC_INSERT_BLOCK: Arc<Meter> =
        register_meter_with_group("timer", "sync::insert_block");
}

const NULL: usize = !0;
const BLOCK_INVALID: u8 = 0;
const BLOCK_HEADER_ONLY: u8 = 1;
const BLOCK_HEADER_PARENTAL_TREE_READY: u8 = 2;
const BLOCK_HEADER_GRAPH_READY: u8 = 3;
const BLOCK_GRAPH_READY: u8 = 4;

#[derive(Debug)]
pub struct SyncGraphStatistics {
    pub inserted_block_count: usize,
}

impl SyncGraphStatistics {
    pub fn new() -> SyncGraphStatistics {
        SyncGraphStatistics {
            // Already counted genesis block
            inserted_block_count: 1,
        }
    }
}

pub struct SynchronizationGraphNode {
    pub block_header: Arc<BlockHeader>,
    /// The status of graph connectivity in the current block view.
    pub graph_status: u8,
    /// Whether the block body is ready.
    pub block_ready: bool,
    /// Whether parent is in old era and already reclaimed
    pub parent_reclaimed: bool,
    /// The index of the parent of the block.
    pub parent: usize,
    /// The indices of the children of the block.
    pub children: Vec<usize>,
    /// The indices of the blocks referenced by the block.
    pub referees: Vec<usize>,
    /// The number of blocks referenced by the block but
    /// haven't been inserted in synchronization graph.
    pub pending_referee_count: usize,
    /// The indices of the blocks referencing the block.
    pub referrers: Vec<usize>,
    /// the timestamp in seconds when graph_status updated
    pub last_update_timestamp: u64,
}

pub struct SynchronizationGraphInner {
    pub arena: Slab<SynchronizationGraphNode>,
    pub hash_to_arena_indices: HashMap<H256, usize>,
    pub data_man: Arc<BlockDataManager>,
    pub genesis_block_index: usize,
    children_by_hash: HashMap<H256, Vec<usize>>,
    referrers_by_hash: HashMap<H256, Vec<usize>>,
    pub pow_config: ProofOfWorkConfig,
    /// the indices of blocks whose graph_status is not GRAPH_READY
    pub not_ready_blocks_frontier: HashSet<usize>,
    pub not_ready_blocks_count: usize,
    pub old_era_blocks_frontier: VecDeque<usize>,
    pub old_era_blocks_frontier_set: HashSet<usize>,
}

impl SynchronizationGraphInner {
    pub fn with_genesis_block(
        genesis_header: Arc<BlockHeader>, pow_config: ProofOfWorkConfig,
        data_man: Arc<BlockDataManager>,
    ) -> Self
    {
        let mut inner = SynchronizationGraphInner {
            arena: Slab::new(),
            hash_to_arena_indices: HashMap::new(),
            data_man,
            genesis_block_index: NULL,
            children_by_hash: HashMap::new(),
            referrers_by_hash: HashMap::new(),
            pow_config,
            not_ready_blocks_frontier: HashSet::new(),
            not_ready_blocks_count: 0,
            old_era_blocks_frontier: Default::default(),
            old_era_blocks_frontier_set: Default::default(),
        };
        inner.genesis_block_index = inner.insert(genesis_header);
        debug!(
            "genesis_block_index in sync graph: {}",
            inner.genesis_block_index
        );

        inner
            .old_era_blocks_frontier
            .push_back(inner.genesis_block_index);
        inner
            .old_era_blocks_frontier_set
            .insert(inner.genesis_block_index);

        inner
    }

    fn get_genesis_in_current_era(&self) -> usize {
        let genesis_hash = self.data_man.get_cur_consensus_era_genesis_hash();
        *self.hash_to_arena_indices.get(&genesis_hash).unwrap()
    }

    pub fn get_genesis_hash_and_height_in_current_era(&self) -> (H256, u64) {
        let era_genesis = self.get_genesis_in_current_era();
        (
            self.arena[era_genesis].block_header.hash(),
            self.arena[era_genesis].block_header.height(),
        )
    }

    fn try_clear_old_era_blocks(&mut self) {
        let max_num_of_cleared_blocks = 2;
        let mut num_cleared = 0;
        let era_genesis = self.get_genesis_in_current_era();
        let mut era_genesis_in_frontier = false;

        while let Some(index) = self.old_era_blocks_frontier.pop_front() {
            if index == era_genesis {
                era_genesis_in_frontier = true;
                continue;
            }

            // Remove node with index
            if !self.old_era_blocks_frontier_set.contains(&index) {
                continue;
            }

            let hash = self.arena[index].block_header.hash();
            assert!(self.arena[index].parent == NULL);

            let referees: Vec<usize> =
                self.arena[index].referees.iter().map(|x| *x).collect();
            for referee in referees {
                self.arena[referee].referrers.retain(|&x| x != index);
            }
            let referee_hashes: Vec<H256> = self.arena[index]
                .block_header
                .referee_hashes()
                .iter()
                .map(|x| *x)
                .collect();
            for referee_hash in referee_hashes {
                let mut remove_referee_hash: bool = false;
                if let Some(referrers) =
                    self.referrers_by_hash.get_mut(&referee_hash)
                {
                    referrers.retain(|&x| x != index);
                    remove_referee_hash = referrers.len() == 0;
                }
                // clean empty key
                if remove_referee_hash {
                    self.referrers_by_hash.remove(&referee_hash);
                }
            }

            let children: Vec<usize> =
                self.arena[index].children.iter().map(|x| *x).collect();
            for child in children {
                self.arena[child].parent = NULL;
                self.arena[child].parent_reclaimed = true;
                if self.arena[child].graph_status == BLOCK_GRAPH_READY {
                    // We can only reclaim graph-ready blocks
                    self.old_era_blocks_frontier.push_back(child);
                    assert!(!self.old_era_blocks_frontier_set.contains(&child));
                    self.old_era_blocks_frontier_set.insert(child);
                }
            }

            let referrers: Vec<usize> =
                self.arena[index].referrers.iter().map(|x| *x).collect();
            for referrer in referrers {
                self.arena[referrer].referees.retain(|&x| x != index);
            }

            self.old_era_blocks_frontier_set.remove(&index);
            self.arena.remove(index);
            self.hash_to_arena_indices.remove(&hash);
            self.data_man.remove_block_header(&hash);

            num_cleared += 1;
            if num_cleared == max_num_of_cleared_blocks {
                break;
            }
        }

        if era_genesis_in_frontier {
            self.old_era_blocks_frontier.push_front(era_genesis);
        }
    }

    fn try_recover_expire_block(&mut self) -> (Vec<usize>, Vec<usize>) {
        let mut graph_ready_blocks = Vec::new();
        let mut header_graph_ready_blocks = Vec::new();
        for index in &self.not_ready_blocks_frontier {
            let parent_hash = self.arena[*index].block_header.parent_hash();

            // parent and referees are all in memory, status must be
            // BLOCK_HEADER_GRAPH_READY no need to recover
            if self.arena[*index].parent != NULL
                && self.arena[*index].pending_referee_count == 0
            {
                continue;
            }

            // check whether parent is BLOCK_GRAPH_READY
            // 1. parent not in memory and not invalid in disk (assume this
            // block was BLOCK_GRAPH_READY)
            // 2. parent in memory and status is BLOCK_GRAPH_READY
            let parent_graph_ready: bool = {
                if self.arena[*index].parent == NULL {
                    if let Some(_) =
                        self.data_man.block_by_hash(parent_hash, false)
                    {
                        !self.data_man.verified_invalid(parent_hash)
                    } else {
                        false
                    }
                } else if self.arena[*index].parent != NULL
                    && self.arena[self.arena[*index].parent].graph_status
                        == BLOCK_GRAPH_READY
                {
                    true
                } else {
                    false
                }
            };

            if !parent_graph_ready {
                continue;
            }

            // check whether referees are BLOCK_GRAPH_READY
            //  1. referees which are in memory and status is BLOCK_GRAPH_READY
            //  2. referees which are not in memory and not invalid in disk
            // (assume these blocks are BLOCK_GRAPH_READY)
            let mut referee_graph_ready = true;
            if self.arena[*index].pending_referee_count == 0 {
                // since all relcaimed blocks are all BLOCK_GRAPH_READY, only
                // need to check those in memory block
                for referee in self.arena[*index].referees.iter() {
                    referee_graph_ready &=
                        self.arena[*referee].graph_status == BLOCK_GRAPH_READY;
                }
            } else {
                let mut referee_hash_in_mem = HashSet::new();
                for referee in self.arena[*index].referees.iter() {
                    referee_graph_ready &=
                        self.arena[*referee].graph_status == BLOCK_GRAPH_READY;
                    referee_hash_in_mem
                        .insert(self.arena[*referee].block_header.hash());
                }

                for referee_hash in
                    self.arena[*index].block_header.referee_hashes()
                {
                    if !referee_hash_in_mem.contains(referee_hash) {
                        referee_graph_ready &= {
                            if let Some(_) =
                                self.data_man.block_by_hash(referee_hash, false)
                            {
                                !self.data_man.verified_invalid(referee_hash)
                            } else {
                                false
                            }
                        }
                    }
                }
            }

            if referee_graph_ready {
                // do check
                let r = self.verify_header_graph_ready_block(*index);
                if r.is_err() {
                    continue;
                }
                if self.arena[*index].block_ready {
                    // recover as BLOCK_GRAPH_READY
                    graph_ready_blocks.push(*index);
                } else {
                    // recover as BLOCK_HEADER_GRAPH_READY
                    header_graph_ready_blocks.push(*index);
                }
            }
        }

        (graph_ready_blocks, header_graph_ready_blocks)
    }

    pub fn insert_invalid(&mut self, header: Arc<BlockHeader>) -> usize {
        let hash = header.hash();
        let me = self.arena.insert(SynchronizationGraphNode {
            graph_status: BLOCK_INVALID,
            block_ready: false,
            parent_reclaimed: false,
            parent: NULL,
            children: Vec::new(),
            referees: Vec::new(),
            pending_referee_count: 0,
            referrers: Vec::new(),
            block_header: header,
            last_update_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });
        self.hash_to_arena_indices.insert(hash, me);

        if let Some(children) = self.children_by_hash.remove(&hash) {
            for child in &children {
                self.arena[*child].parent = me;
            }
            self.arena[me].children = children;
        }
        if let Some(referrers) = self.referrers_by_hash.remove(&hash) {
            for referrer in &referrers {
                let ref mut node_referrer = self.arena[*referrer];
                node_referrer.referees.push(me);
                debug_assert!(node_referrer.pending_referee_count > 0);
                if node_referrer.pending_referee_count > 0 {
                    node_referrer.pending_referee_count =
                        node_referrer.pending_referee_count - 1;
                }
            }
            self.arena[me].referrers = referrers;
        }

        me
    }

    /// Return the index of the inserted block.
    pub fn insert(&mut self, header: Arc<BlockHeader>) -> usize {
        let hash = header.hash();
        let is_genesis = *header.parent_hash() == H256::default();

        let me = self.arena.insert(SynchronizationGraphNode {
            graph_status: if is_genesis {
                BLOCK_GRAPH_READY
            } else {
                BLOCK_HEADER_ONLY
            },
            block_ready: *header.parent_hash() == H256::default(),
            parent_reclaimed: false,
            parent: NULL,
            children: Vec::new(),
            referees: Vec::new(),
            pending_referee_count: 0,
            referrers: Vec::new(),
            block_header: header.clone(),
            last_update_timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });
        self.hash_to_arena_indices.insert(hash, me);

        let parent_hash = header.parent_hash().clone();
        if parent_hash != H256::default() {
            if let Some(parent) =
                self.hash_to_arena_indices.get(&parent_hash).cloned()
            {
                self.arena[me].parent = parent;
                self.arena[parent].children.push(me);
            } else {
                self.children_by_hash
                    .entry(parent_hash)
                    .or_insert(Vec::new())
                    .push(me);
            }
        }
        for referee_hash in header.referee_hashes() {
            if let Some(referee) =
                self.hash_to_arena_indices.get(referee_hash).cloned()
            {
                self.arena[me].referees.push(referee);
                self.arena[referee].referrers.push(me);
            } else {
                self.arena[me].pending_referee_count =
                    self.arena[me].pending_referee_count + 1;
                self.referrers_by_hash
                    .entry(*referee_hash)
                    .or_insert(Vec::new())
                    .push(me);
            }
        }

        if let Some(children) = self.children_by_hash.remove(&hash) {
            for child in &children {
                self.arena[*child].parent = me;
            }
            self.arena[me].children = children;
        }
        if let Some(referrers) = self.referrers_by_hash.remove(&hash) {
            for referrer in &referrers {
                let ref mut node_referrer = self.arena[*referrer];
                node_referrer.referees.push(me);
                debug_assert!(node_referrer.pending_referee_count > 0);
                if node_referrer.pending_referee_count > 0 {
                    node_referrer.pending_referee_count =
                        node_referrer.pending_referee_count - 1;
                }
            }
            self.arena[me].referrers = referrers;
        }

        me
    }

    pub fn block_older_than_checkpoint(&self, _hash: &H256) -> bool { false }

    pub fn new_to_be_header_parental_tree_ready(&self, index: usize) -> bool {
        let ref node_me = self.arena[index];
        if node_me.graph_status >= BLOCK_HEADER_PARENTAL_TREE_READY {
            return false;
        }

        let parent = node_me.parent;
        node_me.parent_reclaimed
            || (parent != NULL
                && self.arena[parent].graph_status
                    >= BLOCK_HEADER_PARENTAL_TREE_READY)
    }

    pub fn new_to_be_header_graph_ready(&self, index: usize) -> bool {
        let ref node_me = self.arena[index];
        if node_me.graph_status >= BLOCK_HEADER_GRAPH_READY {
            return false;
        }

        if node_me.pending_referee_count > 0 {
            return false;
        }

        let parent = node_me.parent;
        (node_me.parent_reclaimed
            || (parent != NULL
                && self.arena[parent].graph_status >= BLOCK_HEADER_GRAPH_READY))
            && !node_me.referees.iter().any(|&referee| {
                self.arena[referee].graph_status < BLOCK_HEADER_GRAPH_READY
            })
    }

    pub fn new_to_be_block_graph_ready(&self, index: usize) -> bool {
        let ref node_me = self.arena[index];
        if !node_me.block_ready {
            return false;
        }

        if node_me.graph_status >= BLOCK_GRAPH_READY {
            return false;
        }

        let parent = node_me.parent;
        node_me.graph_status >= BLOCK_HEADER_GRAPH_READY
            && (node_me.parent_reclaimed
                || (parent != NULL
                    && self.arena[parent].graph_status >= BLOCK_GRAPH_READY))
            && !node_me.referees.iter().any(|&referee| {
                self.arena[referee].graph_status < BLOCK_GRAPH_READY
            })
    }

    // Get parent (height, timestamp, gas_limit, difficulty)
    // This function assumes that the parent and referee information MUST exist
    // in memory or in disk.
    fn get_parent_and_referee_info(
        &self, index: usize,
    ) -> (u64, u64, U256, U256) {
        let parent_height;
        let parent_timestamp;
        let parent_gas_limit;
        let parent_difficulty;
        let parent = self.arena[index].parent;
        if parent != NULL {
            parent_height = self.arena[parent].block_header.height();
            parent_timestamp = self.arena[parent].block_header.timestamp();
            parent_gas_limit = *self.arena[parent].block_header.gas_limit();
            parent_difficulty = *self.arena[parent].block_header.difficulty();
        } else {
            let parent_hash = self.arena[index].block_header.parent_hash();
            let parent_header = self
                .data_man
                .block_header_by_hash(parent_hash)
                .unwrap()
                .clone();
            parent_height = parent_header.height();
            parent_timestamp = parent_header.timestamp();
            parent_gas_limit = *parent_header.gas_limit();
            parent_difficulty = *parent_header.difficulty();
        }

        (
            parent_height,
            parent_timestamp,
            parent_gas_limit,
            parent_difficulty,
        )
    }

    fn verify_header_graph_ready_block(
        &self, index: usize,
    ) -> Result<(), Error> {
        let epoch = self.arena[index].block_header.height();
        let (
            parent_height,
            parent_timestamp,
            parent_gas_limit,
            parent_difficulty,
        ) = self.get_parent_and_referee_info(index);

        // Verify the height and epoch numbers are correct
        if parent_height + 1 != epoch {
            warn!("Invalid height. mine {}, parent {}", epoch, parent_height);
            return Err(From::from(BlockError::InvalidHeight(Mismatch {
                expected: parent_height + 1,
                found: epoch,
            })));
        }

        // Verify the timestamp being correctly set
        let my_timestamp = self.arena[index].block_header.timestamp();
        if parent_timestamp > my_timestamp {
            let my_timestamp = UNIX_EPOCH + Duration::from_secs(my_timestamp);
            let pa_timestamp =
                UNIX_EPOCH + Duration::from_secs(parent_timestamp);

            warn!("Invalid timestamp: parent {:?} timestamp {}, me {:?} timestamp {}",
                  self.arena[index].block_header.parent_hash().clone(),
                  parent_timestamp,
                  self.arena[index].block_header.hash(),
                  self.arena[index].block_header.timestamp());
            return Err(From::from(BlockError::InvalidTimestamp(
                OutOfBounds {
                    max: Some(my_timestamp),
                    min: Some(pa_timestamp),
                    found: my_timestamp,
                },
            )));
        }

        // Verify the gas limit is respected
        let machine = new_machine();
        let gas_limit_divisor = machine.params().gas_limit_bound_divisor;
        let min_gas_limit = machine.params().min_gas_limit;
        let gas_lower = max(
            parent_gas_limit - parent_gas_limit / gas_limit_divisor,
            min_gas_limit,
        );
        let gas_upper = parent_gas_limit + parent_gas_limit / gas_limit_divisor;
        let self_gas_limit = *self.arena[index].block_header.gas_limit();

        if self_gas_limit <= gas_lower || self_gas_limit >= gas_upper {
            return Err(From::from(BlockError::InvalidGasLimit(OutOfBounds {
                min: Some(gas_lower),
                max: Some(gas_upper),
                found: self_gas_limit,
            })));
        }

        // Verify difficulty being correctly set
        let mut difficulty_invalid = false;
        let my_diff = *self.arena[index].block_header.difficulty();
        let mut min_diff = my_diff;
        let mut max_diff = my_diff;
        let initial_difficulty: U256 =
            self.pow_config.initial_difficulty.into();

        if parent_height < self.pow_config.difficulty_adjustment_epoch_period {
            if my_diff != initial_difficulty {
                difficulty_invalid = true;
                min_diff = initial_difficulty;
                max_diff = initial_difficulty;
            }
        } else {
            let last_period_upper = (parent_height
                / self.pow_config.difficulty_adjustment_epoch_period)
                * self.pow_config.difficulty_adjustment_epoch_period;
            if last_period_upper != parent_height {
                // parent_epoch should not trigger difficulty adjustment
                if my_diff != parent_difficulty {
                    difficulty_invalid = true;
                    min_diff = parent_difficulty;
                    max_diff = parent_difficulty;
                }
            } else {
                let (lower, upper) =
                    self.pow_config.get_adjustment_bound(parent_difficulty);
                min_diff = lower;
                max_diff = upper;
                if my_diff < min_diff || my_diff > max_diff {
                    difficulty_invalid = true;
                }
            }
        }

        if difficulty_invalid {
            return Err(From::from(BlockError::InvalidDifficulty(
                OutOfBounds {
                    min: Some(min_diff),
                    max: Some(max_diff),
                    found: my_diff,
                },
            )));
        }

        Ok(())
    }

    fn process_invalid_blocks(&mut self, invalid_set: &HashSet<usize>) {
        for index in invalid_set {
            let hash = self.arena[*index].block_header.hash();
            // Mark this block as invalid, so we don't need to request/verify it
            // again
            self.data_man.invalidate_block(hash);
        }
        self.remove_blocks(invalid_set);
    }

    fn remove_blocks(&mut self, invalid_set: &HashSet<usize>) {
        for index in invalid_set {
            let hash = self.arena[*index].block_header.hash();
            self.not_ready_blocks_frontier.remove(index);
            self.not_ready_blocks_count -= 1;
            self.old_era_blocks_frontier_set.remove(index);

            let parent = self.arena[*index].parent;
            if parent != NULL {
                self.arena[parent].children.retain(|&x| x != *index);
            }
            let parent_hash = *self.arena[*index].block_header.parent_hash();
            let mut remove_parent_hash: bool = false;
            if let Some(children) = self.children_by_hash.get_mut(&parent_hash)
            {
                children.retain(|&x| x != *index);
                remove_parent_hash = children.len() == 0;
            }
            // clean empty hash key
            if remove_parent_hash {
                self.children_by_hash.remove(&parent_hash);
            }

            let referees: Vec<usize> =
                self.arena[*index].referees.iter().map(|x| *x).collect();
            for referee in referees {
                self.arena[referee].referrers.retain(|&x| x != *index);
            }
            let referee_hashes: Vec<H256> = self.arena[*index]
                .block_header
                .referee_hashes()
                .iter()
                .map(|x| *x)
                .collect();
            for referee_hash in referee_hashes {
                let mut remove_referee_hash: bool = false;
                if let Some(referrers) =
                    self.referrers_by_hash.get_mut(&referee_hash)
                {
                    referrers.retain(|&x| x != *index);
                    remove_referee_hash = referrers.len() == 0;
                }
                // clean empty hash key
                if remove_referee_hash {
                    self.referrers_by_hash.remove(&parent_hash);
                }
            }

            let children: Vec<usize> =
                self.arena[*index].children.iter().map(|x| *x).collect();
            for child in children {
                debug_assert!(invalid_set.contains(&child));
                debug_assert!(self.arena[child].graph_status == BLOCK_INVALID);
                self.arena[child].parent = NULL;
            }

            let referrers: Vec<usize> =
                self.arena[*index].referrers.iter().map(|x| *x).collect();
            for referrer in referrers {
                debug_assert!(invalid_set.contains(&referrer));
                debug_assert!(
                    self.arena[referrer].graph_status == BLOCK_INVALID
                );
                self.arena[referrer].referees.retain(|&x| x != *index);
            }

            self.arena.remove(*index);
            self.hash_to_arena_indices.remove(&hash);
            self.data_man.remove_block_header(&hash);
            self.data_man.remove_block_from_kv(&hash);
        }
    }

    fn set_and_propagate_invalid(
        &mut self, queue: &mut VecDeque<usize>,
        invalid_set: &mut HashSet<usize>, index: usize,
    )
    {
        let children =
            mem::replace(&mut self.arena[index].children, Vec::new());
        for child in &children {
            if !invalid_set.contains(&child) {
                self.arena[*child].graph_status = BLOCK_INVALID;
                queue.push_back(*child);
                invalid_set.insert(*child);
            }
        }
        mem::replace(&mut self.arena[index].children, children);
        let referrers =
            mem::replace(&mut self.arena[index].referrers, Vec::new());
        for referrer in &referrers {
            if !invalid_set.contains(&referrer) {
                self.arena[*referrer].graph_status = BLOCK_INVALID;
                queue.push_back(*referrer);
                invalid_set.insert(*referrer);
            }
        }
        mem::replace(&mut self.arena[index].referrers, referrers);
    }
}

pub struct SynchronizationGraph {
    pub inner: Arc<RwLock<SynchronizationGraphInner>>,
    pub consensus: SharedConsensusGraph,
    pub data_man: Arc<BlockDataManager>,
    pub initial_missed_block_hashes: Mutex<HashSet<H256>>,
    pub verification_config: VerificationConfig,
    pub statistics: SharedStatistics,

    /// Channel used to send work to `ConsensusGraph`
    /// Each element is <block_hash, ignore_body>
    consensus_sender: Mutex<Sender<(H256, bool)>>,
}

pub type SharedSynchronizationGraph = Arc<SynchronizationGraph>;

impl SynchronizationGraph {
    pub fn new(
        consensus: SharedConsensusGraph,
        verification_config: VerificationConfig, pow_config: ProofOfWorkConfig,
    ) -> Self
    {
        let data_man = consensus.data_man.clone();
        let (consensus_sender, consensus_receiver) = mpsc::channel();
        let inner = Arc::new(RwLock::new(
            SynchronizationGraphInner::with_genesis_block(
                Arc::new(data_man.genesis_block().block_header.clone()),
                pow_config,
                data_man.clone(),
            ),
        ));
        let sync_graph = SynchronizationGraph {
            inner: inner.clone(),
            data_man: data_man.clone(),
            initial_missed_block_hashes: Mutex::new(HashSet::new()),
            verification_config,
            consensus: consensus.clone(),
            statistics: consensus.statistics.clone(),
            consensus_sender: Mutex::new(consensus_sender),
        };

        // It receives `BLOCK_GRAPH_READY` blocks in order and handles them in
        // `ConsensusGraph`
        thread::Builder::new()
            .name("Consensus Worker".into())
            .spawn(move || loop {
                match consensus_receiver.recv() {
                    Ok((hash, ignore_body)) => {
                        consensus.on_new_block(&hash, ignore_body)
                    }
                    Err(_) => break,
                }
            })
            .expect("Cannot fail");

        sync_graph
    }

    pub fn get_genesis_hash_and_height_in_current_era(&self) -> (H256, u64) {
        self.inner
            .read()
            .get_genesis_hash_and_height_in_current_era()
    }

    /// Compute the expected difficulty for a block given its
    /// parent hash
    pub fn expected_difficulty(&self, parent_hash: &H256) -> U256 {
        self.consensus.expected_difficulty(parent_hash)
    }

    pub fn get_to_propagate_trans(
        &self,
    ) -> HashMap<H256, Arc<SignedTransaction>> {
        self.consensus.txpool.get_to_be_propagated_transactions()
    }

    pub fn set_to_propagate_trans(
        &self, transactions: HashMap<H256, Arc<SignedTransaction>>,
    ) {
        self.consensus
            .txpool
            .set_to_be_propagated_transactions(transactions);
    }

    pub fn check_mining_adaptive_block(
        &self, inner: &mut ConsensusGraphInner, parent_hash: &H256,
        difficulty: &U256,
    ) -> bool
    {
        self.consensus.check_mining_adaptive_block(
            inner,
            parent_hash,
            difficulty,
        )
    }

    pub fn block_header_by_hash(&self, hash: &H256) -> Option<BlockHeader> {
        if !self.contains_block_header(hash) {
            // Only return headers in sync graph
            return None;
        }
        self.data_man
            .block_header_by_hash(hash)
            .map(|header_ref| header_ref.as_ref().clone())
    }

    pub fn block_height_by_hash(&self, hash: &H256) -> Option<u64> {
        self.block_header_by_hash(hash)
            .map(|header| header.height())
    }

    pub fn block_timestamp_by_hash(&self, hash: &H256) -> Option<u64> {
        self.block_header_by_hash(hash)
            .map(|header| header.timestamp())
    }

    pub fn block_by_hash(&self, hash: &H256) -> Option<Arc<Block>> {
        self.data_man.block_by_hash(hash, true)
    }

    pub fn genesis_hash(&self) -> H256 { self.data_man.genesis_block().hash() }

    pub fn contains_block_header(&self, hash: &H256) -> bool {
        self.inner.read().hash_to_arena_indices.contains_key(hash)
    }

    fn parent_or_referees_invalid(&self, header: &BlockHeader) -> bool {
        self.data_man.verified_invalid(header.parent_hash())
            || header
                .referee_hashes()
                .iter()
                .any(|referee| self.data_man.verified_invalid(referee))
    }

    /// subroutine called by `insert_block_header` and `remove_expire_blocks`
    fn propagate_header_graph_status(
        &self, inner: &mut SynchronizationGraphInner,
        frontier_index_list: Vec<usize>, need_to_verify: bool,
        header_index_to_insert: usize, insert_to_consensus: bool,
    ) -> (HashSet<usize>, Vec<H256>)
    {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut need_to_relay: Vec<H256> = Vec::new();
        let mut invalid_set: HashSet<usize> = HashSet::new();
        let mut queue = VecDeque::new();

        for index in frontier_index_list {
            if inner.arena[index].graph_status == BLOCK_INVALID {
                invalid_set.insert(index);
            }
            queue.push_back(index);
        }

        while let Some(index) = queue.pop_front() {
            if inner.arena[index].graph_status == BLOCK_INVALID {
                inner.set_and_propagate_invalid(
                    &mut queue,
                    &mut invalid_set,
                    index,
                );
            } else {
                if inner.new_to_be_header_graph_ready(index) {
                    inner.arena[index].graph_status = BLOCK_HEADER_GRAPH_READY;
                    inner.arena[index].last_update_timestamp = now;
                    debug!("BlockIndex {} parent_index {} hash {} is header graph ready", index,
                           inner.arena[index].parent, inner.arena[index].block_header.hash());

                    let r = inner.verify_header_graph_ready_block(index);

                    if need_to_verify && r.is_err() {
                        warn!(
                            "Invalid header_arc! inserted_header={:?} err={:?}",
                            inner.arena[index].block_header.clone(),
                            r
                        );
                        invalid_set.insert(index);
                        inner.arena[index].graph_status = BLOCK_INVALID;
                        inner.set_and_propagate_invalid(
                            &mut queue,
                            &mut invalid_set,
                            index,
                        );
                        continue;
                    }

                    // Note that when called by `insert_block_header` we have to
                    // insert header here immediately instead of
                    // after the loop because its children may
                    // become ready and being processed in the loop later. It
                    // requires this block already being inserted
                    // into the BlockDataManager!
                    if index == header_index_to_insert {
                        self.data_man.insert_block_header(
                            inner.arena[index].block_header.hash(),
                            inner.arena[index].block_header.clone(),
                        );
                    }
                    if insert_to_consensus {
                        self.consensus_sender
                            .lock()
                            .send((
                                inner.arena[index].block_header.hash(),
                                true,
                            ))
                            .expect("Receiver not dropped");
                    }

                    // Passed verification on header_arc.
                    if inner.arena[index].block_ready {
                        need_to_relay
                            .push(inner.arena[index].block_header.hash());
                    }

                    for child in &inner.arena[index].children {
                        if inner.arena[*child].graph_status
                            < BLOCK_HEADER_GRAPH_READY
                        {
                            queue.push_back(*child);
                        }
                    }
                    for referrer in &inner.arena[index].referrers {
                        if inner.arena[*referrer].graph_status
                            < BLOCK_HEADER_GRAPH_READY
                        {
                            queue.push_back(*referrer);
                        }
                    }
                } else if inner.new_to_be_header_parental_tree_ready(index) {
                    if index == header_index_to_insert {
                        self.data_man.insert_block_header(
                            inner.arena[index].block_header.hash(),
                            inner.arena[index].block_header.clone(),
                        );
                    }
                    inner.arena[index].graph_status =
                        BLOCK_HEADER_PARENTAL_TREE_READY;
                    inner.arena[index].last_update_timestamp = now;
                    for child in &inner.arena[index].children {
                        debug_assert!(
                            inner.arena[*child].graph_status
                                < BLOCK_HEADER_PARENTAL_TREE_READY
                        );
                        queue.push_back(*child);
                    }
                } else {
                    if index == header_index_to_insert {
                        self.data_man.insert_block_header(
                            inner.arena[index].block_header.hash(),
                            inner.arena[index].block_header.clone(),
                        );
                    }
                }
            }
        }
        (invalid_set, need_to_relay)
    }

    pub fn insert_block_header(
        &self, header: &mut BlockHeader, need_to_verify: bool,
        bench_mode: bool, insert_to_consensus: bool,
    ) -> (bool, Vec<H256>)
    {
        let _timer = MeterTimer::time_func(SYNC_INSERT_HEADER.as_ref());
        let inner = &mut *self.inner.write();
        let hash = header.hash();

        if self.data_man.verified_invalid(&hash) {
            return (false, Vec::new());
        }

        if inner.hash_to_arena_indices.contains_key(&hash) {
            if need_to_verify {
                // Compute pow_quality, because the input header may be used as
                // a part of block later
                VerificationConfig::compute_header_pow_quality(header);
            }
            return (true, Vec::new());
        }

        let verification_passed = if need_to_verify {
            !(self.parent_or_referees_invalid(header)
                || self
                    .verification_config
                    .verify_header_params(header)
                    .is_err())
        } else {
            if !bench_mode {
                self.verification_config
                    .verify_pow(header)
                    .expect("local mined block should pass this check!");
            }
            true
        };

        let header_arc = Arc::new(header.clone());
        let me = if verification_passed {
            inner.insert(header_arc.clone())
        } else {
            inner.insert_invalid(header_arc.clone())
        };

        if inner.arena[me].graph_status != BLOCK_GRAPH_READY {
            inner.not_ready_blocks_count += 1;
            if inner.arena[me].parent == NULL
                || inner.arena[inner.arena[me].parent].graph_status
                    == BLOCK_GRAPH_READY
            {
                inner.not_ready_blocks_frontier.insert(me);
                let mut to_be_removed = Vec::new();
                for child in &inner.arena[me].children {
                    if inner.not_ready_blocks_frontier.contains(child) {
                        to_be_removed.push(*child);
                    }
                }
                for x in to_be_removed {
                    inner.not_ready_blocks_frontier.remove(&x);
                }
            }
        }

        debug!("insert_block_header() Block = {}, index = {}, need_to_verify = {}, bench_mode = {} insert_to_consensus = {}",
               header.hash(), me, need_to_verify, bench_mode, insert_to_consensus);

        // Start to pass influence to descendants
        let (invalid_set, need_to_relay) = self.propagate_header_graph_status(
            inner,
            vec![me],
            need_to_verify,
            me,
            insert_to_consensus,
        );

        let me_invalid = invalid_set.contains(&me);

        // Post-processing invalid blocks.
        inner.process_invalid_blocks(&invalid_set);

        if me_invalid {
            return (false, need_to_relay);
        }

        inner.try_clear_old_era_blocks();

        (true, need_to_relay)
    }

    pub fn contains_block(&self, hash: &H256) -> bool {
        let inner = self.inner.read();
        if let Some(index) = inner.hash_to_arena_indices.get(hash) {
            inner.arena[*index].block_ready
        } else {
            false
        }
    }

    fn set_graph_ready(
        &self, inner: &mut SynchronizationGraphInner, index: usize,
        sync_graph_only: bool,
    )
    {
        inner.arena[index].graph_status = BLOCK_GRAPH_READY;
        if inner.arena[index].parent_reclaimed {
            inner.old_era_blocks_frontier.push_back(index);
            inner.old_era_blocks_frontier_set.insert(index);
        }

        // maintain not_ready_blocks_frontier set
        inner.not_ready_blocks_count -= 1;
        inner.not_ready_blocks_frontier.remove(&index);
        for child in &inner.arena[index].children {
            inner.not_ready_blocks_frontier.insert(*child);
        }

        let h = inner.arena[index].block_header.hash();
        debug!("Block {:?} is graph ready", h);
        if !sync_graph_only {
            // Make Consensus Worker handle the block in order
            // asynchronously
            self.consensus_sender
                .lock()
                .send((h, false))
                .expect("Cannot fail");
        } else {
            self.consensus.on_new_block(&h, true);
        }
    }

    /// subroutine called by `insert_block` and `remove_expire_blocks`
    fn propagate_graph_status(
        &self, inner: &mut SynchronizationGraphInner,
        frontier_index_list: Vec<usize>, sync_graph_only: bool,
    ) -> HashSet<usize>
    {
        let mut queue = VecDeque::new();
        let mut invalid_set = HashSet::new();
        for index in frontier_index_list {
            if inner.arena[index].graph_status == BLOCK_INVALID {
                invalid_set.insert(index);
            }
            queue.push_back(index);
        }

        while let Some(index) = queue.pop_front() {
            if inner.arena[index].graph_status == BLOCK_INVALID {
                inner.set_and_propagate_invalid(
                    &mut queue,
                    &mut invalid_set,
                    index,
                );
            } else if inner.new_to_be_block_graph_ready(index) {
                self.set_graph_ready(inner, index, sync_graph_only);
                for child in &inner.arena[index].children {
                    debug_assert!(
                        inner.arena[*child].graph_status < BLOCK_GRAPH_READY
                    );
                    queue.push_back(*child);
                }
                for referrer in &inner.arena[index].referrers {
                    debug_assert!(
                        inner.arena[*referrer].graph_status < BLOCK_GRAPH_READY
                    );
                    queue.push_back(*referrer);
                }
            }
        }

        invalid_set
    }

    pub fn insert_block(
        &self, block: Block, need_to_verify: bool, persistent: bool,
        sync_graph_only: bool,
    ) -> (bool, bool)
    {
        let _timer = MeterTimer::time_func(SYNC_INSERT_BLOCK.as_ref());
        let mut insert_success = true;
        let mut need_to_relay = false;

        let hash = block.hash();

        let inner = &mut *self.inner.write();

        if self.data_man.verified_invalid(&hash) {
            insert_success = false;
            // (false, false)
            return (insert_success, need_to_relay);
        }

        let contains_block =
            if let Some(index) = inner.hash_to_arena_indices.get(&hash) {
                inner.arena[*index].block_ready
            } else {
                // Sync graph is cleaned after inserting the header, so we can
                // ignore the block body
                return (true, false);
            };

        if contains_block {
            // (true, false)
            return (insert_success, need_to_relay);
        }

        self.statistics.inc_sync_graph_inserted_block_count();

        let me = *inner.hash_to_arena_indices.get(&hash).unwrap();
        debug_assert!(hash == inner.arena[me].block_header.hash());
        debug_assert!(!inner.arena[me].block_ready);
        inner.arena[me].block_ready = true;

        if need_to_verify {
            let r = self.verification_config.verify_block_basic(&block);
            match r {
                Err(Error(
                    ErrorKind::Block(BlockError::InvalidTransactionsRoot(e)),
                    _,
                )) => {
                    warn ! ("BlockTransactionRoot not match! inserted_block={:?} err={:?}", block, e);
                    insert_success = false;
                    return (insert_success, need_to_relay);
                }
                Err(e) => {
                    warn!(
                        "Invalid block! inserted_block={:?} err={:?}",
                        block, e
                    );
                    inner.arena[me].graph_status = BLOCK_INVALID;
                }
                _ => {}
            };
        }

        let block = Arc::new(block);
        if inner.arena[me].graph_status != BLOCK_INVALID {
            // If we are rebuilding the graph from db, we do not insert all
            // blocks into memory
            if !sync_graph_only {
                // Here we always build a new compact block because we should
                // not reuse the nonce
                self.data_man.insert_compact_block(block.to_compact());
                self.data_man.insert_block_to_kv(block.clone(), persistent);
            }
        } else {
            insert_success = false;
        }

        let invalid_set =
            self.propagate_graph_status(inner, vec![me], sync_graph_only);

        if inner.arena[me].graph_status >= BLOCK_HEADER_GRAPH_READY {
            need_to_relay = true;
        }

        // Post-processing invalid blocks.
        inner.process_invalid_blocks(&invalid_set);
        if self.data_man.db.key_value().flush().is_err() {
            warn!("db error when flushing block data");
            insert_success = false;
        }

        debug!(
            "new block inserted into graph: block_header={:?}, tx_count={}, block_size={}",
            block.block_header,
            block.transactions.len(),
            block.size(),
        );

        (insert_success, need_to_relay)
    }

    pub fn get_block_hashes_by_epoch(
        &self, epoch_number: u64,
    ) -> Result<Vec<H256>, String> {
        self.consensus
            .get_block_hashes_by_epoch(EpochNumber::Number(epoch_number.into()))
    }

    pub fn log_statistics(&self) { self.statistics.log_statistics(); }

    pub fn update_total_weight_in_past(&self) {
        self.consensus.update_total_weight_in_past();
    }

    /// Get the current number of blocks in the synchronization graph
    /// This only returns cached block count, and this is enough since this is
    /// only used in test.
    pub fn block_count(&self) -> usize { self.data_man.cached_block_count() }

    // Manage statistics
    pub fn stat_inc_inserted_count(&self) {
        let mut inner = self.statistics.inner.write();
        inner.sync_graph.inserted_block_count += 1;
    }

    pub fn remove_expire_blocks(
        &self, expire_time: u64, recover: bool,
    ) -> Vec<H256> {
        let inner = &mut *self.inner.write();
        let mut to_relay_blocks = Vec::new();

        if recover {
            // TODO: maybe we need to relay those blocks
            // TODO: maybe we need to propagate header graph status
            let (new_graph_ready_blocks, new_header_graph_ready_blocks) =
                inner.try_recover_expire_block();

            for index in &new_graph_ready_blocks {
                if inner.arena[*index].parent == NULL {
                    // make sure this block will be insert into
                    // old_era_blocks_frontier later
                    inner.arena[*index].parent_reclaimed = true;
                }
                inner.arena[*index].graph_status = BLOCK_HEADER_GRAPH_READY;
                inner.arena[*index].pending_referee_count = 0;
                to_relay_blocks.push(inner.arena[*index].block_header.hash());
            }

            for index in &new_header_graph_ready_blocks {
                if inner.arena[*index].parent == NULL {
                    inner.arena[*index].parent_reclaimed = true;
                }
                inner.arena[*index].pending_referee_count = 0;
            }
            // propagate BLOCK_HEADER_GRAPH_READY status to descendants
            let (invalid_set, need_to_relay) = self
                .propagate_header_graph_status(
                    inner,
                    new_header_graph_ready_blocks,
                    true,
                    NULL,
                    false,
                );
            inner.process_invalid_blocks(&invalid_set);
            for hash in need_to_relay {
                to_relay_blocks.push(hash);
            }

            // since in `new_to_be_block_graph_ready`, we only check
            // graph_status and parent_reclaimed
            // in function `propagate_graph_status` will change graph status
            // from BLOCK_HEADER_GRAPH_READY to BLOCK_GRAPH_READY
            let invalid_set = self.propagate_graph_status(
                inner,
                new_graph_ready_blocks,
                false,
            );
            debug_assert!(invalid_set.len() == 0);
        }

        // only remove when there are more than 10% expired blocks
        if inner.not_ready_blocks_count * 10 <= inner.arena.len() {
            return to_relay_blocks;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut queue = VecDeque::new();
        let mut expire_set = HashSet::new();
        for index in &inner.not_ready_blocks_frontier {
            if now - inner.arena[*index].last_update_timestamp > expire_time {
                queue.push_back(*index);
                expire_set.insert(*index);
            }
        }
        while let Some(index) = queue.pop_front() {
            inner.arena[index].graph_status = BLOCK_INVALID;
            for child in &inner.arena[index].children {
                if !expire_set.contains(child) {
                    expire_set.insert(*child);
                    queue.push_back(*child);
                }
            }
            for referrer in &inner.arena[index].referrers {
                if !expire_set.contains(referrer) {
                    expire_set.insert(*referrer);
                    queue.push_back(*referrer);
                }
            }
        }

        debug!("expire_set: {:?}", expire_set);
        inner.remove_blocks(&expire_set);

        to_relay_blocks
    }
}
