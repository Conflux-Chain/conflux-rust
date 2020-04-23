// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::{BlockDataManager, BlockStatus},
    channel::Channel,
    consensus::SharedConsensusGraph,
    error::{BlockError, Error, ErrorKind},
    machine::Machine,
    parameters::sync::OLD_ERA_BLOCK_GC_BATCH_SIZE,
    pow::ProofOfWorkConfig,
    state_exposer::{SyncGraphBlockState, STATE_EXPOSER},
    statistics::SharedStatistics,
    verification::*,
    ConsensusGraph, Notifications,
};
use cfx_types::{H256, U256};
use futures::executor::block_on;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use metrics::{
    register_meter_with_group, register_queue, Meter, MeterTimer, Queue,
};
use parking_lot::{Mutex, RwLock};
use primitives::{
    transaction::SignedTransaction, Block, BlockHeader, EpochNumber,
};
use slab::Slab;
use std::{
    cmp::max,
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    mem, panic,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc::error::TryRecvError;
use unexpected::{Mismatch, OutOfBounds};

lazy_static! {
    static ref SYNC_INSERT_HEADER: Arc<dyn Meter> =
        register_meter_with_group("timer", "sync::insert_block_header");
    static ref SYNC_INSERT_BLOCK: Arc<dyn Meter> =
        register_meter_with_group("timer", "sync::insert_block");
    static ref CONSENSUS_WORKER_QUEUE: Arc<dyn Queue> =
        register_queue("consensus_worker_queue");
}

const NULL: usize = !0;
const BLOCK_INVALID: u8 = 0;
const BLOCK_HEADER_ONLY: u8 = 1;
const BLOCK_HEADER_GRAPH_READY: u8 = 2;
const BLOCK_GRAPH_READY: u8 = 3;

#[derive(Copy, Clone)]
pub struct SyncGraphConfig {
    pub enable_state_expose: bool,
    pub is_consortium: bool,
}

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

    pub fn clear(&mut self) { self.inserted_block_count = 1; }
}

#[derive(DeriveMallocSizeOf)]
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

#[derive(DeriveMallocSizeOf)]
pub struct UnreadyBlockFrontier {
    frontier: HashSet<usize>,
    updated: bool,
}

impl UnreadyBlockFrontier {
    fn new() -> Self {
        UnreadyBlockFrontier {
            frontier: HashSet::new(),
            updated: false,
        }
    }

    pub fn reset_update_state(&mut self) { self.updated = false; }

    pub fn updated(&self) -> bool { self.updated }

    pub fn get_frontier(&self) -> &HashSet<usize> { &self.frontier }

    pub fn remove(&mut self, index: &usize) -> bool {
        self.updated = true;
        self.frontier.remove(index)
    }

    pub fn contains(&self, index: &usize) -> bool {
        self.frontier.contains(index)
    }

    pub fn insert(&mut self, index: usize) -> bool {
        self.updated = true;
        self.frontier.insert(index)
    }

    pub fn len(&self) -> usize { self.frontier.len() }
}

pub struct SynchronizationGraphInner {
    pub arena: Slab<SynchronizationGraphNode>,
    pub hash_to_arena_indices: HashMap<H256, usize>,
    pub data_man: Arc<BlockDataManager>,
    children_by_hash: HashMap<H256, Vec<usize>>,
    referrers_by_hash: HashMap<H256, Vec<usize>>,
    pub pow_config: ProofOfWorkConfig,
    pub config: SyncGraphConfig,
    /// The indices of blocks whose graph_status is not GRAPH_READY.
    /// It may consider not header-graph-ready in phases
    /// `CatchUpRecoverBlockHeaderFromDB` and `CatchUpSyncBlockHeader`.
    /// Or, it may consider not block-graph-ready in phases
    /// `CatchUpRecoverBlockFromDB`, `CatchUpSyncBlock`, and `Normal`.
    pub not_ready_blocks_frontier: UnreadyBlockFrontier,
    pub not_ready_blocks_count: usize,
    pub old_era_blocks_frontier: VecDeque<usize>,
    pub old_era_blocks_frontier_set: HashSet<usize>,
    machine: Arc<Machine>,
}

impl MallocSizeOf for SynchronizationGraphInner {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.arena.size_of(ops)
            + self.hash_to_arena_indices.size_of(ops)
            + self.data_man.size_of(ops)
            + self.children_by_hash.size_of(ops)
            + self.referrers_by_hash.size_of(ops)
            + self.pow_config.size_of(ops)
            + self.not_ready_blocks_frontier.size_of(ops)
            + self.old_era_blocks_frontier.size_of(ops)
            + self.old_era_blocks_frontier_set.size_of(ops)
        // Does not count size_of machine.
    }
}

impl SynchronizationGraphInner {
    pub fn with_genesis_block(
        genesis_header: Arc<BlockHeader>, pow_config: ProofOfWorkConfig,
        config: SyncGraphConfig, data_man: Arc<BlockDataManager>,
        machine: Arc<Machine>,
    ) -> Self
    {
        let mut inner = SynchronizationGraphInner {
            arena: Slab::new(),
            hash_to_arena_indices: HashMap::new(),
            data_man,
            children_by_hash: HashMap::new(),
            referrers_by_hash: HashMap::new(),
            pow_config,
            config,
            not_ready_blocks_frontier: UnreadyBlockFrontier::new(),
            not_ready_blocks_count: 0,
            old_era_blocks_frontier: Default::default(),
            old_era_blocks_frontier_set: Default::default(),
            machine,
        };
        let genesis_hash = genesis_header.hash();
        let genesis_block_index = inner.insert(genesis_header);
        debug!(
            "genesis block {:?} has index {} in sync graph",
            genesis_hash, genesis_block_index
        );

        inner.old_era_blocks_frontier.push_back(genesis_block_index);
        inner
            .old_era_blocks_frontier_set
            .insert(genesis_block_index);

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

    pub fn get_stable_hash_and_height_in_current_era(&self) -> (H256, u64) {
        let stable_hash = self.data_man.get_cur_consensus_era_stable_hash();
        // The stable block may not be in the sync-graph when this function is
        // invoked during the synchronization phase, let's query the
        // data from data manager
        let height = self
            .data_man
            .block_header_by_hash(&stable_hash)
            .expect("stable block must exist in data manager")
            .height();
        (stable_hash, height)
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
            // only remove block header in memory cache
            self.data_man
                .remove_block_header(&hash, false /* remove_db */);

            num_cleared += 1;
            if num_cleared == max_num_of_cleared_blocks {
                break;
            }
        }

        if era_genesis_in_frontier {
            self.old_era_blocks_frontier.push_front(era_genesis);
        }
    }

    // This function tries to recover graph-unready blocks to be ready
    // again by checking whether the parent and referees of a graph-unready
    // block are all graph-ready based on their on-disk information.
    // There are only two cases to consider. For clarity, let's consider
    // block `young` and block `old`. `young`->`old`, where -> can be
    // parent or reference edge.
    // 1) `young` and `old` both exist in synchronization graph once,
    //    but `old` is removed out of memory by memory reclamation
    //    mechanism for handling era forward movement, and `old` must
    //    be already graph-ready in this case.

    //    Then, if -> is parent edge,
    //    `young`.parent == NULL && `young`.parent_reclaimed == true.
    //    So, this predicate assures `old` to be graph-ready.
    //
    //    If -> is reference edge, `young`.pending_referee_count
    //    has removed the 1 of `old`, and `old` is removed from
    //    `young`.referees. Therefore, we do not really care about
    //    whether `old` is graph-ready or not, and only need to
    //    consider other edges of `young`.
    //
    // 2) `old` has already not existed in memory when `young`
    //    comes to synchronization graph. In this case, `old` is
    //    graph-ready if and only if `old`.seq_num < genesis_seq_num
    //    or `old`.instance_id == current_instance_id.
    //
    // The graph-ready is header-graph-ready in phases
    // `CatchUpRecoverBlockHeaderFromDB` or `CatchUpSyncBlockHeader`.
    // And it is block-graph-ready for other phase.
    fn try_recover_graph_unready_block(
        &mut self,
    ) -> (Vec<usize>, Vec<usize>, Vec<usize>) {
        let mut graph_ready_blocks = Vec::new();
        let mut header_graph_ready_blocks = Vec::new();
        let mut invalid_blocks = Vec::new();

        let data_man = self.data_man.as_ref();

        // Get the sequence number of genesis block.
        // FIXME: we may store `genesis_sequence_number` in data_man to avoid db
        // access.
        let genesis_hash = self.data_man.get_cur_consensus_era_genesis_hash();
        let genesis_seq_num = self
            .data_man
            .local_block_info_from_db(&genesis_hash)
            .expect("local_block_info for genesis must exist")
            .get_seq_num();

        // This function decides graph-ready based on block info from db
        // which is persisted after a block enters consensus graph.
        // If the current synchronization phase is
        // `CatchUpRecoverBlockHeaderFromDB` or `CatchUpSyncBlockHeader`, this
        // function returns true only if the block is in `HEADER_GRAPH_READY`,
        // because in these phases, header-graph-ready block can be sent into
        // consensus graph.
        // If the current synchronization phase is `CatchUpRecoverBlockFromDB`
        // or `CatchUpSyncBlock` or `Normal`, this function returns true only if
        // the block is in `BLOCK_GRAPH_READY`, because in these phases, only
        // block-graph-ready block can be put into consensus graph.
        let mut is_graph_ready =
            |parent_or_referee_hash: &H256, index: &usize| {
                if let Some(info) =
                    data_man.local_block_info_from_db(parent_or_referee_hash)
                {
                    if info.get_status() == BlockStatus::Invalid {
                        invalid_blocks.push(*index);
                        false
                    } else {
                        info.get_seq_num() < genesis_seq_num
                            || info.get_instance_id()
                                == data_man.get_instance_id()
                    }
                } else {
                    false
                }
            };

        for index in self.not_ready_blocks_frontier.get_frontier() {
            let parent_hash = self.arena[*index].block_header.parent_hash();

            // No need to recover `BLOCK_HEADER_GRAPH_READY` blocks
            if self.arena[*index].graph_status >= BLOCK_HEADER_GRAPH_READY {
                continue;
            }

            // check whether parent is
            // `BLOCK_GRAPH_READY`/`BLOCK_HEADER_GRAPH_READY`
            // 1. `parent_reclaimed==true`, during recovery, parent is not in
            // the future of the current checkpoint.
            // 2. parent not in memory and not invalid in disk (assume this
            // block was `BLOCK_GRAPH_READY`/`BLOCK_HEADER_GRAPH_READY`)
            // 3. parent in memory and status is
            // `BLOCK_GRAPH_READY`/`BLOCK_HEADER_GRAPH_READY`
            let (parent_block_graph_ready, parent_header_graph_ready) = {
                if self.arena[*index].parent == NULL {
                    if self.arena[*index].parent_reclaimed
                        || is_graph_ready(parent_hash, index)
                    {
                        (true, true)
                    } else {
                        (false, false)
                    }
                } else {
                    let parent = self.arena[*index].parent;
                    (
                        self.arena[parent].graph_status == BLOCK_GRAPH_READY,
                        self.arena[parent].graph_status
                            >= BLOCK_HEADER_GRAPH_READY,
                    )
                }
            };

            if !parent_block_graph_ready && !parent_header_graph_ready {
                continue;
            } else if self.arena[*index].parent == NULL {
                self.arena[*index].parent_reclaimed = true;
            }

            // check whether referees are `BLOCK_GRAPH_READY` /
            // `BLOCK_HEADER_GRAPH_READY`  1. referees which are in
            // memory and status is BLOCK_GRAPH_READY  2. referees
            // which are not in memory and not invalid in disk
            // (assume these blocks are BLOCK_GRAPH_READY)
            let mut referee_block_graph_ready = true;
            let mut referee_header_graph_ready = true;
            if self.arena[*index].pending_referee_count == 0 {
                // since all relcaimed blocks are all BLOCK_GRAPH_READY, only
                // need to check those in memory block
                for referee in self.arena[*index].referees.iter() {
                    referee_block_graph_ready &=
                        self.arena[*referee].graph_status == BLOCK_GRAPH_READY;
                    referee_header_graph_ready &= self.arena[*referee]
                        .graph_status
                        >= BLOCK_HEADER_GRAPH_READY;
                }
            } else {
                let mut referee_hash_in_mem = HashSet::new();
                for referee in self.arena[*index].referees.iter() {
                    referee_block_graph_ready &=
                        self.arena[*referee].graph_status == BLOCK_GRAPH_READY;
                    referee_header_graph_ready &= self.arena[*referee]
                        .graph_status
                        >= BLOCK_HEADER_GRAPH_READY;
                    referee_hash_in_mem
                        .insert(self.arena[*referee].block_header.hash());
                }

                for referee_hash in
                    self.arena[*index].block_header.referee_hashes()
                {
                    if !referee_hash_in_mem.contains(referee_hash)
                        && (referee_block_graph_ready
                            || referee_header_graph_ready)
                    {
                        let graph_ready = is_graph_ready(referee_hash, index);
                        referee_block_graph_ready &= graph_ready;
                        referee_header_graph_ready &= graph_ready;
                    }
                }
            }

            if parent_header_graph_ready && referee_header_graph_ready {
                // do check
                let r = self.verify_header_graph_ready_block(*index);
                if r.is_err() {
                    continue;
                }
                // recover all ready blocks as BLOCK_HEADER_GRAPH_READY first so
                // that the status can be properly propagated
                header_graph_ready_blocks.push(*index);
            }

            if parent_block_graph_ready
                && referee_block_graph_ready
                && self.arena[*index].block_ready
            {
                // recover as BLOCK_GRAPH_READY
                graph_ready_blocks.push(*index);
            }
        }

        (
            graph_ready_blocks,
            header_graph_ready_blocks,
            invalid_blocks,
        )
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
        let is_genesis =
            hash == self.data_man.get_cur_consensus_era_genesis_hash();

        let me = self.arena.insert(SynchronizationGraphNode {
            graph_status: if is_genesis {
                BLOCK_GRAPH_READY
            } else {
                BLOCK_HEADER_ONLY
            },
            block_ready: is_genesis,
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

        if !is_genesis {
            let parent_hash = header.parent_hash().clone();
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

    // TODO local_block_info is also loaded for invalid check, so maybe we can
    // refactor code to avoid loading it twice.
    fn is_graph_ready_in_db(
        &self, parent_or_referee_hash: &H256, genesis_seq_num: u64,
    ) -> bool {
        if let Some(info) = self
            .data_man
            .local_block_info_from_db(parent_or_referee_hash)
        {
            if info.get_status() == BlockStatus::Invalid {
                false
            } else {
                info.get_seq_num() < genesis_seq_num
                    || info.get_instance_id() == self.data_man.get_instance_id()
            }
        } else {
            false
        }
    }

    fn new_to_be_graph_ready(
        &mut self, index: usize, minimal_status: u8,
    ) -> bool {
        let ref node_me = self.arena[index];
        // If a block has become graph-ready before and reclaimed,
        // it will be marked as `already_processed`
        // in `insert_block_header`, so we do not need to handle this case here.
        // And thus we also won't propagate graph-ready to already processed
        // blocks.
        if node_me.graph_status >= minimal_status {
            return false;
        }

        // FIXME: we may store `genesis_sequence_number` in data_man to avoid db
        // access.
        let genesis_hash = self.data_man.get_cur_consensus_era_genesis_hash();
        let genesis_seq_num = self
            .data_man
            .local_block_info_from_db(&genesis_hash)
            .expect("local_block_info for genesis must exist")
            .get_seq_num();
        let parent = self.arena[index].parent;
        let parent_graph_ready = if parent == NULL {
            self.arena[index].parent_reclaimed
                || self.is_graph_ready_in_db(
                    self.arena[index].block_header.parent_hash(),
                    genesis_seq_num,
                )
        } else {
            self.arena[parent].graph_status >= minimal_status
        };

        if !parent_graph_ready {
            return false;
        } else if parent == NULL {
            self.arena[index].parent_reclaimed = true;
        }

        // check whether referees are `BLOCK_HEADER_GRAPH_READY`
        // 1. referees which are in
        // memory and status is BLOCK_HEADER_GRAPH_READY.
        // 2. referees
        // which are not in memory and not invalid in disk
        // (assume these blocks are BLOCK_GRAPH_READY)
        let mut referee_hash_in_mem = HashSet::new();
        for referee in self.arena[index].referees.iter() {
            if self.arena[*referee].graph_status < minimal_status {
                return false;
            } else {
                referee_hash_in_mem
                    .insert(self.arena[*referee].block_header.hash());
            }
        }

        for referee_hash in self.arena[index].block_header.referee_hashes() {
            if !referee_hash_in_mem.contains(referee_hash) {
                if !self.is_graph_ready_in_db(referee_hash, genesis_seq_num) {
                    return false;
                }
            }
        }

        // parent and referees are all header graph ready.
        true
    }

    fn new_to_be_header_graph_ready(&mut self, index: usize) -> bool {
        self.new_to_be_graph_ready(index, BLOCK_HEADER_GRAPH_READY)
    }

    fn new_to_be_block_graph_ready(&mut self, index: usize) -> bool {
        self.new_to_be_graph_ready(index, BLOCK_GRAPH_READY)
            && self.arena[index].block_ready
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

        // Verify the timestamp being correctly set.
        // Conflux tries to maintain the timestamp drift among blocks
        // in the graph, which probably being generated at the same time,
        // within a small bound (specified by ACCEPTABLE_TIME_DRIFT).
        // This is achieved through the following mechanism. Anytime
        // when receiving a new block from the peer, if the timestamp of
        // the block is more than ACCEPTABLE_TIME_DRIFT later than the
        // current timestamp of the node, the block is postponed to be
        // added into the graph until the current timestamp passes the
        // the timestamp of the block. Otherwise, this block can be added
        // into the graph.
        // Meanwhile, Conflux also requires that the timestamp of each
        // block must be later than or equal to its parent's timestamp.
        // This is achieved through adjusting the timestamp of a newly
        // generated block to the one later than its parent's timestamp.
        // This is also enough for difficulty adjustment computation where
        // the timespan in the adjustment period is only computed based on
        // timestamps of pivot chain blocks.
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
        let self_gas_limit = *self.arena[index].block_header.gas_limit();
        let gas_limit_divisor = self.machine.params().gas_limit_bound_divisor;
        let min_gas_limit = self.machine.params().min_gas_limit;
        let gas_upper =
            parent_gas_limit + parent_gas_limit / gas_limit_divisor - 1;
        let gas_lower = max(
            parent_gas_limit - parent_gas_limit / gas_limit_divisor + 1,
            min_gas_limit,
        );

        if self_gas_limit < gas_lower || self_gas_limit > gas_upper {
            return Err(From::from(BlockError::InvalidGasLimit(OutOfBounds {
                min: Some(gas_lower),
                max: Some(gas_upper),
                found: self_gas_limit,
            })));
        }

        if !self.config.is_consortium {
            // Verify difficulty being correctly set
            let mut difficulty_invalid = false;
            let my_diff = *self.arena[index].block_header.difficulty();
            let mut min_diff = my_diff;
            let mut max_diff = my_diff;
            let initial_difficulty: U256 =
                self.pow_config.initial_difficulty.into();

            if parent_height
                < self.pow_config.difficulty_adjustment_epoch_period
            {
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
                    self.referrers_by_hash.remove(&referee_hash);
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
            // remove header/block in memory cache and header/block in db
            self.data_man.remove_block(&hash, true /* remove_db */);
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
    pub sync_config: SyncGraphConfig,
    pub statistics: SharedStatistics,
    /// This is the boolean state shared with the underlying consensus worker
    /// to indicate whether the worker is now finished all pending blocks.
    /// Since the critical section is very short, a `Mutex` is enough.
    consensus_unprocessed_count: Arc<AtomicUsize>,

    /// Channel used to send block hashes to `ConsensusGraph` and PubSub.
    /// Each element is <block_hash, ignore_body>
    new_block_hashes: Arc<Channel<(H256, bool)>>,

    /// whether it is a archive node or full node
    is_full_node: bool,
    machine: Arc<Machine>,
}

impl MallocSizeOf for SynchronizationGraph {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let inner_size = self.inner.read().size_of(ops);
        let initial_missed_block_hashes_size =
            self.initial_missed_block_hashes.lock().size_of(ops);
        let mut malloc_size = inner_size
            + self.data_man.size_of(ops)
            + initial_missed_block_hashes_size;

        // TODO: Add statistics for consortium.
        if !self.is_consortium() {
            let consensus_graph = self
                .consensus
                .as_any()
                .downcast_ref::<ConsensusGraph>()
                .expect("downcast should succeed");
            malloc_size += consensus_graph.size_of(ops);
        }
        // Does not count size_of machine.

        malloc_size
    }
}

pub type SharedSynchronizationGraph = Arc<SynchronizationGraph>;

impl SynchronizationGraph {
    pub fn new(
        consensus: SharedConsensusGraph,
        verification_config: VerificationConfig, pow_config: ProofOfWorkConfig,
        sync_config: SyncGraphConfig, notifications: Arc<Notifications>,
        is_full_node: bool, machine: Arc<Machine>,
    ) -> Self
    {
        let data_man = consensus.get_data_manager().clone();
        let genesis_hash = data_man.get_cur_consensus_era_genesis_hash();
        let genesis_block_header = data_man
            .block_header_by_hash(&genesis_hash)
            .expect("genesis block header should exist here");

        // It should not be initialized to `true` now, otherwise consensus
        // worker will be blocked on waiting the first block forever.
        let consensus_unprocessed_count = Arc::new(AtomicUsize::new(0));
        let mut consensus_receiver = notifications.new_block_hashes.subscribe();
        let inner = Arc::new(RwLock::new(
            SynchronizationGraphInner::with_genesis_block(
                genesis_block_header.clone(),
                pow_config,
                sync_config,
                data_man.clone(),
                machine.clone(),
            ),
        ));
        let sync_graph = SynchronizationGraph {
            inner: inner.clone(),
            data_man: data_man.clone(),
            initial_missed_block_hashes: Mutex::new(HashSet::new()),
            verification_config,
            sync_config,
            consensus: consensus.clone(),
            statistics: consensus.get_statistics().clone(),
            consensus_unprocessed_count: consensus_unprocessed_count.clone(),
            new_block_hashes: notifications.new_block_hashes.clone(),
            is_full_node,
            machine,
        };

        // It receives `BLOCK_GRAPH_READY` blocks in order and handles them in
        // `ConsensusGraph`
        thread::Builder::new()
            .name("Consensus Worker".into())
            .spawn(move || {
                // The Consensus Worker will prioritize blocks based on its parent epoch number while respecting the topological order. This has the following two benefits:
                //
                // 1. It will almost make sure that the self mined block being processed first
                //
                // 2. In case of a DoS attack that a malicious player releases a large chunk of old blocks. This strategy will make the consensus to process the meaningful blocks first.
                let mut priority_queue: BinaryHeap<(u64, H256, bool)> = BinaryHeap::new();
                let mut reverse_map : HashMap<H256, Vec<H256>> = HashMap::new();
                let mut counter_map = HashMap::new();

                'outer: loop {
                    // Only block when we have processed all received blocks.
                    let mut blocking = priority_queue.is_empty();
                    'inner: loop {
                        // Use blocking `recv` for the first element, and then drain the receiver
                        // with non-blocking `try_recv`.
                        let maybe_item = if blocking {
                            blocking = false;
                            match block_on(consensus_receiver.recv()) {
                                Some(item) => Ok(item),
                                None => break 'outer,
                            }
                        } else {
                            consensus_receiver.try_recv()
                        };

                        match maybe_item {
                            // FIXME: We need to investigate why duplicate hash may send to the consensus worker
                            Ok((hash, ignore_body)) => if !reverse_map.contains_key(&hash) {
                                debug!("Worker thread receive: block = {}", hash);
                                let header = data_man.block_header_by_hash(&hash).expect("Header must exist before sending to the consensus worker!");
                                let mut cnt: usize = 0;
                                let parent_hash = header.parent_hash();
                                if let Some(v) = reverse_map.get_mut(parent_hash) {
                                    v.push(hash.clone());
                                    cnt += 1;
                                }
                                for referee in header.referee_hashes() {
                                    if let Some(v) = reverse_map.get_mut(referee) {
                                        v.push(hash.clone());
                                        cnt += 1;
                                    }
                                }
                                reverse_map.insert(hash.clone(), Vec::new());
                                if cnt == 0 {
                                    let epoch_number = consensus.get_block_epoch_number(parent_hash).unwrap_or(0);
                                    priority_queue.push((epoch_number, hash, ignore_body));
                                } else {
                                    counter_map.insert(hash, (cnt, ignore_body));
                                }
                            } else {
                                warn!("Duplicate block = {} sent to the consensus worker", hash);
                            },
                            Err(TryRecvError::Empty) => break 'inner,
                            Err(TryRecvError::Closed) => break 'outer,
                        }
                    }
                    if let Some((_, hash, ignore_body)) = priority_queue.pop() {
                        CONSENSUS_WORKER_QUEUE.dequeue(1);
                        let successors = reverse_map.remove(&hash).unwrap();
                        for succ in successors {
                            let cnt_tuple = counter_map.get_mut(&succ).unwrap();
                            cnt_tuple.0 -= 1;
                            if cnt_tuple.0 == 0 {
                                let ignore_body = cnt_tuple.1;
                                counter_map.remove(&succ);
                                let header_succ = data_man.block_header_by_hash(&succ).expect("Header must exist before sending to the consensus worker!");
                                let parent_succ = header_succ.parent_hash();
                                let epoch_number = consensus.get_block_epoch_number(parent_succ).unwrap_or(0);
                                priority_queue.push((epoch_number, succ, ignore_body));
                            }
                        }
                        consensus.on_new_block(
                            &hash,
                            ignore_body,
                            true, /* update_best_info */
                        );
                        consensus_unprocessed_count.fetch_sub(1, Ordering::SeqCst);
                    }
                }
            })
            .expect("Cannot fail");
        sync_graph
    }

    pub fn is_consortium(&self) -> bool { self.sync_config.is_consortium }

    pub fn machine(&self) -> Arc<Machine> { self.machine.clone() }

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
        self.consensus
            .get_tx_pool()
            .get_to_be_propagated_transactions()
    }

    pub fn set_to_propagate_trans(
        &self, transactions: HashMap<H256, Arc<SignedTransaction>>,
    ) {
        self.consensus
            .get_tx_pool()
            .set_to_be_propagated_transactions(transactions);
    }

    pub fn try_remove_old_era_blocks_from_disk(&self) {
        let mut num_of_blocks_to_remove = OLD_ERA_BLOCK_GC_BATCH_SIZE;
        while let Some(hash) = self.consensus.retrieve_old_era_blocks() {
            // only full node should remove blocks and receipts in old eras
            if self.is_full_node {
                // remove block body in memory cache and db
                self.data_man
                    .remove_block_body(&hash, true /* remove_db */);
                self.data_man
                    .remove_block_results(&hash, true /* remove_db */);
            }
            // All nodes will not maintain old era states, so related data can
            // be removed safely. The in-memory data is already
            // removed in `make_checkpoint`.
            // TODO Only call remove for executed epochs.
            self.data_man
                .remove_epoch_execution_commitment_from_db(&hash);
            self.data_man.remove_epoch_execution_context_from_db(&hash);
            num_of_blocks_to_remove -= 1;
            if num_of_blocks_to_remove == 0 {
                break;
            }
        }
    }

    /// In full/archive node, this function can be invoked during
    /// CatchUpRecoverBlockHeaderFromDbPhase phase and
    /// CatchUpRecoverBlockFromDbPhase phase.
    /// It tries to construct the consensus graph based on block/header
    /// information stored in db.
    pub fn recover_graph_from_db(&self, header_only: bool) {
        info!("Start fast recovery of the block DAG from database");

        // Recover the initial sequence number in consensus graph
        // based on the sequence number of genesis block in db.
        let genesis_hash = self.data_man.get_cur_consensus_era_genesis_hash();
        let genesis_local_info =
            self.data_man.local_block_info_from_db(&genesis_hash);
        if genesis_local_info.is_none() {
            // Local info of genesis block must exist.
            panic!(
                "failed to get local block info from db for genesis[{}]",
                genesis_hash
            );
        }
        let genesis_seq_num = genesis_local_info.unwrap().get_seq_num();
        self.consensus.set_initial_sequence_number(genesis_seq_num);
        let genesis_header =
            self.data_man.block_header_by_hash(&genesis_hash).unwrap();
        debug!(
            "Get current genesis_block hash={:?}, height={}, seq_num={}",
            genesis_hash,
            genesis_header.height(),
            genesis_seq_num
        );

        // Get terminals stored in db.
        let terminals_opt = self.data_man.terminals_from_db();
        if terminals_opt.is_none() {
            return;
        }
        let terminals = terminals_opt.unwrap();
        debug!("Get terminals {:?}", terminals);

        // Reconstruct the consensus graph by traversing backward from
        // terminals. This traversal will visit all the blocks under the
        // future of current era genesis till the terminals. However,
        // some blocks may not be graph-ready since they may have
        // references or parents which are out of the current era. We
        // need to resolve these out-of-era dependencies later and make
        // those blocks be graph-ready again.
        let mut queue = VecDeque::new();
        let mut visited_blocks: HashSet<H256> = HashSet::new();
        for terminal in terminals {
            queue.push_back(terminal);
            visited_blocks.insert(terminal);
        }

        // Remember the hashes of blocks that belong to the current genesis
        // era but are missed in db. The missed blocks will be fetched from
        // peers.
        let mut missed_hashes = HashSet::new();
        while let Some(hash) = queue.pop_front() {
            if hash == genesis_hash {
                // Genesis block is already in consensus graph.
                continue;
            }

            // Ignore blocks beyond the future of current genesis era.
            // If block_local_info is missing, consider it is in current
            // genesis era.
            if let Some(block_local_info) =
                self.data_man.local_block_info_from_db(&hash)
            {
                if block_local_info.get_seq_num() < genesis_seq_num {
                    debug!(
                        "Skip block {:?} before checkpoint: seq_num={}",
                        hash,
                        block_local_info.get_seq_num()
                    );
                    continue;
                }
            }

            // FIXME: for full node in `CatchUpRecoverBlockHeaderFromDB` phase,
            // we may only have header in db
            if let Some(mut block) = self.data_man.block_from_db(&hash) {
                // Only construct synchronization graph if is not header_only.
                // Construct both sync and consensus graph if is header_only.
                let (insert_result, _) = self.insert_block_header(
                    &mut block.block_header,
                    true,        /* need_to_verify */
                    false,       /* bench_mode */
                    header_only, /* insert_to_consensus */
                    false,       /* persistent */
                );
                assert!(!insert_result.is_invalid());

                let parent = block.block_header.parent_hash().clone();
                let referees = block.block_header.referee_hashes().clone();

                // Construct consensus graph if is not header_only.
                if !header_only {
                    let result = self.insert_block(
                        block, true,  /* need_to_verify */
                        false, /* persistent */
                        true,  /* recover_from_db */
                    );
                    assert!(result.is_valid());
                }

                if !visited_blocks.contains(&parent) {
                    queue.push_back(parent);
                    visited_blocks.insert(parent);
                }

                for referee in referees {
                    if !visited_blocks.contains(&referee) {
                        queue.push_back(referee);
                        visited_blocks.insert(referee);
                    }
                }
            } else {
                missed_hashes.insert(hash);
            }
        }

        debug!("Initial missed blocks {:?}", missed_hashes);
        *self.initial_missed_block_hashes.lock() = missed_hashes;

        // Resolve out-of-era dependencies for graph-unready blocks.
        self.resolve_outside_dependencies(
            true,        /* recover_from_db */
            header_only, /* insert_header_into_consensus */
        );
        debug!(
            "Current frontier after recover from db: {:?}",
            self.inner.read().not_ready_blocks_frontier.get_frontier()
        );

        info!("Finish reading {} blocks from db, start to reconstruct the pivot chain and the state", visited_blocks.len());
        if !header_only && !self.is_consortium() {
            // Rebuild pivot chain state info.
            self.consensus.construct_pivot_state();
        }
        self.consensus.update_best_info();
        self.consensus
            .get_tx_pool()
            .notify_new_best_info(self.consensus.best_info())
            // FIXME: propogate error.
            .expect(&concat!(file!(), ":", line!(), ":", column!()));
        info!("Finish reconstructing the pivot chain of length {}, start to sync from peers", self.consensus.best_epoch_number());
    }

    /// Return None if `hash` is not in sync graph
    pub fn block_header_by_hash(&self, hash: &H256) -> Option<BlockHeader> {
        if !self.contains_block_header(hash) {
            // Only return headers in sync graph
            return None;
        }
        self.data_man
            .block_header_by_hash(hash)
            .map(|header_ref| header_ref.as_ref().clone())
    }

    /// Return None if `hash` is not in sync graph
    pub fn block_height_by_hash(&self, hash: &H256) -> Option<u64> {
        self.block_header_by_hash(hash)
            .map(|header| header.height())
    }

    /// Return None if `hash` is not in sync graph
    pub fn block_timestamp_by_hash(&self, hash: &H256) -> Option<u64> {
        self.block_header_by_hash(hash)
            .map(|header| header.timestamp())
    }

    /// TODO Be more specific about which functions only return in-memory data
    /// and which can return the in-database data
    pub fn block_by_hash(&self, hash: &H256) -> Option<Arc<Block>> {
        self.data_man.block_by_hash(hash, true /* update_cache */)
    }

    pub fn contains_block_header(&self, hash: &H256) -> bool {
        self.inner.read().hash_to_arena_indices.contains_key(hash)
    }

    fn parent_or_referees_invalid(&self, header: &BlockHeader) -> bool {
        self.data_man.verified_invalid(header.parent_hash()).0
            || header
                .referee_hashes()
                .iter()
                .any(|referee| self.data_man.verified_invalid(referee).0)
    }

    /// subroutine called by `insert_block_header` and `remove_expire_blocks`
    fn propagate_header_graph_status(
        &self, inner: &mut SynchronizationGraphInner,
        frontier_index_list: Vec<usize>, need_to_verify: bool,
        header_index_to_insert: usize, insert_to_consensus: bool,
        persistent: bool,
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
            } else if inner.new_to_be_header_graph_ready(index) {
                inner.arena[index].graph_status = BLOCK_HEADER_GRAPH_READY;
                inner.arena[index].last_update_timestamp = now;
                debug!("BlockIndex {} parent_index {} hash {:?} is header graph ready", index,
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
                        persistent,
                    );
                }
                if insert_to_consensus {
                    CONSENSUS_WORKER_QUEUE.enqueue(1);

                    self.consensus_unprocessed_count
                        .fetch_add(1, Ordering::SeqCst);
                    assert!(
                        self.new_block_hashes.send((
                            inner.arena[index].block_header.hash(),
                            true, /* ignore_body */
                        )),
                        "consensus receiver dropped"
                    );

                    // maintain not_ready_blocks_frontier
                    inner.not_ready_blocks_count -= 1;
                    inner.not_ready_blocks_frontier.remove(&index);
                    for child in &inner.arena[index].children {
                        inner.not_ready_blocks_frontier.insert(*child);
                    }
                }

                // Passed verification on header_arc.
                if inner.arena[index].block_ready {
                    need_to_relay.push(inner.arena[index].block_header.hash());
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
            } else {
                debug!(
                    "BlockIndex {} parent_index {} hash {:?} is not ready",
                    index,
                    inner.arena[index].parent,
                    inner.arena[index].block_header.hash()
                );
                if index == header_index_to_insert {
                    self.data_man.insert_block_header(
                        inner.arena[index].block_header.hash(),
                        inner.arena[index].block_header.clone(),
                        persistent,
                    );
                }
            }
        }
        (invalid_set, need_to_relay)
    }

    pub fn insert_block_header(
        &self, header: &mut BlockHeader, need_to_verify: bool,
        bench_mode: bool, insert_to_consensus: bool, persistent: bool,
    ) -> (BlockHeaderInsertionResult, Vec<H256>)
    {
        let _timer = MeterTimer::time_func(SYNC_INSERT_HEADER.as_ref());
        let inner = &mut *self.inner.write();
        let hash = header.hash();

        let (invalid, local_info_opt) = self.data_man.verified_invalid(&hash);
        if invalid {
            return (BlockHeaderInsertionResult::Invalid, Vec::new());
        }

        if let Some(info) = local_info_opt {
            // If the block is ordered before current era genesis or it has
            // already entered consensus graph in this run, we do not need to
            // process it. And it these two cases, the block is considered
            // valid.
            let already_processed = info.get_seq_num()
                < self.consensus.current_era_genesis_seq_num()
                || info.get_instance_id() == self.data_man.get_instance_id();
            if already_processed {
                if need_to_verify && !self.is_consortium() {
                    // Compute pow_quality, because the input header may be used
                    // as a part of block later
                    VerificationConfig::compute_header_pow_quality(header);
                }
                return (
                    BlockHeaderInsertionResult::AlreadyProcessed,
                    Vec::new(),
                );
            }
        }

        if inner.hash_to_arena_indices.contains_key(&hash) {
            if need_to_verify {
                // Compute pow_quality, because the input header may be used as
                // a part of block later
                VerificationConfig::compute_header_pow_quality(header);
            }
            return (BlockHeaderInsertionResult::AlreadyProcessed, Vec::new());
        }

        // skip check for consortium currently
        debug!("is_consortium={:?}", self.is_consortium());
        let verification_passed = if need_to_verify {
            self.is_consortium()
                || !(self.parent_or_referees_invalid(header)
                    || self
                        .verification_config
                        .verify_header_params(header)
                        .is_err())
        } else {
            if !bench_mode && !self.is_consortium() {
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

        // Currently, `inner.arena[me].graph_status` will only be
        //   1. `BLOCK_GRAPH_READY` for genesis block.
        //   2. `BLOCK_HEADER_ONLY` for non genesis block.
        //   3. `BLOCK_INVALID` for invalid block.
        if inner.arena[me].graph_status != BLOCK_GRAPH_READY {
            inner.not_ready_blocks_count += 1;
            // This block will become a new `not_ready_blocks_frontier` if
            //   1. It's parent block has not inserted yet.
            //   2. We are in `Catch Up Blocks Phase` and the graph status of
            // parent block is `BLOCK_GRAPH_READY`.
            //   3. We are in `Catch Up Headers Phase` and the graph status of
            // parent block is `BLOCK_HEADER_GRAPH_READY`.
            if inner.arena[me].parent == NULL
                || inner.arena[inner.arena[me].parent].graph_status
                    == BLOCK_GRAPH_READY
                || (insert_to_consensus
                    && inner.arena[inner.arena[me].parent].graph_status
                        == BLOCK_HEADER_GRAPH_READY)
            {
                inner.not_ready_blocks_frontier.insert(me);
            }
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

        debug!("insert_block_header() Block = {:?}, index = {}, need_to_verify = {}, bench_mode = {} insert_to_consensus = {}",
               header.hash(), me, need_to_verify, bench_mode, insert_to_consensus);

        // Start to pass influence to descendants
        let (invalid_set, need_to_relay) = self.propagate_header_graph_status(
            inner,
            vec![me],
            need_to_verify,
            me,
            insert_to_consensus,
            persistent,
        );

        let me_invalid = invalid_set.contains(&me);

        // Post-processing invalid blocks.
        inner.process_invalid_blocks(&invalid_set);

        if me_invalid {
            return (BlockHeaderInsertionResult::Invalid, need_to_relay);
        }

        inner.try_clear_old_era_blocks();

        (BlockHeaderInsertionResult::NewValid, need_to_relay)
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
        recover_from_db: bool,
    )
    {
        inner.arena[index].graph_status = BLOCK_GRAPH_READY;
        if inner.arena[index].parent_reclaimed {
            inner.old_era_blocks_frontier.push_back(index);
            inner.old_era_blocks_frontier_set.insert(index);
        }

        // maintain not_ready_blocks_frontier
        inner.not_ready_blocks_count -= 1;
        inner.not_ready_blocks_frontier.remove(&index);
        for child in &inner.arena[index].children {
            inner.not_ready_blocks_frontier.insert(*child);
        }

        let h = inner.arena[index].block_header.hash();
        debug!("Block {:?} is graph ready", h);
        // If this block is recovered from db, we need to explicitly call
        // consensus.on_new_block since we need to call
        // consensus.construct_pivot_state after all the blocks are inserted
        // into consensus graph; Otherwise Consensus Worker can handle the
        // block in order asynchronously. In addition, if this block is
        // recovered from db, we can simply ignore body.
        if !recover_from_db {
            CONSENSUS_WORKER_QUEUE.enqueue(1);

            self.consensus_unprocessed_count
                .fetch_add(1, Ordering::SeqCst);
            assert!(
                self.new_block_hashes.send((h, false /* ignore_body */)),
                "consensus receiver dropped"
            );

            if inner.config.enable_state_expose {
                STATE_EXPOSER.sync_graph.lock().ready_block_vec.push(
                    SyncGraphBlockState {
                        block_hash: h,
                        parent: inner.arena[index]
                            .block_header
                            .parent_hash()
                            .clone(),
                        referees: inner.arena[index]
                            .block_header
                            .referee_hashes()
                            .clone(),
                        nonce: inner.arena[index].block_header.nonce(),
                        timestamp: inner.arena[index].block_header.timestamp(),
                        adaptive: inner.arena[index].block_header.adaptive(),
                    },
                );
            }
        } else {
            // best info only needs to be updated after all blocks have been
            // inserted into consensus
            self.consensus.on_new_block(
                &h, true,  /* ignore_body */
                false, /* update_best_info */
            );
        }
    }

    /// subroutine called by `insert_block` and `remove_expire_blocks`
    fn propagate_graph_status(
        &self, inner: &mut SynchronizationGraphInner,
        frontier_index_list: Vec<usize>, recover_from_db: bool,
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
                self.set_graph_ready(inner, index, recover_from_db);
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
            } else {
                trace!("Block index {:?} not block_graph_ready, current frontier: {:?}", index, inner.not_ready_blocks_frontier.get_frontier());
            }
        }

        invalid_set
    }

    pub fn insert_block(
        &self, block: Block, need_to_verify: bool, persistent: bool,
        recover_from_db: bool,
    ) -> BlockInsertionResult
    {
        let _timer = MeterTimer::time_func(SYNC_INSERT_BLOCK.as_ref());
        let hash = block.hash();

        debug!("insert_block {:?}", hash);

        let inner = &mut *self.inner.write();

        if self.data_man.verified_invalid(&hash).0 {
            return BlockInsertionResult::Invalid;
        }

        let contains_block =
            if let Some(index) = inner.hash_to_arena_indices.get(&hash) {
                inner.arena[*index].block_ready
            } else {
                // Sync graph is cleaned after inserting the header, so we can
                // ignore the block body
                return BlockInsertionResult::Ignored;
            };

        if contains_block {
            return BlockInsertionResult::AlreadyProcessed;
        }

        self.statistics.inc_sync_graph_inserted_block_count();

        let me = *inner.hash_to_arena_indices.get(&hash).unwrap();
        debug_assert!(hash == inner.arena[me].block_header.hash());
        debug_assert!(!inner.arena[me].block_ready);
        inner.arena[me].block_ready = true;

        if need_to_verify {
            let r = self
                .verification_config
                .verify_block_basic(&block, self.consensus.best_chain_id());
            match r {
                Err(Error(
                    ErrorKind::Block(BlockError::InvalidTransactionsRoot(e)),
                    _,
                )) => {
                    warn ! ("BlockTransactionRoot not match! inserted_block={:?} err={:?}", block, e);
                    // If the transaction root does not match, it might be
                    // caused by receiving wrong
                    // transactions because of conflicting ShortId in
                    // CompactBlock, or caused by
                    // adversaries. In either case, we should request the block
                    // again, and the received block body is
                    // discarded.
                    inner.arena[me].block_ready = false;
                    return BlockInsertionResult::RequestAgain;
                }
                Err(e) => {
                    warn!(
                        "Invalid block! inserted_block={:?} err={:?}",
                        block.block_header, e
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
            if !recover_from_db {
                // Here we always build a new compact block because we should
                // not reuse the nonce
                self.data_man.insert_compact_block(block.to_compact());
                // block header was inserted in before, only insert block body
                // here
                self.data_man.insert_block_body(
                    block.hash(),
                    block.clone(),
                    persistent,
                );
            }
        }

        let invalid_set =
            self.propagate_graph_status(inner, vec![me], recover_from_db);

        // Post-processing invalid blocks.
        inner.process_invalid_blocks(&invalid_set);

        debug!(
            "new block inserted into graph: block_header={:?}, tx_count={}, block_size={}",
            block.block_header,
            block.transactions.len(),
            block.size(),
        );

        if inner.arena[me].graph_status == BLOCK_INVALID {
            BlockInsertionResult::Invalid
        } else if inner.arena[me].graph_status >= BLOCK_HEADER_GRAPH_READY {
            BlockInsertionResult::ShouldRelay
        } else {
            BlockInsertionResult::SuccessWithoutRelay
        }
    }

    pub fn get_all_block_hashes_by_epoch(
        &self, epoch_number: u64,
    ) -> Result<Vec<H256>, String> {
        let mut res = self.consensus.get_skipped_block_hashes_by_epoch(
            EpochNumber::Number(epoch_number.into()),
        )?;
        res.append(&mut self.consensus.get_block_hashes_by_epoch(
            EpochNumber::Number(epoch_number.into()),
        )?);
        Ok(res)
    }

    pub fn log_statistics(&self) { self.statistics.log_statistics(); }

    pub fn update_total_weight_delta_heartbeat(&self) {
        self.consensus.update_total_weight_delta_heartbeat();
    }

    /// Get the current number of blocks in the synchronization graph
    /// This only returns cached block count, and this is enough since this is
    /// only used in test.
    pub fn block_count(&self) -> usize { self.data_man.cached_block_count() }

    /// Resolve outside parent or referees dependencies for blocks which
    /// are not graph-ready.
    /// The parameter `recover_from_db` is needed for deciding to invoke
    /// consensus.on_new_block() in sync or async mode for the blocks that
    /// just become graph-ready. When  `recover_from_db` is true, the
    /// consensus.on_new_block() will be called in sync mode with
    /// `ignore_body` being true.
    pub fn resolve_outside_dependencies(
        &self, recover_from_db: bool, insert_header_to_consensus: bool,
    ) -> Vec<H256> {
        // Maintains the set of blocks that just become block-graph-ready
        // and may need to be relayed to peers.
        let mut to_relay_blocks = Vec::new();

        loop {
            let inner = &mut *self.inner.write();
            debug!(
                "not_ready_blocks_frontier: {:?}",
                inner.not_ready_blocks_frontier.get_frontier()
            );
            inner.not_ready_blocks_frontier.reset_update_state();
            let (
                new_graph_ready_blocks,
                mut new_header_graph_ready_blocks,
                invalid_blocks,
            ) = inner.try_recover_graph_unready_block();
            info!(
                "Recover blocks into graph_ready {:?}",
                new_graph_ready_blocks
            );
            info!(
                "Recover blocks into header graph_ready {:?}",
                new_header_graph_ready_blocks
            );

            for index in &new_graph_ready_blocks {
                to_relay_blocks.push(inner.arena[*index].block_header.hash());
            }

            for index in &new_header_graph_ready_blocks {
                inner.arena[*index].pending_referee_count = 0;
            }

            for index in &invalid_blocks {
                // propagate_header_graph_status will also pass BLOCK_INVALID to
                // descendants
                inner.arena[*index].graph_status = BLOCK_INVALID;
                new_header_graph_ready_blocks.push(*index);
            }
            // propagate BLOCK_HEADER_GRAPH_READY status to descendants
            let (invalid_set, need_to_relay) = self
                .propagate_header_graph_status(
                    inner,
                    new_header_graph_ready_blocks,
                    true, /* need_to_verify */
                    NULL, /* header_index_to_insert */
                    insert_header_to_consensus,
                    true, /* persistent */
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
                recover_from_db,
            );
            assert!(invalid_set.len() == 0);
            if !inner.not_ready_blocks_frontier.updated() {
                break;
            }
        }
        to_relay_blocks
    }

    /// Remove all blocks which have not been updated for a long time. We
    /// maintain a set `not_ready_blocks_frontier` which is the root nodes in
    /// the parental tree formed by not graph ready blocks. Find all expire
    /// blocks which can be reached by `not_ready_blocks_frontier`.
    pub fn remove_expire_blocks(&self, expire_time: u64) {
        let inner = &mut *self.inner.write();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut queue = VecDeque::new();
        let mut expire_set = HashSet::new();
        let mut visited = HashSet::new();
        // find expire blocks
        for index in inner.not_ready_blocks_frontier.get_frontier() {
            queue.push_back(*index);
            visited.insert(*index);
        }
        while let Some(index) = queue.pop_front() {
            if inner.arena[index].last_update_timestamp + expire_time < now {
                expire_set.insert(index);
            }
            for child in &inner.arena[index].children {
                if !visited.contains(child) {
                    visited.insert(*child);
                    queue.push_back(*child);
                }
            }
            for referrer in &inner.arena[index].referrers {
                if !visited.contains(referrer) {
                    visited.insert(*referrer);
                    queue.push_back(*referrer);
                }
            }
        }
        // find blocks reached by previous found expired blocks
        for index in &expire_set {
            queue.push_back(*index);
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
    }

    pub fn is_consensus_worker_busy(&self) -> bool {
        self.consensus_unprocessed_count.load(Ordering::SeqCst) != 0
    }
}

pub enum BlockInsertionResult {
    // The block is valid and already processed before.
    AlreadyProcessed,
    // The block is valid and is new to be block-graph-ready.
    ShouldRelay,
    // The block is valid but not block-graph-ready.
    SuccessWithoutRelay,
    // The block is definitely invalid. It's not inserted to sync graph
    // and should not be requested again.
    Invalid,
    // The case where transaction root does not match.
    // We should request again to get
    // the correct transactions for full verification.
    RequestAgain,
    // This is only for the case the the header is removed, possibly because
    // we switch phases.
    // We ignore the block without verification.
    Ignored,
}

impl BlockInsertionResult {
    pub fn is_valid(&self) -> bool {
        matches!(
            self,
            BlockInsertionResult::AlreadyProcessed
                | BlockInsertionResult::ShouldRelay
                | BlockInsertionResult::SuccessWithoutRelay
        )
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, BlockInsertionResult::Invalid)
    }

    pub fn should_relay(&self) -> bool {
        matches!(self, BlockInsertionResult::ShouldRelay)
    }

    pub fn request_again(&self) -> bool {
        matches!(self, BlockInsertionResult::RequestAgain)
    }
}

pub enum BlockHeaderInsertionResult {
    // The block is valid and already processed before.
    AlreadyProcessed,
    // The block is valid and is processed for the first time.
    NewValid,
    // The block is definitely invalid. It's not inserted to sync graph
    // and should not be requested again.
    Invalid,
}

impl BlockHeaderInsertionResult {
    pub fn is_new_valid(&self) -> bool {
        matches!(self, BlockHeaderInsertionResult::NewValid)
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, BlockHeaderInsertionResult::Invalid)
    }
}
