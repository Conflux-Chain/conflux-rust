// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    cache_manager::{CacheId, CacheManager, CacheSize},
    consensus::{SharedConsensusGraph, HEAVY_BLOCK_DIFFICULTY_RATIO},
    db::COL_MISC,
    error::{BlockError, Error, ErrorKind},
    machine::new_machine,
    pow::ProofOfWorkConfig,
    statistics::SharedStatistics,
    verification::*,
};
use cfx_types::{H256, U256, U512};
use heapsize::HeapSizeOf;
use parking_lot::{Mutex, RwLock};
use primitives::{block::CompactBlock, Block, BlockHeader};
use rlp::Rlp;
use slab::Slab;
use std::{
    cmp::{max, min},
    collections::{HashMap, HashSet, VecDeque},
    ops::DerefMut,
    sync::{
        mpsc::{self, Sender},
        Arc,
    },
    thread,
};
use unexpected::{Mismatch, OutOfBounds};

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
            inserted_block_count: 0,
        }
    }
}

pub struct BestInformation {
    pub best_block_hash: H256,
    pub current_difficulty: U256,
    pub terminal_block_hashes: Vec<H256>,
    pub deferred_state_root: H256,
    pub deferred_receipts_root: H256,
}

pub struct SynchronizationGraphNode {
    pub block_header: Arc<BlockHeader>,
    /// The status of graph connectivity in the current block view.
    pub graph_status: u8,
    /// Whether the block is a heavy block
    pub is_heavy: bool,
    /// Whether the block body is ready.
    pub block_ready: bool,
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
    /// The indices set of the blocks in the epoch when the current
    /// block is as pivot chain block. This set does not contain
    /// the block itself.
    pub blockset_in_own_view_of_epoch: HashSet<usize>,
    /// The minimum epoch number of the block in the view of other
    /// blocks including itself.
    pub min_epoch_in_other_views: u64,
}

impl SynchronizationGraphNode {
    pub fn light_difficulty(&self) -> U256 {
        if self.is_heavy {
            *self.block_header.difficulty()
                / U256::from(HEAVY_BLOCK_DIFFICULTY_RATIO)
        } else {
            *self.block_header.difficulty()
        }
    }
}

pub struct SynchronizationGraphInner {
    pub arena: Slab<SynchronizationGraphNode>,
    pub indices: HashMap<H256, usize>,
    pub genesis_block_index: usize,
    children_by_hash: HashMap<H256, Vec<usize>>,
    referrers_by_hash: HashMap<H256, Vec<usize>>,
    pow_config: ProofOfWorkConfig,
}

impl SynchronizationGraphInner {
    pub fn with_genesis_block(
        genesis_header: Arc<BlockHeader>, pow_config: ProofOfWorkConfig,
    ) -> Self {
        let mut inner = SynchronizationGraphInner {
            arena: Slab::new(),
            indices: HashMap::new(),
            genesis_block_index: NULL,
            children_by_hash: HashMap::new(),
            referrers_by_hash: HashMap::new(),
            pow_config,
        };
        inner.genesis_block_index = inner.insert(genesis_header);
        debug!(
            "genesis_block_index in sync graph: {}",
            inner.genesis_block_index
        );

        inner
    }

    pub fn insert_invalid(&mut self, header: Arc<BlockHeader>) -> usize {
        let hash = header.hash();
        let me = self.arena.insert(SynchronizationGraphNode {
            graph_status: BLOCK_INVALID,
            is_heavy: false,
            block_ready: false,
            parent: NULL,
            children: Vec::new(),
            referees: Vec::new(),
            pending_referee_count: 0,
            referrers: Vec::new(),
            blockset_in_own_view_of_epoch: HashSet::new(),
            min_epoch_in_other_views: header.height(),
            block_header: header,
        });
        self.indices.insert(hash, me);

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
        let me = self.arena.insert(SynchronizationGraphNode {
            graph_status: if *header.parent_hash() == H256::default() {
                BLOCK_GRAPH_READY
            } else {
                BLOCK_HEADER_ONLY
            },
            is_heavy: false,
            block_ready: *header.parent_hash() == H256::default(),
            parent: NULL,
            children: Vec::new(),
            referees: Vec::new(),
            pending_referee_count: 0,
            referrers: Vec::new(),
            blockset_in_own_view_of_epoch: HashSet::new(),
            min_epoch_in_other_views: header.height(),
            block_header: header.clone(),
        });
        self.indices.insert(hash, me);

        let parent_hash = header.parent_hash().clone();
        if parent_hash != H256::default() {
            if let Some(parent) = self.indices.get(&parent_hash).cloned() {
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
            if let Some(referee) = self.indices.get(referee_hash).cloned() {
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

    pub fn new_to_be_header_parental_tree_ready(&self, index: usize) -> bool {
        let ref node_me = self.arena[index];
        if node_me.graph_status >= BLOCK_HEADER_PARENTAL_TREE_READY {
            return false;
        }

        let parent = node_me.parent;
        parent != NULL
            && self.arena[parent].graph_status
                >= BLOCK_HEADER_PARENTAL_TREE_READY
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
        parent != NULL
            && self.arena[parent].graph_status >= BLOCK_HEADER_GRAPH_READY
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
            && parent != NULL
            && self.arena[parent].graph_status >= BLOCK_GRAPH_READY
            && !node_me.referees.iter().any(|&referee| {
                self.arena[referee].graph_status < BLOCK_GRAPH_READY
            })
    }

    fn collect_blockset_in_own_view_of_epoch(&mut self, pivot: usize) {
        let mut queue = VecDeque::new();
        for referee in &self.arena[pivot].referees {
            queue.push_back(*referee);
        }

        let mut visited = HashSet::new();
        while let Some(index) = queue.pop_front() {
            visited.insert(index);
            let mut in_old_epoch = false;
            let mut cur_pivot = pivot;
            loop {
                let parent = self.arena[cur_pivot].parent;
                debug_assert!(parent != NULL);
                if self.arena[parent].block_header.height()
                    < self.arena[index].min_epoch_in_other_views
                {
                    break;
                }
                if parent == index
                    || self.arena[parent]
                        .blockset_in_own_view_of_epoch
                        .contains(&index)
                {
                    in_old_epoch = true;
                    break;
                }
                cur_pivot = parent;
            }

            if !in_old_epoch {
                let parent = self.arena[index].parent;
                if !visited.contains(&parent) {
                    queue.push_back(parent);
                }
                for referee in &self.arena[index].referees {
                    if !visited.contains(referee) {
                        queue.push_back(*referee);
                    }
                }
                self.arena[index].min_epoch_in_other_views = min(
                    self.arena[index].min_epoch_in_other_views,
                    self.arena[pivot].block_header.height(),
                );
                self.arena[pivot]
                    .blockset_in_own_view_of_epoch
                    .insert(index);
            }
        }
    }

    fn verify_header_graph_ready_block(
        &self, index: usize,
    ) -> Result<bool, Error> {
        let mut is_heavy_block = false;
        let epoch = self.arena[index].block_header.height();
        let parent = self.arena[index].parent;
        if self.arena[parent].block_header.height() + 1 != epoch {
            warn!(
                "Invalid height. mine {}, parent {}",
                epoch,
                self.arena[parent].block_header.height()
            );
            return Err(From::from(BlockError::InvalidHeight(Mismatch {
                expected: self.arena[parent].block_header.height() + 1,
                found: epoch,
            })));
        }

        let machine = new_machine();
        let gas_limit_divisor = machine.params().gas_limit_bound_divisor;
        let min_gas_limit = machine.params().min_gas_limit;
        let parent_gas_limit = *self.arena[parent].block_header.gas_limit();
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

        let expected_difficulty: U256 = self
            .expected_difficulty(self.arena[index].block_header.parent_hash());
        let my_difficulty = *self.arena[index].block_header.difficulty();

        if U512::from(my_difficulty)
            == U512::from(expected_difficulty)
                * U512::from(HEAVY_BLOCK_DIFFICULTY_RATIO)
        {
            is_heavy_block = true;
        } else if my_difficulty != expected_difficulty {
            warn!(
                "expected_difficulty {}; difficulty {}",
                expected_difficulty,
                *self.arena[index].block_header.difficulty()
            );
            return Err(From::from(BlockError::InvalidDifficulty(Mismatch {
                expected: expected_difficulty,
                found: self.arena[index].block_header.difficulty().clone(),
            })));
        }

        Ok(is_heavy_block)
    }

    /// The input `my_hash` must have been inserted to sync_graph, otherwise
    /// it'll panic.
    pub fn total_difficulty_in_own_epoch(&self, my_hash: &H256) -> U256 {
        let my_index = *self.indices.get(my_hash).expect("exist");
        self.arena[my_index]
            .blockset_in_own_view_of_epoch
            .iter()
            .fold(
                self.arena[my_index].block_header.difficulty().clone(),
                |acc, x| acc + *self.arena[*x].block_header.difficulty(),
            )
    }

    /// The input `cur_hash` must have been inserted to sync_graph, otherwise
    /// it'll panic.
    pub fn target_difficulty(&self, cur_hash: &H256) -> U256 {
        let cur_index = *self.indices.get(cur_hash).expect("exist");
        let epoch = self.arena[cur_index].block_header.height();
        assert_ne!(epoch, 0);
        debug_assert!(
            epoch
                == (epoch / self.pow_config.difficulty_adjustment_epoch_period)
                    * self.pow_config.difficulty_adjustment_epoch_period
        );

        let mut cur = cur_index;
        let cur_difficulty = self.arena[cur].light_difficulty();
        let mut block_count = 0 as u64;
        let mut max_time = u64::min_value();
        let mut min_time = u64::max_value();
        for _ in 0..self.pow_config.difficulty_adjustment_epoch_period {
            for index in self.arena[cur].blockset_in_own_view_of_epoch.iter() {
                if self.arena[*index].is_heavy {
                    block_count += HEAVY_BLOCK_DIFFICULTY_RATIO as u64;
                } else {
                    block_count += 1;
                }
            }

            if self.arena[cur].is_heavy {
                block_count += HEAVY_BLOCK_DIFFICULTY_RATIO as u64;
            } else {
                block_count += 1;
            }

            max_time = max(max_time, self.arena[cur].block_header.timestamp());
            min_time = min(min_time, self.arena[cur].block_header.timestamp());
            cur = self.arena[cur].parent;
        }
        self.pow_config.target_difficulty(
            block_count,
            max_time - min_time,
            &cur_difficulty,
        )
    }

    pub fn expected_difficulty(&self, parent_hash: &H256) -> U256 {
        let index = *self.indices.get(parent_hash).unwrap();
        let epoch = self.arena[index].block_header.height();
        if epoch < self.pow_config.difficulty_adjustment_epoch_period {
            self.pow_config.initial_difficulty.into()
        } else {
            let last_period_upper = (epoch
                / self.pow_config.difficulty_adjustment_epoch_period)
                * self.pow_config.difficulty_adjustment_epoch_period;
            let mut cur = index;
            while self.arena[cur].block_header.height() > last_period_upper {
                cur = self.arena[cur].parent;
            }
            self.target_difficulty(&self.arena[cur].block_header.hash())
        }
    }

    pub fn is_in_past(&self, index: usize, pivot: usize) -> bool {
        let mut cur_pivot = pivot;
        loop {
            debug_assert!(cur_pivot != NULL);
            if self.arena[cur_pivot].block_header.height()
                < self.arena[index].min_epoch_in_other_views
            {
                break;
            }
            if cur_pivot == index
                || self.arena[cur_pivot]
                    .blockset_in_own_view_of_epoch
                    .contains(&index)
            {
                return true;
            }
            cur_pivot = self.arena[cur_pivot].parent;
        }
        false
    }
}

pub struct SynchronizationGraph {
    pub inner: Arc<RwLock<SynchronizationGraphInner>>,
    pub consensus: SharedConsensusGraph,
    pub block_headers: Arc<RwLock<HashMap<H256, Arc<BlockHeader>>>>,
    pub compact_blocks: RwLock<HashMap<H256, CompactBlock>>,
    pub blocks: Arc<RwLock<HashMap<H256, Arc<Block>>>>,
    genesis_block_hash: H256,
    pub initial_missed_block_hashes: Mutex<HashSet<H256>>,
    pub verification_config: VerificationConfig,
    pub cache_man: Arc<Mutex<CacheManager<CacheId>>>,
    pub statistics: SharedStatistics,

    /// Channel used to send work to `ConsensusGraph`
    consensus_sender: Mutex<Sender<H256>>,
}

pub type SharedSynchronizationGraph = Arc<SynchronizationGraph>;

impl SynchronizationGraph {
    pub fn new(
        consensus: SharedConsensusGraph,
        verification_config: VerificationConfig, pow_config: ProofOfWorkConfig,
        fast_recover: bool,
    ) -> Self
    {
        let genesis_block_hash = consensus.genesis_block().hash();
        let genesis_block_header = consensus
            .block_headers
            .read()
            .get(&genesis_block_hash)
            .expect("genesis exists")
            .clone();
        let (consensus_sender, consensus_receiver) = mpsc::channel();
        let inner = Arc::new(RwLock::new(
            SynchronizationGraphInner::with_genesis_block(
                genesis_block_header,
                pow_config,
            ),
        ));
        let mut sync_graph = SynchronizationGraph {
            inner: inner.clone(),
            compact_blocks: RwLock::new(HashMap::new()),
            blocks: consensus.blocks.clone(),
            block_headers: consensus.block_headers.clone(),
            genesis_block_hash,
            initial_missed_block_hashes: Mutex::new(HashSet::new()),
            verification_config,
            cache_man: consensus.cache_man.clone(),
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
                    Ok(hash) => consensus.on_new_block(&hash, inner.as_ref()),
                    Err(_) => break,
                }
            })
            .expect("Cannot fail");

        if fast_recover {
            sync_graph.fast_recover_graph_from_db();
        } else {
            sync_graph.recover_graph_from_db();
        }

        sync_graph
    }

    fn recover_graph_from_db(&mut self) {
        info!("Start full recovery of the block DAG and state from database");
        let terminals = match self.consensus.db.key_value().get(COL_MISC, b"terminals")
            .expect("Low-level database error when fetching 'terminals' block. Some issue with disk?")
            {
                Some(terminals) => {
                    let rlp = Rlp::new(&terminals);
                    rlp.as_list::<H256>().expect("Failed to decode terminals!")
                }
                None => {
                    info!("No terminals got from db");
                    return;
                }
            };

        debug!("Get terminals {:?}", terminals);
        let mut queue = VecDeque::new();
        for terminal in terminals {
            queue.push_back(terminal);
        }

        let mut missed_hashes = self.initial_missed_block_hashes.lock();
        let mut visited_blocks: HashSet<H256> = HashSet::new();
        while let Some(hash) = queue.pop_front() {
            if hash == self.genesis_block_hash {
                continue;
            }

            if let Some(mut block) = self.block_by_hash_from_db(&hash) {
                // This is for constructing synchronization graph.
                let res =
                    self.insert_block_header(&mut block.block_header, true);
                assert!(res.0);

                let parent = block.block_header.parent_hash().clone();
                let referees = block.block_header.referee_hashes().clone();

                // This is necessary to construct consensus graph.
                self.insert_block(block, true, false, false);

                if !self.contains_block(&parent)
                    && !visited_blocks.contains(&parent)
                {
                    queue.push_back(parent);
                    visited_blocks.insert(parent);
                }

                for referee in referees {
                    if !self.contains_block(&referee)
                        && !visited_blocks.contains(&referee)
                    {
                        queue.push_back(referee);
                        visited_blocks.insert(referee);
                    }
                }
            } else {
                missed_hashes.insert(hash);
            }
        }
        debug!("Initial missed blocks {:?}", *missed_hashes);
        info!(
            "Finish recovering {} blocks for SyncGraph",
            visited_blocks.len()
        );
    }

    fn fast_recover_graph_from_db(&mut self) {
        info!("Start fast recovery of the block DAG from database");
        let terminals = match self.consensus.db.key_value().get(COL_MISC, b"terminals")
            .expect("Low-level database error when fetching 'terminals' block. Some issue with disk?")
            {
                Some(terminals) => {
                    let rlp = Rlp::new(&terminals);
                    rlp.as_list::<H256>().expect("Failed to decode terminals!")
                }
                None => {
                    info!("No terminals got from db");
                    return;
                }
            };
        debug!("Get terminals {:?}", terminals);

        let mut queue = VecDeque::new();
        let mut visited_blocks: HashSet<H256> = HashSet::new();
        for terminal in terminals {
            queue.push_back(terminal);
            visited_blocks.insert(terminal);
        }

        let mut missed_hashes = self.initial_missed_block_hashes.lock();
        while let Some(hash) = queue.pop_front() {
            if hash == self.genesis_block_hash {
                continue;
            }

            if let Some(mut block) = self.block_by_hash_from_db(&hash) {
                // This is for constructing synchronization graph.
                let res =
                    self.insert_block_header(&mut block.block_header, true);
                assert!(res.0);

                let parent = block.block_header.parent_hash().clone();
                let referees = block.block_header.referee_hashes().clone();

                // TODO Avoid reading blocks from db twice,
                // TODO possible by inserting blocks in topological order
                // TODO Read only headers from db
                // This is necessary to construct consensus graph.
                self.insert_block(block, true, false, true);

                if !self.contains_block(&parent)
                    && !visited_blocks.contains(&parent)
                {
                    queue.push_back(parent);
                    visited_blocks.insert(parent);
                }

                for referee in referees {
                    if !self.contains_block(&referee)
                        && !visited_blocks.contains(&referee)
                    {
                        queue.push_back(referee);
                        visited_blocks.insert(referee);
                    }
                }
            } else {
                missed_hashes.insert(hash);
            }
        }

        debug!("Initial missed blocks {:?}", *missed_hashes);
        info!("Finish reading {} blocks from db, start to reconstruct the pivot chain and the state", visited_blocks.len());
        self.consensus.construct_pivot(&*self.inner.read());
        info!("Finish reconstructing the pivot chain of length {}, start to sync from peers", self.consensus.best_epoch_number());
    }

    pub fn check_mining_heavy_block(
        &self, parent_hash: &H256, light_difficulty: &U256,
    ) -> bool {
        self.consensus
            .check_mining_heavy_block(parent_hash, light_difficulty)
    }

    pub fn best_epoch_number(&self) -> u64 {
        self.consensus.best_epoch_number() as u64
    }

    pub fn block_header_by_hash(&self, hash: &H256) -> Option<BlockHeader> {
        self.block_headers
            .read()
            .get(hash)
            .map(|header_ref| (**header_ref).clone())
    }

    pub fn block_height_by_hash(&self, hash: &H256) -> Option<u64> {
        self.block_header_by_hash(hash)
            .map(|header| header.height())
    }

    pub fn block_by_hash(&self, hash: &H256) -> Option<Arc<Block>> {
        self.consensus.block_by_hash(hash, true)
    }

    pub fn block_by_hash_from_db(&self, hash: &H256) -> Option<Block> {
        self.consensus.block_by_hash_from_db(hash)
    }

    pub fn compact_block_by_hash(&self, hash: &H256) -> Option<CompactBlock> {
        self.compact_blocks.read().get(hash).map(|b| {
            self.cache_man
                .lock()
                .note_used(CacheId::CompactBlock(b.hash()));
            b.clone()
        })
    }

    pub fn genesis_hash(&self) -> &H256 { &self.genesis_block_hash }

    pub fn contains_block_header(&self, hash: &H256) -> bool {
        self.inner.read().indices.contains_key(hash)
    }

    pub fn contains_compact_block(&self, hash: &H256) -> bool {
        self.compact_blocks.read().contains_key(hash)
    }

    pub fn insert_compact_block(&self, cb: CompactBlock) {
        let hash = cb.hash();
        self.compact_blocks.write().insert(hash, cb);
        self.cache_man.lock().note_used(CacheId::CompactBlock(hash));
    }

    fn parent_or_referees_invalid(&self, header: &BlockHeader) -> bool {
        self.consensus.verified_invalid(header.parent_hash())
            || header
                .referee_hashes()
                .iter()
                .any(|referee| self.consensus.verified_invalid(referee))
    }

    fn set_and_propagate_invalid(
        inner: &mut SynchronizationGraphInner, queue: &mut VecDeque<usize>,
        invalid_set: &mut HashSet<usize>, index: usize,
    )
    {
        if !invalid_set.contains(&index) {
            invalid_set.insert(index);
            let children: Vec<usize> =
                inner.arena[index].children.iter().map(|x| *x).collect();
            for child in children {
                inner.arena[child].graph_status = BLOCK_INVALID;
                queue.push_back(child);
            }
            let referrers: Vec<usize> =
                inner.arena[index].referrers.iter().map(|x| *x).collect();
            for referrer in referrers {
                inner.arena[referrer].graph_status = BLOCK_INVALID;
                queue.push_back(referrer);
            }
        }
    }

    fn process_invalid_blocks(
        &self, inner: &mut SynchronizationGraphInner,
        invalid_set: &HashSet<usize>,
    )
    {
        for index in invalid_set {
            let hash = inner.arena[*index].block_header.hash();
            self.consensus.invalidate_block(&hash);

            let parent = inner.arena[*index].parent;
            if parent != NULL {
                inner.arena[parent].children.retain(|&x| x != *index);
            }
            let parent_hash = *inner.arena[*index].block_header.parent_hash();
            if let Some(children) = inner.children_by_hash.get_mut(&parent_hash)
            {
                children.retain(|&x| x != *index);
            }

            let referees: Vec<usize> =
                inner.arena[*index].referees.iter().map(|x| *x).collect();
            for referee in referees {
                inner.arena[referee].referrers.retain(|&x| x != *index);
            }
            let referee_hashes: Vec<H256> = inner.arena[*index]
                .block_header
                .referee_hashes()
                .iter()
                .map(|x| *x)
                .collect();
            for referee_hash in referee_hashes {
                if let Some(referrers) =
                    inner.referrers_by_hash.get_mut(&referee_hash)
                {
                    referrers.retain(|&x| x != *index);
                }
            }

            let children: Vec<usize> =
                inner.arena[*index].children.iter().map(|x| *x).collect();
            for child in children {
                debug_assert!(invalid_set.contains(&child));
                debug_assert!(inner.arena[child].graph_status == BLOCK_INVALID);
                inner.arena[child].parent = NULL;
            }

            let referrers: Vec<usize> =
                inner.arena[*index].referrers.iter().map(|x| *x).collect();
            for referrer in referrers {
                debug_assert!(invalid_set.contains(&referrer));
                debug_assert!(
                    inner.arena[referrer].graph_status == BLOCK_INVALID
                );
                inner.arena[referrer].referees.retain(|&x| x != *index);
            }

            inner.arena.remove(*index);
            inner.indices.remove(&hash);
            self.block_headers.write().remove(&hash);
            self.remove_block_from_kv(&hash);
        }
    }

    pub fn insert_block_header(
        &self, header: &mut BlockHeader, need_to_verify: bool,
    ) -> (bool, Vec<H256>) {
        let mut inner = self.inner.write();
        let hash = header.hash();

        if self.verified_invalid(&hash) {
            return (false, Vec::new());
        }

        if inner.indices.contains_key(&hash) {
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
            self.verification_config
                .verify_pow(header)
                .expect("local mined block should pass this check!");
            true
        };

        let header_arc = Arc::new(header.clone());
        let me = if verification_passed {
            inner.insert(header_arc.clone())
        } else {
            inner.insert_invalid(header_arc.clone())
        };

        // Start to pass influence to descendants
        let mut need_to_relay: Vec<H256> = Vec::new();
        let mut me_invalid = false;
        let mut invalid_set: HashSet<usize> = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(me);
        while let Some(index) = queue.pop_front() {
            if inner.arena[index].graph_status == BLOCK_INVALID {
                if me == index {
                    me_invalid = true;
                }
                Self::set_and_propagate_invalid(
                    inner.deref_mut(),
                    &mut queue,
                    &mut invalid_set,
                    index,
                );
            } else if inner.new_to_be_header_graph_ready(index) {
                inner.arena[index].graph_status = BLOCK_HEADER_GRAPH_READY;
                debug_assert!(inner.arena[index].parent != NULL);

                let r = inner.verify_header_graph_ready_block(index);
                inner.arena[index].is_heavy = match r {
                    Ok(is_heavy) => is_heavy,
                    _ => false,
                };

                if need_to_verify && r.is_err() {
                    warn!(
                        "Invalid header_arc! inserted_header={:?} err={:?}",
                        header_arc, r
                    );
                    if me == index {
                        me_invalid = true;
                    }
                    inner.arena[index].graph_status = BLOCK_INVALID;
                    Self::set_and_propagate_invalid(
                        inner.deref_mut(),
                        &mut queue,
                        &mut invalid_set,
                        index,
                    );
                    continue;
                }

                // Passed verification on header_arc.
                if inner.arena[index].block_ready {
                    need_to_relay.push(inner.arena[index].block_header.hash());
                }

                inner.collect_blockset_in_own_view_of_epoch(index);

                for child in &inner.arena[index].children {
                    debug_assert!(
                        inner.arena[*child].graph_status
                            < BLOCK_HEADER_GRAPH_READY
                    );
                    queue.push_back(*child);
                }
                for referrer in &inner.arena[index].referrers {
                    debug_assert!(
                        inner.arena[*referrer].graph_status
                            < BLOCK_HEADER_GRAPH_READY
                    );
                    queue.push_back(*referrer);
                }
            } else if inner.new_to_be_header_parental_tree_ready(index) {
                inner.arena[index].graph_status =
                    BLOCK_HEADER_PARENTAL_TREE_READY;
                for child in &inner.arena[index].children {
                    debug_assert!(
                        inner.arena[*child].graph_status
                            < BLOCK_HEADER_PARENTAL_TREE_READY
                    );
                    queue.push_back(*child);
                }
            }
        }

        // Post-processing invalid blocks.
        self.process_invalid_blocks(inner.deref_mut(), &invalid_set);

        if me_invalid {
            return (false, need_to_relay);
        }

        self.block_headers
            .write()
            .insert(header_arc.hash(), header_arc);
        (true, need_to_relay)
    }

    pub fn contains_block(&self, hash: &H256) -> bool {
        let inner = self.inner.read();
        if let Some(index) = inner.indices.get(hash) {
            inner.arena[*index].block_ready
        } else {
            false
        }
    }

    pub fn insert_block_to_kv(&self, block: Arc<Block>, persistent: bool) {
        self.consensus.insert_block_to_kv(block, persistent)
    }

    fn remove_block_from_kv(&self, hash: &H256) {
        self.consensus.remove_block_from_kv(hash)
    }

    pub fn insert_block(
        &self, block: Block, need_to_verify: bool, persistent: bool,
        sync_graph_only: bool,
    ) -> (bool, bool)
    {
        let mut insert_success = true;
        let mut need_to_relay = false;

        let hash = block.hash();

        let mut inner = self.inner.write();

        if self.verified_invalid(&hash) {
            insert_success = false;
            // (false, false)
            return (insert_success, need_to_relay);
        }

        let contains_block = if let Some(index) = inner.indices.get(&hash) {
            inner.arena[*index].block_ready
        } else {
            false
        };

        if contains_block {
            // (true, false)
            return (insert_success, need_to_relay);
        }

        self.statistics.inc_sync_graph_inserted_block_count();

        let me = *inner.indices.get(&hash).unwrap();
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

        let mut invalid_set: HashSet<usize> = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(me);

        let block = Arc::new(block);
        if inner.arena[me].graph_status != BLOCK_INVALID {
            // If we are rebuilding the graph from db, we do not insert all
            // blocks into memory
            if !sync_graph_only {
                // Here we always build a new compact block because we should
                // not reuse the nonce
                self.insert_compact_block(block.to_compact());
                self.insert_block_to_kv(block.clone(), persistent);
            }
        } else {
            insert_success = false;
        }

        while let Some(index) = queue.pop_front() {
            if inner.arena[index].graph_status == BLOCK_INVALID {
                Self::set_and_propagate_invalid(
                    inner.deref_mut(),
                    &mut queue,
                    &mut invalid_set,
                    index,
                );
            } else if inner.new_to_be_block_graph_ready(index) {
                inner.arena[index].graph_status = BLOCK_GRAPH_READY;

                let h = inner.arena[index].block_header.hash();
                debug!("Block {:?} is graph ready", h);
                if !sync_graph_only {
                    // Make Consensus Worker handle the block in order
                    // asynchronously
                    self.consensus_sender.lock().send(h).expect("Cannot fail");
                } else {
                    self.consensus.on_new_block_construction_only(&h, &*inner);
                }

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
        if inner.arena[me].graph_status >= BLOCK_HEADER_GRAPH_READY {
            need_to_relay = true;
        }

        // Post-processing invalid blocks.
        self.process_invalid_blocks(inner.deref_mut(), &invalid_set);
        if self.consensus.db.key_value().flush().is_err() {
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

    pub fn get_best_info(&self) -> BestInformation {
        let consensus_inner = self.consensus.inner.read();
        BestInformation {
            best_block_hash: consensus_inner.best_block_hash(),
            current_difficulty: consensus_inner.current_difficulty,
            terminal_block_hashes: consensus_inner.terminal_hashes(),
            deferred_state_root: consensus_inner
                .deferred_state_root_following_best_block(),
            deferred_receipts_root: consensus_inner
                .deferred_receipts_root_following_best_block(),
        }
    }

    pub fn verified_invalid(&self, hash: &H256) -> bool {
        self.consensus.verified_invalid(hash)
    }

    /// Get current cache size.
    pub fn cache_size(&self) -> CacheSize {
        let consensus_inner = self.consensus.inner.write();
        let compact_blocks = self.compact_blocks.read().heap_size_of_children();
        let blocks = self.blocks.read().heap_size_of_children();
        let block_receipts =
            consensus_inner.block_receipts.heap_size_of_children();
        let transaction_addresses = consensus_inner
            .transaction_addresses
            .heap_size_of_children()
            + self
                .consensus
                .txpool
                .unexecuted_transaction_addresses
                .lock()
                .heap_size_of_children();
        let transaction_pubkey = self
            .consensus
            .txpool
            .transaction_pubkey_cache
            .read()
            .heap_size_of_children();
        CacheSize {
            blocks,
            block_receipts,
            transaction_addresses,
            compact_blocks,
            transaction_pubkey,
        }
    }

    pub fn log_statistics(&self) { self.statistics.log_statistics(); }

    pub fn block_cache_gc(&self) {
        let current_size = self.cache_size().total();
        let mut consensus_inner = self.consensus.inner.write();
        let mut compact_blocks = self.compact_blocks.write();
        let mut blocks = self.blocks.write();
        let mut transaction_pubkey_cache =
            self.consensus.txpool.transaction_pubkey_cache.write();
        let mut unexecuted_transaction_addresses = self
            .consensus
            .txpool
            .unexecuted_transaction_addresses
            .lock();
        let mut cache_man = self.cache_man.lock();
        info!(
            "Before gc cache_size={} {} {} {} {} {} {}",
            current_size,
            blocks.len(),
            compact_blocks.len(),
            consensus_inner.block_receipts.len(),
            consensus_inner.transaction_addresses.len(),
            transaction_pubkey_cache.len(),
            unexecuted_transaction_addresses.len()
        );

        cache_man.collect_garbage(current_size, |ids| {
            for id in &ids {
                match *id {
                    CacheId::Block(ref h) => {
                        blocks.remove(h);
                    }
                    CacheId::BlockReceipts(ref h) => {
                        consensus_inner.block_receipts.remove(h);
                    }
                    CacheId::TransactionAddress(ref h) => {
                        consensus_inner.transaction_addresses.remove(h);
                    }
                    CacheId::UnexecutedTransactionAddress(ref h) => {
                        unexecuted_transaction_addresses.remove(h);
                    }
                    CacheId::CompactBlock(ref h) => {
                        compact_blocks.remove(h);
                    }
                    CacheId::TransactionPubkey(ref h) => {
                        transaction_pubkey_cache.remove(h);
                    }
                }
            }

            blocks.shrink_to_fit();
            consensus_inner.block_receipts.shrink_to_fit();
            consensus_inner.transaction_addresses.shrink_to_fit();
            transaction_pubkey_cache.shrink_to_fit();
            unexecuted_transaction_addresses.shrink_to_fit();
            compact_blocks.shrink_to_fit();

            blocks.heap_size_of_children()
                + consensus_inner.block_receipts.heap_size_of_children()
                + consensus_inner
                    .transaction_addresses
                    .heap_size_of_children()
                + transaction_pubkey_cache.heap_size_of_children()
                + unexecuted_transaction_addresses.heap_size_of_children()
                + compact_blocks.heap_size_of_children()
        });
    }

    // Manage statistics

    pub fn stat_inc_inserted_count(&self) {
        let mut inner = self.statistics.inner.write();
        inner.sync_graph.inserted_block_count += 1;
    }
}
