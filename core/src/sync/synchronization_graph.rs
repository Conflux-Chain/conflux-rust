// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockDataManager,
    consensus::{ConsensusGraphInner, SharedConsensusGraph},
    db::COL_MISC,
    error::{BlockError, Error, ErrorKind},
    machine::new_machine,
    pow::{target_difficulty, ProofOfWorkConfig},
    statistics::SharedStatistics,
    storage::GuardedValue,
    verification::*,
};
use cfx_types::{H256, U256};
use link_cut_tree::MinLinkCutTree;
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};
use primitives::{
    transaction::SignedTransaction, Block, BlockHeader, EpochNumber,
    StateRootWithAuxInfo,
};
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
    time::{Duration, UNIX_EPOCH},
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
            // Already counted genesis block
            inserted_block_count: 1,
        }
    }
}

pub struct BestInformation {
    pub best_block_hash: H256,
    pub best_epoch_number: usize,
    pub current_difficulty: U256,
    pub terminal_block_hashes: Vec<H256>,
    pub deferred_state_root: StateRootWithAuxInfo,
    pub deferred_receipts_root: H256,
}

pub struct SynchronizationGraphNode {
    pub block_header: Arc<BlockHeader>,
    /// The status of graph connectivity in the current block view.
    pub graph_status: u8,
    /// Whether the block body is ready.
    pub block_ready: bool,
    /// Wether the parent or uncles of the block are older than checkpoint.
    pub parent_referees_too_old: bool,
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
    /// The minimum/maximum epoch number of the block in the view of other
    /// blocks including itself.
    pub min_epoch_in_other_views: u64,
    pub max_epoch_in_other_views: u64,
    pub sequence_number: u64,
}

pub struct SynchronizationGraphInner {
    pub arena: Slab<SynchronizationGraphNode>,
    pub indices: HashMap<H256, usize>,
    pub data_man: Arc<BlockDataManager>,
    pub genesis_block_index: usize,
    children_by_hash: HashMap<H256, Vec<usize>>,
    referrers_by_hash: HashMap<H256, Vec<usize>>,
    ancestor_tree: MinLinkCutTree,
    pow_config: ProofOfWorkConfig,
    pub sequence_number_of_header_entrance: u64,
}

impl SynchronizationGraphInner {
    pub fn with_genesis_block(
        genesis_header: Arc<BlockHeader>, pow_config: ProofOfWorkConfig,
        data_man: Arc<BlockDataManager>,
    ) -> Self
    {
        let mut inner = SynchronizationGraphInner {
            arena: Slab::new(),
            indices: HashMap::new(),
            data_man,
            genesis_block_index: NULL,
            children_by_hash: HashMap::new(),
            referrers_by_hash: HashMap::new(),
            ancestor_tree: MinLinkCutTree::new(),
            pow_config,
            sequence_number_of_header_entrance: 0,
        };
        inner.genesis_block_index = inner.insert(genesis_header);
        debug!(
            "genesis_block_index in sync graph: {}",
            inner.genesis_block_index
        );

        inner
    }

    pub fn get_next_sequence_number(&mut self) -> u64 {
        let sn = self.sequence_number_of_header_entrance;
        self.sequence_number_of_header_entrance += 1;
        sn
    }

    pub fn insert_invalid(&mut self, header: Arc<BlockHeader>) -> usize {
        let hash = header.hash();
        let me = self.arena.insert(SynchronizationGraphNode {
            graph_status: BLOCK_INVALID,
            block_ready: false,
            parent_referees_too_old: false,
            parent: NULL,
            children: Vec::new(),
            referees: Vec::new(),
            pending_referee_count: 0,
            referrers: Vec::new(),
            blockset_in_own_view_of_epoch: HashSet::new(),
            min_epoch_in_other_views: header.height(),
            max_epoch_in_other_views: header.height(),
            block_header: header,
            sequence_number: NULL as u64,
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
        let is_genesis = *header.parent_hash() == H256::default();
        let sn = if is_genesis {
            let sn = self.get_next_sequence_number();
            assert!(sn == 0);
            sn
        } else {
            NULL as u64
        };

        let me = self.arena.insert(SynchronizationGraphNode {
            graph_status: if is_genesis {
                BLOCK_GRAPH_READY
            } else {
                BLOCK_HEADER_ONLY
            },
            block_ready: *header.parent_hash() == H256::default(),
            parent_referees_too_old: false,
            parent: NULL,
            children: Vec::new(),
            referees: Vec::new(),
            pending_referee_count: 0,
            referrers: Vec::new(),
            blockset_in_own_view_of_epoch: HashSet::new(),
            min_epoch_in_other_views: header.height(),
            max_epoch_in_other_views: header.height(),
            block_header: header.clone(),
            sequence_number: sn,
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

    pub fn block_older_than_checkpoint(&self, _hash: &H256) -> bool { false }

    pub fn check_parent_referees_too_old(
        &mut self, me: usize, header: Arc<BlockHeader>,
    ) -> bool {
        let mut too_old = false;

        if self.block_older_than_checkpoint(header.parent_hash()) {
            too_old = true;
        }

        // FIXME: not sure the correct way to handle here.
        /*
        for referee in header.referee_hashes() {
            if self.block_older_than_checkpoint(referee) {
                assert!(self.arena[me].pending_referee_count > 0);
                self.arena[me].pending_referee_count -= 1;
            }
        }
        */

        if too_old {
            self.arena[me].parent_referees_too_old = true;
        }

        too_old
    }

    pub fn new_to_be_header_parental_tree_ready(&self, index: usize) -> bool {
        let ref node_me = self.arena[index];
        if node_me.graph_status >= BLOCK_HEADER_PARENTAL_TREE_READY {
            return false;
        }

        if node_me.parent_referees_too_old {
            return true;
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

        //FIXME: revisit this logic later.
        if node_me.parent_referees_too_old {
            if node_me.referrers.is_empty() && node_me.children.is_empty() {
                return false;
            } else {
                return !node_me.referees.iter().any(|&referee| {
                    self.arena[referee].graph_status < BLOCK_HEADER_GRAPH_READY
                });
            }
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
        let mut visited = HashSet::new();
        for referee in &self.arena[pivot].referees {
            visited.insert(*referee);
            queue.push_back(*referee);
        }

        while let Some(index) = queue.pop_front() {
            let mut in_old_epoch = false;
            let mut cur_pivot = pivot;
            if self.arena[cur_pivot].block_header.height()
                > self.arena[index].max_epoch_in_other_views + 1
            {
                cur_pivot = self.ancestor_tree.ancestor_at(
                    cur_pivot,
                    self.arena[index].max_epoch_in_other_views as usize + 1,
                );
            }
            loop {
                let parent = self.arena[cur_pivot].parent;
                debug_assert!(parent != NULL);

                if self.arena[parent].block_header.height()
                    < self.arena[index].min_epoch_in_other_views
                    || (self.arena[index].sequence_number
                        > self.arena[parent].sequence_number)
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
                    visited.insert(parent);
                    queue.push_back(parent);
                }
                for referee in &self.arena[index].referees {
                    if !visited.contains(referee) {
                        visited.insert(*referee);
                        queue.push_back(*referee);
                    }
                }
                self.arena[index].min_epoch_in_other_views = min(
                    self.arena[index].min_epoch_in_other_views,
                    self.arena[pivot].block_header.height(),
                );
                self.arena[index].max_epoch_in_other_views = max(
                    self.arena[index].max_epoch_in_other_views,
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
    ) -> Result<(), Error> {
        let epoch = self.arena[index].block_header.height();
        let parent = self.arena[index].parent;
        // Verify the height and epoch numbers are correct
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

        // Verify the timestamp being correctly set
        let my_timestamp = self.arena[index].block_header.timestamp();
        let parent_timestamp = self.arena[parent].block_header.timestamp();
        if parent_timestamp > my_timestamp {
            let my_timestamp = UNIX_EPOCH + Duration::from_secs(my_timestamp);
            let parent_timestamp =
                UNIX_EPOCH + Duration::from_secs(parent_timestamp);

            warn!("Invalid timestamp: parent {:?} timestamp {}, me {:?} timestamp {}",
                  self.arena[parent].block_header.hash(),
                  self.arena[parent].block_header.timestamp(),
                  self.arena[index].block_header.hash(),
                  self.arena[index].block_header.timestamp());
            return Err(From::from(BlockError::InvalidTimestamp(OutOfBounds {
                max: Some(my_timestamp),
                min: Some(parent_timestamp),
                found: my_timestamp,
            })));
        }

        for referee in &self.arena[index].referees {
            let referee_timestamp =
                self.arena[*referee].block_header.timestamp();
            if referee_timestamp > my_timestamp {
                let my_timestamp =
                    UNIX_EPOCH + Duration::from_secs(my_timestamp);
                let referee_timestamp =
                    UNIX_EPOCH + Duration::from_secs(referee_timestamp);

                warn!("Invalid timestamp: referee {:?} timestamp {}, me {:?} timestamp {}",
                      self.arena[*referee].block_header.hash(),
                      self.arena[*referee].block_header.timestamp(),
                      self.arena[index].block_header.hash(),
                      self.arena[index].block_header.timestamp());
                return Err(From::from(BlockError::InvalidTimestamp(
                    OutOfBounds {
                        max: Some(my_timestamp),
                        min: Some(referee_timestamp),
                        found: my_timestamp,
                    },
                )));
            }
        }

        // Verify the gas limit is respected
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

        // Verify difficulty being correctly set
        let expected_difficulty: U256 = self
            .expected_difficulty(self.arena[index].block_header.parent_hash());
        let my_difficulty = *self.arena[index].block_header.difficulty();

        if my_difficulty != expected_difficulty {
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

        Ok(())
    }

    /// Compute the expected difficulty (light_difficulty) for a block given its
    /// parent hash
    pub fn expected_difficulty(&self, parent_hash: &H256) -> U256 {
        let index = *self.indices.get(parent_hash).unwrap();
        let epoch = self.arena[index].block_header.height();
        if epoch < self.pow_config.difficulty_adjustment_epoch_period {
            // Use initial difficulty for early epochs
            self.pow_config.initial_difficulty.into()
        } else {
            // FIXME: I believe for most cases, we should be able to reuse the
            // parent difficulty! Only those in the boundary need to
            // be recomputed!
            let last_period_upper = (epoch
                / self.pow_config.difficulty_adjustment_epoch_period)
                * self.pow_config.difficulty_adjustment_epoch_period;
            let mut cur = index;
            while self.arena[cur].block_header.height() > last_period_upper {
                cur = self.arena[cur].parent;
            }
            // self.target_difficulty(&self.arena[cur].block_header.hash())
            target_difficulty(
                &self.data_man,
                &self.pow_config,
                &self.arena[cur].block_header.hash(),
                |h| {
                    let index = self.indices.get(h).unwrap();
                    self.arena[*index].blockset_in_own_view_of_epoch.len()
                },
            )
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

    /// This function translate the blockset_in_own_epoch from sync_index to
    /// consensus_index. It assumes all past blocks are in the consensus
    /// graph already. Otherwise, this function will panic!
    pub fn translate_blockset_in_own_epoch(
        &self, my_hash: &H256, consensus: SharedConsensusGraph,
    ) -> HashSet<usize> {
        let consensus_inner = consensus.inner.read();
        let my_sync_index = self.indices.get(my_hash).expect("exist");
        let mut consensus_blockset_in_own_epoch = HashSet::new();
        for index_in_sync in self.arena[*my_sync_index]
            .blockset_in_own_view_of_epoch
            .iter()
        {
            let hash = self.arena[*index_in_sync].block_header.hash();
            let index_in_consensus =
                consensus_inner.indices.get(&hash).unwrap();
            consensus_blockset_in_own_epoch.insert(*index_in_consensus);
        }
        consensus_blockset_in_own_epoch
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
        let data_man = consensus.data_man.clone();
        let (consensus_sender, consensus_receiver) = mpsc::channel();
        let inner = Arc::new(RwLock::new(
            SynchronizationGraphInner::with_genesis_block(
                Arc::new(data_man.genesis_block().block_header.clone()),
                pow_config,
                data_man.clone(),
            ),
        ));
        let mut sync_graph = SynchronizationGraph {
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
                    Ok(hash) => {
                        let translated_blockset =
                            inner.read().translate_blockset_in_own_epoch(
                                &hash,
                                consensus.clone(),
                            );
                        consensus.on_new_block(&hash, translated_blockset)
                    }
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

    pub fn get_to_propagate_trans(
        &self,
    ) -> HashMap<H256, Arc<SignedTransaction>> {
        self.consensus.get_to_propagate_trans()
    }

    pub fn set_to_propagate_trans(
        &self, transactions: HashMap<H256, Arc<SignedTransaction>>,
    ) {
        self.consensus.set_to_propagate_trans(transactions);
    }

    fn recover_graph_from_db(&mut self) {
        info!("Start full recovery of the block DAG and state from database");
        let terminals = match self.data_man.db.key_value().get(COL_MISC, b"terminals")
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
            if hash == self.data_man.genesis_block().hash() {
                continue;
            }

            if let Some(mut block) = self.block_by_hash_from_db(&hash) {
                // This is for constructing synchronization graph.
                let (success, _, is_old) = self.insert_block_header(
                    &mut block.block_header,
                    true,
                    false,
                );
                assert!(success);

                let parent = block.block_header.parent_hash().clone();
                let referees = block.block_header.referee_hashes().clone();

                // This is necessary to construct consensus graph.
                self.insert_block(block, !is_old, false, false);

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
        let terminals = match self.data_man.db.key_value().get(COL_MISC, b"terminals")
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
            if hash == self.data_man.genesis_block().hash() {
                continue;
            }

            if let Some(mut block) = self.block_by_hash_from_db(&hash) {
                // This is for constructing synchronization graph.
                let (success, _, is_old) = self.insert_block_header(
                    &mut block.block_header,
                    true,
                    false,
                );
                assert!(success);

                let parent = block.block_header.parent_hash().clone();
                let referees = block.block_header.referee_hashes().clone();

                // TODO Avoid reading blocks from db twice,
                // TODO possible by inserting blocks in topological order
                // TODO Read only headers from db
                // This is necessary to construct consensus graph.
                self.insert_block(block, !is_old, false, true);

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
        self.consensus.construct_pivot();
        info!("Finish reconstructing the pivot chain of length {}, start to sync from peers", self.consensus.best_epoch_number());
    }

    pub fn check_mining_adaptive_block(
        &self, inner: &mut ConsensusGraphInner, parent_hash: &H256,
        light_difficulty: &U256,
    ) -> bool
    {
        self.consensus.check_mining_adaptive_block(
            inner,
            parent_hash,
            light_difficulty,
        )
    }

    pub fn best_epoch_number(&self) -> u64 {
        self.consensus.best_epoch_number() as u64
    }

    pub fn block_header_by_hash(&self, hash: &H256) -> Option<BlockHeader> {
        self.data_man
            .block_header_by_hash(hash)
            .map(|header_ref| header_ref.as_ref().clone())
    }

    pub fn block_height_by_hash(&self, hash: &H256) -> Option<u64> {
        self.block_header_by_hash(hash)
            .map(|header| header.height())
    }

    pub fn block_by_hash(&self, hash: &H256) -> Option<Arc<Block>> {
        self.data_man.block_by_hash(hash, true)
    }

    pub fn block_by_hash_from_db(&self, hash: &H256) -> Option<Block> {
        self.data_man.block_by_hash_from_db(hash)
    }

    pub fn genesis_hash(&self) -> H256 { self.data_man.genesis_block().hash() }

    pub fn contains_block_header(&self, hash: &H256) -> bool {
        self.inner.read().indices.contains_key(hash)
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
            self.data_man.remove_block_header(&hash);
            self.remove_block_from_kv(&hash);
        }
    }

    pub fn insert_block_header(
        &self, header: &mut BlockHeader, need_to_verify: bool, bench_mode: bool,
    ) -> (bool, Vec<H256>, bool) {
        let mut me_is_old = false;
        let mut inner = self.inner.write();
        let hash = header.hash();

        if self.verified_invalid(&hash) {
            return (false, Vec::new(), me_is_old);
        }

        if let Some(me) = inner.indices.get(&hash) {
            if need_to_verify {
                // Compute pow_quality, because the input header may be used as
                // a part of block later
                VerificationConfig::compute_header_pow_quality(header);
            }
            return (true, Vec::new(), inner.arena[*me].parent_referees_too_old);
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
        debug!("insert_block_header() Block = {}, index = {}, need_to_verify = {}, bench_mode = {}",
               header.hash(), me, need_to_verify, bench_mode);

        me_is_old = inner.check_parent_referees_too_old(me, header_arc.clone());

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
            } else {
                if inner.new_to_be_header_graph_ready(index) {
                    inner.arena[index].sequence_number =
                        inner.get_next_sequence_number();
                    inner.arena[index].graph_status = BLOCK_HEADER_GRAPH_READY;
                    debug_assert!(inner.arena[index].parent != NULL);
                    debug!("BlockIndex {} parent_index {} hash {} is header graph ready", index,
                           inner.arena[index].parent, inner.arena[index].block_header.hash());

                    let r = inner.verify_header_graph_ready_block(index);

                    if need_to_verify && r.is_err() {
                        warn!(
                            "Invalid header_arc! inserted_header={:?} err={:?}",
                            header_arc.clone(),
                            r
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
                    let parent = inner.arena[index].parent;
                    inner.ancestor_tree.make_tree(index);
                    inner.ancestor_tree.link(parent, index);
                    inner.collect_blockset_in_own_view_of_epoch(index);

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

                let index_parent = inner.arena[index].parent;
                if index_parent != NULL {
                    if inner.arena[index_parent].parent_referees_too_old
                        && inner.arena[index_parent].graph_status
                            < BLOCK_HEADER_GRAPH_READY
                    {
                        queue.push_back(index_parent);
                    }
                }

                for referee in inner.arena[index].referees.iter() {
                    if inner.arena[*referee].parent_referees_too_old
                        && inner.arena[*referee].graph_status
                            < BLOCK_HEADER_GRAPH_READY
                    {
                        queue.push_back(*referee);
                    }
                }

                // Note that we have to insert it here immediately instead of
                // after the loop because its children may
                // become ready and being processed in the loop later. It
                // requires this block already being inserted
                // into the BlockDataManager!
                if me == index {
                    self.data_man.insert_block_header(
                        header_arc.hash(),
                        header_arc.clone(),
                    );
                }
            }
        }

        // Post-processing invalid blocks.
        self.process_invalid_blocks(inner.deref_mut(), &invalid_set);

        if me_invalid {
            return (false, need_to_relay, me_is_old);
        }

        (true, need_to_relay, me_is_old)
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
        self.data_man.insert_block_to_kv(block, persistent)
    }

    fn remove_block_from_kv(&self, hash: &H256) {
        self.data_man.remove_block_from_kv(hash)
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
                self.data_man.insert_compact_block(block.to_compact());
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
                    let translated_blockset = inner
                        .translate_blockset_in_own_epoch(
                            &h,
                            self.consensus.clone(),
                        );
                    self.consensus.on_new_block_construction_only(
                        &h,
                        translated_blockset,
                    );
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

    pub fn get_best_info(
        &self,
    ) -> GuardedValue<
        RwLockUpgradableReadGuard<ConsensusGraphInner>,
        BestInformation,
    > {
        let consensus_inner = self.consensus.inner.upgradable_read();
        let (deferred_state_root, deferred_receipts_root) = self
            .consensus
            .wait_for_block_state(&consensus_inner.best_state_block_hash());
        let value = BestInformation {
            best_block_hash: consensus_inner.best_block_hash(),
            best_epoch_number: consensus_inner.best_epoch_number(),
            current_difficulty: consensus_inner.current_difficulty,
            terminal_block_hashes: consensus_inner.terminal_hashes(),
            deferred_state_root: deferred_state_root,
            deferred_receipts_root,
        };
        GuardedValue::new(consensus_inner, value)
    }

    pub fn get_block_hashes_by_epoch(
        &self, epoch_number: u64,
    ) -> Result<Vec<H256>, String> {
        self.consensus
            .get_block_hashes_by_epoch(EpochNumber::Number(epoch_number.into()))
    }

    pub fn verified_invalid(&self, hash: &H256) -> bool {
        self.consensus.verified_invalid(hash)
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
}
