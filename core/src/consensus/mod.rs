// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    block_data_manager::BlockDataManager,
    cache_manager::{CacheId, CacheManager},
    db::COL_MISC,
    executive::{ExecutionError, Executive},
    ext_db::SystemDB,
    hash::KECCAK_EMPTY_LIST_RLP,
    machine::new_machine,
    pow::ProofOfWorkConfig,
    state::{CleanupMode, State},
    statedb::StateDb,
    statistics::SharedStatistics,
    storage::{state::StateTrait, StorageManager, StorageManagerTrait},
    sync::SynchronizationGraphInner,
    transaction_pool::SharedTransactionPool,
    vm::{EnvInfo, Spec},
    vm_factory::VmFactory,
};
use cfx_types::{Address, Bloom, H160, H256, U256, U512};
use link_cut_tree::{LinkCutTree, SignedBigNum};
use monitor::Monitor;
use parking_lot::{Mutex, RwLock};
use primitives::{
    filter::{Filter, FilterError},
    log_entry::{LocalizedLogEntry, LogEntry},
    receipt::{
        Receipt, TRANSACTION_OUTCOME_EXCEPTION, TRANSACTION_OUTCOME_SUCCESS,
    },
    transaction::Action,
    Block, BlockHeaderBuilder, EpochNumber, SignedTransaction,
    TransactionAddress,
};
use rayon::prelude::*;
use rlp::RlpStream;
use slab::Slab;
use std::{
    cell::RefCell,
    cmp::min,
    collections::{HashMap, HashSet, VecDeque},
    iter::FromIterator,
    sync::Arc,
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

const NULL: usize = !0;
const EPOCH_LIMIT_OF_RELATED_TRANSACTIONS: usize = 100;

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

pub struct ConsensusGraphNode {
    pub hash: H256,
    pub height: u64,
    pub difficulty: U256,
    /// The total difficulty of its past set (include itself)
    pub past_difficulty: U256,
    pub pow_quality: U256,
    pub parent: usize,
    pub children: Vec<usize>,
    pub referrers: Vec<usize>,
    pub referees: Vec<usize>,
    pub data: ConsensusGraphNodeData,
}

pub struct ConsensusGraphInner {
    pub arena: Slab<ConsensusGraphNode>,
    pub indices: HashMap<H256, usize>,
    pub pivot_chain: Vec<usize>,
    pub block_receipts_root: HashMap<usize, H256>,
    pub terminal_hashes: HashSet<H256>,
    genesis_block_index: usize,
    genesis_block_state_root: H256,
    genesis_block_receipts_root: H256,
    indices_in_epochs: HashMap<usize, Vec<usize>>,
    vm: VmFactory,
    weight_tree: LinkCutTree,
    pow_config: ProofOfWorkConfig,
    pub current_difficulty: U256,
    data_man: Arc<BlockDataManager>,
    pub storage_manager: Arc<StorageManager>,
}

impl ConsensusGraphInner {
    pub fn with_genesis_block(
        genesis_block: &Block, storage_manager: Arc<StorageManager>,
        vm: VmFactory, pow_config: ProofOfWorkConfig,
        data_man: Arc<BlockDataManager>,
    ) -> Self
    {
        let mut inner = ConsensusGraphInner {
            arena: Slab::new(),
            indices: HashMap::new(),
            pivot_chain: Vec::new(),
            block_receipts_root: Default::default(),
            terminal_hashes: Default::default(),
            genesis_block_index: NULL,
            genesis_block_state_root: genesis_block
                .block_header
                .deferred_state_root()
                .clone(),
            genesis_block_receipts_root: genesis_block
                .block_header
                .deferred_receipts_root()
                .clone(),
            indices_in_epochs: HashMap::new(),
            vm,
            weight_tree: LinkCutTree::new(),
            pow_config,
            current_difficulty: pow_config.initial_difficulty.into(),
            data_man,
            storage_manager,
        };

        // NOTE: Only genesis block will be first inserted into consensus graph
        // and then into synchronization graph. All the other blocks will be
        // inserted first into synchronization graph then consensus graph.
        // At current point, genesis block is not in synchronization graph,
        // so we cannot compute its past_difficulty from
        // sync_graph.total_difficulty_in_own_epoch().
        // For genesis block, its past_difficulty is simply its own difficulty.
        let (genesis_index, _) = inner
            .insert(genesis_block, *genesis_block.block_header.difficulty());
        inner.genesis_block_index = genesis_index;
        inner.weight_tree.make_tree(inner.genesis_block_index);
        inner.weight_tree.update_weight(
            inner.genesis_block_index,
            &SignedBigNum::pos(*genesis_block.block_header.difficulty()),
        );
        *inner.arena[inner.genesis_block_index]
            .data
            .epoch_number
            .borrow_mut() = 0;
        inner.pivot_chain.push(inner.genesis_block_index);
        assert!(inner.genesis_block_receipts_root == KECCAK_EMPTY_LIST_RLP);
        inner.block_receipts_root.insert(
            inner.genesis_block_index,
            inner.genesis_block_receipts_root,
        );
        inner
            .indices_in_epochs
            .insert(0, vec![inner.genesis_block_index]);

        inner
    }

    pub fn check_mining_heavy_block(
        &mut self, parent_index: usize, light_difficulty: U256,
    ) -> bool {
        let mut index = parent_index;
        let mut parent = self.arena[index].parent;
        let total_difficulty =
            self.weight_tree.subtree_weight(self.genesis_block_index);

        while index != self.genesis_block_index {
            debug_assert!(parent != NULL);
            let m = total_difficulty - self.arena[parent].past_difficulty;
            let n = self.weight_tree.subtree_weight(index);
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
            self.weight_tree.subtree_weight(self.genesis_block_index)
                - total_difficulty_to_minus
        };

        while index != self.genesis_block_index {
            debug_assert!(parent != NULL);
            let index_height = self.arena[index].height;
            if let Some(difficulty) = difficulties_to_minus.get(&index_height) {
                difficulty_to_minus = difficulty_to_minus + difficulty;
            }

            let m = total_difficulty - self.arena[parent].past_difficulty;
            let mut n = self.weight_tree.subtree_weight(index);
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
        &mut self, block: &Block, past_difficulty: U256,
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
            difficulty: *block.block_header.difficulty(),
            past_difficulty,
            pow_quality: block.block_header.pow_quality,
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
                .update_weight(*index, &SignedBigNum::neg(difficulty));
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

            let fork_subtree_weight = self.weight_tree.subtree_weight(fork);
            let pivot_subtree_weight = self.weight_tree.subtree_weight(pivot);

            if (fork_subtree_weight > pivot_subtree_weight)
                || ((fork_subtree_weight == pivot_subtree_weight)
                    && (self.arena[fork].hash > self.arena[pivot].hash))
            {
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
                .update_weight(*index, &SignedBigNum::pos(difficulty));
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

    fn process_epoch_transactions(
        &mut self, state: &mut State, epoch_blocks: &Vec<Arc<Block>>,
        unexecuted_transaction_addresses_lock: &Mutex<
            HashMap<H256, HashSet<TransactionAddress>>,
        >,
        on_local_pivot: bool, to_pending: &mut Vec<Arc<SignedTransaction>>,
    ) -> Vec<Arc<Vec<Receipt>>>
    {
        let pivot_block = epoch_blocks.last().expect("Epoch not empty");
        let spec = Spec::new_spec();
        let machine = new_machine();
        let mut epoch_receipts = Vec::with_capacity(epoch_blocks.len());
        for block in epoch_blocks.iter() {
            let mut receipts = Vec::new();
            debug!(
                "process txs in block: hash={:?}, tx count={:?}",
                block.hash(),
                block.transactions.len()
            );
            let mut env = EnvInfo {
                number: 0, // TODO: replace 0 with correct cardinal number
                author: block.block_header.author().clone(),
                timestamp: block.block_header.timestamp(),
                difficulty: block.block_header.difficulty().clone(),
                gas_used: U256::zero(),
                gas_limit: U256::from(block.block_header.gas_limit()),
            };
            let mut accumulated_fee: U256 = 0.into();
            let mut ex = Executive::new(state, &mut env, &machine, &spec);
            let mut n_invalid_nonce = 0;
            let mut n_ok = 0;
            let mut n_other = 0;
            let mut last_cumulative_gas_used = U256::zero();
            {
                // TODO We acquire the lock at the start to avoid acquiring it
                // for every tx. But if the server does not need
                // to handle tx related rpc, the lock is not needed.
                let mut transaction_addresses =
                    self.data_man.transaction_addresses.write();
                let mut unexecuted_transaction_addresses =
                    unexecuted_transaction_addresses_lock.lock();
                for (idx, transaction) in block.transactions.iter().enumerate()
                {
                    let mut tx_outcome_status = TRANSACTION_OUTCOME_EXCEPTION;
                    let mut transaction_logs = Vec::new();

                    let r = ex.transact(transaction);
                    // TODO Store fine-grained output status in receipts.
                    // Note now NotEnoughCash has
                    // outcome_status=TRANSACTION_OUTCOME_EXCEPTION,
                    // but its nonce is increased, which might need fixing.
                    match r {
                        Err(ExecutionError::NotEnoughBaseGas {
                            required: _,
                            got: _,
                        })
                        | Err(ExecutionError::SenderMustExist {})
                        | Err(ExecutionError::Internal(_)) => {
                            warn!(
                                    "tx execution error: transaction={:?}, err={:?}",
                                    transaction, r
                                );
                        }
                        Err(ExecutionError::InvalidNonce { expected, got }) => {
                            n_invalid_nonce += 1;
                            trace!("tx execution InvalidNonce without inc_nonce: transaction={:?}, err={:?}", transaction.clone(), r);
                            // Add future transactions back to pool if we are
                            // not verifying forking chain
                            if on_local_pivot && got > expected {
                                trace!(
                                        "To re-add transaction ({:?}) to pending pool",
                                        transaction.clone()
                                    );
                                to_pending.push(transaction.clone());
                            }
                        }
                        Ok(executed) => {
                            last_cumulative_gas_used =
                                executed.cumulative_gas_used;
                            n_ok += 1;
                            trace!("tx executed successfully: transaction={:?}, result={:?}, in block {:?}", transaction, executed, block.hash());
                            accumulated_fee += executed.fee;
                            transaction_logs = executed.logs;
                            tx_outcome_status = TRANSACTION_OUTCOME_SUCCESS;
                        }
                        _ => {
                            n_other += 1;
                            trace!("tx executed: transaction={:?}, result={:?}, in block {:?}", transaction, r, block.hash());
                        }
                    }
                    let receipt = Receipt::new(
                        tx_outcome_status,
                        last_cumulative_gas_used,
                        transaction_logs,
                    );
                    receipts.push(receipt);

                    if on_local_pivot {
                        let hash = transaction.hash();
                        let tx_addr = TransactionAddress {
                            block_hash: block.hash(),
                            index: idx,
                        };
                        if tx_outcome_status == TRANSACTION_OUTCOME_SUCCESS {
                            self.data_man.insert_transaction_address_to_kv(
                                &hash, &tx_addr,
                            );
                            if transaction_addresses.contains_key(&hash) {
                                transaction_addresses.insert(hash, tx_addr);
                                self.data_man.cache_man.lock().note_used(
                                    CacheId::TransactionAddress(hash),
                                );
                            }
                            unexecuted_transaction_addresses.remove(&hash);
                        } else {
                            let mut remove = false;
                            if let Some(addr_set) =
                                unexecuted_transaction_addresses.get_mut(&hash)
                            {
                                addr_set.remove(&tx_addr);
                                if addr_set.is_empty() {
                                    remove = true;
                                }
                            }
                            if remove {
                                // If a tx is not executed in all blocks, we
                                // will pack it again
                                // and it has already been in to_pending now.
                                unexecuted_transaction_addresses.remove(&hash);
                            }
                        }
                    }
                }
            }

            let block_receipts = Arc::new(receipts);
            self.data_man.insert_block_results_to_kv(
                block.hash(),
                pivot_block.hash(),
                block_receipts.clone(),
                on_local_pivot,
            );
            epoch_receipts.push(block_receipts);
            debug!(
                "n_invalid_nonce={}, n_ok={}, n_other={}",
                n_invalid_nonce, n_ok, n_other
            );
        }
        self.block_receipts_root.insert(
            *self.indices.get(&pivot_block.hash()).expect("in arena"),
            BlockHeaderBuilder::compute_block_receipts_root(&epoch_receipts),
        );
        debug!("Finish processing tx for epoch");
        epoch_receipts
    }

    // TODO remove stored fees in forks after processing rewards, and recompute
    // if it's needed in the future
    fn process_rewards_and_fees(
        &mut self, state: &mut State, pivot_index: usize,
        pivot_block_upper: usize, on_local_pivot: bool,
    )
    {
        /// (Fee, PackingBlockIndexSet)
        struct TxExecutionInfo(U256, HashSet<usize>);

        let pivot_hash = self.arena[pivot_index].hash.clone();
        debug!("Process rewards and fees for {:?}", pivot_hash);
        let difficulty = self.arena[pivot_index].difficulty;
        let mut rewards: Vec<(Address, U256)> = Vec::new();

        // Tx fee for each block in this epoch
        let mut tx_fee = HashMap::new();
        // Author of each block in this epoch
        let mut authors = HashMap::new();

        // Compute tx_fee of each block based on gas_used and gas_price of every
        // tx
        let indices_in_epoch =
            self.indices_in_epochs.get(&pivot_index).unwrap().clone();
        let mut epoch_receipts = None;
        for (enum_idx, index) in indices_in_epoch.iter().enumerate() {
            let block_hash = self.arena[*index].hash;
            let block = self
                .data_man
                .block_by_hash(&block_hash, false)
                .expect("exist");
            authors.insert(*index, block.block_header.author().clone());

            let receipts = match self.data_man.block_results_by_hash_with_epoch(
                &block_hash,
                &pivot_hash,
                true,
            ) {
                Some(receipts) => receipts.receipts,
                None => {
                    debug_assert!(!on_local_pivot);
                    // We need to return receipts instead of getting it through
                    // function get_receipts, because it's
                    // possible that the computed receipts is deleted by garbage
                    // collection before we try get it
                    if epoch_receipts.is_none() {
                        epoch_receipts =
                            Some(self.recompute_states(pivot_index));
                    }
                    epoch_receipts.as_ref().unwrap()[enum_idx].clone()
                }
            };

            let mut last_gas_used = U256::zero();
            debug_assert!(receipts.len() == block.transactions.len());
            for (idx, tx) in block.transactions.iter().enumerate() {
                let gas_used = receipts[idx].gas_used - last_gas_used;
                let fee = tx.gas_price * gas_used;
                let info = tx_fee
                    .entry(tx.hash())
                    .or_insert(TxExecutionInfo(fee, HashSet::default()));
                info.1.insert(*index);
                if !fee.is_zero() {
                    debug_assert!(info.1.len() == 1 || info.0.is_zero());
                    info.0 = fee;
                }
                last_gas_used = receipts[idx].gas_used;
            }
        }

        let mut block_tx_fees = HashMap::new();
        for TxExecutionInfo(fee, block_set) in tx_fee.values() {
            let block_count = U256::from(block_set.len());
            let quotient: U256 = *fee / block_count;
            let mut remainder: U256 = *fee - (block_count * quotient);
            for block_index in block_set {
                let reward =
                    block_tx_fees.entry(*block_index).or_insert(U256::zero());
                *reward += quotient;
                if !remainder.is_zero() {
                    *reward += 1.into();
                    remainder -= 1.into();
                }
            }
        }

        for index in &indices_in_epoch {
            if self.arena[*index].data.partial_invalid {
                continue;
            }
            let block_hash = self.arena[*index].hash;

            let mut reward: U512 =
                if self.arena[*index].pow_quality >= difficulty {
                    U512::from(BASE_MINING_REWARD) * U512::from(CONFLUX_TOKEN)
                } else {
                    debug!(
                        "Block {} pow_quality {} is less than difficulty {}!",
                        block_hash, self.arena[*index].pow_quality, difficulty
                    );
                    0.into()
                };

            // Add tx fee to base reward, and penalize them together
            if let Some(fee) = block_tx_fees.get(index) {
                reward += U512::from(*fee);
            }

            if reward > 0.into() {
                let anticone_set = self.arena[*index]
                    .data
                    .anticone
                    .difference(&self.arena[pivot_block_upper].data.anticone)
                    .cloned()
                    .collect::<HashSet<_>>();

                let mut anticone_difficulty: U512 = 0.into();
                for a_index in anticone_set {
                    anticone_difficulty +=
                        U512::from(self.arena[a_index].difficulty);
                }

                let penalty = reward * anticone_difficulty
                    / U512::from(self.arena[*index].difficulty)
                    * anticone_difficulty
                    / U512::from(self.arena[*index].difficulty)
                    / U512::from(ANTICONE_PENALTY_RATIO)
                    / U512::from(ANTICONE_PENALTY_RATIO);

                if penalty > reward {
                    debug!("Block {} penalty {} larger than reward {}! anticone_difficulty={}", self.arena[*index].hash, penalty, reward, anticone_difficulty);
                    reward = 0.into();
                } else {
                    reward -= penalty;
                }
            }

            debug_assert!(reward <= U512::from(U256::max_value()));
            let reward = U256::from(reward);
            let author = *authors.get(index).unwrap();
            rewards.push((author, reward));
            if on_local_pivot {
                self.data_man
                    .receipts_retain_epoch(&block_hash, &pivot_hash);
            }
        }
        debug!("Give rewards reward={:?}", rewards);

        for (address, reward) in rewards {
            state
                .add_balance(&address, &reward, CleanupMode::ForceCreate)
                .unwrap();
        }
    }

    /// Return the consensus graph indexes of the pivot block where the rewards
    /// of its epoch should be computed The rewards are needed to compute
    /// the state of the epoch at height `state_at` of `chain`
    fn get_pivot_reward_index(
        &self, state_at: usize, chain: &Vec<usize>,
    ) -> Option<(usize, usize)> {
        if state_at > REWARD_EPOCH_COUNT as usize {
            let epoch_num = state_at - REWARD_EPOCH_COUNT as usize;
            let anticone_penalty_epoch_upper =
                epoch_num + ANTICONE_PENALTY_UPPER_EPOCH_COUNT as usize;
            let pivot_index = chain[epoch_num];
            debug_assert!(epoch_num == self.arena[pivot_index].height as usize);
            debug_assert!(
                epoch_num
                    == *self.arena[pivot_index].data.epoch_number.borrow()
            );
            Some((pivot_index, chain[anticone_penalty_epoch_upper]))
        } else {
            None
        }
    }

    pub fn adjust_difficulty(
        &mut self, new_best_index: usize,
        sync_inner: &SynchronizationGraphInner,
    )
    {
        let new_best_hash = self.arena[new_best_index].hash.clone();
        let new_best_index_in_sync =
            *sync_inner.indices.get(&new_best_hash).unwrap();
        let new_best_light_difficulty =
            if sync_inner.arena[new_best_index_in_sync].is_heavy {
                self.arena[new_best_index].difficulty
                    / U256::from(HEAVY_BLOCK_DIFFICULTY_RATIO)
            } else {
                self.arena[new_best_index].difficulty
            };
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

    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch: EpochNumber,
    ) -> Result<(Vec<u8>, U256), String> {
        // only allow to call against stated epoch
        self.validate_stated_epoch(&epoch)?;

        let epoch_id = self.get_hash_from_epoch_number(epoch)?;
        let spec = Spec::new_spec();
        let machine = new_machine();
        let mut state = State::new(
            StateDb::new(self.storage_manager.get_state_at(epoch_id).unwrap()),
            0.into(),
            self.vm.clone(),
        );
        let mut env = EnvInfo {
            number: 0, // TODO: replace 0 with correct cardinal number
            author: Default::default(),
            timestamp: Default::default(),
            difficulty: Default::default(),
            gas_used: U256::zero(),
            gas_limit: tx.gas.clone(),
        };
        let mut ex = Executive::new(&mut state, &mut env, &machine, &spec);
        let r = ex.transact(tx);
        trace!("Execution result {:?}", r);
        r.map(|r| (r.output, r.gas_used))
            .map_err(|e| format!("execution error: {:?}", e))
    }

    pub fn recompute_states(
        &mut self, pivot_index: usize,
    ) -> Vec<Arc<Vec<Receipt>>> {
        let reversed_indices =
            self.indices_in_epochs.get(&pivot_index).unwrap();

        let mut epoch_blocks = Vec::new();
        {
            for idx in reversed_indices {
                let block = self
                    .data_man
                    .block_by_hash(&self.arena[*idx].hash, false)
                    .expect("Exist");
                epoch_blocks.push(block);
            }
        }
        debug!(
            "Recompute receipts epoch_id={}, block_count={}",
            self.arena[pivot_index].hash,
            reversed_indices.len()
        );
        // TODO This clone is only needed to pass borrow check. Needs to be
        // refactored.
        let storage_manager = self.storage_manager.clone();
        let mut state = State::new(
            StateDb::new(
                storage_manager
                    .get_state_at(
                        self.arena[self.arena[pivot_index].parent].hash,
                    )
                    .unwrap(),
            ),
            0.into(),
            self.vm.clone(),
        );
        self.process_epoch_transactions(
            &mut state,
            &epoch_blocks,
            &Mutex::new(Default::default()),
            false,
            &mut Vec::new(),
        )
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

    pub fn deferred_state_root(&self, chain: &[usize]) -> Option<H256> {
        let chain_len = chain.len();
        let index = if chain_len < DEFERRED_STATE_EPOCH_COUNT as usize {
            0
        } else {
            chain_len - DEFERRED_STATE_EPOCH_COUNT as usize
        };
        let state = self
            .storage_manager
            .get_state_at(self.arena[chain[index]].hash)
            .unwrap();
        trace!(
            "get state, hash ({:?}), chain len: {}, chain index: {}",
            self.arena[chain[index]].hash,
            chain_len,
            index
        );
        state.get_state_root().unwrap()
    }

    pub fn deferred_state_root_following_best_block(&self) -> H256 {
        self.deferred_state_root(&self.pivot_chain).unwrap()
    }

    pub fn deferred_receipts_root(&self, chain: &[usize]) -> Option<H256> {
        let chain_len = chain.len();
        let index = if chain_len < DEFERRED_STATE_EPOCH_COUNT as usize {
            0
        } else {
            chain_len - DEFERRED_STATE_EPOCH_COUNT as usize
        };

        let root = self.block_receipts_root.get(&chain[index])?;
        Some(root.clone())
    }

    pub fn deferred_receipts_root_following_best_block(&self) -> H256 {
        self.deferred_receipts_root(&self.pivot_chain).unwrap()
    }

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

    pub fn epoch_hash(&self, epoch_number: usize) -> H256 {
        assert!(epoch_number < self.pivot_chain.len());
        self.arena[self.pivot_chain[epoch_number]].hash
    }

    pub fn get_epoch_hash_for_block(&self, hash: &H256) -> Option<H256> {
        self.indices.get(hash).and_then(|block_index| {
            let epoch_number =
                self.arena[*block_index].data.epoch_number.borrow().clone();
            Some(self.epoch_hash(epoch_number))
        })
    }

    pub fn get_balance(
        &self, address: H160, epoch_number: EpochNumber,
    ) -> Result<U256, String> {
        let hash = self.get_hash_from_epoch_number(epoch_number)?;
        let state_db =
            StateDb::new(self.storage_manager.get_state_at(hash).unwrap());
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

    pub fn receipts_root_by_hash(&self, hash: &H256) -> Option<H256> {
        self.indices.get(hash).and_then(|index| {
            self.block_receipts_root.get(&index).map(Clone::clone)
        })
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
        let state_db =
            StateDb::new(self.storage_manager.get_state_at(hash).unwrap());
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
}

pub struct ConsensusGraph {
    pub inner: RwLock<ConsensusGraphInner>,
    genesis_block: Arc<Block>,
    pub txpool: SharedTransactionPool,
    pub data_man: Arc<BlockDataManager>,
    pub invalid_blocks: RwLock<HashSet<H256>>,
    storage_manager: Arc<StorageManager>,
    pub statistics: SharedStatistics,
}

pub type SharedConsensusGraph = Arc<ConsensusGraph>;

impl ConsensusGraph {
    pub fn with_genesis_block(
        genesis_block: Block, storage_manager: Arc<StorageManager>,
        vm: VmFactory, txpool: SharedTransactionPool,
        statistics: SharedStatistics, db: Arc<SystemDB>,
        cache_man: Arc<Mutex<CacheManager<CacheId>>>,
        pow_config: ProofOfWorkConfig,
    ) -> Self
    {
        let data_man = Arc::new(BlockDataManager::new(db, cache_man));
        let consensus_graph = ConsensusGraph {
            inner: RwLock::new(ConsensusGraphInner::with_genesis_block(
                &genesis_block,
                storage_manager.clone(),
                vm,
                pow_config,
                data_man.clone(),
            )),
            genesis_block: Arc::new(genesis_block),
            txpool,
            data_man: data_man.clone(),
            invalid_blocks: RwLock::new(HashSet::new()),
            storage_manager,
            statistics,
        };

        let genesis = consensus_graph.genesis_block();
        data_man.insert_block_header(
            genesis.hash(),
            Arc::new(genesis.block_header.clone()),
        );
        data_man.insert_block_to_kv(genesis, true);

        consensus_graph
    }

    pub fn check_mining_heavy_block(
        &self, parent_hash: &H256, light_difficulty: &U256,
    ) -> bool {
        let mut inner = self.inner.write();

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

    pub fn genesis_block(&self) -> Arc<Block> { self.genesis_block.clone() }

    pub fn verified_invalid(&self, hash: &H256) -> bool {
        self.invalid_blocks.read().contains(hash)
    }

    pub fn invalidate_block(&self, hash: &H256) {
        self.invalid_blocks.write().insert(hash.clone());
    }

    pub fn get_block_total_difficulty(&self, hash: &H256) -> Option<U256> {
        let mut w = self.inner.write();
        if let Some(idx) = w.indices.get(hash).cloned() {
            Some(w.weight_tree.subtree_weight(idx))
        } else {
            None
        }
    }

    pub fn get_block_epoch_number(&self, hash: &H256) -> Option<usize> {
        self.inner.read().get_block_epoch_number(hash)
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
        let mut epoch_blocks = Vec::new();
        let reversed_indices =
            inner.indices_in_epochs.get(&epoch_index).unwrap();
        {
            for idx in reversed_indices {
                let block = self
                    .data_man
                    .block_by_hash(&inner.arena[*idx].hash, false)
                    .expect("Exist");
                epoch_blocks.push(block);
            }
        }
        epoch_blocks
    }

    /// Compute the epoch `epoch_index`, and skip it if already computed.
    /// After the function is called, it's assured that the state, the receipt
    /// root, and the receipts of blocks executed by this epoch exist (receipt
    /// root must be in memory because it's not persisted now).
    /// The parameters are indexes in consensus graph.
    pub fn compute_epoch(
        &self, inner: &mut ConsensusGraphInner, epoch_index: usize,
        parent_index: usize, reward_index: Option<(usize, usize)>,
        on_local_pivot: bool, to_pending: &mut Vec<Arc<SignedTransaction>>,
    )
    {
        let epoch_hash = inner.arena[epoch_index].hash;

        // Check if the state has been computed
        if inner.storage_manager.state_exists(epoch_hash)
            && self.epoch_executed_and_recovered(
                epoch_index,
                inner,
                on_local_pivot,
            )
        {
            debug!("Skip execution in prefix {:?}", epoch_hash);
            return;
        }

        // Get blocks in this epoch after skip checking
        let epoch_blocks = self.get_epoch_blocks(inner, epoch_index);

        debug!(
            "Process tx epoch_id={}, block_count={}",
            epoch_hash,
            epoch_blocks.len()
        );

        let mut state = State::new(
            StateDb::new(
                self.storage_manager
                    .get_state_at(inner.arena[parent_index].hash)
                    .unwrap(),
            ),
            0.into(),
            inner.vm.clone(),
        );
        inner.process_epoch_transactions(
            &mut state,
            &epoch_blocks,
            &self.txpool.unexecuted_transaction_addresses,
            on_local_pivot,
            to_pending,
        );

        if let Some((reward_pivot_index, reward_pivot_upper_index)) =
            reward_index
        {
            // Calculate the block reward for blocks inside the epoch
            // All transaction fees are shared among blocks inside one epoch
            inner.process_rewards_and_fees(
                &mut state,
                reward_pivot_index,
                reward_pivot_upper_index,
                on_local_pivot,
            );
        }

        // FIXME: We may want to propagate the error up
        if on_local_pivot {
            state.commit_and_notify(epoch_hash, &self.txpool).unwrap();
        } else {
            state.commit(epoch_hash).unwrap();
        }
        debug!(
            "compute_epoch: on_local_pivot={}, epoch={:?} state_root={:?} receipt_root={:?}",
            on_local_pivot,
            epoch_hash,
            inner
                .storage_manager
                .get_state_at(epoch_hash)
                .unwrap()
                .get_state_root()
                .unwrap(),
            inner
                .block_receipts_root
                .get(&epoch_index)
                .unwrap()
        );
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
            let cached_state = inner
                .storage_manager
                .get_state_at(block_hash.clone())
                .unwrap();
            if cached_state.does_exist() {
                if let Some(receipts_root) =
                    inner.receipts_root_by_hash(&block_hash)
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
        debug!("Forked at index {}", idx);
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
            let reward_index = inner
                .get_pivot_reward_index(last_state_height, &inner.pivot_chain);
            self.compute_epoch(
                inner,
                inner.pivot_chain[last_state_height],
                inner.pivot_chain[last_state_height - 1],
                reward_index,
                false,
                &mut Vec::new(),
            );
            last_state_height += 1;
        }

        for fork_at in 1..chain.len() {
            let reward_index =
                if fork_height + fork_at > REWARD_EPOCH_COUNT as usize {
                    let epoch_num =
                        fork_height + fork_at - REWARD_EPOCH_COUNT as usize;
                    let anticone_penalty_epoch_upper =
                        epoch_num + ANTICONE_PENALTY_UPPER_EPOCH_COUNT as usize;
                    let pivot_block_upper =
                        if anticone_penalty_epoch_upper > fork_height {
                            chain[anticone_penalty_epoch_upper - fork_height]
                        } else {
                            inner.pivot_chain[anticone_penalty_epoch_upper]
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
            self.compute_epoch(
                inner,
                chain[fork_at],
                chain[fork_at - 1],
                reward_index,
                false,
                &mut Vec::new(),
            );
        }

        // FIXME: Propagate errors upward
        let state_root = inner
            .storage_manager
            .get_state_at(inner.arena[me].hash)
            .unwrap()
            .get_state_root()
            .unwrap()
            .unwrap();

        let receipts_root = inner.block_receipts_root.get(&me).unwrap().clone();
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
        if inner.arena[new].parent != *inner.pivot_chain.last().unwrap() {
            if !inner.check_correct_parent(new, sync_graph) {
                warn!(
                    "Partially invalid due to picking incorrect parent. {:?}",
                    block.block_header.clone()
                );
                return false;
            }
        }

        // Check heavy block
        let my_hash = inner.arena[new].hash;
        let my_index_in_sync_graph = *sync_graph.indices.get(&my_hash).unwrap();
        let is_heavy = sync_graph.arena[my_index_in_sync_graph].is_heavy;
        if is_heavy {
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

            if inner
                .storage_manager
                .contains_state(inner.arena[deferred].hash)
                && inner.block_receipts_root.contains_key(&deferred)
            {
                let mut valid = true;
                let correct_state_root = inner
                    .storage_manager
                    .get_state_at(inner.arena[deferred].hash)
                    .unwrap()
                    .get_state_root()
                    .unwrap()
                    .unwrap();
                if *block.block_header.deferred_state_root()
                    != correct_state_root
                {
                    warn!(
                        "Invalid state root: should be {:?}",
                        correct_state_root
                    );
                    valid = false;
                }
                let correct_receipts_root =
                    inner.block_receipts_root.get(&deferred).unwrap().clone();
                if *block.block_header.deferred_receipts_root()
                    != correct_receipts_root
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

    pub fn construct_pivot(&self, sync_inner: &SynchronizationGraphInner) {
        let mut inner = &mut *self.inner.write();

        assert_eq!(inner.pivot_chain.len(), 1);
        assert_eq!(inner.pivot_chain[0], inner.genesis_block_index);

        let mut new_pivot_chain = Vec::new();
        let mut u = inner.genesis_block_index;
        loop {
            new_pivot_chain.push(u);
            let mut heaviest = NULL;
            let mut heaviest_weight = U256::zero();
            for index in &inner.arena[u].children {
                let weight = inner.weight_tree.subtree_weight(*index);
                if heaviest == NULL
                    || weight > heaviest_weight
                    || (weight == heaviest_weight
                        && inner.arena[*index].hash
                            > inner.arena[heaviest].hash)
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
                inner.block_receipts_root.insert(
                    new_pivot_chain[height],
                    self.data_man
                        .block_header_by_hash(&future_block_hash)
                        .unwrap()
                        .deferred_receipts_root()
                        .clone(),
                );
            }

            height += 1;
        }

        // If the db is not corrupted, all unwrap in the following should pass.
        // TODO Verify db state in case of data missing
        // TODO Recompute missing data if needed
        inner.adjust_difficulty(
            *new_pivot_chain.last().expect("not empty"),
            sync_inner,
        );
        inner.pivot_chain = new_pivot_chain;
        // Compute receipts root for the deferred block of the mining block,
        // which is not in the db
        if inner.pivot_chain.len() > DEFERRED_STATE_EPOCH_COUNT as usize {
            let state_height =
                inner.pivot_chain.len() - DEFERRED_STATE_EPOCH_COUNT as usize;
            let pivot_index = inner.pivot_chain[state_height];
            let pivot_hash = inner.arena[pivot_index].hash.clone();
            let epoch_indexes =
                inner.indices_in_epochs.get(&pivot_index).unwrap().clone();
            let mut epoch_receipts = Vec::with_capacity(epoch_indexes.len());

            let mut receipts_correct = true;
            for i in epoch_indexes {
                if let Some(r) = self.data_man.block_results_by_hash_with_epoch(
                    &inner.arena[i].hash,
                    &pivot_hash,
                    true,
                ) {
                    epoch_receipts.push(r.receipts);
                } else {
                    // Constructed pivot chain does not match receipts in db, so
                    // we have to recompute the receipts of this epoch
                    receipts_correct = false;
                    break;
                }
            }
            if receipts_correct {
                inner.block_receipts_root.insert(
                    pivot_index,
                    BlockHeaderBuilder::compute_block_receipts_root(
                        &epoch_receipts,
                    ),
                );
            } else {
                let reward_index = inner
                    .get_pivot_reward_index(state_height, &inner.pivot_chain);
                self.compute_epoch(
                    inner,
                    pivot_index,
                    inner.arena[pivot_index].parent,
                    reward_index,
                    true,
                    &mut Vec::new(),
                );
            }
        }
    }

    pub fn on_new_block_construction_only(
        &self, hash: &H256, sync_inner: &SynchronizationGraphInner,
    ) {
        let block = self.data_man.block_by_hash(hash, false).unwrap();

        let inner = &mut *self.inner.write();
        let difficulty_in_my_epoch =
            sync_inner.total_difficulty_in_own_epoch(hash);
        let parent_idx =
            *inner.indices.get(block.block_header.parent_hash()).unwrap();
        let past_difficulty =
            inner.arena[parent_idx].past_difficulty + difficulty_in_my_epoch;

        let (me, indices_len) = inner.insert(block.as_ref(), past_difficulty);
        self.statistics
            .set_consensus_graph_inserted_block_count(indices_len);
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

        inner.weight_tree.make_tree(me);
        inner.weight_tree.link(inner.arena[me].parent, me);
        inner.weight_tree.update_weight(
            me,
            &SignedBigNum::pos(*block.block_header.difficulty()),
        );
    }

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
                self.txpool.remove_pending(tx.as_ref());
                self.txpool.remove_ready(tx.clone());
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
        info!("Transaction pool size={}", self.txpool.len());

        let mut inner = &mut *self.inner.write();

        let difficulty_in_my_epoch =
            sync_inner_lock.read().total_difficulty_in_own_epoch(hash);
        let parent_idx =
            *inner.indices.get(block.block_header.parent_hash()).unwrap();
        let past_difficulty =
            inner.arena[parent_idx].past_difficulty + difficulty_in_my_epoch;

        let (me, indices_len) = inner.insert(block.as_ref(), past_difficulty);
        self.statistics
            .set_consensus_graph_inserted_block_count(indices_len);
        inner.compute_anticone(me);

        let fully_valid = self.check_block_full_validity(
            me,
            block.as_ref(),
            inner,
            &*sync_inner_lock.read(),
        );
        self.data_man.insert_block_status_to_db(hash, !fully_valid);
        if !fully_valid {
            inner.arena[me].data.partial_invalid = true;
            return;
        }
        debug!("Block {} is fully valid", inner.arena[me].hash);

        inner.weight_tree.make_tree(me);
        inner.weight_tree.link(inner.arena[me].parent, me);
        inner.weight_tree.update_weight(
            me,
            &SignedBigNum::pos(*block.block_header.difficulty()),
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
            assert!(fork_at < inner.pivot_chain.len());
            let prev = inner.pivot_chain[fork_at];
            let prev_weight = inner.weight_tree.subtree_weight(prev);
            let new = inner.weight_tree.ancestor_at(me, fork_at as usize);
            let new_weight = inner.weight_tree.subtree_weight(new);

            if prev_weight < new_weight
                || (prev_weight == new_weight
                    && inner.arena[prev].hash < inner.arena[new].hash)
            {
                // The new subtree is heavier, update pivot chain
                new_pivot_chain.truncate(fork_at);
                let mut u = new;
                loop {
                    new_pivot_chain.push(u);
                    let mut heaviest = NULL;
                    let mut heaviest_weight = U256::zero();
                    for index in &inner.arena[u].children {
                        let weight = inner.weight_tree.subtree_weight(*index);
                        if heaviest == NULL
                            || weight > heaviest_weight
                            || (weight == heaviest_weight
                                && inner.arena[*index].hash
                                    > inner.arena[heaviest].hash)
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

        let mut to_pending = Vec::new();
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
            let reward_index =
                inner.get_pivot_reward_index(state_at, &new_pivot_chain);
            self.compute_epoch(
                inner,
                new_pivot_chain[state_at],
                new_pivot_chain[state_at - 1],
                reward_index,
                true,
                &mut to_pending,
            );
            state_at += 1;
        }

        if state_at > 1 {
            state_at -= 1;
            let state = inner
                .storage_manager
                .get_state_at(inner.arena[new_pivot_chain[state_at]].hash)
                .unwrap();
            self.txpool.recycle_future_transactions(to_pending, state);
        }

        inner.adjust_difficulty(
            *new_pivot_chain.last().expect("not empty"),
            &*sync_inner_lock.read(),
        );
        inner.pivot_chain = new_pivot_chain;
        inner.persist_terminals();

        // update latest state of pivot chain into monitor
        let mut state_epoch_number: usize = 0;
        if inner.pivot_chain.len() > DEFERRED_STATE_EPOCH_COUNT as usize {
            state_epoch_number =
                inner.pivot_chain.len() - DEFERRED_STATE_EPOCH_COUNT as usize;
        };
        let state_hash =
            inner.arena[inner.pivot_chain[state_epoch_number]].hash;
        Monitor::update_state(state_epoch_number, &state_hash);
    }

    /// Check if all executed results of an epoch exist
    ///
    /// This function will require lock of block_receipts
    pub fn epoch_executed_and_recovered(
        &self, epoch_index: usize, inner: &ConsensusGraphInner,
        on_local_pivot: bool,
    ) -> bool
    {
        // `block_receipts_root` is not computed when recovering from db with
        // fast_recover == false And we should force it to recompute
        // without checking receipts when fast_recover == false
        if !inner.block_receipts_root.contains_key(&epoch_index) {
            return false;
        }
        let mut epoch_receipts = Vec::new();
        if let Some(reversed_indices) =
            inner.indices_in_epochs.get(&epoch_index)
        {
            for i in reversed_indices {
                if let Some(r) = self.data_man.block_results_by_hash_with_epoch(
                    &inner.arena[*i].hash,
                    &inner.arena[epoch_index].hash,
                    true,
                ) {
                    epoch_receipts.push(r.receipts);
                } else {
                    return false;
                }
            }
        } else {
            return false;
        }

        // Recover tx address if we will skip pivot chain execution
        if on_local_pivot {
            let epoch_blocks = self.get_epoch_blocks(inner, epoch_index);
            for (block_idx, block) in epoch_blocks.iter().enumerate() {
                let block_hash = block.hash();
                for (tx_idx, tx) in block.transactions.iter().enumerate() {
                    if epoch_receipts[block_idx]
                        .get(tx_idx)
                        .unwrap()
                        .outcome_status
                        == TRANSACTION_OUTCOME_SUCCESS
                    {
                        self.data_man.insert_transaction_address_to_kv(
                            &tx.hash,
                            &TransactionAddress {
                                block_hash,
                                index: tx_idx,
                            },
                        )
                    }
                }
            }
        }
        true
    }

    pub fn best_block_hash(&self) -> H256 {
        self.inner.read().best_block_hash()
    }

    pub fn best_state_epoch_number(&self) -> usize {
        self.inner.read().best_state_epoch_number()
    }

    pub fn epoch_hash(&self, epoch_number: usize) -> H256 {
        self.inner.read().epoch_hash(epoch_number)
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
            assert!(address.index < block.transactions.len());
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

    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch: EpochNumber,
    ) -> Result<Vec<u8>, String> {
        self.inner
            .write()
            .call_virtual(tx, epoch)
            .map(|(output, _)| output)
    }

    pub fn estimate_gas(&self, tx: &SignedTransaction) -> Result<U256, String> {
        self.inner
            .write()
            .call_virtual(tx, EpochNumber::LatestState)
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
}
