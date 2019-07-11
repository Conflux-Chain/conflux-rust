// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod anticone_cache;
mod confirmation;
pub mod consensus_inner;
mod debug;

use super::consensus::consensus_inner::{
    consensus_executor::ConsensusExecutor,
    consensus_new_block_handler::ConsensusNewBlockHandler,
};
use crate::{
    block_data_manager::BlockDataManager,
    consensus::confirmation::ConfirmationTrait, pow::ProofOfWorkConfig,
    state::State, statistics::SharedStatistics,
    transaction_pool::SharedTransactionPool, vm_factory::VmFactory,
};
use cfx_types::{Bloom, H160, H256, U256};
// use fenwick_tree::FenwickTree;
pub use crate::consensus::consensus_inner::{
    ConsensusGraphInner, ConsensusInnerConfig,
};
use crate::storage::GuardedValue;
use metrics::{register_meter_with_group, Meter, MeterTimer};
use parking_lot::{RwLock, RwLockUpgradableReadGuard};
use primitives::{
    filter::{Filter, FilterError},
    log_entry::{LocalizedLogEntry, LogEntry},
    receipt::Receipt,
    Block, EpochNumber, SignedTransaction, StateRootWithAuxInfo,
    TransactionAddress,
};
use rayon::prelude::*;
use std::{
    cmp::{min, Reverse},
    collections::{HashMap, HashSet},
    sync::Arc,
    thread::sleep,
    time::Duration,
};
lazy_static! {
    static ref CONSENSIS_ON_NEW_BLOCK_TIMER: Arc<Meter> =
        register_meter_with_group("timer", "consensus_on_new_block_timer");
}

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

pub struct BestInformation {
    pub best_block_hash: H256,
    pub best_epoch_number: u64,
    pub current_difficulty: U256,
    pub terminal_block_hashes: Vec<H256>,
    pub deferred_state_root: StateRootWithAuxInfo,
    pub deferred_receipts_root: H256,
    pub deferred_logs_bloom_hash: H256,
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

    /// Make sure that it is only modified when holding inner lock to prevent
    /// any inconsistency
    best_epoch_number: RwLock<u64>,
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
            best_epoch_number: RwLock::new(0),
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
        while !self.inner.read().hash_to_arena_indices.contains_key(hash) {
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
        let parent_index =
            *inner.hash_to_arena_indices.get(parent_hash).unwrap();
        inner.check_mining_adaptive_block(parent_index, *difficulty)
    }

    pub fn get_height_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<u64, String> {
        self.inner.read().get_height_from_epoch_number(epoch_number)
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
        &self, inner: &ConsensusGraphInner, epoch_arena_index: usize,
    ) -> Vec<Arc<Block>> {
        inner.get_executable_epoch_blocks(&self.data_man, epoch_arena_index)
    }

    /// This is a very expensive call to force the engine to recompute the state
    /// root of a given block
    #[inline]
    pub fn compute_state_for_block(
        &self, block_hash: &H256, inner: &ConsensusGraphInner,
    ) -> Result<(StateRootWithAuxInfo, H256, H256), String> {
        self.executor.compute_state_for_block(block_hash, inner)
    }

    /// Force the engine to recompute the deferred state root for a particular
    /// block given a delay.
    pub fn compute_deferred_state_for_block(
        &self, block_hash: &H256, delay: usize,
    ) -> Result<(StateRootWithAuxInfo, H256, H256), String> {
        let inner = &mut *self.inner.write();

        let idx_opt = inner.hash_to_arena_indices.get(block_hash);
        if idx_opt == None {
            return Err(
                "Parent hash is too old for computing the deferred state"
                    .to_owned(),
            );
        }
        let mut idx = *idx_opt.unwrap();
        for _i in 0..delay {
            if idx == inner.cur_era_genesis_block_arena_index {
                // If it is the original genesis, we just break
                if inner.arena[inner.cur_era_genesis_block_arena_index].height
                    == 0
                {
                    break;
                } else {
                    return Err("Parent hash is too old for computing the deferred state".to_owned());
                }
            }
            idx = inner.arena[idx].parent;
        }
        let hash = inner.arena[idx].hash;
        self.executor.compute_state_for_block(&hash, inner)
    }

    /// construct_pivot() should be used after on_new_block_construction_only()
    /// calls. It builds the pivot chain and ists state at once, avoiding
    /// intermediate redundant computation triggered by on_new_block().
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

    /// This is the function to insert a new block into the consensus graph
    /// during construction. We by pass many verifications because those
    /// blocks are from our own database so we trust them. After inserting
    /// all blocks with this function, we need to call construct_pivot() to
    /// finish the building from db!
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

    /// This is the main function that SynchronizationGraph calls to deliver a
    /// new block to the consensus graph.
    pub fn on_new_block(&self, hash: &H256) {
        let _timer =
            MeterTimer::time_func(CONSENSIS_ON_NEW_BLOCK_TIMER.as_ref());
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
        *self.best_epoch_number.write() = inner.best_epoch_number();
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
        let me = *inner.hash_to_arena_indices.get(hash).unwrap();
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
    pub fn block_count(&self) -> usize {
        self.inner.read().hash_to_arena_indices.len()
    }

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
                let epoch_hash = inner.arena
                    [inner.get_pivot_block_arena_index(epoch_number)]
                .hash;
                for index in &inner.arena
                    [inner.get_pivot_block_arena_index(epoch_number)]
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
    /// Return the state_root, receipts_root, and logs_bloom_hash
    pub fn wait_for_block_state(
        &self, block_hash: &H256,
    ) -> (StateRootWithAuxInfo, H256, H256) {
        self.executor.wait_for_result(*block_hash)
    }

    /// Return the current era genesis block (checkpoint block) in the consesus
    /// graph. This API is used by the SynchronizationLayer to trim data
    /// before the checkpoint.
    pub fn current_era_genesis_hash(&self) -> H256 {
        let inner = self.inner.read();
        inner.arena[inner.cur_era_genesis_block_arena_index]
            .hash
            .clone()
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
        let (
            deferred_state_root,
            deferred_receipts_root,
            deferred_logs_bloom_hash,
        ) = self.wait_for_block_state(&consensus_inner.best_state_block_hash());
        let mut bounded_terminal_hashes = consensus_inner.terminal_hashes();
        if let Some(referee_bound) = referee_bound_opt {
            if bounded_terminal_hashes.len() > referee_bound {
                let mut tmp = Vec::new();
                let best_idx = consensus_inner.pivot_chain.last().unwrap();
                for hash in bounded_terminal_hashes {
                    let a_idx = consensus_inner
                        .hash_to_arena_indices
                        .get(&hash)
                        .unwrap();
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
            deferred_logs_bloom_hash,
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

    pub fn best_epoch_number(&self) -> u64 { *self.best_epoch_number.read() }
}

impl Drop for ConsensusGraph {
    fn drop(&mut self) { self.executor.stop(); }
}
