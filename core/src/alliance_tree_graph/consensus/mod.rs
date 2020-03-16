// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub mod consensus_inner;
mod debug;
pub mod error;

use super::consensus::consensus_inner::{
    consensus_executor::ConsensusExecutor,
    consensus_new_block_handler::ConsensusNewBlockHandler, ConsensusGraphInner,
    ConsensusInnerConfig,
};

use crate::{
    block_data_manager::{
        block_data_types::EpochExecutionCommitment, BlockDataManager,
        BlockExecutionResultWithEpoch,
    },
    bytes::Bytes,
    consensus::{BestInformation, ConsensusGraphTrait},
    parameters::{block::REFEREE_BOUND, consensus::*, consensus_internal::*},
    pow::ProofOfWorkConfig,
    state::State,
    state_exposer::{ConsensusGraphBlockState, STATE_EXPOSER},
    statedb::StateDb,
    statistics::SharedStatistics,
    storage::state_manager::StateManagerTrait,
    sync::Error,
    transaction_pool::SharedTransactionPool,
    vm_factory::VmFactory,
};
use cfx_types::{Address, Bloom, H256, U256};
use futures::channel::oneshot;
use libra_types::block_info::PivotBlockDecision;
use metrics::{register_meter_with_group, Meter, MeterTimer};
use network::PeerId;
use parking_lot::{Mutex, RwLock};
use primitives::{
    epoch::BlockHashOrEpochNumber,
    filter::{Filter, FilterError},
    log_entry::{LocalizedLogEntry, LogEntry},
    receipt::Receipt,
    Block, EpochId, EpochNumber, SignedTransaction, TransactionIndex,
};
use rayon::prelude::*;
use std::{any::Any, cmp::Reverse, collections::HashSet, sync::Arc};

pub type NextSelectedPivotCallbackType =
    oneshot::Sender<Result<PivotBlockDecision, Error>>;
pub type NewCandidatePivotCallbackType =
    oneshot::Sender<Result<bool, anyhow::Error>>;
pub type SetPivotChainCallbackType = oneshot::Sender<Result<(), Error>>;

lazy_static! {
    static ref CONSENSIS_ON_NEW_BLOCK_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "consensus_on_new_block_timer");
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

    pub fn clear(&mut self) {
        self.inserted_block_count = 0;
        self.processed_block_count = 0;
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
pub struct TreeGraphConsensus {
    pub inner: Arc<RwLock<ConsensusGraphInner>>,
    pub txpool: SharedTransactionPool,
    pub data_man: Arc<BlockDataManager>,
    executor: Arc<ConsensusExecutor>,
    pub statistics: SharedStatistics,
    pub new_block_handler: ConsensusNewBlockHandler,
    /// Make sure that it is only modified when holding inner lock to prevent
    /// any inconsistency
    best_info: RwLock<Arc<BestInformation>>,
    /// This is the hash of latest block inserted into consensus graph.
    /// Since the critical section is very short, a `Mutex` is enough.
    pub latest_inserted_block: Mutex<H256>,
}

pub type SharedConsensusGraph = Arc<TreeGraphConsensus>;

impl TreeGraphConsensus {
    /// Build the TreeGraphConsensus with a specific era genesis block and
    /// various other components. The execution will be skipped if
    /// bench_mode sets to true. The height of
    pub fn with_era_genesis(
        conf: ConsensusConfig, vm: VmFactory, txpool: SharedTransactionPool,
        statistics: SharedStatistics, data_man: Arc<BlockDataManager>,
        pow_config: ProofOfWorkConfig, era_genesis_block_hash: &H256,
    ) -> Self
    {
        let inner =
            Arc::new(RwLock::new(ConsensusGraphInner::with_era_genesis(
                pow_config,
                data_man.clone(),
                conf.inner_conf.clone(),
                era_genesis_block_hash,
            )));
        let executor = ConsensusExecutor::start(
            txpool.clone(),
            data_man.clone(),
            vm,
            conf.inner_conf.clone(),
            conf.bench_mode,
        );

        let graph = TreeGraphConsensus {
            inner,
            txpool: txpool.clone(),
            data_man: data_man.clone(),
            executor: executor.clone(),
            statistics: statistics.clone(),
            new_block_handler: ConsensusNewBlockHandler::new(
                conf, txpool, data_man, executor, statistics,
            ),
            best_info: RwLock::new(Arc::new(Default::default())),
            latest_inserted_block: Mutex::new(*era_genesis_block_hash),
        };
        graph.update_best_info();
        graph
            .txpool
            .notify_new_best_info(graph.best_info.read_recursive().clone())
            // FIXME: propogate error.
            .expect(&concat!(file!(), ":", line!(), ":", column!()));
        graph
    }

    /// Build the TreeGraphConsensus with the initial (checkpointed) genesis
    /// block in the data manager and various other components. The
    /// execution will be skipped if bench_mode sets to true.
    pub fn new(
        conf: ConsensusConfig, vm: VmFactory, txpool: SharedTransactionPool,
        statistics: SharedStatistics, data_man: Arc<BlockDataManager>,
        pow_config: ProofOfWorkConfig,
    ) -> Self
    {
        let genesis_hash = data_man.get_cur_consensus_era_genesis_hash();
        TreeGraphConsensus::with_era_genesis(
            conf,
            vm,
            txpool,
            statistics,
            data_man,
            pow_config,
            &genesis_hash,
        )
    }

    /// Convert EpochNumber to height based on the current TreeGraphConsensus
    pub fn get_height_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<u64, String> {
        Ok(match epoch_number {
            EpochNumber::Earliest => 0,
            EpochNumber::LatestMined => self.best_epoch_number(),
            EpochNumber::LatestState => self.best_epoch_number(),
            EpochNumber::Number(num) => {
                let epoch_num = num;
                if epoch_num > self.best_epoch_number() {
                    return Err("Invalid params: expected a numbers with less than largest epoch number.".into());
                }
                epoch_num
            }
        })
    }

    /// Get the average gas price of the last GAS_PRICE_TRANSACTION_SAMPLE_SIZE
    /// blocks
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
                .block_hashes_by_epoch(last_epoch_number.into())
                .unwrap();
            hashes.reverse();
            last_epoch_number -= 1;

            for hash in hashes {
                let block = self
                    .data_man
                    .block_by_hash(&hash, false /* update_cache */)
                    .unwrap();
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

    fn validate_stated_epoch(
        &self, epoch_number: &EpochNumber,
    ) -> Result<(), String> {
        match epoch_number {
            EpochNumber::LatestMined => {
                return Err("Latest mined epoch is not executed".into());
            }
            EpochNumber::Number(num) => {
                let latest_state_epoch = self.best_epoch_number();
                if *num > latest_state_epoch {
                    return Err(format!("Specified epoch {} is not executed, the latest state epoch is {}", num, latest_state_epoch));
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn get_state_db_by_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<StateDb, String> {
        self.validate_stated_epoch(&epoch_number)?;
        let height = self.get_height_from_epoch_number(epoch_number)?;
        let hash = self.inner.read().epoch_hash(height)?;
        // Keep the lock until we get the desired State, otherwise the State may
        // expire.
        let state_availability_boundary =
            self.data_man.state_availability_boundary.read();
        if !state_availability_boundary.check_availability(height, &hash) {
            return Err(format!(
                "State for epoch (number={:?} hash={:?}) does not exist: out-of-bound {:?}",
                height, hash, self.data_man.state_availability_boundary.read()
            )
                .into());
        }
        let (_state_index_guard, maybe_state_readonly_index) =
            self.data_man.get_state_readonly_index(&hash).into();
        let maybe_state = match maybe_state_readonly_index {
            Some(state_readonly_index) => self
                .data_man
                .storage_manager
                .get_state_no_commit(state_readonly_index)
                .map_err(|e| format!("Error to get state, err={:?}", e))?,
            None => None,
        };

        let state = match maybe_state {
            Some(state) => state,
            None => {
                return Err(format!(
                    "State for epoch (number={:?} hash={:?}) does not exist",
                    height, hash
                )
                .into())
            }
        };

        Ok(StateDb::new(state))
    }

    /// Get the code of an address
    pub fn get_code(
        &self, address: Address, epoch_number: EpochNumber,
    ) -> Result<Bytes, String> {
        let state_db =
            self.get_state_db_by_epoch_number(epoch_number.clone())?;
        let acc = match state_db.get_account(&address) {
            Ok(Some(acc)) => acc,
            _ => {
                return Err(format!(
                    "Account {:?} epoch_number={:?} does not exist",
                    address, epoch_number,
                )
                .into())
            }
        };

        match state_db.get_code(&address, &acc.code_hash) {
            Ok(Some(code)) => Ok(code.code),
            _ => Ok(vec![]),
        }
    }

    /// Get the current balance of an address
    pub fn get_balance(
        &self, address: Address, epoch_number: EpochNumber,
    ) -> Result<U256, String> {
        let state_db = self.get_state_db_by_epoch_number(epoch_number)?;
        Ok(if let Ok(maybe_acc) = state_db.get_account(&address) {
            maybe_acc.map_or(U256::zero(), |acc| acc.balance).into()
        } else {
            0.into()
        })
    }

    pub fn on_new_candidate_pivot(
        &self, pivot_decision: &PivotBlockDecision, _peer_id: Option<PeerId>,
        callback: NewCandidatePivotCallbackType,
    ) -> bool
    {
        let inner = &mut *self.inner.write();
        self.new_block_handler.on_new_candidate_pivot(
            inner,
            pivot_decision,
            callback,
            inner.inner_conf.candidate_pivot_waiting_timeout_ms,
        )
    }

    pub fn on_next_selected_pivot_block(
        &self, last_pivot_hash: Option<&H256>,
        callback: NextSelectedPivotCallbackType,
    ) -> Option<Block>
    {
        let inner = &mut *self.inner.write();
        self.new_block_handler.on_next_selected_pivot_block(
            inner,
            last_pivot_hash,
            callback,
        )
    }

    pub fn on_commit(&self, block_hashes: &Vec<H256>) {
        let inner = &mut *self.inner.write();
        self.new_block_handler.on_commit(inner, block_hashes);
    }

    pub fn set_pivot_chain(
        &self, block_hash: &H256, callback: SetPivotChainCallbackType,
    ) -> bool {
        let inner = &mut *self.inner.write();
        assert!(inner.hash_to_arena_indices.contains_key(block_hash));
        self.new_block_handler
            .set_pivot_chain(inner, block_hash, callback)
    }

    pub fn remove_expired_bft_execution(&self) {
        let inner = &mut *self.inner.write();
        inner.remove_expired_bft_execution();
    }

    pub fn get_transaction_receipt_and_block_info(
        &self, tx_hash: &H256,
    ) -> Option<(BlockExecutionResultWithEpoch, TransactionIndex, H256)> {
        let (results_with_epoch, address) = {
            let inner = self.inner.read();
            let address = self.data_man.transaction_index_by_hash(
                tx_hash, false, /* update_cache */
            )?;
            (
                inner.block_execution_results_by_hash(
                    &address.block_hash,
                    true,
                )?,
                address,
            )
        };
        let epoch_hash = results_with_epoch.0;
        // FIXME handle state_root in snapshot
        // We already has transaction address with epoch_hash executed, so we
        // can always get the state_root with `wait_for_result`
        let state_root = self
            .executor
            .wait_for_result(epoch_hash)
            .state_root_with_aux_info
            .state_root
            .compute_state_root_hash();
        Some((results_with_epoch, address, state_root))
    }

    pub fn transaction_count(
        &self, address: Address,
        block_hash_or_epoch_number: BlockHashOrEpochNumber,
    ) -> Result<U256, String>
    {
        let epoch_number = match block_hash_or_epoch_number {
            BlockHashOrEpochNumber::BlockHash(hash) => EpochNumber::Number(
                self.inner
                    .read()
                    .get_block_epoch_number(&hash)
                    .ok_or("block epoch number is NULL")?,
            ),
            BlockHashOrEpochNumber::EpochNumber(epoch_number) => epoch_number,
        };
        let state_db = self.get_state_db_by_epoch_number(epoch_number)?;
        state_db
            .get_account(&address)
            .map(|maybe_acc| maybe_acc.map_or(0.into(), |acc| acc.nonce))
            .map_err(|err| format!("Get transaction count error: {:?}", err))
    }

    /// Estimate the gas of a transaction
    pub fn estimate_gas(
        &self, tx: &SignedTransaction, epoch: EpochNumber,
    ) -> Result<U256, String> {
        self.call_virtual(tx, epoch).map(|(_, gas_used)| gas_used)
    }

    pub fn logs(
        &self, filter: Filter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        let block_hashes = if filter.block_hashes.is_none() {
            let inner = self.inner.read();
            // at most best_epoch
            let from_epoch =
                self.get_height_from_epoch_number(filter.from_epoch.clone())?;

            // at most best_epoch
            let to_epoch =
                self.get_height_from_epoch_number(filter.to_epoch.clone())?;

            if from_epoch > to_epoch {
                return Err(FilterError::InvalidEpochNumber {
                    from_epoch,
                    to_epoch,
                });
            }

            let blooms = filter.bloom_possibilities();
            let mut blocks = vec![];
            for epoch_number in from_epoch..(to_epoch + 1) {
                if epoch_number <= inner.get_cur_era_genesis_height() {
                    // Blocks before (including) `cur_era_genesis` does not has
                    // epoch set in memory, so we should get
                    // the epoch set from db
                    let epoch_set = self
                        .data_man
                        .epoch_set_hashes_from_db(epoch_number)
                        .expect("epoch set past checkpoint should exist");
                    let epoch_hash = epoch_set.last().expect("Not empty");
                    for hash in &epoch_set {
                        if self.block_matches_bloom(hash, epoch_hash, &blooms) {
                            blocks.push(*hash);
                        }
                    }
                } else {
                    // Use the epoch set maintained in memory
                    let pivot_index = inner.height_to_pivot_index(epoch_number);
                    let pivot_arena_index = inner.pivot_chain[pivot_index];
                    let epoch_hash = &inner.arena[pivot_arena_index].hash;
                    for index in &inner.arena[pivot_arena_index]
                        .data
                        .as_ref()
                        .expect("pivot data exists")
                        .ordered_executable_epoch_blocks
                    {
                        let hash = &inner.arena[*index].hash;
                        if self.block_matches_bloom(hash, epoch_hash, &blooms) {
                            blocks.push(*hash);
                        }
                    }
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

    /// Return `true` if block log_bloom exists and matches some filter in given
    /// `blooms`.
    fn block_matches_bloom(
        &self, block_hash: &H256, epoch_hash: &H256, blooms: &Vec<Bloom>,
    ) -> bool {
        if let Some(block_log_bloom) = self
            .data_man
            .block_execution_result_by_hash_with_epoch(
                block_hash, epoch_hash, false, /* update_cache */
            )
            .map(|r| r.bloom)
        {
            if blooms
                .iter()
                .any(|bloom| block_log_bloom.contains_bloom(bloom))
            {
                return true;
            }
        }
        false
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
                        self.inner.read().block_execution_results_by_hash(&hash, false /* update_cache */).map(|r| (hash, r.0, (*r.1.receipts).clone()))
                    )
                    .filter_map(|(hash, epoch_hash, receipts)| self.data_man.block_by_hash(&hash, false /* update_cache */).map(|b| (hash, epoch_hash, receipts, b.transaction_hashes())))
                    .filter_map(|(hash, epoch_hash, receipts, hashes)| self.data_man.block_by_hash(&epoch_hash, false /* update_cache */).map(|b| (hash, b.block_header.height(), receipts, hashes)))
                    .flat_map(|(hash, epoch, mut receipts, mut hashes)| {
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
                                        epoch_number: epoch,
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
        self.validate_stated_epoch(&epoch)?;
        let epoch_id = self.get_hash_from_epoch_number(epoch)?;
        self.executor.call_virtual(tx, &epoch_id)
    }

    /// Get the number of processed blocks (i.e., the number of calls to
    /// on_new_block()
    pub fn get_processed_block_count(&self) -> usize {
        self.statistics.get_consensus_graph_processed_block_count()
    }

    pub fn get_deferred_state_for_generation(
        &self, parent_hash: &H256,
    ) -> EpochExecutionCommitment {
        let inner = &*self.inner.read();
        let parent_arena_index = *inner
            .hash_to_arena_indices
            .get(parent_hash)
            .expect("parent_hash exists");
        let deferred_arena_index = inner.get_deferred_arena_index(
            parent_arena_index,
            DEFERRED_STATE_EPOCH_COUNT - 1,
        );
        let deferred_block_hash = inner.arena[deferred_arena_index].hash;
        self.executor
            .compute_state_for_block(deferred_arena_index, inner)
            .expect("execution in generate_block should succeed");
        self.data_man
            .get_epoch_execution_commitment(&deferred_block_hash)
            .cloned()
            .expect("epoch_execution_commitment exists for generate block")
    }
}

impl Drop for TreeGraphConsensus {
    fn drop(&mut self) { self.executor.stop(); }
}

impl ConsensusGraphTrait for TreeGraphConsensus {
    fn as_any(&self) -> &dyn Any { self }

    /// This is the main function that SynchronizationGraph calls to deliver a
    /// new block to the consensus graph.
    fn on_new_block(
        &self, hash: &H256, _ignore_body: bool, update_best_info: bool,
    ) {
        debug!("enter on new_block hash={:?}", hash);
        let notify_tx_pool = update_best_info;
        let _timer =
            MeterTimer::time_func(CONSENSIS_ON_NEW_BLOCK_TIMER.as_ref());
        self.statistics.inc_consensus_graph_processed_block_count();

        let block_header = self
            .data_man
            .block_header_by_hash(hash)
            .expect("header must exist");

        {
            let inner = &mut *self.inner.write();
            self.new_block_handler.on_new_block(inner, &block_header);

            *self.latest_inserted_block.lock() = *hash;

            if inner.inner_conf.enable_state_expose {
                if let Some(arena_index) = inner.hash_to_arena_indices.get(hash)
                {
                    let local_info = self
                        .data_man
                        .local_block_info_from_db(hash)
                        .expect("local block info must exist in db");
                    let era_block = inner.arena[*arena_index].era_block;
                    let era_block_hash = if era_block != NULL {
                        inner.arena[era_block].hash
                    } else {
                        Default::default()
                    };
                    STATE_EXPOSER.consensus_graph.lock().block_state_vec.push(
                        ConsensusGraphBlockState {
                            block_hash: *hash,
                            best_block_hash: inner.best_block_hash(),
                            block_status: local_info.get_status(),
                            past_era_weight: 0.into(),
                            era_block_hash,
                            adaptive: false,
                        },
                    )
                }
            }
        }
        if update_best_info {
            self.update_best_info();
        }
        if notify_tx_pool {
            self.txpool
                .notify_new_best_info(self.best_info.read().clone())
                // FIXME: propogate error.
                .expect(&concat!(file!(), ":", line!(), ":", column!()));
        }
    }

    fn expected_difficulty(&self, _parent_hash: &H256) -> U256 { U256::zero() }

    /// This function returns the set of blocks that are two eras farther from
    /// current era. They can be safely garbage collected.
    fn retrieve_old_era_blocks(&self) -> Option<H256> {
        self.inner.read().old_era_block_set.lock().pop_front()
    }

    /// construct_pivot_state() rebuild pivot chain state info from db
    /// avoiding intermediate redundant computation triggered by
    /// on_new_block().
    fn construct_pivot_state(&self) {
        let inner = &mut *self.inner.write();
        // Ensure that `state_valid` of the first valid block after
        // cur_era_stable_genesis is set
        self.new_block_handler.construct_pivot_state(inner);
    }

    fn best_info(&self) -> Arc<BestInformation> {
        self.best_info.read_recursive().clone()
    }

    fn best_epoch_number(&self) -> u64 {
        self.best_info.read_recursive().best_epoch_number
    }

    fn best_chain_id(&self) -> u64 {
        self.best_info.read_recursive().best_chain_id()
    }

    fn best_block_hash(&self) -> H256 {
        self.best_info.read_recursive().best_block_hash
    }

    /// FIXME store this in BlockDataManager
    /// Return the sequence number of the current era genesis hash.
    fn current_era_genesis_seq_num(&self) -> u64 {
        let inner = self.inner.read_recursive();
        inner.arena[inner.cur_era_genesis_block_arena_index].sequence_number
    }

    fn get_data_manager(&self) -> &Arc<BlockDataManager> { &self.data_man }

    fn get_tx_pool(&self) -> &SharedTransactionPool { &self.txpool }

    fn get_statistics(&self) -> &SharedStatistics { &self.statistics }

    /// Returns the total number of blocks processed in consensus graph.
    ///
    /// This function should only be used in tests.
    /// If the process crashes and recovered, the blocks in the anticone of the
    /// current checkpoint may not be counted since they will not be
    /// inserted into consensus in the recover process.
    fn block_count(&self) -> u64 {
        self.inner.read_recursive().total_processed_block_count()
    }

    fn get_hash_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<H256, String> {
        self.get_height_from_epoch_number(epoch_number)
            .and_then(|height| self.inner.read().epoch_hash(height))
    }

    fn get_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String> {
        self.get_height_from_epoch_number(epoch_number)
            .and_then(|height| {
                self.inner.read_recursive().block_hashes_by_epoch(height)
            })
    }

    fn get_transaction_info_by_hash(
        &self, hash: &H256,
    ) -> Option<(SignedTransaction, Receipt, TransactionIndex)> {
        // We need to hold the inner lock to ensure that tx_index and receipts
        // are consistent
        let inner = self.inner.read();
        if let Some((receipt, tx_index)) =
            inner.get_transaction_receipt_with_index(hash)
        {
            let block = self.data_man.block_by_hash(
                &tx_index.block_hash,
                false, /* update_cache */
            )?;
            let transaction = (*block.transactions[tx_index.index]).clone();
            Some((transaction, receipt, tx_index))
        } else {
            None
        }
    }

    fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        self.inner.read_recursive().get_block_epoch_number(hash)
    }

    /// Wait until the best state has been executed, and return the state
    fn get_best_state(&self) -> State {
        let (best_state_hash, past_num_blocks) = {
            let inner = self.inner.read();
            let best_state_hash = inner.best_block_hash();
            let arena_index = inner.hash_to_arena_indices[&best_state_hash];
            let past_num_blocks = inner.arena[arena_index]
                .data
                .as_ref()
                .expect("consensus graph node data exists")
                .past_num_blocks;
            (best_state_hash, past_num_blocks)
        };

        self.executor.wait_for_result(best_state_hash);
        // FIXME: it's only absolute safe with lock, otherwise storage /
        // FIXME: epoch_id may be gone due to snapshotting / checkpointing?
        let (_state_index_guard, best_state_index) = self
            .data_man
            .get_state_readonly_index(&best_state_hash)
            .into();
        if let Ok(state) = self
            .data_man
            .storage_manager
            .get_state_no_commit(best_state_index.unwrap())
        {
            state
                .map(|db| {
                    State::new(
                        StateDb::new(db),
                        0.into(),           /* account_start_nonce */
                        Default::default(), /* vm */
                        past_num_blocks,    /* block_number */
                    )
                })
                .expect("Best state has been executed")
        } else {
            panic!("get_best_state: Error for hash {}", best_state_hash);
        }
    }

    fn get_trusted_blame_block_for_snapshot(
        &self, _snapshot_epoch_id: &EpochId,
    ) -> Option<H256> {
        None
    }

    /// Return the epoch that we are going to sync the state
    fn get_to_sync_epoch_id(&self) -> EpochId {
        self.inner.read().get_to_sync_epoch_id()
    }

    fn get_trusted_blame_block(&self, _stable_hash: &H256) -> Option<H256> {
        None
    }

    fn first_trusted_header_starting_from(
        &self, _height: u64, _blame_bound: Option<u32>,
    ) -> Option<u64> {
        None
    }

    fn set_initial_sequence_number(&self, initial_sn: u64) {
        self.inner.write().set_initial_sequence_number(initial_sn);
    }

    /// This function is called after a new block appended to the
    /// TreeGraphConsensus. Because BestInformation is often queried outside. We
    /// store a version of best_info outside the inner to prevent keep
    /// getting inner locks.
    fn update_best_info(&self) {
        let inner = self.inner.read();
        let mut best_info = self.best_info.write();

        let terminal_hashes = inner.terminal_hashes();
        let (terminal_block_hashes, bounded_terminal_block_hashes) =
            if terminal_hashes.len() > REFEREE_BOUND {
                let mut tmp = Vec::new();
                let best_idx = inner.pivot_chain.last().unwrap();
                for hash in terminal_hashes.iter() {
                    let a_idx = inner.hash_to_arena_indices.get(hash).unwrap();
                    let a_lca = inner.lca(*a_idx, *best_idx);
                    tmp.push((inner.arena[a_lca].height, hash));
                }
                tmp.sort_by(|a, b| Reverse(a.0).cmp(&Reverse(b.0)));
                tmp.split_off(REFEREE_BOUND);
                let bounded_hashes =
                    tmp.iter().map(|(_, b)| (*b).clone()).collect();
                (Some(terminal_hashes), bounded_hashes)
            } else {
                (None, terminal_hashes)
            };

        *best_info = Arc::new(BestInformation {
            best_block_hash: inner.best_block_hash(),
            best_epoch_number: inner.best_epoch_number(),
            current_difficulty: 0.into(),
            terminal_block_hashes,
            bounded_terminal_block_hashes,
        });
    }

    fn latest_inserted_block(&self) -> H256 {
        *self.latest_inserted_block.lock()
    }
}
