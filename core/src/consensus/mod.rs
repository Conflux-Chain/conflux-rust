// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod anticone_cache;
pub mod consensus_inner;
pub mod consensus_trait;
pub mod debug_recompute;
mod pastset_cache;

pub use crate::consensus::{
    consensus_inner::{ConsensusGraphInner, ConsensusInnerConfig},
    consensus_trait::{ConsensusGraphTrait, SharedConsensusGraph},
};

use super::consensus::consensus_inner::{
    confirmation_meter::ConfirmationMeter,
    consensus_executor::ConsensusExecutor,
    consensus_new_block_handler::ConsensusNewBlockHandler,
};
use crate::{
    block_data_manager::{BlockDataManager, BlockExecutionResultWithEpoch},
    consensus::consensus_inner::{
        consensus_executor::ConsensusExecutionConfiguration, StateBlameInfo,
    },
    evm::Spec,
    executive::ExecutionOutcome,
    pow::{PowComputer, ProofOfWorkConfig},
    rpc_errors::{invalid_params_check, Result as RpcResult},
    state::State,
    statistics::SharedStatistics,
    transaction_pool::SharedTransactionPool,
    verification::VerificationConfig,
    vm_factory::VmFactory,
    NodeType, Notifications,
};
use cfx_internal_common::ChainIdParams;
use cfx_parameters::{
    consensus::*,
    consensus_internal::REWARD_EPOCH_COUNT,
    rpc::{
        GAS_PRICE_BLOCK_SAMPLE_SIZE, GAS_PRICE_TRANSACTION_SAMPLE_SIZE,
        TRANSACTION_COUNT_PER_BLOCK_WATER_LINE_LOW,
        TRANSACTION_COUNT_PER_BLOCK_WATER_LINE_MEDIUM,
    },
};
use cfx_statedb::StateDb;
use cfx_storage::state_manager::StateManagerTrait;
use cfx_types::{Bloom, H160, H256, U256};
use either::Either;
use itertools::Itertools;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use metrics::{
    register_meter_with_group, Gauge, GaugeUsize, Meter, MeterTimer,
};
use parking_lot::{Mutex, RwLock};
use primitives::{
    epoch::BlockHashOrEpochNumber,
    filter::{Filter, FilterError},
    log_entry::LocalizedLogEntry,
    receipt::Receipt,
    EpochId, EpochNumber, SignedTransaction, TransactionIndex,
};
use rayon::prelude::*;
use std::{
    any::Any,
    cmp::min,
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::sleep,
    time::Duration,
};

lazy_static! {
    static ref CONSENSIS_ON_NEW_BLOCK_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "consensus_on_new_block_timer");
    static ref BEST_EPOCH_NUMBER: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group("graph_statistic", "best_epoch_number");
}

pub struct MaybeExecutedTxExtraInfo {
    pub receipt: Receipt,
    pub block_number: u64,
    pub prior_gas_used: U256,
    pub tx_exec_error_msg: Option<String>,
}

pub struct TransactionInfo {
    pub tx_index: TransactionIndex,
    pub maybe_executed_extra_info: Option<MaybeExecutedTxExtraInfo>,
}

#[derive(Clone)]
pub struct ConsensusConfig {
    /// Chain id configs.
    pub chain_id: ChainIdParams,
    /// When bench_mode is true, the PoW solution verification will be skipped.
    /// The transaction execution will also be skipped and only return the
    /// pair of (KECCAK_NULL_RLP, KECCAK_EMPTY_LIST_RLP) This is for testing
    /// only
    pub bench_mode: bool,
    /// The configuration used by inner data
    pub inner_conf: ConsensusInnerConfig,
    /// The epoch bound for processing a transaction. For a transaction being
    /// process, the epoch height of its enclosing block must be with in
    /// [tx.epoch_height - transaction_epoch_bound, tx.epoch_height +
    /// transaction_epoch_bound]
    pub transaction_epoch_bound: u64,
    /// The number of referees that are allowed for a block.
    pub referee_bound: usize,
    /// Epoch batch size used in log filtering.
    /// Larger batch sizes may improve performance but might also prevent
    /// consensus from making progress under high RPC load.
    pub get_logs_epoch_batch_size: usize,
    pub get_logs_filter_max_epoch_range: Option<u64>,

    /// TODO: These parameters are only utilized in catch-up now.
    /// TODO: They should be used in data garbage collection, too.
    /// TODO: States, receipts, and block bodies need separate parameters.
    /// The starting epoch that we need to sync its state and start replaying
    /// transactions.
    pub sync_state_starting_epoch: Option<u64>,
    /// The number of extra epochs that we want to keep
    /// states/receipts/transactions.
    pub sync_state_epoch_gap: Option<u64>,
}

#[derive(Debug)]
pub struct ConsensusGraphStatistics {
    pub inserted_block_count: usize,
    pub activated_block_count: usize,
    pub processed_block_count: usize,
}

impl ConsensusGraphStatistics {
    pub fn new() -> ConsensusGraphStatistics {
        ConsensusGraphStatistics {
            inserted_block_count: 0,
            activated_block_count: 0,
            processed_block_count: 0,
        }
    }

    pub fn clear(&mut self) {
        self.inserted_block_count = 0;
        self.activated_block_count = 0;
        self.processed_block_count = 0;
    }
}

#[derive(Default, Debug, DeriveMallocSizeOf)]
pub struct BestInformation {
    pub chain_id: u32,
    pub best_block_hash: H256,
    pub best_epoch_number: u64,
    pub current_difficulty: U256,
    pub bounded_terminal_block_hashes: Vec<H256>,
}

impl BestInformation {
    pub fn best_chain_id(&self) -> u32 { self.chain_id }
}

/// ConsensusGraph is a layer on top of SynchronizationGraph. A SyncGraph
/// collect all blocks that the client has received so far, but a block can only
/// be delivered to the ConsensusGraph if 1) the whole block content is
/// available and 2) all of its past blocks are also in the ConsensusGraph.
///
/// ConsensusGraph maintains the TreeGraph structure of the client and
/// implements *Timer Chain GHAST*/*Conflux* algorithm to determine the block
/// total order. It dispatches transactions in epochs to ConsensusExecutor to
/// process. To avoid executing too many execution reroll caused by transaction
/// order oscillation. It defers the transaction execution for a few epochs.
///
/// When recovery from database, ConsensusGraph requires that 1) the data
/// manager is in a consistent state, 2) the data manager stores the correct era
/// genesis and era stable hash, and 3) the data manager contains correct *block
/// status* for all blocks before era stable block (more restrictively speaking,
/// whose past sets do not contain the stable block).
pub struct ConsensusGraph {
    pub inner: Arc<RwLock<ConsensusGraphInner>>,
    pub txpool: SharedTransactionPool,
    pub data_man: Arc<BlockDataManager>,
    executor: Arc<ConsensusExecutor>,
    statistics: SharedStatistics,
    pub new_block_handler: ConsensusNewBlockHandler,
    pub confirmation_meter: ConfirmationMeter,
    /// Make sure that it is only modified when holding inner lock to prevent
    /// any inconsistency
    best_info: RwLock<Arc<BestInformation>>,
    /// Set to `true` when we enter NormalPhase
    ready_for_mining: AtomicBool,

    /// The epoch id of the remotely synchronized state.
    /// This is always `None` for archive nodes.
    pub synced_epoch_id: Mutex<Option<EpochId>>,
    pub config: ConsensusConfig,

    /// The type of this node: Archive, Full, or Light.
    node_type: NodeType,
}

impl MallocSizeOf for ConsensusGraph {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let best_info_size = self.best_info.read().size_of(ops);
        self.inner.read().size_of(ops)
            + self.txpool.size_of(ops)
            + self.data_man.size_of(ops)
            + best_info_size
    }
}

impl ConsensusGraph {
    /// Build the ConsensusGraph with a specific era genesis block and various
    /// other components. The execution will be skipped if bench_mode sets
    /// to true.
    pub fn with_era_genesis(
        conf: ConsensusConfig, vm: VmFactory, txpool: SharedTransactionPool,
        statistics: SharedStatistics, data_man: Arc<BlockDataManager>,
        pow_config: ProofOfWorkConfig, pow: Arc<PowComputer>,
        era_genesis_block_hash: &H256, era_stable_block_hash: &H256,
        notifications: Arc<Notifications>,
        execution_conf: ConsensusExecutionConfiguration,
        verification_config: VerificationConfig, node_type: NodeType,
    ) -> Self
    {
        let inner =
            Arc::new(RwLock::new(ConsensusGraphInner::with_era_genesis(
                pow_config,
                pow.clone(),
                data_man.clone(),
                conf.inner_conf.clone(),
                era_genesis_block_hash,
                era_stable_block_hash,
            )));
        let executor = ConsensusExecutor::start(
            txpool.clone(),
            data_man.clone(),
            vm,
            inner.clone(),
            execution_conf,
            verification_config,
            conf.bench_mode,
        );
        let confirmation_meter = ConfirmationMeter::new();

        let graph = ConsensusGraph {
            inner,
            txpool: txpool.clone(),
            data_man: data_man.clone(),
            executor: executor.clone(),
            statistics: statistics.clone(),
            new_block_handler: ConsensusNewBlockHandler::new(
                conf.clone(),
                txpool,
                data_man,
                executor,
                statistics,
                notifications,
                node_type,
            ),
            confirmation_meter,
            best_info: RwLock::new(Arc::new(Default::default())),
            ready_for_mining: AtomicBool::new(false),
            synced_epoch_id: Default::default(),
            config: conf,
            node_type,
        };
        graph.update_best_info(false /* ready_for_mining */);
        graph
            .txpool
            .notify_new_best_info(graph.best_info.read_recursive().clone())
            // FIXME: propogate error.
            .expect(&concat!(file!(), ":", line!(), ":", column!()));
        graph
    }

    /// Build the ConsensusGraph with the initial (checkpointed) genesis block
    /// in the data manager and various other components. The execution will
    /// be skipped if bench_mode sets to true.
    pub fn new(
        conf: ConsensusConfig, vm: VmFactory, txpool: SharedTransactionPool,
        statistics: SharedStatistics, data_man: Arc<BlockDataManager>,
        pow_config: ProofOfWorkConfig, pow: Arc<PowComputer>,
        notifications: Arc<Notifications>,
        execution_conf: ConsensusExecutionConfiguration,
        verification_conf: VerificationConfig, node_type: NodeType,
    ) -> Self
    {
        let genesis_hash = data_man.get_cur_consensus_era_genesis_hash();
        let stable_hash = data_man.get_cur_consensus_era_stable_hash();
        ConsensusGraph::with_era_genesis(
            conf,
            vm,
            txpool,
            statistics,
            data_man,
            pow_config,
            pow,
            &genesis_hash,
            &stable_hash,
            notifications,
            execution_conf,
            verification_conf,
            node_type,
        )
    }

    /// Wait for the generation and the execution completion of a block in the
    /// consensus graph. This API is used mainly for testing purpose
    pub fn wait_for_generation(&self, hash: &H256) {
        while !self
            .inner
            .read_recursive()
            .hash_to_arena_indices
            .contains_key(hash)
        {
            sleep(Duration::from_millis(1));
        }
        let best_state_block =
            self.inner.read_recursive().best_state_block_hash();
        match self.executor.wait_for_result(best_state_block) {
            Ok(_) => (),
            Err(msg) => warn!("wait_for_generation() gets the following error from the ConsensusExecutor: {}", msg)
        }
    }

    /// Determine whether the next mined block should have adaptive weight or
    /// not
    pub fn check_mining_adaptive_block(
        &self, inner: &mut ConsensusGraphInner, parent_hash: &H256,
        referees: &Vec<H256>, difficulty: &U256,
    ) -> bool
    {
        let parent_index =
            *inner.hash_to_arena_indices.get(parent_hash).expect(
                "parent_hash is the pivot chain tip,\
                 so should still exist in ConsensusInner",
            );
        let referee_indices: Vec<_> = referees
            .iter()
            .map(|h| {
                *inner
                    .hash_to_arena_indices
                    .get(h)
                    .expect("Checked by the caller")
            })
            .collect();
        inner.check_mining_adaptive_block(
            parent_index,
            referee_indices,
            *difficulty,
        )
    }

    /// Convert EpochNumber to height based on the current ConsensusGraph
    pub fn get_height_from_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> Result<u64, String> {
        Ok(match epoch_number {
            EpochNumber::Earliest => 0,
            EpochNumber::LatestCheckpoint => {
                self.latest_checkpoint_epoch_number()
            }
            EpochNumber::LatestConfirmed => {
                self.latest_confirmed_epoch_number()
            }
            EpochNumber::LatestMined => self.best_epoch_number(),
            EpochNumber::LatestState => self.best_executed_state_epoch_number(),
            EpochNumber::Number(num) => {
                let epoch_num = num;
                if epoch_num > self.inner.read_recursive().best_epoch_number() {
                    return Err("Invalid params: expected a numbers with less than largest epoch number.".to_owned());
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
        let mut total_transaction_count_in_processed_blocks = 0;

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
                total_transaction_count_in_processed_blocks +=
                    block.transactions.len();
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

        let processed_block_count =
            GAS_PRICE_BLOCK_SAMPLE_SIZE - number_of_blocks_to_sample;
        let average_transaction_count_per_block = if processed_block_count != 0
        {
            total_transaction_count_in_processed_blocks / processed_block_count
        } else {
            0
        };

        prices.sort();
        if prices.is_empty() {
            Some(U256::from(1))
        } else {
            if average_transaction_count_per_block
                < TRANSACTION_COUNT_PER_BLOCK_WATER_LINE_LOW
            {
                Some(U256::from(1))
            } else if average_transaction_count_per_block
                < TRANSACTION_COUNT_PER_BLOCK_WATER_LINE_MEDIUM
            {
                Some(prices[prices.len() / 8])
            } else {
                Some(prices[prices.len() / 2])
            }
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
                let latest_state_epoch =
                    self.best_executed_state_epoch_number();
                if *num > latest_state_epoch {
                    return Err(format!("Specified epoch {} is not executed, the latest state epoch is {}", num, latest_state_epoch));
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Force the engine to recompute the deferred state root for a particular
    /// block given a delay.
    pub fn force_compute_blame_and_deferred_state_for_generation(
        &self, parent_block_hash: &H256,
    ) -> Result<StateBlameInfo, String> {
        {
            let inner = &mut *self.inner.write();
            let hash = inner
                .get_state_block_with_delay(
                    parent_block_hash,
                    DEFERRED_STATE_EPOCH_COUNT as usize - 1,
                )?
                .clone();
            self.executor.compute_state_for_block(&hash, inner)?;
        }
        self.executor.get_blame_and_deferred_state_for_generation(
            parent_block_hash,
            &self.inner,
        )
    }

    pub fn get_blame_and_deferred_state_for_generation(
        &self, parent_block_hash: &H256,
    ) -> Result<StateBlameInfo, String> {
        self.executor.get_blame_and_deferred_state_for_generation(
            parent_block_hash,
            &self.inner,
        )
    }

    pub fn best_block_hash(&self) -> H256 {
        self.best_info.read_recursive().best_block_hash
    }

    /// Returns the latest epoch whose state can be exposed safely, which means
    /// its state is available and it's not only visible to optimistic
    /// execution.
    pub fn best_executed_state_epoch_number(&self) -> u64 {
        let state_upper_bound =
            self.data_man.state_availability_boundary.read().upper_bound;
        // Here we can also get `best_state_epoch` from `inner`, but that
        // would acquire the inner read lock.
        let best_epoch_number = self.best_info.read().best_epoch_number;
        let deferred_state_height =
            if best_epoch_number < DEFERRED_STATE_EPOCH_COUNT {
                0
            } else {
                best_epoch_number - DEFERRED_STATE_EPOCH_COUNT + 1
            };
        // state upper bound can be lower than deferred_state_height because
        // the execution is async. It can also be higher
        // because of optimistic execution. Here we guarantee
        // to return an available state without exposing optimistically
        // executed states.
        min(state_upper_bound, deferred_state_height)
    }

    pub fn get_transaction_receipt_and_block_info(
        &self, tx_hash: &H256,
    ) -> Option<(
        BlockExecutionResultWithEpoch,
        TransactionIndex,
        Option<H256>,
    )> {
        // Note: `transaction_index_by_hash` might return outdated results if
        // there was a pivot chain reorg but the tx was not re-executed yet. In
        // this case, `block_execution_results_by_hash` will detect that the
        // execution results do not match the current pivot view and return
        // None. If the tx was re-executed in another block on the new pivot
        // chain, `transaction_index_by_hash` will return the updated result.
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
        let maybe_state_root = match self.executor.wait_for_result(epoch_hash) {
            Ok(execution_commitment) => {
                // We already has transaction address with epoch_hash executed,
                // so we can always get the state_root with
                // `wait_for_result`
                Some(
                    execution_commitment
                        .state_root_with_aux_info
                        .aux_info
                        .state_root_hash,
                )
            }
            Err(msg) => {
                warn!("get_transaction_receipt_and_block_info() gets the following error from ConsensusExecutor: {}", msg);
                None
            }
        };
        Some((results_with_epoch, address, maybe_state_root))
    }

    pub fn next_nonce(
        &self, address: H160,
        block_hash_or_epoch_number: BlockHashOrEpochNumber,
    ) -> RpcResult<U256>
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
        let state = self.get_state_by_epoch_number(epoch_number)?;

        Ok(state.nonce(&address)?)
    }

    fn earliest_epoch_available(&self) -> u64 {
        match self.node_type {
            NodeType::Archive => 0,
            _ => self.latest_checkpoint_epoch_number(),
        }
    }

    fn filter_block_receipts<'a>(
        &self, filter: &'a Filter, epoch_number: u64, block_hash: H256,
        mut receipts: Vec<Receipt>, mut tx_hashes: Vec<H256>,
    ) -> impl Iterator<Item = LocalizedLogEntry> + 'a
    {
        // sanity check
        if receipts.len() != tx_hashes.len() {
            warn!("Block ({}) has different number of receipts ({}) to transactions ({}). Database corrupt?", block_hash, receipts.len(), tx_hashes.len());
            assert!(false);
        }

        // iterate in reverse
        receipts.reverse();
        tx_hashes.reverse();

        let mut log_index = receipts
            .iter()
            .fold(0, |sum, receipt| sum + receipt.logs.len());

        let receipts_len = receipts.len();

        receipts
            .into_iter()
            .map(|receipt| receipt.logs)
            .zip(tx_hashes)
            .enumerate()
            .flat_map(move |(index, (mut logs, transaction_hash))| {
                let current_log_index = log_index;
                let no_of_logs = logs.len();
                log_index -= no_of_logs;

                logs.reverse();
                logs.into_iter().enumerate().map(move |(i, log)| {
                    LocalizedLogEntry {
                        entry: log,
                        block_hash,
                        epoch_number,
                        transaction_hash,
                        // iterating in reverse order
                        transaction_index: receipts_len - index - 1,
                        transaction_log_index: no_of_logs - i - 1,
                        log_index: current_log_index - i - 1,
                    }
                })
            })
            .filter(move |log_entry| filter.matches(&log_entry.entry))
            .take(filter.limit.unwrap_or(::std::usize::MAX))
    }

    fn filter_block<'a>(
        &self, filter: &'a Filter, bloom_possibilities: &'a Vec<Bloom>,
        epoch: u64, pivot_hash: H256, block_hash: H256,
    ) -> Result<impl Iterator<Item = LocalizedLogEntry> + 'a, FilterError>
    {
        // special case for genesis (for now, genesis has no logs)
        if epoch == 0 {
            return Ok(Either::Left(std::iter::empty()));
        }

        // check if epoch is still available
        let min = self.earliest_epoch_available();

        if epoch < min {
            return Err(FilterError::EpochAlreadyPruned { epoch, min });
        }

        // get block bloom and receipts from db
        let (block_bloom, receipts) = match self
            .data_man
            .block_execution_result_by_hash_with_epoch(
                &block_hash,
                &pivot_hash,
                false, /* update_pivot_assumption */
                false, /* update_cache */
            ) {
            Some(r) => (r.bloom, r.block_receipts.receipts.clone()),
            None => {
                // `block_hash` must exist so the block not executed yet
                return Err(FilterError::BlockNotExecutedYet { block_hash });
            }
        };

        // filter block
        if !bloom_possibilities
            .iter()
            .any(|bloom| block_bloom.contains_bloom(bloom))
        {
            return Ok(Either::Left(std::iter::empty()));
        }

        // get block body from db
        let block = match self.data_man.block_by_hash(&block_hash, false) {
            Some(b) => b,
            None => {
                // `block_hash` must exist so this is an internal error
                error!(
                    "Block {:?} in epoch {} ({:?}) not found",
                    block_hash, epoch, pivot_hash
                );

                return Err(FilterError::UnknownBlock { hash: block_hash });
            }
        };

        Ok(Either::Right(self.filter_block_receipts(
            &filter,
            epoch,
            block_hash,
            receipts,
            block.transaction_hashes(),
        )))
    }

    fn filter_single_epoch<'a>(
        &'a self, filter: &'a Filter, bloom_possibilities: &'a Vec<Bloom>,
        epoch: u64,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError>
    {
        // retrieve epoch hashes and pivot hash
        let mut epoch_hashes =
            self.inner.read_recursive().block_hashes_by_epoch(epoch)?;

        let pivot_hash = *epoch_hashes.last().expect("Epoch set not empty");

        // process hashes in reverse order
        epoch_hashes.reverse();

        epoch_hashes
            .into_iter()
            .map(move |block_hash| {
                self.filter_block(
                    &filter,
                    &bloom_possibilities,
                    epoch,
                    pivot_hash,
                    block_hash,
                )
            })
            // flatten results
            // Iterator<Result<Iterator<_>>> -> Iterator<Result<_>>
            .flat_map(|res| match res {
                Ok(it) => Either::Left(it.map(Ok)),
                Err(e) => Either::Right(std::iter::once(Err(e))),
            })
            .take(filter.limit.unwrap_or(::std::usize::MAX))
            .collect()
    }

    fn filter_epoch_batch(
        &self, filter: &Filter, bloom_possibilities: &Vec<Bloom>,
        epochs: Vec<u64>, consistency_check_data: &mut Option<(u64, H256)>,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError>
    {
        // lock so that we have a consistent view during this batch
        let inner = self.inner.read();

        // NOTE: as batches are processed atomically and only the
        // first batch (last few epochs) is likely to fluctuate, is is unlikely
        // that releasing the lock between batches would cause inconsistency:
        // we assume there are no pivot chain reorgs deeper than batch_size.
        // However, we still add a simple sanity check here:

        if let Some((epoch, pivot)) = *consistency_check_data {
            let new_pivot = inner.get_pivot_hash_from_epoch_number(epoch)?;

            if pivot != new_pivot {
                return Err(FilterError::PivotChainReorg {
                    epoch,
                    from: pivot,
                    to: new_pivot,
                });
            }
        }

        *consistency_check_data = Some((
            epochs[0],
            inner.get_pivot_hash_from_epoch_number(epochs[0])?,
        ));

        let epoch_batch_logs = epochs
            .into_par_iter() // process each epoch of this batch in parallel
            .map(|e| self.filter_single_epoch(filter, bloom_possibilities, e))
            .collect::<Result<Vec<Vec<LocalizedLogEntry>>, FilterError>>()?; // short-circuit on error

        Ok(epoch_batch_logs
            .into_iter()
            .flatten()
            .take(filter.limit.unwrap_or(::std::usize::MAX))
            .collect())
    }

    pub fn get_filter_epoch_range(
        &self, filter: &Filter,
    ) -> Result<impl Iterator<Item = u64>, FilterError> {
        // lock so that we have a consistent view
        let _inner = self.inner.read();

        let from_epoch =
            self.get_height_from_epoch_number(filter.from_epoch.clone())?;
        let to_epoch =
            self.get_height_from_epoch_number(filter.to_epoch.clone())?;

        if from_epoch > to_epoch {
            return Err(FilterError::InvalidEpochNumber {
                from_epoch,
                to_epoch,
            });
        }

        if from_epoch < self.earliest_epoch_available() {
            return Err(FilterError::EpochAlreadyPruned {
                epoch: from_epoch,
                min: self.earliest_epoch_available(),
            });
        }

        if let Some(max_gap) = self.config.get_logs_filter_max_epoch_range {
            // The range includes both ends.
            if to_epoch - from_epoch + 1 > max_gap {
                return Err(FilterError::EpochNumberGapTooLarge {
                    from_epoch,
                    to_epoch,
                    max_gap,
                });
            }
        }

        return Ok((from_epoch..=to_epoch).rev());
    }

    fn filter_logs_by_epochs(
        &self, filter: Filter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        assert!(filter.block_hashes.is_none());
        let bloom_possibilities = filter.bloom_possibilities();
        let limit = filter.limit.unwrap_or(::std::usize::MAX);

        // we store the last epoch processed and the corresponding pivot hash so
        // that we can check whether it changed between batches
        let mut consistency_check_data: Option<(u64, H256)> = None;

        let mut logs = self
            // iterate over epochs in reverse order
            .get_filter_epoch_range(&filter)?
            // we process epochs in each batch in parallel
            // but batches are processed one-by-one
            .chunks(self.config.get_logs_epoch_batch_size)
            .into_iter()
            .map(move |epochs| {
                self.filter_epoch_batch(
                    &filter,
                    &bloom_possibilities,
                    epochs.into_iter().collect(),
                    &mut consistency_check_data,
                )
            })
            // flatten results
            .flat_map(|res| match res {
                Ok(vec) => Either::Left(vec.into_iter().map(Ok)),
                Err(e) => Either::Right(std::iter::once(Err(e))),
            })
            // take as many as we need
            .take(limit)
            // short-circuit on error
            .collect::<Result<Vec<LocalizedLogEntry>, FilterError>>()?;

        logs.reverse();
        Ok(logs)
    }

    // collect epoch number, block index in epoch, block hash, pivot hash
    fn collect_block_info(
        &self, block_hash: H256,
    ) -> Result<(u64, usize, H256, H256), FilterError> {
        // special case for genesis
        if block_hash == self.data_man.true_genesis.hash() {
            return Ok((0, 0, block_hash, block_hash));
        }

        // check if block exists
        if self.data_man.block_header_by_hash(&block_hash).is_none() {
            return Err(FilterError::UnknownBlock { hash: block_hash });
        };

        // find pivot block
        let pivot_hash = match self
            .inner
            .read_recursive()
            .block_execution_results_by_hash(&block_hash, false)
        {
            Some(r) => r.0,
            None => {
                // exec results are either pruned already or block has not been
                // executed yet
                // TODO(thegaram): is there a way to tell these apart?
                return Err(FilterError::BlockNotExecutedYet { block_hash });
            }
        };

        // find epoch number
        let epoch = match self.data_man.block_header_by_hash(&pivot_hash) {
            Some(h) => h.height(),
            None => {
                // internal error
                error!("Header of pivot block {:?} not found", pivot_hash);
                return Err(FilterError::UnknownBlock { hash: pivot_hash });
            }
        };

        let index_in_epoch = self
            .inner
            .read_recursive()
            .block_hashes_by_epoch(epoch)?
            .into_iter()
            .position(|h| h == block_hash)
            .expect("Block should exit in epoch set");

        Ok((epoch, index_in_epoch, block_hash, pivot_hash))
    }

    fn filter_logs_by_block_hashes(
        &self, mut filter: Filter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        assert!(filter.block_hashes.is_some());
        let block_hashes = filter.block_hashes.take().unwrap();
        let bloom_possibilities = filter.bloom_possibilities();

        // keep a consistent view during filtering
        let _inner = self.inner.read();

        // collect all block info in memory
        // note: we allow at most 128 block hashes so this should be fine
        let mut block_infos = block_hashes
            .into_par_iter()
            .map(|block_hash| self.collect_block_info(block_hash))
            .collect::<Result<Vec<_>, _>>()?;

        // lexicographic order will match execution order
        block_infos.sort();

        // process blocks in reverse
        block_infos.reverse();

        let mut logs = block_infos
            .into_iter()
            .map(|(epoch, _, block_hash, pivot_hash)| {
                self.filter_block(
                    &filter,
                    &bloom_possibilities,
                    epoch,
                    pivot_hash,
                    block_hash,
                )
            })
            // flatten results
            .flat_map(|res| match res {
                Ok(it) => Either::Left(it.into_iter().map(Ok)),
                Err(e) => Either::Right(std::iter::once(Err(e))),
            })
            // take as many as we need
            .take(filter.limit.unwrap_or(::std::usize::MAX))
            // short-circuit on error
            .collect::<Result<Vec<_>, _>>()?;

        logs.reverse();
        Ok(logs)
    }

    pub fn logs(
        &self, filter: Filter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        match filter.block_hashes {
            None => self.filter_logs_by_epochs(filter),
            Some(_) => self.filter_logs_by_block_hashes(filter),
        }
    }

    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch: EpochNumber,
    ) -> RpcResult<ExecutionOutcome> {
        // only allow to call against stated epoch
        self.validate_stated_epoch(&epoch)?;
        let (epoch_id, epoch_size) = if let Ok(v) =
            self.get_block_hashes_by_epoch(epoch)
        {
            (v.last().expect("pivot block always exist").clone(), v.len())
        } else {
            bail!("cannot get block hashes in the specified epoch, maybe it does not exist?");
        };
        self.executor.call_virtual(tx, &epoch_id, epoch_size)
    }

    /// Get the number of processed blocks (i.e., the number of calls to
    /// on_new_block()
    pub fn get_processed_block_count(&self) -> usize {
        self.statistics.get_consensus_graph_processed_block_count()
    }

    fn get_state_db_by_height_and_hash(
        &self, height: u64, hash: &H256,
    ) -> RpcResult<StateDb> {
        // Keep the lock until we get the desired State, otherwise the State may
        // expire.
        let state_availability_boundary =
            self.data_man.state_availability_boundary.read();
        if !state_availability_boundary.check_availability(height, &hash) {
            debug!(
                "State for epoch (number={:?} hash={:?}) does not exist: out-of-bound {:?}",
                height, hash, state_availability_boundary
            );
            bail!(format!(
                "State for epoch (number={:?} hash={:?}) does not exist: out-of-bound {:?}",
                height, hash, state_availability_boundary
            ));
        }
        let maybe_state_readonly_index =
            self.data_man.get_state_readonly_index(&hash).into();
        let maybe_state = match maybe_state_readonly_index {
            Some(state_readonly_index) => self
                .data_man
                .storage_manager
                .get_state_no_commit(
                    state_readonly_index,
                    /* try_open = */ true,
                )
                .map_err(|e| format!("Error to get state, err={:?}", e))?,
            None => None,
        };

        let state = match maybe_state {
            Some(state) => state,
            None => {
                bail!(format!(
                    "State for epoch (number={:?} hash={:?}) does not exist",
                    height, hash
                ));
            }
        };

        Ok(StateDb::new(state))
    }

    /// This function is called after a new block appended to the
    /// ConsensusGraph. Because BestInformation is often queried outside. We
    /// store a version of best_info outside the inner to prevent keep
    /// getting inner locks.
    /// If `ready_for_mining` is `false`, the terminal information will not be
    /// needed, so we do not compute bounded terminals in this case.
    fn update_best_info(&self, ready_for_mining: bool) {
        let mut inner = self.inner.write();
        let mut best_info = self.best_info.write();

        let bounded_terminal_block_hashes = if ready_for_mining {
            inner.bounded_terminal_block_hashes(self.config.referee_bound)
        } else {
            // `bounded_terminal` is only needed for mining and serve syncing.
            // As the computation cost is high, we do not compute it when we are
            // catching up because we cannot mine blocks in
            // catching-up phases. Use `best_block_hash` to
            // represent terminals here to remain consistent.
            vec![inner.best_block_hash()]
        };
        let best_epoch_number = inner.best_epoch_number();
        BEST_EPOCH_NUMBER.update(best_epoch_number as usize);
        *best_info = Arc::new(BestInformation {
            chain_id: self
                .config
                .chain_id
                .read()
                .get_chain_id(best_epoch_number),
            best_block_hash: inner.best_block_hash(),
            best_epoch_number,
            current_difficulty: inner.current_difficulty,
            bounded_terminal_block_hashes,
        });
        debug!("update_best_info to {:?}", best_info);
    }
}

impl Drop for ConsensusGraph {
    fn drop(&mut self) { self.executor.stop(); }
}

impl ConsensusGraphTrait for ConsensusGraph {
    type ConsensusConfig = ConsensusConfig;

    fn as_any(&self) -> &dyn Any { self }

    fn get_config(&self) -> &Self::ConsensusConfig { &self.config }

    /// This is the main function that SynchronizationGraph calls to deliver a
    /// new block to the consensus graph.
    fn on_new_block(&self, hash: &H256) {
        let _timer =
            MeterTimer::time_func(CONSENSIS_ON_NEW_BLOCK_TIMER.as_ref());
        self.statistics.inc_consensus_graph_processed_block_count();

        self.new_block_handler.on_new_block(
            &mut *self.inner.write(),
            &self.confirmation_meter,
            hash,
        );

        let ready_for_mining = self.ready_for_mining.load(Ordering::SeqCst);
        self.update_best_info(ready_for_mining);
        if ready_for_mining {
            self.txpool
                .notify_new_best_info(self.best_info.read().clone())
                // FIXME: propogate error.
                .expect(&concat!(file!(), ":", line!(), ":", column!()));
        }
        debug!("Finish Consensus::on_new_block for {:?}", hash);
    }

    /// This function is a wrapper function for the function in the confirmation
    /// meter. The synchronization layer is supposed to call this function
    /// every 2 * BLOCK_PROPAGATION_DELAY seconds
    fn update_total_weight_delta_heartbeat(&self) {
        self.confirmation_meter
            .update_total_weight_delta_heartbeat();
    }

    /// This function returns the set of blocks that are two eras farther from
    /// current era. They can be safely garbage collected.
    fn retrieve_old_era_blocks(&self) -> Option<H256> {
        self.inner.read().pop_old_era_block_set()
    }

    /// construct_pivot_state() rebuild pivot chain state info from db
    /// avoiding intermediate redundant computation triggered by
    /// on_new_block().
    fn construct_pivot_state(&self) {
        let inner = &mut *self.inner.write();
        // Ensure that `state_valid` of the first valid block after
        // cur_era_stable_genesis is set
        inner.recover_state_valid();
        self.new_block_handler.construct_pivot_state(inner);
        inner.finish_block_recovery();
    }

    fn best_info(&self) -> Arc<BestInformation> {
        self.best_info.read_recursive().clone()
    }

    fn best_epoch_number(&self) -> u64 {
        self.best_info.read_recursive().best_epoch_number
    }

    fn latest_checkpoint_epoch_number(&self) -> u64 {
        self.data_man
            .block_height_by_hash(
                &self.data_man.get_cur_consensus_era_genesis_hash(),
            )
            .expect("header for cur_era_genesis should exist")
    }

    fn latest_confirmed_epoch_number(&self) -> u64 {
        self.confirmation_meter.get_confirmed_epoch_num()
    }

    fn best_chain_id(&self) -> u32 {
        self.best_info.read_recursive().best_chain_id()
    }

    fn best_block_hash(&self) -> H256 {
        self.best_info.read_recursive().best_block_hash
    }

    /// Compute the expected difficulty of a new block given its parent
    fn expected_difficulty(&self, parent_hash: &H256) -> U256 {
        let inner = self.inner.read();
        inner.expected_difficulty(parent_hash)
    }

    // FIXME store this in BlockDataManager
    /// Return the sequence number of the current era genesis hash.
    fn current_era_genesis_seq_num(&self) -> u64 {
        self.inner.read_recursive().current_era_genesis_seq_num()
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
            .and_then(|height| {
                self.inner.read().get_pivot_hash_from_epoch_number(height)
            })
    }

    fn get_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String> {
        self.get_height_from_epoch_number(epoch_number)
            .and_then(|height| {
                self.inner.read_recursive().block_hashes_by_epoch(height)
            })
    }

    fn get_skipped_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String> {
        self.get_height_from_epoch_number(epoch_number)
            .and_then(|height| {
                self.inner
                    .read_recursive()
                    .skipped_block_hashes_by_epoch(height)
            })
    }

    fn get_transaction_info_by_hash(
        &self, hash: &H256,
    ) -> Option<(SignedTransaction, TransactionInfo)> {
        // We need to hold the inner lock to ensure that tx_index and receipts
        // are consistent
        let inner = self.inner.read();
        if let Some(tx_info) = inner.get_transaction_info(hash) {
            let block = self.data_man.block_by_hash(
                &tx_info.tx_index.block_hash,
                false, /* update_cache */
            )?;
            let transaction =
                (*block.transactions[tx_info.tx_index.index]).clone();
            Some((transaction, tx_info))
        } else {
            None
        }
    }

    fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        self.inner.read_recursive().get_block_epoch_number(hash)
    }

    fn get_block_number(
        &self, block_hash: &H256,
    ) -> Result<Option<u64>, String> {
        let inner = self.inner.read_recursive();
        let epoch_number = match inner.get_block_epoch_number(block_hash) {
            None => return Ok(None),
            Some(epoch_number) => epoch_number,
        };
        let epoch_hash = match inner.epoch_hash(epoch_number) {
            None => return Ok(None),
            Some(hash) => hash,
        };
        let blocks =
            self.get_block_hashes_by_epoch(EpochNumber::Number(epoch_number))?;
        let start_block_number =
            match self.data_man.get_epoch_execution_context(&epoch_hash) {
                None => return Ok(None),
                Some(ctx) => ctx.start_block_number,
            };
        let index_of_block = match blocks.iter().position(|x| x == block_hash) {
            None => return Ok(None),
            Some(index) => index as u64,
        };
        return Ok(Some(start_block_number + index_of_block));
    }

    /// Find a trusted blame block for snapshot full sync
    fn get_trusted_blame_block_for_snapshot(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Option<H256> {
        self.inner
            .read()
            .get_trusted_blame_block_for_snapshot(snapshot_epoch_id)
    }

    /// Return the epoch that we are going to sync the state
    fn get_to_sync_epoch_id(&self) -> EpochId {
        self.inner.read().get_to_sync_epoch_id()
    }

    /// Find a trusted blame block for checkpoint
    fn get_trusted_blame_block(&self, stable_hash: &H256) -> Option<H256> {
        self.inner.read().get_trusted_blame_block(stable_hash, 0)
    }

    fn set_initial_sequence_number(&self, initial_sn: u64) {
        self.inner.write().set_initial_sequence_number(initial_sn);
    }

    fn get_state_by_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> RpcResult<State> {
        self.validate_stated_epoch(&epoch_number)?;
        let height = self.get_height_from_epoch_number(epoch_number)?;
        let (epoch_id, epoch_size) = if let Ok(v) =
            self.inner.read_recursive().block_hashes_by_epoch(height)
        {
            (v.last().expect("pivot block always exist").clone(), v.len())
        } else {
            bail!("cannot get block hashes in the specified epoch, maybe it does not exist?");
        };
        let state_db =
            self.get_state_db_by_height_and_hash(height, &epoch_id)?;

        let start_block_number = match self.data_man.get_epoch_execution_context(&epoch_id) {
            Some(v) => v.start_block_number + epoch_size as u64,
            None => bail!("cannot obtain the execution context. Database is potentially corrupted!"),
        };

        Ok(State::new(
            state_db,
            Default::default(), /* vm */
            &Spec::new_spec(),
            start_block_number,
        )?)
    }

    fn get_state_db_by_epoch_number(
        &self, epoch_number: EpochNumber,
    ) -> RpcResult<StateDb> {
        invalid_params_check(
            "epoch_number",
            self.validate_stated_epoch(&epoch_number),
        )?;
        let height = invalid_params_check(
            "epoch_number",
            self.get_height_from_epoch_number(epoch_number),
        )?;
        let hash =
            self.inner.read().get_pivot_hash_from_epoch_number(height)?;
        self.get_state_db_by_height_and_hash(height, &hash)
    }

    /// Return the blocks without bodies in the subtree of stable genesis and
    /// the blocks in the `REWARD_EPOCH_COUNT` epochs before it. Block
    /// bodies of other blocks in the consensus graph will never be needed
    /// for executions after this stable genesis, as long as the checkpoint
    /// is not reverted.
    fn get_blocks_needing_bodies(&self) -> HashSet<H256> {
        let inner = self.inner.read();
        // TODO: This may not be stable genesis with other configurations.
        let stable_genesis = self.data_man.get_cur_consensus_era_stable_hash();
        let mut missing_body_blocks = HashSet::new();
        for block_hash in inner
            .get_subtree(&stable_genesis)
            .expect("stable is in consensus")
        {
            if self.data_man.block_by_hash(&block_hash, false).is_none() {
                missing_body_blocks.insert(block_hash);
            }
        }
        // We also need the block bodies before the checkpoint to compute
        // rewards.
        let stable_height = self
            .data_man
            .block_height_by_hash(&stable_genesis)
            .expect("stable exist");
        let reward_start_epoch = if stable_height >= REWARD_EPOCH_COUNT {
            stable_height - REWARD_EPOCH_COUNT + 1
        } else {
            1
        };
        for height in reward_start_epoch..=stable_height {
            for block_hash in self
                .data_man
                .executed_epoch_set_hashes_from_db(height)
                .expect("epoch sets before stable should exist")
            {
                if self.data_man.block_by_hash(&block_hash, false).is_none() {
                    missing_body_blocks.insert(block_hash);
                }
            }
        }
        missing_body_blocks.remove(&self.data_man.true_genesis.hash());
        missing_body_blocks
    }

    /// Check if we have downloaded all the headers to find the lowest needed
    /// checkpoint. We can enter `CatchUpCheckpoint` if it's true.
    fn catch_up_completed(&self, peer_median_epoch: u64) -> bool {
        let stable_genesis_height = self
            .data_man
            .block_height_by_hash(
                &self.data_man.get_cur_consensus_era_stable_hash(),
            )
            .expect("stable exists");
        if let Some(target_epoch) = self.config.sync_state_starting_epoch {
            if stable_genesis_height < target_epoch {
                return false;
            }
        }
        if let Some(gap) = self.config.sync_state_epoch_gap {
            if self.best_epoch_number() + gap < peer_median_epoch {
                return false;
            }
        }
        true
    }

    fn enter_normal_phase(&self) {
        self.ready_for_mining.store(true, Ordering::SeqCst);
        self.update_best_info(true);
        self.txpool
            .notify_new_best_info(self.best_info.read_recursive().clone())
            .expect("No DB error")
    }

    fn reset(&self) {
        let old_consensus_inner = &mut *self.inner.write();

        let cur_era_genesis_hash =
            self.data_man.get_cur_consensus_era_genesis_hash();
        let cur_era_stable_hash =
            self.data_man.get_cur_consensus_era_stable_hash();
        let new_consensus_inner = ConsensusGraphInner::with_era_genesis(
            old_consensus_inner.pow_config.clone(),
            old_consensus_inner.pow.clone(),
            self.data_man.clone(),
            old_consensus_inner.inner_conf.clone(),
            &cur_era_genesis_hash,
            &cur_era_stable_hash,
        );
        *old_consensus_inner = new_consensus_inner;
        debug!("Build new consensus graph for sync-recovery with identified genesis {} stable block {}", cur_era_genesis_hash, cur_era_stable_hash);

        self.confirmation_meter.clear();
    }
}
