// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod anticone_cache;
pub mod consensus_inner;
pub mod consensus_trait;
pub mod debug_recompute;
mod pastset_cache;
pub mod pos_handler;

use super::consensus::consensus_inner::{
    confirmation_meter::ConfirmationMeter,
    consensus_executor::ConsensusExecutor,
    consensus_new_block_handler::ConsensusNewBlockHandler,
};
pub use crate::consensus::{
    consensus_inner::{ConsensusGraphInner, ConsensusInnerConfig},
    consensus_trait::{ConsensusGraphTrait, SharedConsensusGraph},
};
use crate::{
    block_data_manager::{
        BlockDataManager, BlockExecutionResultWithEpoch, DataVersionTuple,
    },
    consensus::{
        consensus_inner::{
            consensus_executor::ConsensusExecutionConfiguration, StateBlameInfo,
        },
        pos_handler::PosVerifier,
    },
    errors::{invalid_params, invalid_params_check, Result as CoreResult},
    pow::{PowComputer, ProofOfWorkConfig},
    statistics::SharedStatistics,
    transaction_pool::SharedTransactionPool,
    verification::VerificationConfig,
    NodeType, Notifications,
};
use cfx_execute_helper::{
    estimation::{EstimateExt, EstimateRequest},
    exec_tracer::{
        recover_phantom_traces, ActionType, BlockExecTraces, LocalizedTrace,
        TraceFilter,
    },
    phantom_tx::build_bloom_and_recover_phantom,
};
use cfx_executor::{
    executive::ExecutionOutcome, spec::CommonParams, state::State,
};
use geth_tracer::GethTraceWithHash;

use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use cfx_internal_common::ChainIdParams;
use cfx_parameters::{
    consensus::*,
    consensus_internal::REWARD_EPOCH_COUNT,
    rpc::{
        GAS_PRICE_BLOCK_SAMPLE_SIZE, GAS_PRICE_DEFAULT_VALUE,
        GAS_PRICE_TRANSACTION_SAMPLE_SIZE,
    },
};
use cfx_rpc_cfx_types::PhantomBlock;
use cfx_statedb::StateDb;
use cfx_storage::{
    state::StateTrait, state_manager::StateManagerTrait, StorageState,
};
use cfx_types::{AddressWithSpace, AllChainID, Bloom, Space, H256, U256};
use either::Either;
use itertools::Itertools;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use metrics::{
    register_meter_with_group, Gauge, GaugeUsize, Meter, MeterTimer,
};
use parking_lot::{Mutex, RwLock};
use primitives::{
    compute_block_number,
    epoch::BlockHashOrEpochNumber,
    filter::{FilterError, LogFilter},
    log_entry::LocalizedLogEntry,
    pos::PosBlockId,
    receipt::Receipt,
    Block, EpochId, EpochNumber, SignedTransaction, TransactionIndex,
    TransactionStatus,
};
use rayon::prelude::*;
use std::{
    any::Any,
    cmp::{max, min},
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

    /// Limits on epoch and block number ranges during log filtering.
    pub get_logs_filter_max_epoch_range: Option<u64>,
    pub get_logs_filter_max_block_number_range: Option<u64>,
    /// Max limiation for logs
    pub get_logs_filter_max_limit: Option<usize>,

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
    pub chain_id: AllChainID,
    pub best_block_hash: H256,
    pub best_epoch_number: u64,
    pub current_difficulty: U256,
    pub bounded_terminal_block_hashes: Vec<H256>,
    pub best_block_number: u64,
}

impl BestInformation {
    pub fn best_chain_id(&self) -> AllChainID { self.chain_id }
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
    pub ready_for_mining: AtomicBool,

    /// The epoch id of the remotely synchronized state.
    /// This is always `None` for archive nodes.
    pub synced_epoch_id: Mutex<Option<EpochId>>,
    pub config: ConsensusConfig,
    pub params: CommonParams,
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
        conf: ConsensusConfig, txpool: SharedTransactionPool,
        statistics: SharedStatistics, data_man: Arc<BlockDataManager>,
        pow_config: ProofOfWorkConfig, pow: Arc<PowComputer>,
        era_genesis_block_hash: &H256, era_stable_block_hash: &H256,
        notifications: Arc<Notifications>,
        execution_conf: ConsensusExecutionConfiguration,
        verification_config: VerificationConfig, node_type: NodeType,
        pos_verifier: Arc<PosVerifier>, params: CommonParams,
    ) -> Self {
        let inner =
            Arc::new(RwLock::new(ConsensusGraphInner::with_era_genesis(
                pow_config,
                pow.clone(),
                pos_verifier.clone(),
                data_man.clone(),
                conf.inner_conf.clone(),
                era_genesis_block_hash,
                era_stable_block_hash,
            )));
        let executor = ConsensusExecutor::start(
            txpool.clone(),
            data_man.clone(),
            inner.clone(),
            execution_conf,
            verification_config,
            conf.bench_mode,
            pos_verifier.clone(),
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
                pos_verifier,
            ),
            confirmation_meter,
            best_info: RwLock::new(Arc::new(Default::default())),
            ready_for_mining: AtomicBool::new(false),
            synced_epoch_id: Default::default(),
            config: conf,
            params,
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
        conf: ConsensusConfig, txpool: SharedTransactionPool,
        statistics: SharedStatistics, data_man: Arc<BlockDataManager>,
        pow_config: ProofOfWorkConfig, pow: Arc<PowComputer>,
        notifications: Arc<Notifications>,
        execution_conf: ConsensusExecutionConfiguration,
        verification_conf: VerificationConfig, node_type: NodeType,
        pos_verifier: Arc<PosVerifier>, params: CommonParams,
    ) -> Self {
        let genesis_hash = data_man.get_cur_consensus_era_genesis_hash();
        let stable_hash = data_man.get_cur_consensus_era_stable_hash();
        ConsensusGraph::with_era_genesis(
            conf,
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
            pos_verifier,
            params,
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
        // Ensure that `best_info` has been updated when this returns, so if we
        // are calling RPCs to generate many blocks, they will form a
        // strict chain. Note that it's okay to call `update_best_info`
        // multiple times, and we only generate blocks after
        // `ready_for_mining` is true.
        self.update_best_info(true);
        if let Err(e) = self
            .txpool
            .notify_new_best_info(self.best_info.read_recursive().clone())
        {
            error!("wait for generation: notify_new_best_info err={:?}", e);
        }
    }

    /// Determine whether the next mined block should have adaptive weight or
    /// not
    pub fn check_mining_adaptive_block(
        &self, inner: &mut ConsensusGraphInner, parent_hash: &H256,
        referees: &Vec<H256>, difficulty: &U256,
        pos_reference: Option<PosBlockId>,
    ) -> bool {
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
            pos_reference,
        )
    }

    /// After considering the latest `pos_reference`, `parent_hash` may become
    /// an invalid choice, so this function tries to update the parent and
    /// referee choices with `pos_reference` provided.
    pub fn choose_correct_parent(
        &self, parent_hash: &mut H256, referees: &mut Vec<H256>,
        blame_info: &mut StateBlameInfo, pos_reference: Option<PosBlockId>,
    ) {
        let correct_parent_hash = {
            if let Some(pos_ref) = &pos_reference {
                loop {
                    let inner = self.inner.read();
                    let pivot_decision = inner
                        .pos_verifier
                        .get_pivot_decision(pos_ref)
                        .expect("pos ref committed");
                    if inner.hash_to_arena_indices.contains_key(&pivot_decision)
                        || inner.pivot_block_processed(&pivot_decision)
                    {
                        // If this pos ref is processed in catching-up, its
                        // pivot decision may have not been processed
                        break;
                    } else {
                        // Wait without holding consensus inner lock.
                        drop(inner);
                        warn!("Wait for PoW to catch up with PoS");
                        sleep(Duration::from_secs(1));
                    }
                }
            }
            // recompute `blame_info` needs locking `self.inner`, so we limit
            // the lock scope here.
            let mut inner = self.inner.write();
            referees.retain(|h| inner.hash_to_arena_indices.contains_key(h));
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
            let correct_parent = inner.choose_correct_parent(
                parent_index,
                referee_indices,
                pos_reference,
            );
            inner.arena[correct_parent].hash
        };

        if correct_parent_hash != *parent_hash {
            debug!(
                "Change parent from {:?} to {:?}",
                parent_hash, correct_parent_hash
            );

            // correct_parent may be among referees, so check and remove it.
            referees.retain(|i| *i != correct_parent_hash);

            // Old parent is a valid block terminal to refer to.
            if referees.len() < self.config.referee_bound {
                referees.push(*parent_hash);
            }

            // correct_parent may not be on the pivot chain, so recompute
            // blame_info if needed.
            *blame_info = self
                .force_compute_blame_and_deferred_state_for_generation(
                    &correct_parent_hash,
                )
                .expect("blame info computation error");
            *parent_hash = correct_parent_hash;
        }
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
            EpochNumber::LatestFinalized => {
                self.latest_finalized_epoch_number()
            }
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
    pub fn gas_price(&self, space: Space) -> Option<U256> {
        let inner = self.inner.read();
        let mut last_epoch_number = inner.best_epoch_number();
        let (
            number_of_tx_to_sample,
            mut number_of_blocks_to_sample,
            block_gas_ratio,
        ) = (
            GAS_PRICE_TRANSACTION_SAMPLE_SIZE,
            GAS_PRICE_BLOCK_SAMPLE_SIZE,
            1,
        );
        let mut prices = Vec::new();
        let mut total_block_gas_limit: u64 = 0;
        let mut total_tx_gas_limit: u64 = 0;

        loop {
            if number_of_blocks_to_sample == 0 || last_epoch_number == 0 {
                break;
            }
            if prices.len() == number_of_tx_to_sample {
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
                total_block_gas_limit +=
                    block.block_header.gas_limit().as_u64() * block_gas_ratio;
                for tx in block.transactions.iter() {
                    if space == Space::Native && tx.space() != Space::Native {
                        // For cfx_gasPrice, we only count Native transactions.
                        continue;
                    }
                    // add the tx.gas() to total_tx_gas_limit even it is packed
                    // multiple times because these tx all
                    // will occupy block's gas space
                    total_tx_gas_limit += tx.transaction.gas().as_u64();
                    prices.push(tx.gas_price().clone());
                    if prices.len() == number_of_tx_to_sample {
                        break;
                    }
                }
                number_of_blocks_to_sample -= 1;
                if number_of_blocks_to_sample == 0
                    || prices.len() == number_of_tx_to_sample
                {
                    break;
                }
            }
        }

        prices.sort();
        if prices.is_empty() || total_tx_gas_limit == 0 {
            Some(U256::from(GAS_PRICE_DEFAULT_VALUE))
        } else {
            let average_gas_limit_multiple =
                total_block_gas_limit / total_tx_gas_limit;
            if average_gas_limit_multiple > 5 {
                // used less than 20%
                Some(U256::from(GAS_PRICE_DEFAULT_VALUE))
            } else if average_gas_limit_multiple >= 2 {
                // used less than 50%
                Some(prices[prices.len() / 8])
            } else {
                // used more than 50%
                Some(prices[prices.len() / 2])
            }
        }
    }

    pub fn validate_stated_epoch(
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

    pub fn get_block_execution_info(
        &self, block_hash: &H256,
    ) -> Option<(BlockExecutionResultWithEpoch, Option<H256>)> {
        let results_with_epoch = self
            .inner
            .read_recursive()
            .block_execution_results_by_hash(block_hash, true)?;

        let pivot_hash = results_with_epoch.0;

        let maybe_state_root = match self.executor.wait_for_result(pivot_hash) {
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

        Some((results_with_epoch, maybe_state_root))
    }

    pub fn get_block_epoch_number_with_pivot_check(
        &self, hash: &H256, require_pivot: bool,
    ) -> CoreResult<u64> {
        let inner = &*self.inner.read();
        // TODO: block not found error
        let epoch_number =
            inner.get_block_epoch_number(&hash).ok_or(invalid_params(
                "epoch parameter",
                format!("block's epoch number is not found: {:?}", hash),
            ))?;

        if require_pivot {
            if let Err(..) =
                inner.check_block_pivot_assumption(&hash, epoch_number)
            {
                bail!(invalid_params(
                    "epoch parameter",
                    format!(
                        "should receive a pivot block hash, receives: {:?}",
                        hash
                    ),
                ))
            }
        }
        Ok(epoch_number)
    }

    // TODO: maybe return error for reserved address? Not sure where is the best
    //  place to do the check.
    pub fn next_nonce(
        &self, address: AddressWithSpace,
        block_hash_or_epoch_number: BlockHashOrEpochNumber,
        rpc_param_name: &str,
    ) -> CoreResult<U256> {
        let epoch_number = match block_hash_or_epoch_number {
            BlockHashOrEpochNumber::BlockHashWithOption {
                hash,
                require_pivot,
            } => EpochNumber::Number(
                self.get_block_epoch_number_with_pivot_check(
                    &hash,
                    require_pivot.unwrap_or(true),
                )?,
            ),
            BlockHashOrEpochNumber::EpochNumber(epoch_number) => epoch_number,
        };
        let state = State::new(
            self.get_state_db_by_epoch_number(epoch_number, rpc_param_name)?,
        )?;

        Ok(state.nonce(&address)?)
    }

    fn earliest_epoch_for_log_filter(&self) -> u64 {
        max(
            self.data_man.earliest_epoch_with_block_body(),
            self.data_man.earliest_epoch_with_execution_result(),
        )
    }

    fn earliest_epoch_for_trace_filter(&self) -> u64 {
        self.data_man.earliest_epoch_with_trace()
    }

    fn filter_block_receipts<'a>(
        &self, filter: &'a LogFilter, epoch_number: u64, block_hash: H256,
        mut receipts: Vec<Receipt>, mut tx_hashes: Vec<H256>,
    ) -> impl Iterator<Item = LocalizedLogEntry> + 'a {
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
            .flat_map(|r| r.logs.iter())
            .filter(|l| l.space == filter.space)
            .count();

        let receipts_len = receipts.len();

        receipts
            .into_iter()
            .map(|receipt| receipt.logs)
            .zip(tx_hashes)
            .enumerate()
            .flat_map(move |(index, (logs, transaction_hash))| {
                let mut logs: Vec<_> = logs
                    .into_iter()
                    .filter(|l| l.space == filter.space)
                    .collect();

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
    }

    fn filter_block<'a>(
        &self, filter: &'a LogFilter, bloom_possibilities: &'a Vec<Bloom>,
        epoch: u64, pivot_hash: H256, block_hash: H256,
    ) -> Result<impl Iterator<Item = LocalizedLogEntry> + 'a, FilterError> {
        // special case for genesis (for now, genesis has no logs)
        if epoch == 0 {
            return Ok(Either::Left(std::iter::empty()));
        }

        // check if epoch is still available
        let min = self.earliest_epoch_for_log_filter();

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
            block.transaction_hashes(/* space filter */ None),
        )))
    }

    fn filter_phantom_block<'a>(
        &self, filter: &'a LogFilter, bloom_possibilities: &'a Vec<Bloom>,
        epoch: u64, pivot_hash: H256,
    ) -> Result<impl Iterator<Item = LocalizedLogEntry> + 'a, FilterError> {
        // special case for genesis (for now, genesis has no logs)
        if epoch == 0 {
            return Ok(Either::Left(std::iter::empty()));
        }

        // check if epoch is still available
        let min = self.earliest_epoch_for_log_filter();

        if epoch < min {
            return Err(FilterError::EpochAlreadyPruned { epoch, min });
        }

        // filter block
        let epoch_bloom = match self.get_phantom_block_bloom_filter(
            EpochNumber::Number(epoch),
            pivot_hash,
        )? {
            Some(b) => b,
            None => {
                return Err(FilterError::BlockNotExecutedYet {
                    block_hash: pivot_hash,
                })
            }
        };

        if !bloom_possibilities
            .iter()
            .any(|bloom| epoch_bloom.contains_bloom(bloom))
        {
            return Ok(Either::Left(std::iter::empty()));
        }

        // construct phantom block
        let pb = match self.get_phantom_block_by_number(
            EpochNumber::Number(epoch),
            Some(pivot_hash),
            false, /* include_traces */
        )? {
            Some(b) => b,
            None => {
                return Err(FilterError::BlockNotExecutedYet {
                    block_hash: pivot_hash,
                })
            }
        };

        Ok(Either::Right(self.filter_block_receipts(
            &filter,
            epoch,
            pivot_hash,
            pb.receipts,
            pb.transactions.iter().map(|t| t.hash()).collect(),
        )))
    }

    fn filter_single_epoch<'a>(
        &'a self, filter: &'a LogFilter, bloom_possibilities: &'a Vec<Bloom>,
        epoch: u64,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        // retrieve epoch hashes and pivot hash
        let mut epoch_hashes =
            self.inner.read_recursive().block_hashes_by_epoch(epoch)?;

        let pivot_hash = *epoch_hashes.last().expect("Epoch set not empty");

        // process hashes in reverse order
        epoch_hashes.reverse();

        if filter.space == Space::Ethereum {
            Ok(self
                .filter_phantom_block(
                    &filter,
                    &bloom_possibilities,
                    epoch,
                    pivot_hash,
                )?
                .collect())
        } else {
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
                .collect()
        }
    }

    fn filter_epoch_batch(
        &self, filter: &LogFilter, bloom_possibilities: &Vec<Bloom>,
        epochs: Vec<u64>, consistency_check_data: &mut Option<(u64, H256)>,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        // lock so that we have a consistent view during this batch
        let inner = self.inner.read();

        // NOTE: as batches are processed atomically and only the
        // first batch (last few epochs) is likely to fluctuate, it is unlikely
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

        Ok(epoch_batch_logs.into_iter().flatten().collect())
    }

    pub fn get_log_filter_epoch_range(
        &self, from_epoch: EpochNumber, to_epoch: EpochNumber,
        check_range: bool,
    ) -> Result<impl Iterator<Item = u64>, FilterError> {
        // lock so that we have a consistent view
        let _inner = self.inner.read_recursive();

        let from_epoch =
            self.get_height_from_epoch_number(from_epoch.clone())?;
        let to_epoch = self.get_height_from_epoch_number(to_epoch.clone())?;

        if from_epoch > to_epoch {
            return Err(FilterError::InvalidEpochNumber {
                from_epoch,
                to_epoch,
            });
        }

        if from_epoch < self.earliest_epoch_for_log_filter() {
            return Err(FilterError::EpochAlreadyPruned {
                epoch: from_epoch,
                min: self.earliest_epoch_for_log_filter(),
            });
        }

        if check_range {
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
        }

        return Ok((from_epoch..=to_epoch).rev());
    }

    pub fn get_trace_filter_epoch_range(
        &self, filter: &TraceFilter,
    ) -> Result<impl Iterator<Item = u64>, FilterError> {
        // lock so that we have a consistent view
        let _inner = self.inner.read_recursive();

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

        if from_epoch < self.earliest_epoch_for_trace_filter() {
            return Err(FilterError::EpochAlreadyPruned {
                epoch: from_epoch,
                min: self.earliest_epoch_for_trace_filter(),
            });
        }
        Ok(from_epoch..=to_epoch)
    }

    fn filter_logs_by_epochs(
        &self, from_epoch: EpochNumber, to_epoch: EpochNumber,
        filter: &LogFilter, blocks_to_skip: HashSet<H256>, check_range: bool,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        let bloom_possibilities = filter.bloom_possibilities();

        // we store the last epoch processed and the corresponding pivot hash so
        // that we can check whether it changed between batches
        let mut consistency_check_data: Option<(u64, H256)> = None;

        let mut logs = self
            // iterate over epochs in reverse order
            .get_log_filter_epoch_range(from_epoch, to_epoch, check_range)?
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
            .skip_while(|res| match res {
                Ok(log) => blocks_to_skip.contains(&log.block_hash),
                Err(_) => false,
            })
            // Limit logs can return
            .take(
                self.config
                    .get_logs_filter_max_limit
                    .unwrap_or(::std::usize::MAX - 1)
                    + 1,
            )
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
            bail!(FilterError::UnknownBlock { hash: block_hash });
        };

        // find pivot block
        let pivot_hash = match self
            .inner
            .read_recursive()
            .block_execution_results_by_hash(&block_hash, false)
        {
            Some(r) => r.0,
            None => {
                match self.data_man.local_block_info_by_hash(&block_hash) {
                    // if local block info is not available, that means this
                    // block has never entered the consensus graph.
                    None => {
                        bail!(FilterError::BlockNotExecutedYet { block_hash })
                    }
                    // if the local block info is available, then it is very
                    // likely that we have already executed this block and the
                    // results are not available because they have been pruned.
                    // NOTE: it might be possible that the block has entered
                    // consensus graph but has not been executed yet, or that it
                    // was not executed because it was invalid. these cases seem
                    // rare enough to not require special handling here; we can
                    // add more fine-grained errors in the future if necessary.
                    Some(_) => {
                        bail!(FilterError::BlockAlreadyPruned { block_hash })
                    }
                }
            }
        };

        // find epoch number
        let epoch = match self.data_man.block_header_by_hash(&pivot_hash) {
            Some(h) => h.height(),
            None => {
                // internal error
                error!("Header of pivot block {:?} not found", pivot_hash);
                bail!(FilterError::UnknownBlock { hash: pivot_hash });
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
        &self, block_hashes: Vec<H256>, filter: LogFilter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
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
            // Limit logs can return
            .take(
                self.config
                    .get_logs_filter_max_limit
                    .unwrap_or(::std::usize::MAX - 1)
                    + 1,
            )
            // short-circuit on error
            .collect::<Result<Vec<_>, _>>()?;

        logs.reverse();
        Ok(logs)
    }

    fn filter_logs_by_block_numbers(
        &self, from_block: u64, to_block: u64, filter: LogFilter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        // check range
        if from_block > to_block {
            return Err(FilterError::InvalidBlockNumber {
                from_block,
                to_block,
            });
        }

        if let Some(max_gap) =
            self.config.get_logs_filter_max_block_number_range
        {
            // The range includes both ends.
            if to_block - from_block + 1 > max_gap {
                return Err(FilterError::BlockNumberGapTooLarge {
                    from_block,
                    to_block,
                    max_gap,
                });
            }
        }

        // collect info from db
        let from_hash = match self
            .data_man
            .hash_by_block_number(from_block, true /* update_cache */)
        {
            Some(h) => h,
            None => bail!(FilterError::Custom(format!(
                "Unable to find block hash for from_block {:?}",
                from_block
            ))),
        };

        let to_hash = match self
            .data_man
            .hash_by_block_number(to_block, true /* update_cache */)
        {
            Some(h) => h,
            None => bail!(FilterError::Custom(format!(
                "Unable to find block hash for to_block {:?}",
                to_block
            ))),
        };

        let from_epoch = match self.get_block_epoch_number(&from_hash) {
            Some(e) => e,
            None => bail!(FilterError::Custom(format!(
                "Unable to find epoch number for block {:?}",
                from_hash
            ))),
        };

        let to_epoch = match self.get_block_epoch_number(&to_hash) {
            Some(e) => e,
            None => bail!(FilterError::Custom(format!(
                "Unable to find epoch number for block {:?}",
                to_hash
            ))),
        };

        let (from_epoch_hashes, to_epoch_hashes) = {
            let inner = self.inner.read();
            (
                inner.block_hashes_by_epoch(from_epoch)?,
                inner.block_hashes_by_epoch(to_epoch)?,
            )
        };

        // filter logs based on epochs
        // out-of-range blocks from the _end_ of the range
        // are handled by `filter_logs_by_epochs`
        let skip_from_end = to_epoch_hashes
            .into_iter()
            .skip_while(|h| *h != to_hash)
            .skip(1)
            .collect();

        let epoch_range_logs = self.filter_logs_by_epochs(
            EpochNumber::Number(from_epoch),
            EpochNumber::Number(to_epoch),
            &filter,
            skip_from_end,
            false, /* check_range */
        )?;

        // remove out-of-range blocks from the _start_ of the range
        let skip_from_start: HashSet<_> = from_epoch_hashes
            .into_iter()
            .take_while(|h| *h != from_hash)
            .collect();

        Ok(epoch_range_logs
            .into_iter()
            .skip_while(|log| skip_from_start.contains(&log.block_hash))
            .collect())
    }

    pub fn logs(
        &self, filter: LogFilter,
    ) -> Result<Vec<LocalizedLogEntry>, FilterError> {
        match &filter {
            // filter by epoch numbers
            LogFilter::EpochLogFilter {
                from_epoch,
                to_epoch,
                ..
            } => {
                // When query logs, if epoch number greater than
                // best_executed_state_epoch_number, use LatestState instead of
                // epoch number, in this case we can return logs from from_epoch
                // to LatestState
                let to_epoch = if let EpochNumber::Number(num) = to_epoch {
                    let epoch_number =
                        if *num > self.best_executed_state_epoch_number() {
                            EpochNumber::LatestState
                        } else {
                            to_epoch.clone()
                        };

                    epoch_number
                } else {
                    to_epoch.clone()
                };

                self.filter_logs_by_epochs(
                    from_epoch.clone(),
                    to_epoch,
                    &filter,
                    Default::default(),
                    !filter.trusted, /* check_range */
                )
            }

            // filter by block hashes
            LogFilter::BlockHashLogFilter { block_hashes, .. } => {
                self.filter_logs_by_block_hashes(block_hashes.clone(), filter)
            }

            // filter by block numbers
            LogFilter::BlockNumberLogFilter {
                from_block,
                to_block,
                ..
            } => self.filter_logs_by_block_numbers(
                from_block.clone(),
                to_block.clone(),
                filter,
            ),
        }
    }

    // TODO(lpl): Limit epoch range in filter.
    pub fn filter_traces(
        &self, mut filter: TraceFilter,
    ) -> Result<Vec<LocalizedTrace>, FilterError> {
        let traces = match filter.block_hashes.take() {
            None => self.filter_traces_by_epochs(&filter),
            Some(hashes) => self.filter_traces_by_block_hashes(&filter, hashes),
        }?;
        // Apply `filter.after` and `filter.count` after getting all trace
        // entries.
        Ok(traces
            .into_iter()
            .skip(filter.after.unwrap_or(0))
            .take(filter.count.unwrap_or(usize::max_value()))
            .collect())
    }

    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch: EpochNumber,
        request: EstimateRequest,
    ) -> CoreResult<(ExecutionOutcome, EstimateExt)> {
        // only allow to call against stated epoch
        self.validate_stated_epoch(&epoch)?;
        let (epoch_id, epoch_size) = if let Ok(v) =
            self.get_block_hashes_by_epoch(epoch)
        {
            (v.last().expect("pivot block always exist").clone(), v.len())
        } else {
            bail!("cannot get block hashes in the specified epoch, maybe it does not exist?");
        };
        self.executor
            .call_virtual(tx, &epoch_id, epoch_size, request)
    }

    pub fn collect_epoch_geth_trace(
        &self, epoch_num: u64, tx_hash: Option<H256>,
        opts: GethDebugTracingOptions,
    ) -> CoreResult<Vec<GethTraceWithHash>> {
        let epoch = EpochNumber::Number(epoch_num);
        self.validate_stated_epoch(&epoch)?;

        let epoch_block_hashes = if let Ok(v) =
            self.get_block_hashes_by_epoch(epoch)
        {
            v
        } else {
            bail!("cannot get block hashes in the specified epoch, maybe it does not exist?");
        };

        let blocks = self
            .data_man
            .blocks_by_hash_list(
                &epoch_block_hashes,
                true, /* update_cache */
            )
            .expect("blocks exist");

        let pivot_block = blocks.last().expect("Not empty");
        let parent_pivot_block_hash = pivot_block.block_header.parent_hash();
        let parent_epoch_num = pivot_block.block_header.height() - 1;

        self.collect_blocks_geth_trace(
            *parent_pivot_block_hash,
            parent_epoch_num,
            &blocks,
            opts,
            tx_hash,
        )
    }

    pub fn collect_blocks_geth_trace(
        &self, epoch_id: H256, epoch_num: u64, blocks: &Vec<Arc<Block>>,
        opts: GethDebugTracingOptions, tx_hash: Option<H256>,
    ) -> CoreResult<Vec<GethTraceWithHash>> {
        self.executor.collect_blocks_geth_trace(
            epoch_id, epoch_num, blocks, opts, tx_hash,
        )
    }

    /// Get the number of processed blocks (i.e., the number of calls to
    /// on_new_block()
    pub fn get_processed_block_count(&self) -> usize {
        self.statistics.get_consensus_graph_processed_block_count()
    }

    fn get_storage_state_by_height_and_hash(
        &self, height: u64, hash: &H256,
    ) -> CoreResult<StorageState> {
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
                .get_state_no_commit_inner(
                    state_readonly_index,
                    /* try_open = */ true,
                    true,
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

        Ok(state)
    }

    fn get_state_by_height_and_hash(
        &self, height: u64, hash: &H256, space: Option<Space>,
    ) -> CoreResult<Box<dyn StateTrait>> {
        // Keep the lock until we get the desired State, otherwise the State may
        // expire.
        let state_availability_boundary =
            self.data_man.state_availability_boundary.read();
        if !state_availability_boundary
            .check_read_availability(height, &hash, space)
        {
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
                    space,
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

        Ok(state)
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
            best_block_number: inner.best_block_number(),
            best_epoch_number,
            current_difficulty: inner.current_difficulty,
            bounded_terminal_block_hashes,
        });
        debug!("update_best_info to {:?}", best_info);
    }

    fn filter_traces_by_epochs(
        &self, filter: &TraceFilter,
    ) -> Result<Vec<LocalizedTrace>, FilterError> {
        let epochs_and_pivot_hash = {
            let inner = self.inner.read();
            let mut epochs_and_pivot_hash = Vec::new();
            for epoch_number in self.get_trace_filter_epoch_range(filter)? {
                epochs_and_pivot_hash.push((
                    epoch_number,
                    inner.get_pivot_hash_from_epoch_number(epoch_number)?,
                ))
            }
            epochs_and_pivot_hash
        };

        let block_traces = epochs_and_pivot_hash
            .into_par_iter()
            .map(|(epoch_number, assumed_pivot)| {
                self.collect_traces_single_epoch(
                    filter,
                    epoch_number,
                    assumed_pivot,
                )
            })
            .collect::<Result<Vec<Vec<_>>, FilterError>>()?
            .into_iter()
            .flatten()
            .collect();

        self.filter_block_traces(filter, block_traces)
    }

    /// Return `Vec<(pivot_hash, block_hash, block_traces, block_txs)>`
    pub fn collect_traces_single_epoch(
        &self, filter: &TraceFilter, epoch_number: u64, assumed_pivot: H256,
    ) -> Result<
        Vec<(H256, H256, BlockExecTraces, Vec<Arc<SignedTransaction>>)>,
        FilterError,
    > {
        if filter.space == Space::Ethereum {
            let phantom_block = self
                .get_phantom_block_by_number(
                    EpochNumber::Number(epoch_number),
                    Some(assumed_pivot),
                    true, /* include_traces */
                )?
                .ok_or(FilterError::UnknownBlock {
                    hash: assumed_pivot,
                })?;

            return Ok(vec![(
                assumed_pivot,
                assumed_pivot,
                BlockExecTraces(phantom_block.traces),
                phantom_block.transactions,
            )]);
        }

        let block_hashes = self
            .inner
            .read_recursive()
            .block_hashes_by_epoch(epoch_number)?;
        if block_hashes.last().expect("epoch set not empty") != &assumed_pivot {
            bail!(FilterError::PivotChainReorg {
                epoch: epoch_number,
                from: assumed_pivot,
                to: *block_hashes.last().unwrap()
            })
        }
        let mut traces = Vec::new();
        for block_hash in block_hashes {
            let block = self
                .data_man
                .block_by_hash(&block_hash, false /* update_cache */)
                .ok_or(FilterError::BlockAlreadyPruned { block_hash })?;

            traces.push(
                self.data_man
                    .block_traces_by_hash_with_epoch(
                        &block_hash,
                        &assumed_pivot,
                        false,
                        true,
                    )
                    .map(|trace| {
                        (
                            assumed_pivot,
                            block_hash,
                            trace,
                            block.transactions.clone(),
                        )
                    })
                    .ok_or(FilterError::UnknownBlock { hash: block_hash })?,
            );
        }
        Ok(traces)
    }

    // TODO: We can apply some early return logic based on `filter.count`.
    fn filter_traces_by_block_hashes(
        &self, filter: &TraceFilter, block_hashes: Vec<H256>,
    ) -> Result<Vec<LocalizedTrace>, FilterError> {
        let block_traces = block_hashes
            .into_par_iter()
            .map(|h| {
                let block = self
                    .data_man
                    .block_by_hash(&h, false /* update_cache */)
                    .ok_or(FilterError::BlockAlreadyPruned { block_hash: h })?;

                self.data_man
                    .block_traces_by_hash(&h)
                    .map(|DataVersionTuple(pivot_hash, trace)| {
                        (pivot_hash, h, trace, block.transactions.clone())
                    })
                    .ok_or_else(|| FilterError::BlockNotExecutedYet {
                        block_hash: h,
                    })
            })
            .collect::<Result<Vec<_>, FilterError>>()?;
        self.filter_block_traces(filter, block_traces)
    }

    /// `block_traces` is a list of tuple `(pivot_hash, block_hash,
    /// block_trace)`.
    pub fn filter_block_traces(
        &self, filter: &TraceFilter,
        block_traces: Vec<(
            H256,
            H256,
            BlockExecTraces,
            Vec<Arc<SignedTransaction>>,
        )>,
    ) -> Result<Vec<LocalizedTrace>, FilterError> {
        let mut traces = Vec::new();
        for (pivot_hash, block_hash, block_trace, block_txs) in block_traces {
            if block_txs.len() != block_trace.0.len() {
                bail!(format!(
                    "tx list and trace length unmatch: block_hash={:?}",
                    block_hash
                ));
            }
            let epoch_number = self
                .data_man
                .block_height_by_hash(&pivot_hash)
                .ok_or_else(|| {
                    FilterError::Custom(
                        format!(
                            "pivot block header missing, hash={:?}",
                            pivot_hash
                        )
                        .into(),
                    )
                })?;
            let mut rpc_tx_index = 0;
            for (tx_pos, tx_trace) in block_trace.0.into_iter().enumerate() {
                if filter.space == Space::Native
                    && block_txs[tx_pos].space() == Space::Ethereum
                {
                    continue;
                }
                for trace in filter
                    .filter_traces(tx_trace)
                    .map_err(|e| FilterError::Custom(e))?
                {
                    if !filter
                        .action_types
                        .matches(&ActionType::from(&trace.action))
                    {
                        continue;
                    }
                    let trace = LocalizedTrace {
                        action: trace.action,
                        valid: trace.valid,
                        epoch_hash: pivot_hash,
                        epoch_number: epoch_number.into(),
                        block_hash,
                        transaction_position: rpc_tx_index.into(),
                        transaction_hash: block_txs[tx_pos].hash(),
                    };
                    traces.push(trace);
                }
                rpc_tx_index += 1;
            }
        }
        Ok(traces)
    }

    pub fn get_phantom_block_bloom_filter(
        &self, block_num: EpochNumber, pivot_assumption: H256,
    ) -> Result<Option<Bloom>, String> {
        let hashes = self.get_block_hashes_by_epoch(block_num)?;

        // sanity check: epoch is not empty
        let pivot = match hashes.last() {
            Some(p) => p,
            None => return Err("Inconsistent state: empty epoch".into()),
        };

        if *pivot != pivot_assumption {
            return Ok(None);
        }

        // special handling for genesis block
        let genesis_hash = self.get_data_manager().true_genesis.hash();

        if hashes.last() == Some(&genesis_hash) {
            return Ok(Some(Bloom::zero()));
        }

        let mut bloom = Bloom::zero();

        for h in &hashes {
            let exec_info = match self
                .get_data_manager()
                .block_execution_result_by_hash_with_epoch(
                    h, pivot, false, // update_pivot_assumption
                    false, // update_cache
                ) {
                None => return Ok(None),
                Some(r) => r,
            };

            for receipt in exec_info.block_receipts.receipts.iter() {
                if receipt.outcome_status == TransactionStatus::Skipped {
                    continue;
                }

                // FIXME(thegaram): receipt does not contain `space`
                // so we combine blooms log by log.
                for log in &receipt.logs {
                    if log.space == Space::Ethereum {
                        bloom.accrue_bloom(&log.bloom());
                    }
                }
            }
        }

        Ok(Some(bloom))
    }

    pub fn get_phantom_block_pivot_by_number(
        &self, block_num: EpochNumber, pivot_assumption: Option<H256>,
        include_traces: bool,
    ) -> Result<Option<PhantomBlock>, String> {
        self.get_phantom_block_by_number_inner(
            block_num,
            pivot_assumption,
            include_traces,
            true,
        )
    }

    pub fn get_phantom_block_by_number(
        &self, block_num: EpochNumber, pivot_assumption: Option<H256>,
        include_traces: bool,
    ) -> Result<Option<PhantomBlock>, String> {
        self.get_phantom_block_by_number_inner(
            block_num,
            pivot_assumption,
            include_traces,
            false,
        )
    }

    fn get_phantom_block_by_number_inner(
        &self, block_num: EpochNumber, pivot_assumption: Option<H256>,
        include_traces: bool, only_pivot: bool,
    ) -> Result<Option<PhantomBlock>, String> {
        let hashes = self.get_block_hashes_by_epoch(block_num)?;

        // special handling for genesis block
        let genesis = self.get_data_manager().true_genesis.clone();

        if hashes.last() == Some(&genesis.hash()) {
            return Ok(Some(PhantomBlock {
                pivot_header: genesis.block_header.clone(),
                transactions: vec![],
                receipts: vec![],
                errors: vec![],
                bloom: Bloom::zero(),
                traces: vec![],
                total_gas_limit: U256::from(0),
            }));
        }

        let blocks = match self
            .get_data_manager()
            .blocks_by_hash_list(&hashes, false /* update_cache */)
        {
            None => return Ok(None),
            Some(b) => b,
        };

        // sanity check: epoch is not empty
        let pivot = match blocks.last() {
            Some(p) => p,
            None => return Err("Inconsistent state: empty epoch".into()),
        };

        if matches!(pivot_assumption, Some(h) if h != pivot.hash()) {
            return Ok(None);
        }

        let mut phantom_block = PhantomBlock {
            pivot_header: pivot.block_header.clone(),
            transactions: vec![],
            receipts: vec![],
            errors: vec![],
            bloom: Default::default(),
            traces: vec![],
            total_gas_limit: U256::from(0),
        };

        let mut accumulated_gas_used = U256::from(0);
        let mut gas_used_offset;
        let mut total_gas_limit = U256::from(0);

        let iter_blocks = if only_pivot {
            &blocks[blocks.len() - 1..]
        } else {
            &blocks[..]
        };

        for b in iter_blocks {
            gas_used_offset = accumulated_gas_used;
            // note: we need the receipts to reconstruct a phantom block.
            // as a result, we cannot return unexecuted blocks in eth_* RPCs.
            let exec_info = match self
                .get_data_manager()
                .block_execution_result_by_hash_with_epoch(
                    &b.hash(),
                    &pivot.hash(),
                    false, // update_pivot_assumption
                    false, // update_cache
                ) {
                None => return Ok(None),
                Some(r) => r,
            };

            // note: we only include gas limit for blocks that will pack eSpace
            // tx(multiples of 5)
            total_gas_limit += b.block_header.espace_gas_limit(
                self.params
                    .can_pack_evm_transaction(b.block_header.height()),
            );

            let block_receipts = &exec_info.block_receipts.receipts;
            let errors = &exec_info.block_receipts.tx_execution_error_messages;

            let block_traces = if include_traces {
                match self
                    .get_data_manager()
                    .transactions_traces_by_block_hash(&b.hash())
                {
                    None => {
                        return Err("Error while creating phantom block: state is ready but traces not found, did you enable 'executive_trace'?".into());
                    }
                    Some((pivot_hash, block_traces)) => {
                        // sanity check: transaction and trace length
                        if b.transactions.len() != block_traces.len() {
                            return Err("Inconsistent state: transactions and traces length mismatch".into());
                        }

                        // sanity check: no pivot reorg during processing
                        if pivot_hash != pivot.hash() {
                            return Err(
                                "Inconsistent state: pivot hash mismatch"
                                    .into(),
                            );
                        }

                        block_traces
                    }
                }
            } else {
                vec![]
            };

            // sanity check: transaction and receipt length
            if b.transactions.len() != block_receipts.len() {
                return Err("Inconsistent state: transactions and receipts length mismatch".into());
            }

            let evm_chain_id = self.best_chain_id().in_evm_space();

            for (id, tx) in b.transactions.iter().enumerate() {
                match tx.space() {
                    Space::Ethereum => {
                        let receipt = &block_receipts[id];

                        // we do not return non-executed transaction
                        if receipt.outcome_status == TransactionStatus::Skipped
                        {
                            continue;
                        }

                        phantom_block.transactions.push(tx.clone());

                        // sanity check: gas price must be positive
                        if *tx.gas_price() == 0.into() {
                            return Err("Inconsistent state: zero transaction gas price".into());
                        }

                        accumulated_gas_used =
                            gas_used_offset + receipt.accumulated_gas_used;

                        phantom_block.receipts.push(Receipt {
                            accumulated_gas_used,
                            outcome_status: receipt.outcome_status,
                            ..receipt.clone()
                        });

                        phantom_block.errors.push(errors[id].clone());
                        phantom_block.bloom.accrue_bloom(&receipt.log_bloom);

                        if include_traces {
                            phantom_block.traces.push(block_traces[id].clone());
                        }
                    }
                    Space::Native => {
                        // note: failing transactions will not produce any
                        // phantom txs or traces
                        if block_receipts[id].outcome_status
                            != TransactionStatus::Success
                        {
                            continue;
                        }

                        let (phantom_txs, _) = build_bloom_and_recover_phantom(
                            &block_receipts[id].logs[..],
                            tx.hash(),
                        );

                        if include_traces {
                            let tx_traces = block_traces[id].clone();

                            let phantom_traces =
                                recover_phantom_traces(tx_traces, tx.hash())?;

                            // sanity check: one trace for each phantom tx
                            if phantom_txs.len() != phantom_traces.len() {
                                error!("Inconsistent state: phantom tx and trace length mismatch, txs.len = {:?}, traces.len = {:?}", phantom_txs.len(), phantom_traces.len());
                                return Err("Inconsistent state: phantom tx and trace length mismatch".into());
                            }

                            phantom_block.traces.extend(phantom_traces);
                        }

                        for p in phantom_txs {
                            phantom_block.transactions.push(Arc::new(
                                p.clone().into_eip155(evm_chain_id),
                            ));

                            // note: phantom txs consume no gas
                            let phantom_receipt =
                                p.into_receipt(accumulated_gas_used);

                            phantom_block
                                .bloom
                                .accrue_bloom(&phantom_receipt.log_bloom);

                            phantom_block.receipts.push(phantom_receipt);

                            // note: phantom txs never fail
                            phantom_block.errors.push("".into());
                        }
                    }
                }
            }
        }

        phantom_block.total_gas_limit = total_gas_limit;
        Ok(Some(phantom_block))
    }

    pub fn get_phantom_block_by_hash(
        &self, hash: &H256, include_traces: bool,
    ) -> Result<Option<PhantomBlock>, String> {
        let epoch_num = match self.get_block_epoch_number(hash) {
            None => return Ok(None),
            Some(n) => n,
        };

        self.get_phantom_block_by_number(
            EpochNumber::Number(epoch_num),
            Some(*hash),
            include_traces,
        )
    }

    fn get_state_db_by_epoch_number_with_space(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
        space: Option<Space>,
    ) -> CoreResult<StateDb> {
        invalid_params_check(
            rpc_param_name,
            self.validate_stated_epoch(&epoch_number),
        )?;
        let height = invalid_params_check(
            rpc_param_name,
            self.get_height_from_epoch_number(epoch_number),
        )?;
        let hash =
            self.inner.read().get_pivot_hash_from_epoch_number(height)?;
        Ok(StateDb::new(
            self.get_state_by_height_and_hash(height, &hash, space)?,
        ))
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

    /// construct_pivot_state() rebuild pivot chain state info from db
    /// avoiding intermediate redundant computation triggered by
    /// on_new_block().
    fn construct_pivot_state(&self) {
        let inner = &mut *self.inner.write();
        // Ensure that `state_valid` of the first valid block after
        // cur_era_stable_genesis is set
        inner.recover_state_valid();
        self.new_block_handler
            .construct_pivot_state(inner, &self.confirmation_meter);
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

    fn latest_finalized_epoch_number(&self) -> u64 {
        self.inner
            .read_recursive()
            .latest_epoch_confirmed_by_pos()
            .1
    }

    fn best_chain_id(&self) -> AllChainID {
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
            if let Some(executed) = &tx_info.maybe_executed_extra_info {
                if executed.receipt.outcome_status == TransactionStatus::Skipped
                {
                    // A skipped transaction is not visible to clients if
                    // accessed by its hash.
                    return None;
                }
            }
            let block = self.data_man.block_by_hash(
                &tx_info.tx_index.block_hash,
                false, /* update_cache */
            )?;
            let transaction =
                (*block.transactions[tx_info.tx_index.real_index]).clone();
            Some((transaction, tx_info))
        } else {
            None
        }
    }

    fn get_block_number(
        &self, block_hash: &H256,
    ) -> Result<Option<u64>, String> {
        let inner = self.inner.read_recursive();

        let epoch_number = match inner
            .get_block_epoch_number(block_hash)
            .or_else(|| self.data_man.block_epoch_number(&block_hash))
        {
            None => return Ok(None),
            Some(epoch_number) => epoch_number,
        };

        let blocks = match self
            .get_block_hashes_by_epoch(EpochNumber::Number(epoch_number))
            .ok()
            .or_else(|| {
                self.data_man
                    .executed_epoch_set_hashes_from_db(epoch_number)
            }) {
            None => return Ok(None),
            Some(hashes) => hashes,
        };

        let epoch_hash = blocks.last().expect("Epoch not empty");

        let start_block_number =
            match self.data_man.get_epoch_execution_context(&epoch_hash) {
                None => return Ok(None),
                Some(ctx) => ctx.start_block_number,
            };

        let index_of_block = match blocks.iter().position(|x| x == block_hash) {
            None => return Ok(None),
            Some(index) => index as u64,
        };

        return Ok(Some(compute_block_number(
            start_block_number,
            index_of_block,
        )));
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

    fn get_storage_state_by_epoch_number(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
    ) -> CoreResult<StorageState> {
        invalid_params_check(
            rpc_param_name,
            self.validate_stated_epoch(&epoch_number),
        )?;
        let height = invalid_params_check(
            rpc_param_name,
            self.get_height_from_epoch_number(epoch_number),
        )?;
        let hash =
            self.inner.read().get_pivot_hash_from_epoch_number(height)?;
        self.get_storage_state_by_height_and_hash(height, &hash)
    }

    fn get_state_db_by_epoch_number(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
    ) -> CoreResult<StateDb> {
        self.get_state_db_by_epoch_number_with_space(
            epoch_number,
            rpc_param_name,
            None,
        )
    }

    fn get_eth_state_db_by_epoch_number(
        &self, epoch_number: EpochNumber, rpc_param_name: &str,
    ) -> CoreResult<StateDb> {
        self.get_state_db_by_epoch_number_with_space(
            epoch_number,
            rpc_param_name,
            Some(Space::Ethereum),
        )
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

        if self.best_epoch_number() < stable_genesis_height {
            // For an archive node, if its terminals are overwritten with
            // earlier blocks during recovery, it's possible to
            // reach here with a pivot chain before stable era
            // checkpoint. Here we wait for it to recover the missing headers
            // after the overwritten terminals.
            return false;
        }
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
        self.txpool.set_ready();
        self.txpool
            .notify_new_best_info(self.best_info.read_recursive().clone())
            .expect("No DB error")
    }

    /// Reset the information in consensus graph with only checkpoint
    /// information kept.
    fn reset(&self) {
        let old_consensus_inner = &mut *self.inner.write();

        let cur_era_genesis_hash =
            self.data_man.get_cur_consensus_era_genesis_hash();
        let cur_era_stable_hash =
            self.data_man.get_cur_consensus_era_stable_hash();
        let new_consensus_inner = ConsensusGraphInner::with_era_genesis(
            old_consensus_inner.pow_config.clone(),
            old_consensus_inner.pow.clone(),
            old_consensus_inner.pos_verifier.clone(),
            self.data_man.clone(),
            old_consensus_inner.inner_conf.clone(),
            &cur_era_genesis_hash,
            &cur_era_stable_hash,
        );
        *old_consensus_inner = new_consensus_inner;
        debug!("Build new consensus graph for sync-recovery with identified genesis {} stable block {}", cur_era_genesis_hash, cur_era_stable_hash);

        self.confirmation_meter.clear();
    }

    fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        // try to get from memory
        if let Some(e) =
            self.inner.read_recursive().get_block_epoch_number(hash)
        {
            return Some(e);
        }

        // try to get from db
        self.data_man.block_epoch_number(hash)
    }

    fn get_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String> {
        self.get_height_from_epoch_number(epoch_number)
            .and_then(|height| {
                self.inner.read_recursive().block_hashes_by_epoch(height)
            })
    }

    fn to_arc_consensus(self: Arc<Self>) -> Arc<ConsensusGraph> { self }
}
