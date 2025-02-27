// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod epoch_execution;

use core::convert::TryFrom;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    convert::From,
    fmt::{Debug, Formatter},
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        mpsc::{channel, RecvError, Sender, TryRecvError},
        Arc,
    },
    thread::{self, JoinHandle},
};

use crate::hash::KECCAK_EMPTY_LIST_RLP;
use parking_lot::{Mutex, RwLock};
use rayon::{ThreadPool, ThreadPoolBuilder};
use rustc_hex::ToHex;

use cfx_internal_common::{
    debug::*, EpochExecutionCommitment, StateRootWithAuxInfo,
};
use cfx_parameters::consensus::*;
use cfx_statedb::{Result as DbResult, StateDb};
use cfx_storage::{
    defaults::DEFAULT_EXECUTION_PREFETCH_THREADS, StateIndex,
    StorageManagerTrait,
};
use cfx_types::{
    address_util::AddressUtil, AddressSpaceUtil, AllChainID, BigEndianHash,
    Space, H160, H256, KECCAK_EMPTY_BLOOM, U256, U512,
};
use metrics::{register_meter_with_group, Meter, MeterTimer};
use primitives::{
    compute_block_number, receipt::BlockReceipts, Block, BlockHeader,
    BlockHeaderBuilder, SignedTransaction, MERKLE_NULL_NODE,
};

use crate::{
    block_data_manager::{BlockDataManager, BlockRewardResult, PosRewardInfo},
    consensus::{
        consensus_inner::{
            consensus_new_block_handler::ConsensusNewBlockHandler,
            StateBlameInfo,
        },
        pos_handler::PosVerifier,
        ConsensusGraphInner,
    },
    errors::{invalid_params_check, Result as CoreResult},
    verification::{
        compute_receipts_root, VerificationConfig, VerifyTxLocalMode,
        VerifyTxMode,
    },
    SharedTransactionPool,
};
use cfx_execute_helper::estimation::{
    EstimateExt, EstimateRequest, EstimationContext,
};
use cfx_executor::{
    executive::{ExecutionOutcome, ExecutiveContext},
    machine::Machine,
    state::{
        distribute_pos_interest, update_pos_status, CleanupMode, State,
        StateCommitResult,
    },
};
use cfx_vm_types::{Env, Spec};
use geth_tracer::GethTraceWithHash;

use alloy_rpc_types_trace::geth::GethDebugTracingOptions;
use cfx_rpc_eth_types::EvmOverrides;

use self::epoch_execution::{GethTask, VirtualCall};

lazy_static! {
    static ref CONSENSIS_EXECUTION_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "consensus::handle_epoch_execution");
    static ref CONSENSIS_COMPUTE_STATE_FOR_BLOCK_TIMER: Arc<dyn Meter> =
        register_meter_with_group(
            "timer",
            "consensus::compute_state_for_block"
        );
    static ref GOOD_TPS_METER: Arc<dyn Meter> =
        register_meter_with_group("system_metrics", "good_tps");
}

/// The RewardExecutionInfo struct includes most information to compute rewards
/// for old epochs
pub struct RewardExecutionInfo {
    pub past_block_count: u64,
    pub epoch_blocks: Vec<Arc<Block>>,
    pub epoch_block_no_reward: Vec<bool>,
    pub epoch_block_anticone_difficulties: Vec<U512>,
}

impl Debug for RewardExecutionInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "RewardExecutionInfo{{ past_block_count: {} \
             epoch_blocks: {:?} \
             epoch_block_no_reward: {:?} \
             epoch_block_anticone_difficulties: {:?}}}",
            self.past_block_count,
            self.epoch_blocks
                .iter()
                .map(|b| b.hash())
                .collect::<Vec<H256>>(),
            self.epoch_block_no_reward,
            self.epoch_block_anticone_difficulties
        )
    }
}

#[derive(Debug)]
enum ExecutionTask {
    ExecuteEpoch(EpochExecutionTask),
    GetResult(GetExecutionResultTask),

    /// Stop task is used to stop the execution thread
    Stop,
}

/// The EpochExecutionTask struct includes all the information needed to execute
/// an epoch
#[derive(Debug)]
pub struct EpochExecutionTask {
    epoch_hash: H256,
    epoch_block_hashes: Vec<H256>,
    start_block_number: u64,
    reward_info: Option<RewardExecutionInfo>,
    // TODO:
    //  on_local_pivot should be computed at the beginning of the
    //  epoch execution, not to be set from task.
    on_local_pivot: bool,
    force_recompute: bool,
}

impl EpochExecutionTask {
    pub fn new(
        epoch_arena_index: usize, inner: &ConsensusGraphInner,
        reward_execution_info: Option<RewardExecutionInfo>,
        on_local_pivot: bool, force_recompute: bool,
    ) -> Self {
        Self {
            epoch_hash: inner.arena[epoch_arena_index].hash,
            epoch_block_hashes: inner.get_epoch_block_hashes(epoch_arena_index),
            start_block_number: inner
                .get_epoch_start_block_number(epoch_arena_index),
            reward_info: reward_execution_info,
            on_local_pivot,
            force_recompute,
        }
    }
}

/// `sender` is used to return the computed `(state_root, receipts_root,
/// logs_bloom_hash)` to the thread who sends this task.
#[derive(Debug)]
struct GetExecutionResultTask {
    pub epoch_hash: H256,
    pub sender: Sender<Option<EpochExecutionCommitment>>,
}

/// ConsensusExecutor processes transaction execution tasks.
pub struct ConsensusExecutor {
    /// The thread responsible for execution transactions
    thread: Mutex<Option<JoinHandle<()>>>,

    /// The sender to send tasks to be executed by `self.thread`
    sender: Mutex<Sender<ExecutionTask>>,

    /// The state indicating whether the thread should be stopped
    stopped: AtomicBool,

    /// The handler to provide functions to handle `ExecutionTask` and execute
    /// transactions It is used both asynchronously by `self.thread` and
    /// synchronously by the executor itself
    pub handler: Arc<ConsensusExecutionHandler>,

    consensus_graph_bench_mode: bool,
}

impl ConsensusExecutor {
    pub fn start(
        tx_pool: SharedTransactionPool, data_man: Arc<BlockDataManager>,
        consensus_inner: Arc<RwLock<ConsensusGraphInner>>,
        config: ConsensusExecutionConfiguration,
        verification_config: VerificationConfig, bench_mode: bool,
        pos_verifier: Arc<PosVerifier>,
    ) -> Arc<Self> {
        let machine = tx_pool.machine();
        let handler = Arc::new(ConsensusExecutionHandler::new(
            tx_pool,
            data_man.clone(),
            config,
            verification_config,
            machine,
            pos_verifier,
        ));
        let (sender, receiver) = channel();

        let executor_raw = ConsensusExecutor {
            thread: Mutex::new(None),
            sender: Mutex::new(sender),
            stopped: AtomicBool::new(false),
            handler: handler.clone(),
            consensus_graph_bench_mode: bench_mode,
        };
        let executor = Arc::new(executor_raw);
        let executor_thread = executor.clone();
        // It receives blocks hashes from on_new_block and execute them
        let handle = thread::Builder::new()
            .name("Consensus Execution Worker".into())
            .spawn(move || loop {
                if executor_thread.stopped.load(Relaxed) {
                    // The thread should be stopped. The rest tasks in the queue
                    // will be discarded.
                    break;
                }

                let get_optimistic_task = || {
                    let mut inner = consensus_inner.try_write()?;

                    let task = executor_thread
                        .get_optimistic_execution_task(&mut *inner)?;

                    debug!("Get optimistic_execution_task {:?}", task);
                    Some(ExecutionTask::ExecuteEpoch(task))
                };

                let maybe_task = {
                    // Here we use `try_write` because some thread
                    // may wait for execution results while holding the
                    // Consensus Inner lock, if we wait on
                    // inner lock here we may get deadlock.
                    match receiver.try_recv() {
                        Ok(task) => Some(task),
                        Err(TryRecvError::Empty) => {
                            // The channel is empty, so we try to optimistically
                            // get later epochs to execute.
                            get_optimistic_task()
                        }
                        Err(TryRecvError::Disconnected) => {
                            info!("Channel disconnected, stop thread");
                            break;
                        }
                    }
                };
                let task = match maybe_task {
                    Some(task) => task,
                    None => {
                        //  Even optimistic tasks are all finished, so we block
                        // and wait for  new execution
                        // tasks.  New optimistic tasks
                        // will only exist if pivot_chain changes,
                        //  and new tasks will be sent to `receiver` in this
                        // case, so this waiting will
                        // not prevent new optimistic tasks from being executed.
                        match receiver.recv() {
                            Ok(task) => task,
                            Err(RecvError) => {
                                info!("Channel receive error, stop thread");
                                break;
                            }
                        }
                    }
                };
                if !handler.handle_execution_work(task) {
                    // `task` is `Stop`, so just stop.
                    break;
                }
            })
            .expect("Cannot fail");
        *executor.thread.lock() = Some(handle);
        executor
    }

    // TODO: The comments and method name are not precise,
    // TODO: given the single-threaded design.
    /// Wait until all tasks currently in the queue to be executed and return
    /// `(state_root, receipts_root, logs_bloom_hash)` of the given
    /// `epoch_hash`.
    ///
    /// It is the caller's responsibility to ensure that `epoch_hash` is indeed
    /// computed when all the tasks before are finished.
    // TODO Release Consensus inner lock if possible when the function is called
    pub fn wait_for_result(
        &self, epoch_hash: H256,
    ) -> Result<EpochExecutionCommitment, String> {
        // In consensus_graph_bench_mode execution is skipped.
        if self.consensus_graph_bench_mode {
            Ok(EpochExecutionCommitment {
                state_root_with_aux_info: StateRootWithAuxInfo::genesis(
                    &MERKLE_NULL_NODE,
                ),
                receipts_root: KECCAK_EMPTY_LIST_RLP,
                logs_bloom_hash: KECCAK_EMPTY_BLOOM,
            })
        } else {
            if self.handler.data_man.epoch_executed(&epoch_hash) {
                // The epoch already executed, so we do not need wait for the
                // queue to be empty
                return self
                    .handler
                    .get_execution_result(&epoch_hash).ok_or("Cannot get expected execution results from the data base. Probably the database is corrupted!".to_string());
            }
            let (sender, receiver) = channel();
            debug!("Wait for execution result of epoch {:?}", epoch_hash);
            self.sender
                .lock()
                .send(ExecutionTask::GetResult(GetExecutionResultTask {
                    epoch_hash,
                    sender,
                }))
                .expect("Cannot fail");
            receiver.recv().map_err(|e| e.to_string())?.ok_or(
                "Waiting for an execution result that is not enqueued!"
                    .to_string(),
            )
        }
    }

    fn get_optimistic_execution_task(
        &self, inner: &mut ConsensusGraphInner,
    ) -> Option<EpochExecutionTask> {
        if !inner.inner_conf.enable_optimistic_execution {
            return None;
        }

        let epoch_arena_index = {
            let mut state_availability_boundary =
                inner.data_man.state_availability_boundary.write();
            let opt_height =
                state_availability_boundary.optimistic_executed_height?;
            if opt_height != state_availability_boundary.upper_bound + 1 {
                // The `opt_height` parent's state has not been executed.
                // This may happen when the pivot chain switches between
                // the checks of the execution queue and the opt task.
                return None;
            }
            let next_opt_height = opt_height + 1;
            if next_opt_height
                >= inner.pivot_index_to_height(inner.pivot_chain.len())
            {
                state_availability_boundary.optimistic_executed_height = None;
            } else {
                state_availability_boundary.optimistic_executed_height =
                    Some(next_opt_height);
            }
            inner.get_pivot_block_arena_index(opt_height)
        };

        // `on_local_pivot` is set to `true` because when we later skip its
        // execution on pivot chain, we will not notify tx pool, so we
        // will also notify in advance.
        let reward_execution_info =
            self.get_reward_execution_info(inner, epoch_arena_index);
        let execution_task = EpochExecutionTask::new(
            epoch_arena_index,
            inner,
            reward_execution_info,
            true,  /* on_local_pivot */
            false, /* force_compute */
        );
        Some(execution_task)
    }

    pub fn get_reward_execution_info_from_index(
        &self, inner: &mut ConsensusGraphInner,
        reward_index: Option<(usize, usize)>,
    ) -> Option<RewardExecutionInfo> {
        reward_index.map(
            |(pivot_arena_index, anticone_penalty_cutoff_epoch_arena_index)| {
                // We have to wait here because blame information will determine the reward of each block.
                // In order to compute the correct blame information locally, we have to wait for the execution to return.
                let height = inner.arena[pivot_arena_index].height;
                if !self.consensus_graph_bench_mode
                {
                    debug!(
                        "wait_and_compute_state_valid_locked, idx = {}, \
                         height = {}, era_genesis_height = {} era_stable_height = {}",
                        pivot_arena_index, height, inner.cur_era_genesis_height, inner.cur_era_stable_height
                    );
                    self.wait_and_compute_state_valid_and_blame_info_locked(
                        pivot_arena_index,
                        inner,
                    )
                        .unwrap();
                }

                let epoch_blocks =
                    inner.get_executable_epoch_blocks(pivot_arena_index);

                let mut epoch_block_no_reward =
                    Vec::with_capacity(epoch_blocks.len());
                let mut epoch_block_anticone_difficulties =
                    Vec::with_capacity(epoch_blocks.len());

                let epoch_difficulty =
                    inner.arena[pivot_arena_index].difficulty;
                let anticone_cutoff_epoch_anticone_set_ref_opt = inner
                    .anticone_cache
                    .get(anticone_penalty_cutoff_epoch_arena_index);
                let anticone_cutoff_epoch_anticone_set;
                if let Some(r) = anticone_cutoff_epoch_anticone_set_ref_opt {
                    anticone_cutoff_epoch_anticone_set = r.clone();
                } else {
                    anticone_cutoff_epoch_anticone_set = ConsensusNewBlockHandler::compute_anticone_hashset_bruteforce(inner, anticone_penalty_cutoff_epoch_arena_index);
                }
                let ordered_epoch_blocks = inner.get_ordered_executable_epoch_blocks(pivot_arena_index).clone();
                for index in ordered_epoch_blocks.iter() {
                    let block_consensus_node = &inner.arena[*index];

                    let mut no_reward =
                        block_consensus_node.data.partial_invalid;
                    if !self.consensus_graph_bench_mode && !no_reward {
                        if *index == pivot_arena_index {
                            no_reward = !inner.arena[pivot_arena_index]
                                .data
                                .state_valid.expect("computed in wait_and_compute_state_valid_locked");
                        } else {
                            no_reward = !inner
                                .compute_vote_valid_for_pivot_block(
                                    *index,
                                    pivot_arena_index,
                                );
                        }
                    }
                    // If a block is partial_invalid, it won't have reward and
                    // anticone_difficulty will not be used, so it's okay to set
                    // it to 0.
                    let mut anticone_difficulty: U512 = 0.into();
                    if !no_reward {
                        let block_consensus_node_anticone_opt =
                            inner.anticone_cache.get(*index);
                        let block_consensus_node_anticone = if let Some(r) = block_consensus_node_anticone_opt {
                            r.clone()
                        } else {
                            ConsensusNewBlockHandler::compute_anticone_hashset_bruteforce(inner, *index)
                        };

                        for idx in block_consensus_node_anticone {
                            if inner.is_same_era(idx, pivot_arena_index) && !anticone_cutoff_epoch_anticone_set.contains(&idx) {
                                anticone_difficulty +=
                                    U512::from(U256::from(inner.block_weight(
                                        idx
                                    )));
                            }
                        }

                        // TODO: check the clear definition of anticone penalty,
                        // normally and around the time of difficulty
                        // adjustment.
                        // LINT.IfChange(ANTICONE_PENALTY_1)
                        if anticone_difficulty / U512::from(epoch_difficulty)
                            >= U512::from(self.handler.machine.params().anticone_penalty_ratio)
                        {
                            no_reward = true;
                        }
                        // LINT.ThenChange(consensus/consensus_executor.
                        // rs#ANTICONE_PENALTY_2)
                    }
                    epoch_block_no_reward.push(no_reward);
                    epoch_block_anticone_difficulties.push(anticone_difficulty);
                }
                RewardExecutionInfo {
                    past_block_count: inner.arena[pivot_arena_index].past_num_blocks,
                    epoch_blocks,
                    epoch_block_no_reward,
                    epoch_block_anticone_difficulties,
                }
            },
        )
    }

    pub fn get_reward_execution_info(
        &self, inner: &mut ConsensusGraphInner, epoch_arena_index: usize,
    ) -> Option<RewardExecutionInfo> {
        self.get_reward_execution_info_from_index(
            inner,
            inner.get_pivot_reward_index(epoch_arena_index),
        )
    }

    /// Wait for the deferred state to be executed and compute `state_valid` and
    /// `blame_info` for `me`.
    fn wait_and_compute_state_valid_and_blame_info(
        &self, me: usize, inner_lock: &RwLock<ConsensusGraphInner>,
    ) -> Result<(), String> {
        // TODO:
        //  can we only wait for the deferred block?
        //  waiting for its parent seems redundant.
        // We go up from deferred state block of `me`
        // and find all states whose commitments are missing
        let waiting_blocks = inner_lock
            .read()
            .collect_defer_blocks_missing_execution_commitments(me)?;
        // Now we wait without holding the inner lock
        // Note that we must use hash instead of index because once we release
        // the lock, there might be a checkpoint coming in to break
        // index
        for state_block_hash in waiting_blocks {
            self.wait_for_result(state_block_hash)?;
        }
        // Now we need to wait for the execution information of all missing
        // blocks to come back
        // TODO: can we merge the state valid computation into the consensus
        // executor?
        inner_lock
            .write()
            .compute_state_valid_and_blame_info(me, self)?;
        Ok(())
    }

    fn wait_and_compute_state_valid_and_blame_info_locked(
        &self, me: usize, inner: &mut ConsensusGraphInner,
    ) -> Result<(), String> {
        // TODO:
        //  can we only wait for the deferred block?
        //  waiting for its parent seems redundant.
        // We go up from deferred state block of `me`
        // and find all states whose commitments are missing
        let waiting_blocks =
            inner.collect_defer_blocks_missing_execution_commitments(me)?;
        trace!(
            "wait_and_compute_state_valid_locked: waiting_blocks={:?}",
            waiting_blocks
        );
        // for this rare case, we should make wait_for_result to pop up errors!
        for state_block_hash in waiting_blocks {
            self.wait_for_result(state_block_hash)?;
        }
        // Now we need to wait for the execution information of all missing
        // blocks to come back
        // TODO: can we merge the state valid computation into the consensus
        // executor?
        inner.compute_state_valid_and_blame_info(me, self)?;
        Ok(())
    }

    pub fn get_blame_and_deferred_state_for_generation(
        &self, parent_block_hash: &H256,
        inner_lock: &RwLock<ConsensusGraphInner>,
    ) -> Result<StateBlameInfo, String> {
        let (parent_arena_index, last_state_block) = {
            let inner = inner_lock.read();
            let parent_opt = inner.hash_to_arena_indices.get(parent_block_hash);
            if parent_opt.is_none() {
                return Err(format!(
                    "Too old parent for generation, parent_hash={:?}",
                    parent_block_hash
                ));
            }
            (
                *parent_opt.unwrap(),
                inner
                    .get_state_block_with_delay(
                        parent_block_hash,
                        DEFERRED_STATE_EPOCH_COUNT as usize - 1,
                    )?
                    .clone(),
            )
        };
        let last_result = self.wait_for_result(last_state_block)?;
        self.wait_and_compute_state_valid_and_blame_info(
            parent_arena_index,
            inner_lock,
        )?;
        {
            let inner = &mut *inner_lock.write();
            if inner.arena[parent_arena_index].hash == *parent_block_hash {
                Ok(inner.compute_blame_and_state_with_execution_result(
                    parent_arena_index,
                    last_result
                        .state_root_with_aux_info
                        .aux_info
                        .state_root_hash,
                    last_result.receipts_root,
                    last_result.logs_bloom_hash,
                )?)
            } else {
                Err("Too old parent/subtree to prepare for generation"
                    .to_owned())
            }
        }
    }

    /// Enqueue the epoch to be executed by the background execution thread
    /// The parameters are needed for the thread to execute this epoch without
    /// holding inner lock.
    pub fn enqueue_epoch(&self, task: EpochExecutionTask) -> bool {
        if !self.consensus_graph_bench_mode {
            self.sender
                .lock()
                .send(ExecutionTask::ExecuteEpoch(task))
                .is_ok()
        } else {
            true
        }
    }

    /// Execute the epoch synchronously
    pub fn compute_epoch(
        &self, task: EpochExecutionTask,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
        recover_mpt_during_construct_pivot_state: bool,
    ) {
        if self.consensus_graph_bench_mode {
            return;
        }
        self.handler.handle_epoch_execution(
            task,
            debug_record,
            recover_mpt_during_construct_pivot_state,
        )
    }

    pub fn epoch_executed_and_recovered(
        &self, epoch_hash: &H256, epoch_block_hashes: &Vec<H256>,
        on_local_pivot: bool,
        reward_execution_info: &Option<RewardExecutionInfo>, epoch_height: u64,
    ) -> bool {
        self.handler.epoch_executed_and_recovered(
            epoch_hash,
            epoch_block_hashes,
            on_local_pivot,
            reward_execution_info,
            epoch_height,
        )
    }

    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch_id: &H256, epoch_size: usize,
        request: EstimateRequest, evm_overrides: EvmOverrides,
    ) -> CoreResult<(ExecutionOutcome, EstimateExt)> {
        self.handler.call_virtual(
            tx,
            epoch_id,
            epoch_size,
            request,
            evm_overrides,
        )
    }

    pub fn collect_blocks_geth_trace(
        &self, epoch_id: H256, epoch_num: u64, blocks: &Vec<Arc<Block>>,
        opts: GethDebugTracingOptions, tx_hash: Option<H256>,
    ) -> CoreResult<Vec<GethTraceWithHash>> {
        self.handler.collect_blocks_geth_trace(
            epoch_id, epoch_num, blocks, opts, tx_hash,
        )
    }

    pub fn stop(&self) {
        // `stopped` is used to allow the execution thread to stopped even the
        // queue is not empty and `ExecutionTask::Stop` has not been
        // processed.
        self.stopped.store(true, Relaxed);

        // We still need this task because otherwise if the execution queue is
        // empty the execution thread will block on `recv` forever and
        // unable to check `stopped`
        self.sender
            .lock()
            .send(ExecutionTask::Stop)
            .expect("execution receiver exists");
        if let Some(thread) = self.thread.lock().take() {
            thread.join().ok();
        }
    }

    /// Binary search to find the starting point so we can execute to the end of
    /// the chain.
    /// Return the first index that is not executed,
    /// or return `chain.len()` if they are all executed (impossible for now).
    ///
    /// NOTE: If a state for an block exists, all the blocks on its pivot chain
    /// must have been executed and state committed. The receipts for these
    /// past blocks may not exist because the receipts on forks will be
    /// garbage-collected, but when we need them, we will recompute these
    /// missing receipts in `process_rewards_and_fees`. This 'recompute' is safe
    /// because the parent state exists. Thus, it's okay that here we do not
    /// check existence of the receipts that will be needed for reward
    /// computation during epoch execution.
    fn find_start_chain_index(
        inner: &ConsensusGraphInner, chain: &Vec<usize>,
    ) -> usize {
        let mut base = 0;
        let mut size = chain.len();
        while size > 1 {
            let half = size / 2;
            let mid = base + half;
            let epoch_hash = inner.arena[chain[mid]].hash;
            base = if inner.data_man.epoch_executed(&epoch_hash) {
                mid
            } else {
                base
            };
            size -= half;
        }
        let epoch_hash = inner.arena[chain[base]].hash;
        if inner.data_man.epoch_executed(&epoch_hash) {
            base + 1
        } else {
            base
        }
    }

    // TODO:
    //  this method contains bugs but it's not a big problem since
    //  it's test-rpc only.
    /// This is a blocking call to force the execution engine to compute the
    /// state of a block immediately
    pub fn compute_state_for_block(
        &self, block_hash: &H256, inner: &mut ConsensusGraphInner,
    ) -> Result<(), String> {
        let _timer = MeterTimer::time_func(
            CONSENSIS_COMPUTE_STATE_FOR_BLOCK_TIMER.as_ref(),
        );
        // If we already computed the state of the block before, we should not
        // do it again
        debug!("compute_state_for_block {:?}", block_hash);
        {
            let maybe_state_index =
                self.handler.data_man.get_state_readonly_index(&block_hash);
            // The state is computed and is retrievable from storage.
            if let Some(maybe_cached_state_result) =
                maybe_state_index.map(|state_readonly_index| {
                    self.handler.data_man.storage_manager.get_state_no_commit(
                        state_readonly_index,
                        /* try_open = */ false,
                        None,
                    )
                })
            {
                if let Ok(Some(_)) = maybe_cached_state_result {
                    return Ok(());
                } else {
                    return Err("Internal storage error".to_owned());
                }
            }
        }
        let me_opt = inner.hash_to_arena_indices.get(block_hash);
        if me_opt == None {
            return Err("Block hash not found!".to_owned());
        }
        // FIXME: isolate this part as a method.
        let me: usize = *me_opt.unwrap();
        let block_height = inner.arena[me].height;
        let mut fork_height = block_height;
        let mut chain: Vec<usize> = Vec::new();
        let mut idx = me;
        // FIXME: this is wrong, however.
        while fork_height > 0
            && (fork_height >= inner.get_pivot_height()
                || inner.get_pivot_block_arena_index(fork_height) != idx)
        {
            chain.push(idx);
            fork_height -= 1;
            idx = inner.arena[idx].parent;
        }
        // FIXME: this is wrong, however.
        // Because we have genesis at height 0, this should always be true
        debug_assert!(inner.get_pivot_block_arena_index(fork_height) == idx);
        debug!("Forked at index {} height {}", idx, fork_height);
        chain.push(idx);
        chain.reverse();
        let start_chain_index =
            ConsensusExecutor::find_start_chain_index(inner, &chain);
        debug!("Start execution from index {}", start_chain_index);

        // We need the state of the fork point to start executing the fork
        if start_chain_index == 0 {
            let mut last_state_height =
                if inner.get_pivot_height() > DEFERRED_STATE_EPOCH_COUNT {
                    inner.get_pivot_height() - DEFERRED_STATE_EPOCH_COUNT
                } else {
                    0
                };

            last_state_height += 1;
            while last_state_height < fork_height {
                let epoch_arena_index =
                    inner.get_pivot_block_arena_index(last_state_height);
                let reward_execution_info =
                    self.get_reward_execution_info(inner, epoch_arena_index);
                self.enqueue_epoch(EpochExecutionTask::new(
                    epoch_arena_index,
                    inner,
                    reward_execution_info,
                    false, /* on_local_pivot */
                    false, /* force_recompute */
                ));
                last_state_height += 1;
            }
        }

        for fork_chain_index in start_chain_index..chain.len() {
            let epoch_arena_index = chain[fork_chain_index];
            let reward_index = inner.get_pivot_reward_index(epoch_arena_index);

            let reward_execution_info =
                self.get_reward_execution_info_from_index(inner, reward_index);
            self.enqueue_epoch(EpochExecutionTask::new(
                epoch_arena_index,
                inner,
                reward_execution_info,
                false, /* on_local_pivot */
                false, /* force_recompute */
            ));
        }

        let epoch_execution_result = self.wait_for_result(*block_hash)?;
        debug!(
            "Epoch {:?} has state_root={:?} receipts_root={:?} logs_bloom_hash={:?}",
            inner.arena[me].hash, epoch_execution_result.state_root_with_aux_info,
            epoch_execution_result.receipts_root, epoch_execution_result.logs_bloom_hash
        );

        Ok(())
    }
}

pub struct ConsensusExecutionHandler {
    tx_pool: SharedTransactionPool,
    data_man: Arc<BlockDataManager>,
    config: ConsensusExecutionConfiguration,
    verification_config: VerificationConfig,
    machine: Arc<Machine>,
    pos_verifier: Arc<PosVerifier>,
    execution_state_prefetcher: Option<ThreadPool>,
}

impl ConsensusExecutionHandler {
    pub fn new(
        tx_pool: SharedTransactionPool, data_man: Arc<BlockDataManager>,
        config: ConsensusExecutionConfiguration,
        verification_config: VerificationConfig, machine: Arc<Machine>,
        pos_verifier: Arc<PosVerifier>,
    ) -> Self {
        ConsensusExecutionHandler {
            tx_pool,
            data_man,
            config,
            verification_config,
            machine,
            pos_verifier,
            execution_state_prefetcher: if DEFAULT_EXECUTION_PREFETCH_THREADS
                > 0
            {
                Some(
                    ThreadPoolBuilder::new()
                        .num_threads(DEFAULT_EXECUTION_PREFETCH_THREADS)
                        .build()
                        .unwrap(),
                )
            } else {
                None
            },
        }
    }

    /// Always return `true` for now
    fn handle_execution_work(&self, task: ExecutionTask) -> bool {
        debug!("Receive execution task: {:?}", task);
        match task {
            ExecutionTask::ExecuteEpoch(task) => {
                self.handle_epoch_execution(task, None, false)
            }
            ExecutionTask::GetResult(task) => self.handle_get_result_task(task),
            ExecutionTask::Stop => return false,
        }
        true
    }

    fn handle_epoch_execution(
        &self, task: EpochExecutionTask,
        debug_record: Option<&mut ComputeEpochDebugRecord>,
        recover_mpt_during_construct_pivot_state: bool,
    ) {
        let _timer = MeterTimer::time_func(CONSENSIS_EXECUTION_TIMER.as_ref());
        self.compute_epoch(
            &task.epoch_hash,
            &task.epoch_block_hashes,
            task.start_block_number,
            &task.reward_info,
            task.on_local_pivot,
            debug_record,
            task.force_recompute,
            recover_mpt_during_construct_pivot_state,
        );
    }

    fn handle_get_result_task(&self, task: GetExecutionResultTask) {
        task.sender
            .send(self.get_execution_result(&task.epoch_hash))
            .expect("Consensus Worker fails");
    }

    /// Get `EpochExecutionCommitment` for an executed epoch.
    ///
    /// Return `None` if the commitment does not exist in memory or db.
    /// For archive node, this should only happen when `epoch_hash` is not
    /// executed.
    fn get_execution_result(
        &self, epoch_hash: &H256,
    ) -> Option<EpochExecutionCommitment> {
        self.data_man
            .get_epoch_execution_commitment_with_db(epoch_hash)
    }

    fn new_state(
        &self, pivot_block: &Block,
        recover_mpt_during_construct_pivot_state: bool,
    ) -> DbResult<State> {
        let state_root_with_aux_info = &self
            .data_man
            .get_epoch_execution_commitment(
                pivot_block.block_header.parent_hash(),
            )
            // Unwrapping is safe because the state exists.
            .unwrap()
            .state_root_with_aux_info;

        let state_index = StateIndex::new_for_next_epoch(
            pivot_block.block_header.parent_hash(),
            &state_root_with_aux_info,
            pivot_block.block_header.height() - 1,
            self.data_man.get_snapshot_epoch_count(),
        );

        let storage = self
            .data_man
            .storage_manager
            .get_state_for_next_epoch(
                state_index,
                recover_mpt_during_construct_pivot_state,
            )
            .expect("No db error")
            // Unwrapping is safe because the state exists.
            .expect("State exists");

        let state_db = StateDb::new(storage);
        State::new(state_db)
    }

    pub fn epoch_executed_and_recovered(
        &self, epoch_hash: &H256, epoch_block_hashes: &Vec<H256>,
        on_local_pivot: bool,
        reward_execution_info: &Option<RewardExecutionInfo>, epoch_height: u64,
    ) -> bool {
        // note: the lock on chain_id is never held so this should be OK.
        let evm_chain_id = self
            .machine
            .params()
            .chain_id
            .read()
            .get_chain_id(epoch_height)
            .in_evm_space();

        self.data_man.epoch_executed_and_recovered(
            &epoch_hash,
            &epoch_block_hashes,
            on_local_pivot,
            self.config.executive_trace,
            reward_execution_info,
            self.pos_verifier.as_ref(),
            evm_chain_id,
        )
    }

    /// Compute the epoch `epoch_hash`, and skip it if already computed.
    /// After the function is called, it's assured that the state, the receipt
    /// root, and the receipts of blocks executed by this epoch exist.
    ///
    /// TODO Not sure if this difference is important.
    /// One different between skipped execution in pivot chain is that the
    /// transactions packed in the skipped epoch will be checked if they can
    /// be recycled.
    pub fn compute_epoch(
        &self,
        epoch_hash: &H256,
        epoch_block_hashes: &Vec<H256>,
        start_block_number: u64,
        reward_execution_info: &Option<RewardExecutionInfo>,
        // TODO: this arg should be removed.
        on_local_pivot: bool,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
        force_recompute: bool,
        recover_mpt_during_construct_pivot_state: bool,
    ) {
        // FIXME: Question: where to calculate if we should make a snapshot?
        // FIXME: Currently we make the snapshotting decision when committing
        // FIXME: a new state.

        // persist block number index
        // note: we need to persist before execution because in some cases,
        // execution is skipped. when `compute_epoch` is called, it is
        // guaranteed that `epoch_hash` is on the current pivot chain.
        for (index, hash) in epoch_block_hashes.iter().enumerate() {
            let block_number =
                compute_block_number(start_block_number, index as u64);
            self.data_man
                .insert_hash_by_block_number(block_number, hash);
        }

        let pivot_block_header = self
            .data_man
            .block_header_by_hash(epoch_hash)
            .expect("must exists");

        // Check if epoch is computed
        if !force_recompute
            && debug_record.is_none()
            && self.epoch_executed_and_recovered(
                &epoch_hash,
                &epoch_block_hashes,
                on_local_pivot,
                reward_execution_info,
                pivot_block_header.height(),
            )
        {
            self.update_on_skipped_execution(
                epoch_hash,
                &pivot_block_header,
                on_local_pivot,
            );
            return;
        }

        // Get blocks in this epoch after skip checking
        let epoch_blocks = self
            .data_man
            .blocks_by_hash_list(
                epoch_block_hashes,
                true, /* update_cache */
            )
            .expect("blocks exist");
        let pivot_block = epoch_blocks.last().expect("Not empty");

        debug!(
            "Process tx epoch_id={}, block_count={}",
            epoch_hash,
            epoch_blocks.len(),
        );

        let mut state = self
            .new_state(pivot_block, recover_mpt_during_construct_pivot_state)
            .expect("Cannot init state");

        let epoch_receipts = self
            .process_epoch_transactions(
                &mut state,
                &epoch_blocks,
                start_block_number,
                on_local_pivot,
                /* virtual_call */ None,
            )
            // TODO: maybe propagate the error all the way up so that the
            // program may restart by itself.
            .expect("Can not handle db error in consensus, crashing.");

        let current_block_number =
            start_block_number + epoch_receipts.len() as u64 - 1;

        if let Some(reward_execution_info) = reward_execution_info {
            let spec = self
                .machine
                .spec(current_block_number, pivot_block.block_header.height());
            // Calculate the block reward for blocks inside the epoch
            // All transaction fees are shared among blocks inside one epoch
            self.process_rewards_and_fees(
                &mut state,
                &reward_execution_info,
                epoch_hash,
                on_local_pivot,
                debug_record.as_deref_mut(),
                spec,
            );
        }

        self.process_pos_interest(
            &mut state,
            pivot_block,
            current_block_number,
        )
        .expect("db error");

        let commit_result = state
            .commit(*epoch_hash, debug_record.as_deref_mut())
            .expect(&concat!(file!(), ":", line!(), ":", column!()));

        if on_local_pivot {
            self.notify_txpool(&commit_result, epoch_hash);
        };

        self.data_man.insert_epoch_execution_commitment(
            pivot_block.hash(),
            commit_result.state_root.clone(),
            compute_receipts_root(&epoch_receipts),
            BlockHeaderBuilder::compute_block_logs_bloom_hash(&epoch_receipts),
        );

        let epoch_execution_commitment = self
            .data_man
            .get_epoch_execution_commitment(&epoch_hash)
            .unwrap();
        debug!(
            "compute_epoch: on_local_pivot={}, epoch={:?} state_root={:?} receipt_root={:?}, logs_bloom_hash={:?}",
            on_local_pivot, epoch_hash, commit_result.state_root, epoch_execution_commitment.receipts_root, epoch_execution_commitment.logs_bloom_hash,
        );
        self.data_man
            .state_availability_boundary
            .write()
            .adjust_upper_bound(&pivot_block.block_header);
    }

    fn update_on_skipped_execution(
        &self, epoch_hash: &H256, pivot_block_header: &BlockHeader,
        on_local_pivot: bool,
    ) {
        if on_local_pivot {
            // Unwrap is safe here because it's guaranteed by outer if.
            let state_root = &self
                .data_man
                .get_epoch_execution_commitment(epoch_hash)
                .unwrap()
                .state_root_with_aux_info;
            // When the state have expired, don't inform TransactionPool.
            // TransactionPool doesn't require a precise best_executed_state
            // when pivot chain oscillates.
            if self
                .data_man
                .state_availability_boundary
                .read()
                .check_availability(pivot_block_header.height(), epoch_hash)
            {
                self.tx_pool
                    .set_best_executed_state_by_epoch(
                        StateIndex::new_for_readonly(epoch_hash, &state_root),
                    )
                    // FIXME: propogate error.
                    .expect(&concat!(file!(), ":", line!(), ":", column!()));
            }
        }
        self.data_man
            .state_availability_boundary
            .write()
            .adjust_upper_bound(pivot_block_header);
        debug!("Skip execution in prefix {:?}", epoch_hash);
    }

    fn process_pos_interest(
        &self, state: &mut State, pivot_block: &Block,
        current_block_number: u64,
    ) -> DbResult<()> {
        // TODO(peilun): Specify if we unlock before or after executing the
        // transactions.
        let maybe_parent_pos_ref = self
            .data_man
            .block_header_by_hash(&pivot_block.block_header.parent_hash()) // `None` only for genesis.
            .and_then(|parent| parent.pos_reference().clone());
        if self
            .pos_verifier
            .is_enabled_at_height(pivot_block.block_header.height())
            && maybe_parent_pos_ref.is_some()
            && *pivot_block.block_header.pos_reference() != maybe_parent_pos_ref
        {
            let current_pos_ref = pivot_block
                .block_header
                .pos_reference()
                .as_ref()
                .expect("checked before sync graph insertion");
            let parent_pos_ref = &maybe_parent_pos_ref.expect("checked");
            // The pos_reference is continuous, so after seeing a new
            // pos_reference, we only need to process the new
            // unlock_txs in it.
            for (unlock_node_id, votes) in self
                .pos_verifier
                .get_unlock_nodes(current_pos_ref, parent_pos_ref)
            {
                debug!("unlock node: {:?} {}", unlock_node_id, votes);
                update_pos_status(state, unlock_node_id, votes)?;
            }
            if let Some((pos_epoch, reward_event)) = self
                .pos_verifier
                .get_reward_distribution_event(current_pos_ref, parent_pos_ref)
                .as_ref()
                .and_then(|x| x.first())
            {
                debug!("distribute_pos_interest: {:?}", reward_event);
                let account_rewards: Vec<(H160, H256, U256)> =
                    distribute_pos_interest(
                        state,
                        reward_event.rewards(),
                        current_block_number,
                    )?;
                self.data_man.insert_pos_reward(
                    *pos_epoch,
                    &PosRewardInfo::new(account_rewards, pivot_block.hash()),
                )
            }
        }
        Ok(())
    }

    fn notify_txpool(
        &self, commit_result: &StateCommitResult, epoch_hash: &H256,
    ) {
        // FIXME: We may want to propagate the error up.

        let accounts_for_txpool = commit_result.accounts_for_txpool.clone();
        {
            debug!("Notify epoch[{}]", epoch_hash);

            // TODO: use channel to deliver the message.
            let txpool_clone = self.tx_pool.clone();
            std::thread::Builder::new()
                .name("txpool_update_state".into())
                .spawn(move || {
                    txpool_clone.notify_modified_accounts(accounts_for_txpool);
                })
                .expect("can not notify tx pool to start state");
        }

        self.tx_pool
            .set_best_executed_state_by_epoch(StateIndex::new_for_readonly(
                epoch_hash,
                &commit_result.state_root,
            ))
            .expect(&concat!(file!(), ":", line!(), ":", column!()));
    }

    fn compute_block_base_reward(
        &self, past_block_count: u64, pivot_height: u64,
    ) -> U512 {
        self.machine
            .params()
            .base_reward_in_ucfx(past_block_count, pivot_height)
    }

    /// `epoch_block_states` includes if a block is partial invalid and its
    /// anticone difficulty
    fn process_rewards_and_fees(
        &self, state: &mut State, reward_info: &RewardExecutionInfo,
        epoch_later: &H256, on_local_pivot: bool,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>, spec: Spec,
    ) {
        /// (Fee, SetOfPackingBlockHash)
        struct TxExecutionInfo(U256, BTreeSet<H256>);

        let epoch_blocks = &reward_info.epoch_blocks;
        let pivot_block = epoch_blocks.last().expect("Not empty");
        let reward_epoch_hash = pivot_block.hash();
        debug!("Process rewards and fees for {:?}", reward_epoch_hash);
        let epoch_difficulty = pivot_block.block_header.difficulty();

        let epoch_size = epoch_blocks.len();
        let mut epoch_block_total_rewards = Vec::with_capacity(epoch_size);
        // This is the total primary tokens issued in this epoch.
        let mut total_base_reward: U256 = 0.into();

        let base_reward_per_block = if spec.cip94 {
            U512::from(state.pow_base_reward())
        } else {
            self.compute_block_base_reward(
                reward_info.past_block_count,
                pivot_block.block_header.height(),
            )
        };
        debug!("base_reward: {}", base_reward_per_block);

        // Base reward and anticone penalties.
        for (enum_idx, block) in epoch_blocks.iter().enumerate() {
            let no_reward = reward_info.epoch_block_no_reward[enum_idx];

            if no_reward {
                epoch_block_total_rewards.push(U256::from(0));
                if debug_record.is_some() {
                    let debug_out = debug_record.as_mut().unwrap();
                    debug_out.no_reward_blocks.push(block.hash());
                }
            } else {
                let pow_quality =
                    VerificationConfig::get_or_compute_header_pow_quality(
                        &self.data_man.pow,
                        &block.block_header,
                    );
                let mut reward = if pow_quality >= *epoch_difficulty {
                    base_reward_per_block
                } else {
                    debug!(
                        "Block {} pow_quality {} is less than epoch_difficulty {}!",
                        block.hash(), pow_quality, epoch_difficulty
                    );
                    0.into()
                };

                if let Some(debug_out) = &mut debug_record {
                    debug_out.block_rewards.push(BlockHashAuthorValue(
                        block.hash(),
                        block.block_header.author().clone(),
                        U256::try_from(reward).unwrap(),
                    ));
                }

                if reward > 0.into() {
                    let anticone_difficulty =
                        reward_info.epoch_block_anticone_difficulties[enum_idx];
                    // LINT.IfChange(ANTICONE_PENALTY_2)
                    let anticone_penalty = reward * anticone_difficulty
                        / U512::from(epoch_difficulty)
                        * anticone_difficulty
                        / U512::from(epoch_difficulty)
                        / U512::from(
                            self.machine.params().anticone_penalty_ratio,
                        )
                        / U512::from(
                            self.machine.params().anticone_penalty_ratio,
                        );
                    // Lint.ThenChange(consensus/mod.rs#ANTICONE_PENALTY_1)

                    debug_assert!(reward > anticone_penalty);
                    reward -= anticone_penalty;

                    if debug_record.is_some() {
                        let debug_out = debug_record.as_mut().unwrap();
                        debug_out.anticone_penalties.push(
                            BlockHashAuthorValue(
                                block.hash(),
                                block.block_header.author().clone(),
                                U256::try_from(anticone_penalty).unwrap(),
                            ),
                        );
                        //
                        // debug_out.anticone_set_size.push(BlockHashValue(
                        //                            block.hash(),
                        //
                        // reward_info.epoch_block_anticone_set_sizes
                        //                                [enum_idx],
                        //                        ));
                    }
                }

                debug_assert!(reward <= U512::from(U256::max_value()));
                let reward = U256::try_from(reward).unwrap();
                epoch_block_total_rewards.push(reward);
                if !reward.is_zero() {
                    total_base_reward += reward;
                }
            }
        }

        // Tx fee for each block in this epoch
        let mut tx_fee = HashMap::new();

        // Compute tx_fee of each block based on gas_used and gas_price of every
        // tx
        let mut epoch_receipts = None;
        let mut secondary_reward = U256::zero();
        for (enum_idx, block) in epoch_blocks.iter().enumerate() {
            let block_hash = block.hash();
            // TODO: better redesign to avoid recomputation.
            // FIXME: check state availability boundary here. Actually, it seems
            // FIXME: we should never recompute states here.
            let block_receipts = match self
                .data_man
                .block_execution_result_by_hash_with_epoch(
                    &block_hash,
                    &reward_epoch_hash,
                    false, /* update_pivot_assumption */
                    true,  /* update_cache */
                ) {
                Some(block_exec_result) => block_exec_result.block_receipts,
                None => {
                    let ctx = self
                        .data_man
                        .get_epoch_execution_context(&reward_epoch_hash)
                        .expect("epoch_execution_context should exists here");

                    // We need to return receipts instead of getting it through
                    // function get_receipts, because it's
                    // possible that the computed receipts is deleted by garbage
                    // collection before we try get it
                    if epoch_receipts.is_none() {
                        epoch_receipts = Some(self.recompute_states(
                            &reward_epoch_hash,
                            &epoch_blocks,
                            ctx.start_block_number,
                        )
                            // TODO: maybe propagate the error all the way up so that the
                            // program may restart by itself.
                            .expect("Can not handle db error in consensus, crashing."));
                    }
                    epoch_receipts.as_ref().unwrap()[enum_idx].clone()
                }
            };

            secondary_reward += block_receipts.secondary_reward;
            debug_assert!(
                block_receipts.receipts.len() == block.transactions.len()
            );
            // TODO: fill base_price.
            for (tx, receipt) in block
                .transactions
                .iter()
                .zip(block_receipts.receipts.iter())
            {
                let fee =
                    receipt.gas_fee - receipt.burnt_gas_fee.unwrap_or_default();

                let info = tx_fee
                    .entry(tx.hash())
                    .or_insert(TxExecutionInfo(fee, BTreeSet::default()));
                // The same transaction is executed only once.
                debug_assert!(
                    fee.is_zero() || info.0.is_zero() || info.1.len() == 0
                );
                // `false` means the block is fully valid
                // Partial invalid blocks will not share the tx fee
                if reward_info.epoch_block_no_reward[enum_idx] == false {
                    info.1.insert(block_hash);
                }
                if !fee.is_zero() && info.0.is_zero() {
                    info.0 = fee;
                }
            }
        }

        let mut block_tx_fees = HashMap::new();
        // Note that some transaction fees may get lost due to solely packed by
        // a partially invalid block.
        let mut burnt_fee = U256::from(0);
        for TxExecutionInfo(fee, block_set) in tx_fee.values() {
            if block_set.is_empty() {
                burnt_fee += *fee;
                // tx_fee for the transactions executed in a partial invalid
                // blocks and not packed in other blocks will be lost
                continue;
            }
            let block_count = U256::from(block_set.len());
            let quotient: U256 = *fee / block_count;
            let mut remainder: U256 = *fee - (block_count * quotient);
            for block_hash in block_set {
                let reward =
                    block_tx_fees.entry(*block_hash).or_insert(U256::zero());
                *reward += quotient;
                if !remainder.is_zero() {
                    *reward += 1.into();
                    remainder -= 1.into();
                }
            }
            debug_assert!(remainder.is_zero());
        }

        let mut merged_rewards = BTreeMap::new();
        // Here is the exact secondary reward allocated in total
        let mut allocated_secondary_reward = U256::from(0);

        for (enum_idx, block) in epoch_blocks.iter().enumerate() {
            let base_reward = epoch_block_total_rewards[enum_idx];

            let block_hash = block.hash();
            // Add tx fee to reward.
            let tx_fee = if let Some(fee) = block_tx_fees.get(&block_hash) {
                if let Some(debug_out) = &mut debug_record {
                    debug_out.tx_fees.push(BlockHashAuthorValue(
                        block_hash,
                        block.block_header.author().clone(),
                        *fee,
                    ));
                }
                *fee
            } else {
                U256::from(0)
            };

            // Distribute the secondary reward according to primary reward.
            let total_reward = if base_reward > U256::from(0) {
                let block_secondary_reward =
                    base_reward * secondary_reward / total_base_reward;
                if let Some(debug_out) = &mut debug_record {
                    debug_out.secondary_rewards.push(BlockHashAuthorValue(
                        block_hash,
                        block.block_header.author().clone(),
                        block_secondary_reward,
                    ));
                }
                allocated_secondary_reward += block_secondary_reward;
                base_reward + tx_fee + block_secondary_reward
            } else {
                base_reward + tx_fee
            };

            *merged_rewards
                .entry(*block.block_header.author())
                .or_insert(U256::from(0)) += total_reward;

            if let Some(debug_out) = &mut debug_record {
                debug_out.block_final_rewards.push(BlockHashAuthorValue(
                    block_hash,
                    block.block_header.author().clone(),
                    total_reward,
                ));
            }
            if on_local_pivot {
                self.data_man.insert_block_reward_result(
                    block_hash,
                    epoch_later,
                    BlockRewardResult {
                        total_reward,
                        tx_fee,
                        base_reward,
                    },
                    true,
                );
                self.data_man
                    .receipts_retain_epoch(&block_hash, &reward_epoch_hash);
            }
        }

        debug!("Give rewards merged_reward={:?}", merged_rewards);

        for (address, reward) in merged_rewards {
            if spec.is_valid_address(&address) {
                state
                    .add_balance(
                        &address.with_native_space(),
                        &reward,
                        CleanupMode::ForceCreate,
                    )
                    .unwrap();
            }

            if let Some(debug_out) = &mut debug_record {
                debug_out
                    .merged_rewards_by_author
                    .push(AuthorValue(address, reward));
                debug_out.state_ops.push(StateOp::IncentiveLevelOp {
                    op_name: "add_balance".to_string(),
                    key: address.0.to_hex::<String>().as_bytes().to_vec(),
                    maybe_value: Some({
                        let h: H256 = BigEndianHash::from_uint(&reward);
                        h.0.to_hex::<String>().as_bytes().into()
                    }),
                });
            }
        }
        let new_mint = total_base_reward + allocated_secondary_reward;
        if new_mint >= burnt_fee {
            // The very likely case
            state.add_total_issued(new_mint - burnt_fee);
        } else {
            // The very unlikely case
            state.sub_total_issued(burnt_fee - new_mint);
        }
    }

    fn recompute_states(
        &self, pivot_hash: &H256, epoch_blocks: &Vec<Arc<Block>>,
        start_block_number: u64,
    ) -> DbResult<Vec<Arc<BlockReceipts>>> {
        debug!(
            "Recompute receipts epoch_id={}, block_count={}",
            pivot_hash,
            epoch_blocks.len(),
        );
        let pivot_block = epoch_blocks.last().expect("Not empty");
        let mut state = self.new_state(&pivot_block, false)?;
        self.process_epoch_transactions(
            &mut state,
            &epoch_blocks,
            start_block_number,
            false,
            /* virtual_call */ None,
        )
    }

    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch_id: &H256, epoch_size: usize,
        request: EstimateRequest, evm_overrides: EvmOverrides,
    ) -> CoreResult<(ExecutionOutcome, EstimateExt)> {
        let best_block_header = self.data_man.block_header_by_hash(epoch_id);
        if best_block_header.is_none() {
            bail!("invalid epoch id");
        }
        let best_block_header = best_block_header.unwrap();
        let block_height = best_block_header.height() + 1;

        let pos_id = best_block_header.pos_reference().as_ref();
        let pos_view_number =
            pos_id.and_then(|id| self.pos_verifier.get_pos_view(id));
        let pivot_decision_epoch = pos_id
            .and_then(|id| self.pos_verifier.get_pivot_decision(id))
            .and_then(|hash| self.data_man.block_header_by_hash(&hash))
            .map(|header| header.height());

        let start_block_number = match self.data_man.get_epoch_execution_context(epoch_id) {
            Some(v) => v.start_block_number + epoch_size as u64,
            None => bail!("cannot obtain the execution context. Database is potentially corrupted!"),
        };
        let spec = self.machine.spec(start_block_number, block_height);
        let transitions = &self.machine.params().transition_heights;

        invalid_params_check(
            "tx",
            self.verification_config.verify_transaction_common(
                tx,
                AllChainID::fake_for_virtual(tx.chain_id().unwrap_or(1)),
                block_height,
                transitions,
                VerifyTxMode::Local(VerifyTxLocalMode::Full, &spec),
            ),
        )?;

        let state_space = match tx.space() {
            Space::Native => None,
            Space::Ethereum => Some(Space::Ethereum),
        };
        let statedb = self.get_statedb_by_epoch_id_and_space(
            epoch_id,
            best_block_header.height(),
            state_space,
        )?;
        let mut state = if evm_overrides.has_state() {
            State::new_with_override(
                statedb,
                &evm_overrides.state.as_ref().unwrap(),
                tx.space(),
            )?
        } else {
            State::new(statedb)?
        };

        let time_stamp = best_block_header.timestamp();

        let miner = {
            let mut address = H160::random();
            if tx.space() == Space::Native {
                address.set_user_account_type_bits();
            }
            address
        };

        let base_gas_price = best_block_header.base_price().unwrap_or_default();
        let burnt_gas_price =
            base_gas_price.map_all(|x| state.burnt_gas_price(x));

        let mut env = Env {
            chain_id: self.machine.params().chain_id_map(block_height),
            number: start_block_number,
            author: miner,
            timestamp: time_stamp,
            difficulty: Default::default(),
            accumulated_gas_used: U256::zero(),
            last_hash: epoch_id.clone(),
            gas_limit: tx.gas().clone(),
            epoch_height: block_height,
            pos_view: pos_view_number,
            finalized_epoch: pivot_decision_epoch,
            transaction_epoch_bound: self
                .verification_config
                .transaction_epoch_bound,
            base_gas_price,
            burnt_gas_price,
        };
        if evm_overrides.has_block() {
            ExecutiveContext::apply_env_overrides(
                &mut env,
                evm_overrides.block.unwrap(),
            );
        }
        let spec = self.machine.spec(env.number, env.epoch_height);
        let mut ex = EstimationContext::new(
            &mut state,
            &env,
            self.machine.as_ref(),
            &spec,
        );

        let r = ex.transact_virtual(tx.clone(), request);
        trace!("Execution result {:?}", r);
        Ok(r?)
    }

    /// Execute transactions in the blocks to collect traces.
    pub fn collect_blocks_geth_trace(
        &self, epoch_id: H256, epoch_num: u64, blocks: &Vec<Arc<Block>>,
        opts: GethDebugTracingOptions, tx_hash: Option<H256>,
    ) -> CoreResult<Vec<GethTraceWithHash>> {
        let state_space = None;
        let mut state = self.get_state_by_epoch_id_and_space(
            &epoch_id,
            epoch_num,
            state_space,
        )?;

        let start_block_number = self
            .data_man
            .get_epoch_execution_context(&epoch_id)
            .map(|v| v.start_block_number)
            .expect("should exist");

        let mut answer = vec![];
        let virtual_call = VirtualCall::GethTrace(GethTask {
            tx_hash,
            opts,
            answer: &mut answer,
        });
        self.process_epoch_transactions(
            &mut state,
            blocks,
            start_block_number,
            false,
            Some(virtual_call),
        )?;

        Ok(answer)
    }

    fn get_state_by_epoch_id_and_space(
        &self, epoch_id: &H256, epoch_height: u64, state_space: Option<Space>,
    ) -> DbResult<State> {
        let state_db = self.get_statedb_by_epoch_id_and_space(
            epoch_id,
            epoch_height,
            state_space,
        )?;
        let state = State::new(state_db)?;

        Ok(state)
    }

    fn get_statedb_by_epoch_id_and_space(
        &self, epoch_id: &H256, epoch_height: u64, state_space: Option<Space>,
    ) -> DbResult<StateDb> {
        // Keep the lock until we get the desired State, otherwise the State may
        // expire.
        let state_availability_boundary =
            self.data_man.state_availability_boundary.read();

        if !state_availability_boundary.check_read_availability(
            epoch_height,
            epoch_id,
            state_space,
        ) {
            bail!("state is not ready");
        }

        let state_index = self
            .data_man
            .get_state_readonly_index(epoch_id)
            .expect("state index should exist");

        let state_db = StateDb::new(
            self.data_man
                .storage_manager
                .get_state_no_commit(
                    state_index,
                    /* try_open = */ true,
                    state_space,
                )?
                .ok_or("state deleted")?,
        );

        drop(state_availability_boundary);

        Ok(state_db)
    }
}

pub struct ConsensusExecutionConfiguration {
    pub executive_trace: bool,
}
