// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::{debug::*, ConsensusGraphInner, ConsensusInnerConfig};
use crate::{
    block_data_manager::{
        block_data_types::EpochExecutionCommitment, BlockDataManager,
    },
    executive::{ExecutionError, Executive, InternalContractMap},
    machine::new_machine_with_builtin,
    state::{CleanupMode, State},
    state_exposer::{ConsensusGraphBlockExecutionState, STATE_EXPOSER},
    statedb::StateDb,
    storage::{StateIndex, StateRootWithAuxInfo, StorageManagerTrait},
    vm::{Env, Spec},
    vm_factory::VmFactory,
    SharedTransactionPool,
};
use cfx_types::{BigEndianHash, H256, KECCAK_EMPTY_BLOOM, U256};
use hash::KECCAK_EMPTY_LIST_RLP;
use metrics::{register_meter_with_group, Meter, MeterTimer};
use parity_bytes::ToPretty;
use parking_lot::Mutex;
use primitives::{
    receipt::{
        Receipt, TRANSACTION_OUTCOME_EXCEPTION_WITHOUT_NONCE_BUMPING,
        TRANSACTION_OUTCOME_EXCEPTION_WITH_NONCE_BUMPING,
        TRANSACTION_OUTCOME_SUCCESS,
    },
    Block, BlockHeaderBuilder, SignedTransaction, TransactionIndex,
    MERKLE_NULL_NODE,
};
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
    pub epoch_blocks: Vec<Arc<Block>>,
}

impl Debug for RewardExecutionInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "RewardExecutionInfo{{ epoch_blocks: {:?}}}",
            self.epoch_blocks
                .iter()
                .map(|b| b.hash())
                .collect::<Vec<H256>>(),
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
    pub epoch_hash: H256,
    pub epoch_block_hashes: Vec<H256>,
    pub start_block_number: u64,
    pub reward_info: Option<RewardExecutionInfo>,
    pub debug_record: Arc<Mutex<Option<ComputeEpochDebugRecord>>>,
    pub force_recompute: bool,
}

impl EpochExecutionTask {
    pub fn new(
        epoch_hash: H256, epoch_block_hashes: Vec<H256>,
        start_block_number: u64, reward_info: Option<RewardExecutionInfo>,
        debug_record: bool, force_recompute: bool,
    ) -> Self
    {
        Self {
            epoch_hash,
            epoch_block_hashes,
            start_block_number,
            reward_info,
            debug_record: if debug_record {
                // FIXME: make debug_record great again.
                Default::default()
            } else {
                Arc::new(Mutex::new(None))
            },
            force_recompute,
        }
    }
}

/// `sender` is used to return the computed `(state_root, receipts_root,
/// logs_bloom_hash)` to the thread who sends this task.
#[derive(Debug)]
struct GetExecutionResultTask {
    pub epoch_hash: H256,
    pub sender: Sender<EpochExecutionCommitment>,
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
        vm: VmFactory, conf: ConsensusInnerConfig, bench_mode: bool,
    ) -> Arc<Self>
    {
        let handler = Arc::new(ConsensusExecutionHandler::new(
            tx_pool,
            data_man.clone(),
            conf,
            vm,
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
                let maybe_task = receiver.try_recv();
                match maybe_task {
                    Err(TryRecvError::Empty) => {
                        if !handler.handle_recv_result(receiver.recv()) {
                            break;
                        }
                    }
                    maybe_error => {
                        // Handle execution task in channel.
                        // If `maybe_task` is Err, it can only be
                        // `TryRecvError::Disconnected`, and it has the same
                        // meaning as `RecvError` for `recv()`
                        if !handler.handle_recv_result(
                            maybe_error.map_err(|_| RecvError),
                        ) {
                            break;
                        }
                    }
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
    ) -> EpochExecutionCommitment {
        // In consensus_graph_bench_mode execution is skipped.
        if self.consensus_graph_bench_mode {
            EpochExecutionCommitment {
                state_root_with_aux_info: StateRootWithAuxInfo::genesis(
                    &MERKLE_NULL_NODE,
                ),
                receipts_root: KECCAK_EMPTY_LIST_RLP,
                logs_bloom_hash: KECCAK_EMPTY_BLOOM,
            }
        } else {
            if self.handler.data_man.epoch_executed(&epoch_hash) {
                // The epoch already executed, so we do not need wait for the
                // queue to be empty
                return self
                    .handler
                    .get_execution_result(&epoch_hash)
                    .expect("it should success");
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
            receiver.recv().unwrap()
        }
    }

    pub fn get_reward_execution_info(
        &self, _inner: &mut ConsensusGraphInner, _epoch_arena_index: usize,
    ) -> Option<RewardExecutionInfo> {
        None
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
    pub fn compute_epoch(&self, task: EpochExecutionTask) {
        if !self.consensus_graph_bench_mode {
            self.handler.handle_epoch_execution(task)
        }
    }

    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch_id: &H256,
    ) -> Result<(Vec<u8>, U256), String> {
        self.handler.call_virtual(tx, epoch_id)
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

    /// This is a blocking call to force the execution engine to compute the
    /// state of a block immediately
    pub fn compute_state_for_block(
        &self, arena_index: usize, inner: &ConsensusGraphInner,
    ) -> Result<(), String> {
        let _timer = MeterTimer::time_func(
            CONSENSIS_COMPUTE_STATE_FOR_BLOCK_TIMER.as_ref(),
        );
        let block_hash = inner.arena[arena_index].hash;
        // If we already computed the state of the block before, we should not
        // do it again
        debug!("compute_state_for_block {:?}", block_hash);
        {
            let (_guarded_state_index, maybe_state_index) = self
                .handler
                .data_man
                .get_state_readonly_index(&block_hash)
                .into();
            // The state is computed and is retrievable from storage.
            if let Some(maybe_cached_state_result) =
                maybe_state_index.map(|state_readonly_index| {
                    self.handler
                        .data_man
                        .storage_manager
                        .get_state_no_commit(state_readonly_index)
                })
            {
                if let Ok(Some(_)) = maybe_cached_state_result {
                    return Ok(());
                } else {
                    return Err("internal storage error".to_string());
                }
            }
        }

        let block_height = inner.arena[arena_index].height;
        let mut fork_height = block_height;
        let mut chain: Vec<usize> = Vec::new();
        let mut idx = arena_index;
        while fork_height > 0
            && (fork_height >= inner.get_pivot_height()
                || inner.get_pivot_block_arena_index(fork_height) != idx)
        {
            chain.push(idx);
            fork_height -= 1;
            idx = inner.arena[idx].parent;
        }
        // Because we have genesis at height 0, this should always be true
        assert!(inner.get_pivot_block_arena_index(fork_height) == idx);
        debug!(
            "compute_state_for_block forked at index {} height {}",
            idx, fork_height
        );
        chain.push(idx);
        chain.reverse();
        let start_chain_index =
            ConsensusExecutor::find_start_chain_index(inner, &chain);

        debug!(
            "Start execution from index[{:?}] hash[{:?}]",
            chain[start_chain_index], inner.arena[chain[start_chain_index]]
        );

        for fork_chain_index in start_chain_index..chain.len() {
            let pivot_arena_index = chain[fork_chain_index];
            self.enqueue_epoch(EpochExecutionTask::new(
                inner.arena[pivot_arena_index].hash,
                inner.get_epoch_block_hashes(pivot_arena_index),
                inner.get_epoch_start_block_number(pivot_arena_index),
                None,  /* reward_info */
                false, /* debug_record */
                false, /* force_recompute */
            ));
        }

        let epoch_execution_result = self.wait_for_result(block_hash);
        debug!(
            "Epoch {:?} has state_root={:?} receipts_root={:?} logs_bloom_hash={:?}",
            inner.arena[arena_index].hash, epoch_execution_result.state_root_with_aux_info,
            epoch_execution_result.receipts_root, epoch_execution_result.logs_bloom_hash
        );

        Ok(())
    }
}

pub struct ConsensusExecutionHandler {
    tx_pool: SharedTransactionPool,
    data_man: Arc<BlockDataManager>,
    conf: ConsensusInnerConfig,
    pub vm: VmFactory,
}

impl ConsensusExecutionHandler {
    pub fn new(
        tx_pool: SharedTransactionPool, data_man: Arc<BlockDataManager>,
        conf: ConsensusInnerConfig, vm: VmFactory,
    ) -> Self
    {
        ConsensusExecutionHandler {
            tx_pool,
            data_man,
            conf,
            vm,
        }
    }

    /// Return `false` if someting goes wrong, and we will break the working
    /// loop. `maybe_task` should match results from `recv()`, so it does not
    /// contain `Empty` case.
    fn handle_recv_result(
        &self, maybe_task: Result<ExecutionTask, RecvError>,
    ) -> bool {
        match maybe_task {
            Ok(task) => self.handle_execution_work(task),
            Err(e) => {
                error!("Consensus Executor stopped by Err={:?}", e);
                false
            }
        }
    }

    /// Always return `true` for now
    fn handle_execution_work(&self, task: ExecutionTask) -> bool {
        debug!("Receive execution task: {:?}", task);
        match task {
            ExecutionTask::ExecuteEpoch(task) => {
                self.handle_epoch_execution(task)
            }
            ExecutionTask::GetResult(task) => self.handle_get_result_task(task),
            ExecutionTask::Stop => return false,
        }
        true
    }

    fn handle_epoch_execution(&self, task: EpochExecutionTask) {
        let _timer = MeterTimer::time_func(CONSENSIS_EXECUTION_TIMER.as_ref());
        self.compute_epoch(
            &task.epoch_hash,
            &task.epoch_block_hashes,
            task.start_block_number,
            &task.reward_info,
            &mut *task.debug_record.lock(),
            task.force_recompute,
        );
    }

    fn handle_get_result_task(&self, task: GetExecutionResultTask) {
        task.sender
            .send(
                self.get_execution_result(&task.epoch_hash).expect(
                    "The caller of wait_for_result ensures the existence",
                ),
            )
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

    /// Compute the epoch `epoch_hash`, and skip it if already computed.
    /// After the function is called, it's assured that the state, the receipt
    /// root, and the receipts of blocks executed by this epoch exist.
    ///
    /// TODO Not sure if this difference is important.
    /// One different between skipped execution in pivot chain is that the
    /// transactions packed in the skipped epoch will be checked if they can
    /// be recycled.
    pub fn compute_epoch(
        &self, epoch_hash: &H256, epoch_block_hashes: &Vec<H256>,
        start_block_number: u64,
        reward_execution_info: &Option<RewardExecutionInfo>,
        debug_record: &mut Option<ComputeEpochDebugRecord>,
        force_recompute: bool,
    )
    {
        // FIXME: Question: where to calculate if we should make a snapshot?
        // FIXME: Currently we make the snapshotting decision when committing
        // FIXME: a new state.

        // Check if the state has been computed
        if !force_recompute
            && debug_record.is_none()
            && self.data_man.epoch_executed_and_recovered(
                &epoch_hash,
                &epoch_block_hashes,
                true, /* on_local_pivot */
            )
        {
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
                .check_availability(start_block_number + 1, epoch_hash)
            {
                self.tx_pool
                    .set_best_executed_epoch(StateIndex::new_for_readonly(
                        epoch_hash,
                        &state_root,
                    ))
                    // FIXME: propogate error.
                    .expect(&concat!(file!(), ":", line!(), ":", column!()));
            }
            debug!("Skip execution in prefix[{:?}]", epoch_hash);
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
            "compute_epoch for epoch[{:?}], block_count[{:?}]",
            epoch_hash,
            epoch_blocks.len(),
        );

        let mut state = State::new(
            StateDb::new(
                self.data_man
                    .storage_manager
                    .get_state_for_next_epoch(StateIndex::new_for_next_epoch(
                        pivot_block.block_header.parent_hash(),
                        &self
                            .data_man
                            .get_epoch_execution_commitment(
                                pivot_block.block_header.parent_hash(),
                            )
                            // Unwrapping is safe because the state exists.
                            .unwrap()
                            .state_root_with_aux_info,
                        pivot_block.block_header.height() - 1,
                        self.data_man.get_snapshot_epoch_count(),
                    ))
                    .expect("No db error")
                    // Unwrapping is safe because the state exists.
                    .expect("State exists"),
            ),
            self.vm.clone(),
            start_block_number - 1, /* block_number */
        );
        let epoch_receipts = self.process_epoch_transactions(
            &mut state,
            &epoch_blocks,
            start_block_number,
        );

        if let Some(reward_execution_info) = reward_execution_info {
            // Calculate the block reward for blocks inside the epoch
            // All transaction fees are shared among blocks inside one epoch
            self.process_rewards_and_fees(
                &mut state,
                &reward_execution_info,
                debug_record,
            );
        }

        // FIXME: We may want to propagate the error up.
        let state_root;
        state_root = state
            .commit_and_notify(*epoch_hash, &self.tx_pool)
            .expect(&concat!(file!(), ":", line!(), ":", column!()));
        self.tx_pool
            .set_best_executed_epoch(StateIndex::new_for_readonly(
                epoch_hash,
                &state_root,
            ))
            .expect(&concat!(file!(), ":", line!(), ":", column!()));
        self.data_man.insert_epoch_execution_commitment(
            pivot_block.hash(),
            state_root.clone(),
            BlockHeaderBuilder::compute_block_receipts_root(&epoch_receipts),
            BlockHeaderBuilder::compute_block_logs_bloom_hash(&epoch_receipts),
        );
        let epoch_execution_commitment = self
            .data_man
            .get_epoch_execution_commitment(&epoch_hash)
            .expect("EpochExecutionCommitment should exist");

        if self.conf.enable_state_expose {
            STATE_EXPOSER
                .consensus_graph
                .lock()
                .block_execution_state_vec
                .push(ConsensusGraphBlockExecutionState {
                    block_hash: *epoch_hash,
                    deferred_state_root: state_root
                        .state_root
                        .compute_state_root_hash(),
                    deferred_receipt_root: epoch_execution_commitment
                        .receipts_root,
                    deferred_logs_bloom_hash: epoch_execution_commitment
                        .logs_bloom_hash,
                    state_valid: true,
                })
        }
        debug!(
            "compute_epoch: epoch={:?} state_root={:?} receipt_root={:?}, logs_bloom_hash={:?}",
            epoch_hash, state_root, epoch_execution_commitment.receipts_root, epoch_execution_commitment.logs_bloom_hash,
        );
    }

    fn process_epoch_transactions(
        &self, state: &mut State, epoch_blocks: &Vec<Arc<Block>>,
        start_block_number: u64,
    ) -> Vec<Arc<Vec<Receipt>>>
    {
        let pivot_block = epoch_blocks.last().expect("Epoch not empty");
        let spec = Spec::new_spec();
        let machine = new_machine_with_builtin();
        let internal_contract_map = InternalContractMap::new();
        let mut epoch_receipts = Vec::with_capacity(epoch_blocks.len());
        let mut to_pending = Vec::new();
        let mut block_number = start_block_number;
        for block in epoch_blocks.iter() {
            let mut receipts = Vec::new();
            debug!(
                "process txs in block: hash={:?}, tx count={:?}",
                block.hash(),
                block.transactions.len()
            );
            let mut env = Env {
                number: block_number,
                author: block.block_header.author().clone(),
                timestamp: block.block_header.timestamp(),
                difficulty: block.block_header.difficulty().clone(),
                gas_used: U256::zero(),
                last_hashes: Arc::new(vec![]),
                gas_limit: U256::from(block.block_header.gas_limit()),
            };
            state.increase_block_number();
            assert_eq!(state.block_number(), env.number);
            block_number += 1;
            let mut accumulated_fee: U256 = 0.into();
            let mut n_invalid_nonce = 0;
            let mut n_ok = 0;
            let mut n_other = 0;
            let mut cumulative_gas_used = U256::zero();
            for (idx, transaction) in block.transactions.iter().enumerate() {
                let mut tx_outcome_status =
                    TRANSACTION_OUTCOME_EXCEPTION_WITHOUT_NONCE_BUMPING;
                let mut transaction_logs = Vec::new();
                let mut nonce_increased = false;

                let r = {
                    Executive::new(
                        state,
                        &env,
                        &machine,
                        &spec,
                        &internal_contract_map,
                    )
                    .transact(transaction, &mut nonce_increased)
                };
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
                    Err(ExecutionError::NotEnoughCash {
                        required: _,
                        got: _,
                        actual_gas_cost,
                    }) => {
                        /* We charge `actual_gas_cost`, so increase
                         * `cumulative_gas_used` to make
                         * this charged balance distributed to miners.
                         * Note for the case that `balance < tx_fee`, the
                         * amount of remainder is lost forever. */
                        env.gas_used += actual_gas_cost / transaction.gas_price;
                        cumulative_gas_used = env.gas_used;
                    }
                    Err(ExecutionError::InvalidNonce { expected, got }) => {
                        // not inc nonce
                        n_invalid_nonce += 1;
                        trace!("tx execution InvalidNonce without inc_nonce: transaction={:?}, err={:?}", transaction.clone(), r);
                        // Add future transactions back to pool if we are
                        // not verifying forking chain
                        if got > expected {
                            trace!(
                                "To re-add transaction ({:?}) to pending pool",
                                transaction.clone()
                            );
                            to_pending.push(transaction.clone());
                        }
                    }
                    Ok(ref executed) => {
                        if executed.exception.is_some() {
                            warn!(
                                "tx execution error: transaction={:?}, err={:?}",
                                transaction, r
                            );
                        } else {
                            env.gas_used = executed.cumulative_gas_used;
                            cumulative_gas_used = executed.cumulative_gas_used;
                            n_ok += 1;
                            GOOD_TPS_METER.mark(1);
                            trace!("tx executed successfully: transaction={:?}, result={:?}, in block {:?}", transaction, executed, block.hash());
                            accumulated_fee += executed.fee;
                            transaction_logs = executed.logs.clone();
                            tx_outcome_status = TRANSACTION_OUTCOME_SUCCESS;
                        }
                    }
                    _ => {
                        n_other += 1;
                        trace!("tx executed: transaction={:?}, result={:?}, in block {:?}", transaction, r, block.hash());
                    }
                }

                if nonce_increased
                    && tx_outcome_status != TRANSACTION_OUTCOME_SUCCESS
                {
                    tx_outcome_status =
                        TRANSACTION_OUTCOME_EXCEPTION_WITH_NONCE_BUMPING;
                }

                let receipt = Receipt::new(
                    tx_outcome_status,
                    cumulative_gas_used,
                    transaction_logs,
                    Vec::new(), /* storage_collateralized */
                    Vec::new(), /* storage_released */
                );
                receipts.push(receipt);

                let hash = transaction.hash();
                let tx_index = TransactionIndex {
                    block_hash: block.hash(),
                    index: idx,
                };
                if tx_outcome_status
                    != TRANSACTION_OUTCOME_EXCEPTION_WITHOUT_NONCE_BUMPING
                {
                    self.data_man.insert_transaction_index(&hash, &tx_index);
                }
            }

            let block_receipts = Arc::new(receipts);
            self.data_man.insert_block_results(
                block.hash(),
                pivot_block.hash(),
                block_receipts.clone(),
                true, /* persistent */
            );
            epoch_receipts.push(block_receipts);
            debug!(
                "n_invalid_nonce={}, n_ok={}, n_other={}",
                n_invalid_nonce, n_ok, n_other
            );
        }

        self.tx_pool.recycle_transactions(to_pending);

        debug!(
            "Finish processing tx for epoch[{:?}] epoch_receipts_len={:?}",
            pivot_block.hash(),
            epoch_receipts.len()
        );
        epoch_receipts
    }

    /// `epoch_block_states` includes if a block is partial invalid and its
    /// anticone difficulty
    fn process_rewards_and_fees(
        &self, state: &mut State, reward_info: &RewardExecutionInfo,
        debug_record: &mut Option<ComputeEpochDebugRecord>,
    )
    {
        /// (Fee, SetOfPackingBlockHash)
        struct TxExecutionInfo(U256, BTreeSet<H256>);

        let epoch_blocks = &reward_info.epoch_blocks;
        let pivot_block = epoch_blocks.last().expect("Not empty");
        let reward_epoch_hash = pivot_block.hash();
        debug!("Process rewards and fees for {:?}", reward_epoch_hash);

        // Tx fee for each block in this epoch
        let mut tx_fee = HashMap::new();

        // Compute tx_fee of each block based on gas_used and gas_price of every
        // tx
        for (_, block) in epoch_blocks.iter().enumerate() {
            let block_hash = block.hash();
            // TODO: better redesign to avoid recomputation.
            let receipts = self
                .data_man
                .block_execution_result_by_hash_with_epoch(
                    &block_hash,
                    &reward_epoch_hash,
                    true, /* update_cache */
                )
                .expect("should exists")
                .receipts;

            let mut last_gas_used = U256::zero();
            debug_assert!(receipts.len() == block.transactions.len());
            for (idx, tx) in block.transactions.iter().enumerate() {
                let gas_used = receipts[idx].gas_used - last_gas_used;
                let fee = tx.gas_price * gas_used;
                let info = tx_fee
                    .entry(tx.hash())
                    .or_insert(TxExecutionInfo(fee, BTreeSet::default()));
                // The same transaction is executed only once.
                debug_assert!(
                    fee.is_zero() || info.0.is_zero() || info.1.len() == 0
                );
                info.1.insert(block_hash);
                if !fee.is_zero() && info.0.is_zero() {
                    info.0 = fee;
                }
                last_gas_used = receipts[idx].gas_used;
            }
        }

        let mut block_tx_fees = HashMap::new();
        for TxExecutionInfo(fee, block_set) in tx_fee.values() {
            if block_set.is_empty() {
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
        }

        let mut merged_rewards = BTreeMap::new();

        for (_enum_idx, block) in epoch_blocks.iter().enumerate() {
            let mut reward = U256::zero();
            let block_hash = block.hash();
            // Add tx fee to reward.
            if let Some(fee) = block_tx_fees.get(&block_hash) {
                reward += *fee;
                if !debug_record.is_none() {
                    let debug_out = debug_record.as_mut().unwrap();
                    debug_out.tx_fees.push(BlockHashAuthorValue(
                        block_hash,
                        block.block_header.author().clone(),
                        *fee,
                    ));
                }
            }

            *merged_rewards
                .entry(*block.block_header.author())
                .or_insert(U256::from(0)) += reward;

            if debug_record.is_some() {
                let debug_out = debug_record.as_mut().unwrap();
                debug_out.block_final_rewards.push(BlockHashAuthorValue(
                    block_hash,
                    block.block_header.author().clone(),
                    reward,
                ));
            }
            self.data_man
                .receipts_retain_epoch(&block_hash, &reward_epoch_hash);
        }

        debug!("Give rewards merged_reward={:?}", merged_rewards);

        for (address, reward) in merged_rewards {
            state
                .add_balance(&address, &reward, CleanupMode::ForceCreate)
                .unwrap();

            if debug_record.is_some() {
                let debug_out = debug_record.as_mut().unwrap();
                debug_out
                    .merged_rewards_by_author
                    .push(AuthorValue(address, reward));
                debug_out.state_ops.push(StateOp::OpNameKeyMaybeValue {
                    op_name: "add_balance".to_string(),
                    key: address.to_hex().as_bytes().to_vec(),
                    maybe_value: Some({
                        let h: H256 = BigEndianHash::from_uint(&reward);
                        h.to_hex().as_bytes().to_vec()
                    }),
                });
            }
        }
    }

    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch_id: &H256,
    ) -> Result<(Vec<u8>, U256), String> {
        let spec = Spec::new_spec();
        let machine = new_machine_with_builtin();
        let internal_contract_map = InternalContractMap::new();
        let best_block_header = self.data_man.block_header_by_hash(epoch_id);
        if best_block_header.is_none() {
            return Err("invalid epoch id".to_string());
        }
        let best_block_header = best_block_header.unwrap();

        // Keep the lock until we get the desired State, otherwise the State may
        // expire.
        let state_availability_boundary =
            self.data_man.state_availability_boundary.read();
        if !state_availability_boundary
            .check_availability(best_block_header.height(), epoch_id)
        {
            return Err("state is not ready".to_string());
        }
        let (_state_index_guard, state_index) =
            self.data_man.get_state_readonly_index(epoch_id).into();
        trace!("best_block_header: {:?}", best_block_header);
        let time_stamp = best_block_header.timestamp();
        let mut state = State::new(
            StateDb::new(
                self.data_man
                    .storage_manager
                    .get_state_no_commit(state_index.unwrap())
                    // FIXME: propogate error
                    .expect("No DB Error")
                    // Safe because the state exists.
                    .expect("State Exists"),
            ),
            self.vm.clone(),
            0, /* block_number */
        );
        drop(state_availability_boundary);

        let env = Env {
            number: 0, // TODO: replace 0 with correct cardinal number
            author: Default::default(),
            timestamp: time_stamp,
            difficulty: Default::default(),
            gas_used: U256::zero(),
            last_hashes: Arc::new(vec![]),
            gas_limit: tx.gas.clone(),
        };
        assert_eq!(state.block_number(), env.number);
        let mut ex = Executive::new(
            &mut state,
            &env,
            &machine,
            &spec,
            &internal_contract_map,
        );
        let r = ex.transact_virtual(tx);
        trace!("Execution result {:?}", r);
        r.map(|r| (r.output, r.gas_used))
            .map_err(|e| format!("execution error: {:?}", e))
    }
}
