use super::super::debug::*;
use crate::{
    block_data_manager::BlockDataManager,
    consensus::{
        ConsensusGraphInner, ANTICONE_PENALTY_RATIO, BASE_MINING_REWARD,
        CONFLUX_TOKEN,
    },
    executive::{ExecutionError, Executive},
    machine::new_machine,
    state::{CleanupMode, State},
    statedb::StateDb,
    storage::{
        state::StateTrait,
        state_manager::{SnapshotAndEpochIdRef, StateManagerTrait},
    },
    vm::{Env, Spec},
    vm_factory::VmFactory,
    SharedTransactionPool,
};
use cfx_types::{H256, KECCAK_EMPTY_BLOOM, U256, U512};
use parking_lot::{Mutex, RwLock};
use primitives::{
    receipt::{
        Receipt, TRANSACTION_OUTCOME_EXCEPTION, TRANSACTION_OUTCOME_SUCCESS,
    },
    Block, BlockHeaderBuilder, SignedTransaction, StateRootWithAuxInfo,
    TransactionAddress,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        mpsc::{channel, RecvError, Sender, TryRecvError},
        Arc,
    },
    thread::{self, JoinHandle},
};

use crate::consensus::DEFERRED_STATE_EPOCH_COUNT;
use hash::KECCAK_EMPTY_LIST_RLP;
use std::fmt::{Debug, Formatter};

/// The RewardExecutionInfo struct includes most information to compute rewards
/// for old epochs
pub struct RewardExecutionInfo {
    pub epoch_blocks: Vec<Arc<Block>>,
    pub epoch_block_anticone_overlimited: Vec<bool>,
    pub epoch_block_anticone_difficulties: Vec<U512>,
}

impl Debug for RewardExecutionInfo {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "RewardExecutionInfo{{ epoch_blocks: {:?} \
             epoch_block_anticone_overlimited: {:?} \
             epoch_block_anticone_difficulties: {:?}}}",
            self.epoch_blocks
                .iter()
                .map(|b| b.hash())
                .collect::<Vec<H256>>(),
            self.epoch_block_anticone_overlimited,
            self.epoch_block_anticone_difficulties
        )
    }
}

#[derive(Debug)]
enum ExecutionTask {
    ExecuteEpoch(EpochExecutionTask),
    GetResult(GetExecutionResultTask),
    Stop,
}

/// The EpochExecutionTask struct includes all the information needed to execute
/// an epoch
#[derive(Debug)]
pub struct EpochExecutionTask {
    pub epoch_hash: H256,
    pub epoch_block_hashes: Vec<H256>,
    pub reward_info: Option<RewardExecutionInfo>,
    pub on_local_pivot: bool,
    pub debug_record: Arc<Mutex<Option<ComputeEpochDebugRecord>>>,
}

impl EpochExecutionTask {
    pub fn new(
        epoch_hash: H256, epoch_block_hashes: Vec<H256>,
        reward_info: Option<RewardExecutionInfo>, on_local_pivot: bool,
        debug_record: bool,
    ) -> Self
    {
        Self {
            epoch_hash,
            epoch_block_hashes,
            reward_info,
            on_local_pivot,
            debug_record: if debug_record {
                Arc::new(Mutex::new(Some(ComputeEpochDebugRecord::default())))
            } else {
                Arc::new(Mutex::new(None))
            },
        }
    }
}

/// `sender` is used to return the computed `(state_root, receipts_root,
/// logs_bloom_hash)` to the thread who sends this task.
#[derive(Debug)]
struct GetExecutionResultTask {
    pub epoch_hash: H256,
    pub sender: Sender<(StateRootWithAuxInfo, H256, H256)>,
}

/// ConsensusExecutor processes transaction execution tasks.
pub struct ConsensusExecutor {
    /// The thread responsible for execution transactions
    thread: Mutex<Option<JoinHandle<()>>>,

    /// The sender to send tasks to be executed by `self.thread`
    sender: Mutex<Sender<ExecutionTask>>,

    /// The handler to provide functions to handle `ExecutionTask` and execute
    /// transactions It is used both asynchronously by `self.thread` and
    /// synchronously by the executor itself
    pub handler: Arc<ConsensusExecutionHandler>,

    bench_mode: bool,
}

impl ConsensusExecutor {
    pub fn start(
        tx_pool: SharedTransactionPool, data_man: Arc<BlockDataManager>,
        vm: VmFactory, consensus_inner: Arc<RwLock<ConsensusGraphInner>>,
        bench_mode: bool,
    ) -> Self
    {
        let handler = Arc::new(ConsensusExecutionHandler::new(
            tx_pool,
            data_man.clone(),
            vm,
        ));
        let (sender, receiver) = channel();

        let executor = ConsensusExecutor {
            thread: Mutex::new(None),
            sender: Mutex::new(sender),
            handler: handler.clone(),
            bench_mode,
        };
        // It receives blocks hashes from on_new_block and execute them
        let handle = thread::Builder::new()
            .name("Consensus Execution Worker".into())
            .spawn(move || loop {
                let maybe_task = receiver.try_recv();
                match maybe_task {
                    Err(TryRecvError::Empty) => {
                        // The channel is empty, so we try to optimistically
                        // get later epochs to execute. Here we use `try_write` because some thread
                        // may wait for execution results while holding the Consensus Inner lock,
                        // if we wait on inner lock here we may get deadlock
                        let maybe_optimistic_task = consensus_inner
                            .try_write()
                            .and_then(|mut inner|
                                inner.get_optimistic_execution_task(&data_man)
                            );
                        match maybe_optimistic_task {
                            Some(task) => {
                                debug!("Get optimistic_execution_task {:?}", task);
                                handler.handle_epoch_execution(task)
                            },
                            None => {
                                debug!("No optimistic tasks to execute, block for new tasks");
                                //  Even optimistic tasks are all finished, so we block and wait for
                                //  new execution tasks.
                                //  New optimistic tasks will only exist if pivot_chain changes,
                                //  and new tasks will be sent to `receiver` in this case, so this
                                // waiting will not prevent new optimistic tasks from being executed
                                if !handler.handle_recv_result(receiver.recv())
                                {
                                    break;
                                }
                            }
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

    /// Wait until all tasks currently in the queue to be executed and return
    /// `(state_root, receipts_root, logs_bloom_hash)` of the given
    /// `epoch_hash`.
    ///
    /// It is the caller's responsibility to ensure that `epoch_hash` is indeed
    /// computed when all the tasks before are finished.
    // TODO Release Consensus inner lock if possible when the function is called
    pub fn wait_for_result(
        &self, epoch_hash: H256,
    ) -> (StateRootWithAuxInfo, H256, H256) {
        if self.bench_mode {
            (
                Default::default(),
                KECCAK_EMPTY_LIST_RLP,
                KECCAK_EMPTY_BLOOM,
            )
        } else {
            let (sender, receiver) = channel();
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

    /// Enqueue the epoch to be executed by the background execution thread
    /// The parameters are needed for the thread to execute this epoch without
    /// holding inner lock.
    pub fn enqueue_epoch(&self, task: EpochExecutionTask) -> bool {
        if !self.bench_mode {
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
        if !self.bench_mode {
            self.handler.handle_epoch_execution(task)
        }
    }

    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch_id: &H256,
    ) -> Result<(Vec<u8>, U256), String> {
        self.handler.call_virtual(tx, epoch_id)
    }

    pub fn stop(&self) {
        self.sender
            .lock()
            .send(ExecutionTask::Stop)
            .expect("Receiver exists");
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
    fn find_start_index(
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
        &self, block_hash: &H256, inner: &ConsensusGraphInner,
    ) -> Result<(StateRootWithAuxInfo, H256, H256), String> {
        // If we already computed the state of the block before, we should not
        // do it again
        debug!("compute_state_for_block {:?}", block_hash);
        {
            if let Ok(maybe_cached_state) =
                self.handler.data_man.storage_manager.get_state_no_commit(
                    SnapshotAndEpochIdRef::new(&block_hash.clone(), None),
                )
            {
                match maybe_cached_state {
                    Some(cached_state) => {
                        if let (Some(receipts_root), Some(logs_bloom_hash)) = (
                            self.handler
                                .data_man
                                .get_receipts_root(&block_hash),
                            self.handler
                                .data_man
                                .get_logs_bloom_hash(&block_hash),
                        ) {
                            return Ok((
                                cached_state.get_state_root().unwrap().unwrap(),
                                receipts_root,
                                logs_bloom_hash,
                            ));
                        }
                    }
                    None => {}
                }
            } else {
                return Err("Internal storage error".to_owned());
            }
        }
        let me_opt = inner.indices.get(block_hash);
        if me_opt == None {
            return Err("Block hash not found!".to_owned());
        }
        let me: usize = *me_opt.unwrap();
        let block_height = inner.arena[me].height;
        let mut fork_height = block_height;
        let mut chain: Vec<usize> = Vec::new();
        let mut idx = me;
        while fork_height > 0
            && (fork_height >= inner.get_pivot_height()
                || inner.get_pivot_block_index(fork_height) != idx)
        {
            chain.push(idx);
            fork_height -= 1;
            idx = inner.arena[idx].parent;
        }
        // Because we have genesis at height 0, this should always be true
        debug_assert!(inner.get_pivot_block_index(fork_height) == idx);
        debug!("Forked at index {} height {}", idx, fork_height);
        chain.push(idx);
        chain.reverse();
        let start_index = ConsensusExecutor::find_start_index(inner, &chain);
        debug!("Start execution from index {}", start_index);

        // We need the state of the fork point to start executing the fork
        if start_index != 0 {
            let mut last_state_height =
                if inner.get_pivot_height() > DEFERRED_STATE_EPOCH_COUNT {
                    inner.get_pivot_height() - DEFERRED_STATE_EPOCH_COUNT
                } else {
                    0
                };

            last_state_height += 1;
            while last_state_height <= fork_height {
                let epoch_index =
                    inner.get_pivot_block_index(last_state_height);
                let reward_execution_info = inner.get_reward_execution_info(
                    &self.handler.data_man,
                    epoch_index,
                );
                self.enqueue_epoch(EpochExecutionTask::new(
                    inner.arena[epoch_index].hash,
                    inner.get_epoch_block_hashes(epoch_index),
                    reward_execution_info,
                    false,
                    false,
                ));
                last_state_height += 1;
            }
        }

        for fork_index in start_index..chain.len() {
            let epoch_index = chain[fork_index];
            let reward_index = inner.get_pivot_reward_index(epoch_index);

            let reward_execution_info = inner
                .get_reward_execution_info_from_index(
                    &self.handler.data_man,
                    reward_index,
                );
            self.enqueue_epoch(EpochExecutionTask::new(
                inner.arena[epoch_index].hash,
                inner.get_epoch_block_hashes(epoch_index),
                reward_execution_info,
                false,
                false,
            ));
        }

        let (state_root, receipts_root, logs_bloom_hash) =
            self.wait_for_result(*block_hash);
        debug!(
            "Epoch {:?} has state_root={:?} receipts_root={:?} logs_bloom_hash={:?}",
            inner.arena[me].hash, state_root, receipts_root, logs_bloom_hash
        );

        Ok((state_root, receipts_root, logs_bloom_hash))
    }
}

pub struct ConsensusExecutionHandler {
    tx_pool: SharedTransactionPool,
    data_man: Arc<BlockDataManager>,
    pub vm: VmFactory,
}

impl ConsensusExecutionHandler {
    pub fn new(
        tx_pool: SharedTransactionPool, data_man: Arc<BlockDataManager>,
        vm: VmFactory,
    ) -> Self
    {
        ConsensusExecutionHandler {
            tx_pool,
            data_man,
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
            Ok(ExecutionTask::Stop) => {
                debug!("Consensus Executor stopped by receiving STOP task");
                false
            }
            Ok(task) => self.handle_execution_work(task),
            Err(e) => {
                warn!("Consensus Executor stopped by Err={:?}", e);
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
            _ => {}
        }
        true
    }

    fn handle_epoch_execution(&self, task: EpochExecutionTask) {
        self.compute_epoch(
            &task.epoch_hash,
            &task.epoch_block_hashes,
            &task.reward_info,
            task.on_local_pivot,
            &mut *task.debug_record.lock(),
        );
    }

    fn handle_get_result_task(&self, task: GetExecutionResultTask) {
        let state_root = self
            .data_man
            .storage_manager
            .get_state_no_commit(SnapshotAndEpochIdRef::new(
                &task.epoch_hash,
                None,
            ))
            .unwrap()
            // Unwrapping is safe because the state is assumed to exist.
            .unwrap()
            .get_state_root()
            .unwrap()
            .unwrap();

        let receipts_root =
            self.data_man.get_receipts_root(&task.epoch_hash).unwrap();

        let logs_bloom_hash =
            self.data_man.get_logs_bloom_hash(&task.epoch_hash).unwrap();

        task.sender
            .send((state_root, receipts_root, logs_bloom_hash))
            .expect("Consensus Worker fails");
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
        reward_execution_info: &Option<RewardExecutionInfo>,
        on_local_pivot: bool,
        debug_record: &mut Option<ComputeEpochDebugRecord>,
    )
    {
        // Check if the state has been computed
        if debug_record.is_none()
            && self.data_man.epoch_executed_and_recovered(
                &epoch_hash,
                &epoch_block_hashes,
                on_local_pivot,
            )
        {
            if on_local_pivot {
                *self.tx_pool.best_executed_epoch.lock() = *epoch_hash;
            }
            debug!("Skip execution in prefix {:?}", epoch_hash);
            return;
        }

        // Get blocks in this epoch after skip checking
        let epoch_blocks = self
            .data_man
            .blocks_by_hash_list(epoch_block_hashes, true)
            .expect("blocks exist");
        let pivot_block = epoch_blocks.last().expect("Not empty");

        debug!(
            "Process tx epoch_id={}, block_count={}",
            epoch_hash,
            epoch_blocks.len()
        );

        let mut state = State::new(
            StateDb::new(
                self.data_man
                    .storage_manager
                    .get_state_for_next_epoch(
                        // FIXME: delta height.
                        SnapshotAndEpochIdRef::new(
                            pivot_block.block_header.parent_hash(),
                            Some(pivot_block.block_header.height() - 1),
                        ),
                    )
                    .unwrap()
                    // Unwrapping is safe because the state exists.
                    .unwrap(),
            ),
            0.into(),
            self.vm.clone(),
        );
        self.process_epoch_transactions(
            &mut state,
            &epoch_blocks,
            on_local_pivot,
        );

        if let Some(reward_execution_info) = reward_execution_info {
            // Calculate the block reward for blocks inside the epoch
            // All transaction fees are shared among blocks inside one epoch
            self.process_rewards_and_fees(
                &mut state,
                &reward_execution_info,
                on_local_pivot,
                debug_record,
            );
        }

        // FIXME: We may want to propagate the error up
        let state_root = if on_local_pivot {
            state.commit_and_notify(*epoch_hash, &self.tx_pool).unwrap();
            *self.tx_pool.best_executed_epoch.lock() = *epoch_hash;
        } else {
            state.commit(*epoch_hash).unwrap();
        };
        debug!(
            "compute_epoch: on_local_pivot={}, epoch={:?} state_root={:?} receipt_root={:?}, logs_bloom_hash={:?}",
            on_local_pivot,
            epoch_hash,
            state_root,
            self
                .data_man
                .get_receipts_root(&epoch_hash)
                .unwrap(),
            self
                .data_man
                .get_logs_bloom_hash(&epoch_hash)
                .unwrap()
        );
    }

    fn process_epoch_transactions(
        &self, state: &mut State, epoch_blocks: &Vec<Arc<Block>>,
        on_local_pivot: bool,
    ) -> Vec<Arc<Vec<Receipt>>>
    {
        let pivot_block = epoch_blocks.last().expect("Epoch not empty");
        let spec = Spec::new_spec();
        let machine = new_machine();
        let mut epoch_receipts = Vec::with_capacity(epoch_blocks.len());
        let mut to_pending = Vec::new();
        for block in epoch_blocks.iter() {
            let mut receipts = Vec::new();
            debug!(
                "process txs in block: hash={:?}, tx count={:?}",
                block.hash(),
                block.transactions.len()
            );
            let mut env = Env {
                number: 0, // TODO: replace 0 with correct block number
                author: block.block_header.author().clone(),
                timestamp: block.block_header.timestamp(),
                difficulty: block.block_header.difficulty().clone(),
                gas_used: U256::zero(),
                last_hashes: Arc::new(vec![]),
                gas_limit: U256::from(block.block_header.gas_limit()),
            };
            let mut accumulated_fee: U256 = 0.into();
            let mut n_invalid_nonce = 0;
            let mut n_ok = 0;
            let mut n_other = 0;
            let mut cumulative_gas_used = U256::zero();
            for (idx, transaction) in block.transactions.iter().enumerate() {
                let mut tx_outcome_status = TRANSACTION_OUTCOME_EXCEPTION;
                let mut transaction_logs = Vec::new();

                let r = {
                    Executive::new(state, &env, &machine, &spec)
                        .transact(transaction)
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
                        env.gas_used = executed.cumulative_gas_used;
                        cumulative_gas_used = executed.cumulative_gas_used;
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
                    cumulative_gas_used,
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
                        self.data_man
                            .insert_transaction_address_to_kv(&hash, &tx_addr);
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

        self.data_man.insert_receipts_root(
            pivot_block.hash(),
            BlockHeaderBuilder::compute_block_receipts_root(&epoch_receipts),
        );

        self.data_man.insert_logs_bloom_hash(
            pivot_block.hash(),
            BlockHeaderBuilder::compute_block_logs_bloom_hash(&epoch_receipts),
        );

        if on_local_pivot {
            self.tx_pool.recycle_transactions(to_pending);
        }

        debug!("Finish processing tx for epoch");
        epoch_receipts
    }

    /// `epoch_block_states` includes if a block is partial invalid and its
    /// anticone difficulty
    fn process_rewards_and_fees(
        &self, state: &mut State, reward_info: &RewardExecutionInfo,
        on_local_pivot: bool,
        debug_record: &mut Option<ComputeEpochDebugRecord>,
    )
    {
        /// (Fee, SetOfPackingBlockHash)
        struct TxExecutionInfo(U256, BTreeSet<H256>);

        let epoch_blocks = &reward_info.epoch_blocks;
        let pivot_block = epoch_blocks.last().expect("Not empty");
        let reward_epoch_hash = pivot_block.hash();
        debug!("Process rewards and fees for {:?}", reward_epoch_hash);
        let epoch_difficulty = pivot_block.block_header.difficulty();

        let epoch_size = epoch_blocks.len();
        let mut epoch_block_total_rewards = Vec::with_capacity(epoch_size);

        // Base reward and anticone penalties.
        for (enum_idx, block) in epoch_blocks.iter().enumerate() {
            let anticone_overlimited =
                reward_info.epoch_block_anticone_overlimited[enum_idx];

            if anticone_overlimited {
                epoch_block_total_rewards.push(U256::from(0));
                if debug_record.is_some() {
                    let debug_out = debug_record.as_mut().unwrap();
                    debug_out.anticone_overlimit_blocks.push(block.hash());
                }
            } else {
                let mut reward = if block.block_header.pow_quality
                    >= *epoch_difficulty
                {
                    U512::from(BASE_MINING_REWARD) * U512::from(CONFLUX_TOKEN)
                } else {
                    debug!(
                        "Block {} pow_quality {} is less than epoch_difficulty {}!",
                        block.hash(), block.block_header.pow_quality, epoch_difficulty
                    );
                    0.into()
                };

                if debug_record.is_some() {
                    let debug_out = debug_record.as_mut().unwrap();
                    debug_out.block_rewards.push(BlockHashAuthorValue(
                        block.hash(),
                        block.block_header.author().clone(),
                        U256::from(reward),
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
                        / U512::from(ANTICONE_PENALTY_RATIO)
                        / U512::from(ANTICONE_PENALTY_RATIO);
                    // Lint.ThenChange(consensus/mod.rs#ANTICONE_PENALTY_1)

                    debug_assert!(reward > anticone_penalty);
                    reward -= anticone_penalty;

                    if debug_record.is_some() {
                        let debug_out = debug_record.as_mut().unwrap();
                        debug_out.anticone_penalties.push(
                            BlockHashAuthorValue(
                                block.hash(),
                                block.block_header.author().clone(),
                                U256::from(anticone_penalty),
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
                epoch_block_total_rewards.push(U256::from(reward));
            }
        }

        // Tx fee for each block in this epoch
        let mut tx_fee = HashMap::new();

        // Compute tx_fee of each block based on gas_used and gas_price of every
        // tx
        let mut epoch_receipts = None;
        for (enum_idx, block) in epoch_blocks.iter().enumerate() {
            let block_hash = block.hash();
            // TODO: better redesign to avoid recomputation.
            let receipts = match self.data_man.block_results_by_hash_with_epoch(
                &block_hash,
                &reward_epoch_hash,
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
                        epoch_receipts = Some(self.recompute_states(
                            &reward_epoch_hash,
                            &epoch_blocks,
                        ));
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
                    .or_insert(TxExecutionInfo(fee, BTreeSet::default()));
                // The same transaction is executed only once.
                debug_assert!(
                    fee.is_zero() || info.0.is_zero() || info.1.len() == 0
                );
                // `false` means the block is fully valid
                // Partial invalid blocks will not share the tx fee
                if reward_info.epoch_block_anticone_overlimited[enum_idx]
                    == false
                {
                    info.1.insert(block_hash);
                }
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

        for (enum_idx, block) in epoch_blocks.iter().enumerate() {
            let reward = &mut epoch_block_total_rewards[enum_idx];
            let block_hash = block.hash();
            // Add tx fee to reward.
            if let Some(fee) = block_tx_fees.get(&block_hash) {
                *reward += *fee;
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
                .or_insert(U256::from(0)) += *reward;

            if debug_record.is_some() {
                let debug_out = debug_record.as_mut().unwrap();
                debug_out.block_final_rewards.push(BlockHashAuthorValue(
                    block_hash,
                    block.block_header.author().clone(),
                    *reward,
                ));
            }
            if on_local_pivot {
                self.data_man
                    .receipts_retain_epoch(&block_hash, &reward_epoch_hash);
            }
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
                    key: address.hex().as_bytes().to_vec(),
                    maybe_value: Some(reward.to_hex().as_bytes().to_vec()),
                });
            }
        }
    }

    fn recompute_states(
        &self, pivot_hash: &H256, epoch_blocks: &Vec<Arc<Block>>,
    ) -> Vec<Arc<Vec<Receipt>>> {
        debug!(
            "Recompute receipts epoch_id={}, block_count={}",
            pivot_hash,
            epoch_blocks.len(),
        );
        let pivot_block = epoch_blocks.last().expect("Not empty");
        let mut state = State::new(
            StateDb::new(
                self.data_man
                    .storage_manager
                    .get_state_for_next_epoch(
                        // FIXME: delta height
                        SnapshotAndEpochIdRef::new(
                            pivot_block.block_header.parent_hash(),
                            Some(pivot_block.block_header.height() - 1),
                        ),
                    )
                    .unwrap()
                    // Unwrapping is safe because the state exists.
                    .unwrap(),
            ),
            0.into(),
            self.vm.clone(),
        );
        self.process_epoch_transactions(&mut state, &epoch_blocks, false)
    }

    pub fn call_virtual(
        &self, tx: &SignedTransaction, epoch_id: &H256,
    ) -> Result<(Vec<u8>, U256), String> {
        let spec = Spec::new_spec();
        let machine = new_machine();
        let mut state = State::new(
            StateDb::new(
                self.data_man
                    .storage_manager
                    .get_state_no_commit(SnapshotAndEpochIdRef::new(
                        epoch_id, None,
                    ))
                    .unwrap()
                    // Unwrapping is safe because the state exists.
                    .unwrap(),
            ),
            0.into(),
            self.vm.clone(),
        );
        let env = Env {
            number: 0, // TODO: replace 0 with correct cardinal number
            author: Default::default(),
            timestamp: Default::default(),
            difficulty: Default::default(),
            gas_used: U256::zero(),
            last_hashes: Arc::new(vec![]),
            gas_limit: tx.gas.clone(),
        };
        let mut ex = Executive::new(&mut state, &env, &machine, &spec);
        let r = ex.transact(tx);
        trace!("Execution result {:?}", r);
        r.map(|r| (r.output, r.gas_used))
            .map_err(|e| format!("execution error: {:?}", e))
    }
}
