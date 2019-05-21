use crate::{
    block_data_manager::BlockDataManager,
    cache_manager::CacheId,
    consensus::{ANTICONE_PENALTY_RATIO, BASE_MINING_REWARD, CONFLUX_TOKEN},
    executive::{ExecutionError, Executive},
    machine::new_machine,
    state::{CleanupMode, State},
    statedb::StateDb,
    storage::{state::StateTrait, state_manager::StateManagerTrait},
    vm::{EnvInfo, Spec},
    vm_factory::VmFactory,
};
use cfx_types::{Address, H256, U256, U512};
use parking_lot::Mutex;
use primitives::{
    receipt::{
        Receipt, TRANSACTION_OUTCOME_EXCEPTION, TRANSACTION_OUTCOME_SUCCESS,
    },
    Block, BlockHeaderBuilder, SignedTransaction, TransactionAddress,
};
use std::{
    collections::{btree_set::BTreeSet, HashMap, HashSet},
    sync::{
        mpsc::{channel, Sender},
        Arc,
    },
    thread::{self, JoinHandle},
};

/// The struct includes all the information to compute rewards for old epochs
#[derive(Debug)]
pub struct RewardExecutionInfo {
    pub pivot_hash: H256,
    pub epoch_block_hashes: Vec<H256>,
    pub epoch_block_states: Vec<(bool, U512)>,
}

#[derive(Debug)]
pub enum ExecutionTask {
    ExecuteEpoch(EpochExecutionTask),
    GetResult(GetExecutionResultTask),
    Stop,
}

/// The struct includes all the information needed to execute an epoch
#[derive(Debug)]
pub struct EpochExecutionTask {
    pub epoch_hash: H256,
    pub epoch_block_hashes: Vec<H256>,
    pub reward_info: Option<RewardExecutionInfo>,
    pub on_local_pivot: bool,
}

/// `sender` is used to return the computed `(state_root, receipts_root)` to the
/// thread who sends this task.
#[derive(Debug)]
pub struct GetExecutionResultTask {
    pub epoch_hash: H256,
    pub sender: Sender<(H256, H256)>,
}

pub struct ConsensusExecutor {
    /// The thread responsible for execution transactions
    thread: Mutex<Option<JoinHandle<()>>>,

    /// The sender to send tasks to be executed by `self.thread`
    sender: Mutex<Sender<ExecutionTask>>,

    /// The handler to provide functions to handle `ExecutionTask` and execute
    /// transactions It is used both asynchronously by `self.thread` and
    /// synchronously by the executor itself
    pub handler: Arc<ConsensusExecutionHandler>,
}

impl ConsensusExecutor {
    pub fn start(data_man: Arc<BlockDataManager>, vm: VmFactory) -> Self {
        let handler = Arc::new(ConsensusExecutionHandler::new(data_man, vm));
        let (sender, receiver) = channel();

        let executor = ConsensusExecutor {
            thread: Mutex::new(None),
            sender: Mutex::new(sender),
            handler: handler.clone(),
        };
        // It receives blocks hashes from on_new_block and execute them
        let handle = thread::Builder::new()
            .name("Consensus Execution Worker".into())
            .spawn(move || loop {
                match receiver.recv() {
                    Ok(ExecutionTask::Stop) => {
                        debug!(
                            "Consensus Executor stopped by receiving STOP task"
                        );
                        break;
                    }
                    Ok(task) => handler.handle_execution_work(task),
                    Err(e) => {
                        warn!("Consensus Executor stopped by Err={:?}", e);
                        break;
                    }
                }
            })
            .expect("Cannot fail");
        *executor.thread.lock() = Some(handle);
        executor
    }

    /// Wait until all tasks currently in the queue to be executed and return
    /// `(state_root, receipts_root)` of the given `epoch_hash`.
    ///
    /// It is the caller's responsibility to ensure that `epoch_hash` is indeed
    /// computed when all the tasks before are finished.
    // TODO Release Consensus inner lock if possible when the function is called
    pub fn wait_for_result(&self, epoch_hash: H256) -> (H256, H256) {
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

    /// Enqueue the epoch to be executed by the background execution thread
    /// The parameters are needed for the thread to execute this epoch without
    /// holding inner lock.
    pub fn enqueue_epoch(
        &self, epoch_hash: H256, epoch_block_hashes: Vec<H256>,
        reward_info: Option<RewardExecutionInfo>, on_local_pivot: bool,
    ) -> bool
    {
        self.sender
            .lock()
            .send(ExecutionTask::ExecuteEpoch(EpochExecutionTask {
                epoch_hash,
                epoch_block_hashes,
                reward_info,
                on_local_pivot,
            }))
            .is_ok()
    }

    /// Execute the epoch synchronously
    pub fn compute_epoch(
        &self, epoch_hash: &H256, epoch_block_hashes: &Vec<H256>,
        reward_execution_info: &Option<RewardExecutionInfo>,
        on_local_pivot: bool,
    )
    {
        self.handler.compute_epoch(
            epoch_hash,
            epoch_block_hashes,
            reward_execution_info,
            on_local_pivot,
        )
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
}

pub struct ConsensusExecutionHandler {
    data_man: Arc<BlockDataManager>,
    pub vm: VmFactory,
}

impl ConsensusExecutionHandler {
    pub fn new(data_man: Arc<BlockDataManager>, vm: VmFactory) -> Self {
        ConsensusExecutionHandler { data_man, vm }
    }

    fn handle_execution_work(&self, task: ExecutionTask) {
        debug!("Receive execution task: {:?}", task);
        match task {
            ExecutionTask::ExecuteEpoch(task) => {
                self.handle_epoch_execution(task)
            }
            ExecutionTask::GetResult(task) => self.handle_get_result(task),
            _ => {}
        }
    }

    fn handle_epoch_execution(&self, task: EpochExecutionTask) {
        self.compute_epoch(
            &task.epoch_hash,
            &task.epoch_block_hashes,
            &task.reward_info,
            task.on_local_pivot,
        );
    }

    fn handle_get_result(&self, task: GetExecutionResultTask) {
        let state_root = self
            .data_man
            .storage_manager
            .get_state_at(task.epoch_hash)
            .unwrap()
            .get_state_root()
            .unwrap()
            .unwrap();

        let receipts_root =
            self.data_man.get_receipts_root(&task.epoch_hash).unwrap();
        task.sender
            .send((state_root, receipts_root))
            .expect("Consensus Worker fails");
    }

    /// Compute the epoch `epoch_hash`, and skip it if already computed.
    /// After the function is called, it's assured that the state, the receipt
    /// root, and the receipts of blocks executed by this epoch exist.
    pub fn compute_epoch(
        &self, epoch_hash: &H256, epoch_block_hashes: &Vec<H256>,
        reward_execution_info: &Option<RewardExecutionInfo>,
        on_local_pivot: bool,
    )
    {
        // Check if the state has been computed
        if self.data_man.storage_manager.state_exists(*epoch_hash)
            && self.epoch_executed_and_recovered(
                &epoch_hash,
                &epoch_block_hashes,
                on_local_pivot,
            )
        {
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
                    .get_state_at(*pivot_block.block_header.parent_hash())
                    .unwrap(),
            ),
            0.into(),
            self.vm.clone(),
        );
        self.process_epoch_transactions(
            &mut state,
            &epoch_blocks,
            &self.data_man.txpool.unexecuted_transaction_addresses,
            on_local_pivot,
        );

        if let Some(reward_execution_info) = reward_execution_info {
            // Calculate the block reward for blocks inside the epoch
            // All transaction fees are shared among blocks inside one epoch
            self.process_rewards_and_fees(
                &mut state,
                &reward_execution_info.pivot_hash,
                &reward_execution_info.epoch_block_hashes,
                &reward_execution_info.epoch_block_states,
                on_local_pivot,
            );
        }

        // FIXME: We may want to propagate the error up
        if on_local_pivot {
            state
                .commit_and_notify(*epoch_hash, &self.data_man.txpool)
                .unwrap();
        } else {
            state.commit(*epoch_hash).unwrap();
        }
        debug!(
            "compute_epoch: on_local_pivot={}, epoch={:?} state_root={:?} receipt_root={:?}",
            on_local_pivot,
            epoch_hash,
            self.data_man
                .storage_manager
                .get_state_at(*epoch_hash)
                .unwrap()
                .get_state_root()
                .unwrap(),
            self
                .data_man
                .get_receipts_root(&epoch_hash)
                .unwrap()
        );
    }

    fn process_epoch_transactions(
        &self, state: &mut State, epoch_blocks: &Vec<Arc<Block>>,
        unexecuted_transaction_addresses_lock: &Mutex<
            HashMap<H256, HashSet<TransactionAddress>>,
        >,
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
        self.data_man.insert_receipts_root(
            pivot_block.hash(),
            BlockHeaderBuilder::compute_block_receipts_root(&epoch_receipts),
        );
        if on_local_pivot {
            let parent = pivot_block.block_header.parent_hash();
            if *parent != self.data_man.genesis_block().hash() {
                let state = self
                    .data_man
                    .storage_manager
                    .get_state_at(*parent)
                    .unwrap();
                self.data_man
                    .txpool
                    .recycle_future_transactions(to_pending, state);
            }
        }
        debug!("Finish processing tx for epoch");
        epoch_receipts
    }

    /// `epoch_block_states` includes if a block is partial invalid and its
    /// anticone difficulty
    fn process_rewards_and_fees(
        &self, state: &mut State, pivot_hash: &H256,
        epoch_block_hashes: &Vec<H256>, epoch_block_states: &Vec<(bool, U512)>,
        on_local_pivot: bool,
    )
    {
        /// (Fee, SetOfPackingBlockHash)
        struct TxExecutionInfo(U256, BTreeSet<H256>);

        let epoch_blocks = self
            .data_man
            .blocks_by_hash_list(epoch_block_hashes, false)
            .expect("blocks exist");
        let pivot_block = epoch_blocks.last().expect("Not empty");
        assert!(pivot_block.hash() == *pivot_hash);
        debug!(
            "Process rewards and fees for {:?} with state {:?}",
            pivot_hash, epoch_block_states
        );
        let difficulty = *pivot_block.block_header.difficulty();
        let mut rewards: Vec<(Address, U256)> = Vec::new();

        // Tx fee for each block in this epoch
        let mut tx_fee = HashMap::new();

        // Compute tx_fee of each block based on gas_used and gas_price of every
        // tx
        let mut epoch_receipts = None;
        for (enum_idx, block) in epoch_blocks.iter().enumerate() {
            let block_hash = block.hash();
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
                        epoch_receipts = Some(
                            self.recompute_states(pivot_hash, &epoch_blocks),
                        );
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
                // `false` means the block is fully valid
                // Partial invalid blocks will not share the tx fee
                if epoch_block_states[enum_idx].0 == false {
                    info.1.insert(block_hash);
                }
                if !fee.is_zero() {
                    debug_assert!(info.1.len() == 1 || info.0.is_zero());
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

        for (idx, block) in epoch_blocks.iter().enumerate() {
            // `true` means the block is partial invalid
            if epoch_block_states[idx].0 == true {
                continue;
            }
            let block_hash = block.hash();
            let block_difficulty = block.block_header.difficulty();

            let mut reward: U512 =
                if block.block_header.pow_quality >= difficulty {
                    U512::from(BASE_MINING_REWARD) * U512::from(CONFLUX_TOKEN)
                } else {
                    debug!(
                        "Block {} pow_quality {} is less than difficulty {}!",
                        block_hash, block.block_header.pow_quality, difficulty
                    );
                    0.into()
                };

            // Add tx fee to base reward, and penalize them together
            if let Some(fee) = block_tx_fees.get(&block_hash) {
                reward += U512::from(*fee);
            }

            if reward > 0.into() {
                let anticone_difficulty = epoch_block_states[idx].1;

                let penalty = reward * anticone_difficulty
                    / U512::from(block_difficulty)
                    * anticone_difficulty
                    / U512::from(block_difficulty)
                    / U512::from(ANTICONE_PENALTY_RATIO)
                    / U512::from(ANTICONE_PENALTY_RATIO);

                if penalty > reward {
                    debug!("Block {} penalty {} larger than reward {}! anticone_difficulty={}", block_hash, penalty, reward, anticone_difficulty);
                    reward = 0.into();
                } else {
                    reward -= penalty;
                }
            }

            debug_assert!(reward <= U512::from(U256::max_value()));
            let reward = U256::from(reward);
            rewards.push((*block.block_header.author(), reward));
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
                    .get_state_at(*pivot_block.block_header.parent_hash())
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
        )
    }

    /// Check if all executed results of an epoch exist
    fn epoch_executed_and_recovered(
        &self, epoch_hash: &H256, epoch_block_hashes: &Vec<H256>,
        on_local_pivot: bool,
    ) -> bool
    {
        // `block_receipts_root` is not computed when recovering from db with
        // fast_recover == false And we should force it to recompute
        // without checking receipts when fast_recover == false
        if self.data_man.get_receipts_root(epoch_hash).is_none() {
            return false;
        }
        let mut epoch_receipts = Vec::new();
        for h in epoch_block_hashes {
            if let Some(r) = self
                .data_man
                .block_results_by_hash_with_epoch(h, epoch_hash, true)
            {
                epoch_receipts.push(r.receipts);
            } else {
                return false;
            }
        }

        // Recover tx address if we will skip pivot chain execution
        if on_local_pivot {
            for (block_idx, block_hash) in epoch_block_hashes.iter().enumerate()
            {
                let block = self
                    .data_man
                    .block_by_hash(block_hash, true)
                    .expect("block exists");
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
                                block_hash: *block_hash,
                                index: tx_idx,
                            },
                        )
                    }
                }
            }
        }
        true
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
                    .get_state_at(*epoch_id)
                    .unwrap(),
            ),
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
}
