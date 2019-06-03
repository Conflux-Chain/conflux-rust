// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{Address, H256, U256, U512};
use cfxcore::{
    consensus::{
        ConsensusGraphInner, DEFERRED_STATE_EPOCH_COUNT,
        HEAVY_BLOCK_DIFFICULTY_RATIO,
    },
    pow::*,
    transaction_pool::DEFAULT_MAX_BLOCK_GAS_LIMIT,
    SharedSynchronizationGraph, SharedSynchronizationService,
    SharedTransactionPool,
};
use log::{info, trace, warn};
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};
use primitives::{
    block::{MAX_BLOCK_SIZE_IN_BYTES, MAX_TRANSACTION_COUNT_PER_BLOCK},
    *,
};
use std::{
    sync::{mpsc, Arc},
    thread, time,
};
use time::{SystemTime, UNIX_EPOCH};
use txgen::{SharedTransactionGenerator, SpecialTransactionGenerator};

pub struct BlockGeneratorConfig {
    pub test_chain_path: Option<String>,
}

enum MiningState {
    Start,
    Stop,
}

/// The interface for a conflux block generator
pub struct BlockGenerator {
    pow_config: ProofOfWorkConfig,
    mining_author: Address,
    graph: SharedSynchronizationGraph,
    txpool: SharedTransactionPool,
    txgen: SharedTransactionGenerator,
    special_txgen: Arc<Mutex<SpecialTransactionGenerator>>,
    sync: SharedSynchronizationService,
    state: RwLock<MiningState>,
    workers: Mutex<Vec<(Worker, mpsc::Sender<ProofOfWorkProblem>)>>,
}

pub struct Worker {
    #[allow(dead_code)]
    thread: thread::JoinHandle<()>,
}

impl Worker {
    pub fn new(
        bg: Arc<BlockGenerator>, sender: mpsc::Sender<ProofOfWorkSolution>,
        receiver: mpsc::Receiver<ProofOfWorkProblem>,
    ) -> Self
    {
        let bg_handle = bg.clone();

        let thread = thread::Builder::new()
            .name("blockgen".into())
            .spawn(move || {
                let sleep_duration = time::Duration::from_millis(100);
                let mut problem: Option<ProofOfWorkProblem> = None;

                loop {
                    match *bg_handle.state.read() {
                        MiningState::Stop => return,
                        _ => {}
                    }

                    // check if there is a new problem
                    let new_problem = receiver.try_recv();
                    if new_problem.is_ok() {
                        problem = Some(new_problem.unwrap());
                    }
                    // check if there is a problem to be solved
                    if problem.is_some() {
                        let boundary = problem.unwrap().boundary;
                        let block_hash = problem.unwrap().block_hash;

                        #[cfg(test)]
                        {
                            let difficulty = problem.unwrap().difficulty;
                            if difficulty > 500000.into() {
                                warn!("Difficulty is too high to mine!");
                            }
                        }

                        for _i in 0..100000 {
                            //TODO: adjust the number of times
                            let nonce = rand::random();
                            let hash = compute(nonce, &block_hash);
                            if hash < boundary {
                                // problem solved
                                match sender.send(ProofOfWorkSolution { nonce })
                                {
                                    Ok(_) => {}
                                    Err(e) => {
                                        warn!("{}", e);
                                    }
                                }
                                // TODO Update problem fast. This will cause
                                // miner to stop mining
                                // until the previous blocks is processed by
                                // ConsensusGraph
                                problem = None;
                                break;
                            }
                        }
                    } else {
                        thread::sleep(sleep_duration);
                    }
                }
            })
            .expect("only one blockgen thread, so it should not fail");
        Worker { thread }
    }
}

impl BlockGenerator {
    pub fn new(
        graph: SharedSynchronizationGraph, txpool: SharedTransactionPool,
        sync: SharedSynchronizationService, txgen: SharedTransactionGenerator,
        special_txgen: Arc<Mutex<SpecialTransactionGenerator>>,
        pow_config: ProofOfWorkConfig, mining_author: Address,
    ) -> Self
    {
        BlockGenerator {
            pow_config,
            mining_author,
            graph,
            txpool,
            txgen,
            special_txgen,
            sync,
            state: RwLock::new(MiningState::Start),
            workers: Mutex::new(Vec::new()),
        }
    }

    /// Stop mining
    pub fn stop(bg: &BlockGenerator) {
        {
            let mut write = bg.state.write();
            *write = MiningState::Stop;
        }
        bg.txgen.stop()
    }

    /// Send new PoW problem to workers
    pub fn send_problem(bg: Arc<BlockGenerator>, problem: ProofOfWorkProblem) {
        for item in bg.workers.lock().iter() {
            item.1
                .send(problem)
                .expect("Failed to send the PoW problem.")
        }
    }

    // TODO: should not hold and pass write lock to consensus.
    fn assemble_new_block_impl(
        &self, parent_hash: H256, referee: Vec<H256>,
        deferred_state_root: H256, deferred_receipts_root: H256,
        block_gas_limit: U256, transactions: Vec<Arc<SignedTransaction>>,
        difficulty: u64, consensus_inner: &mut ConsensusGraphInner,
    ) -> Block
    {
        let parent_height =
            self.graph.block_height_by_hash(&parent_hash).unwrap();

        trace!("{} txs packed", transactions.len());

        let mut expected_difficulty =
            self.graph.inner.read().expected_difficulty(&parent_hash);
        if self.graph.check_mining_heavy_block(
            consensus_inner,
            &parent_hash,
            &expected_difficulty,
        ) {
            assert!(
                U512::from(HEAVY_BLOCK_DIFFICULTY_RATIO)
                    * U512::from(expected_difficulty)
                    < U512::from(U256::max_value())
            );
            expected_difficulty =
                U256::from(HEAVY_BLOCK_DIFFICULTY_RATIO) * expected_difficulty;
        }
        if U256::from(difficulty) > expected_difficulty {
            expected_difficulty = U256::from(difficulty);
        }

        let block_header = BlockHeaderBuilder::new()
            .with_transactions_root(Block::compute_transaction_root(
                &transactions,
            ))
            .with_parent_hash(parent_hash)
            .with_height(parent_height + 1)
            .with_timestamp(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            //            .with_timestamp(0)
            .with_author(self.mining_author)
            .with_deferred_state_root(deferred_state_root)
            .with_deferred_receipts_root(deferred_receipts_root)
            .with_difficulty(expected_difficulty)
            .with_referee_hashes(referee)
            .with_nonce(0)
            .with_gas_limit(block_gas_limit)
            .build();

        Block::new(block_header, transactions)
    }

    /// Assemble a new block with specified parent and referee, this is for test
    /// only
    pub fn assemble_new_fixed_block(
        &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize,
        difficulty: u64,
    ) -> Block
    {
        let (state_root, receipts_root) =
            self.graph.consensus.compute_deferred_state_for_block(
                &parent_hash,
                DEFERRED_STATE_EPOCH_COUNT as usize - 1,
            );

        let block_gas_limit = DEFAULT_MAX_BLOCK_GAS_LIMIT.into();
        let block_size_limit = MAX_BLOCK_SIZE_IN_BYTES;

        let transactions = self.txpool.pack_transactions(
            num_txs,
            block_gas_limit,
            block_size_limit,
            self.txgen.get_best_state(),
        );

        self.assemble_new_block_impl(
            parent_hash,
            referee,
            state_root,
            receipts_root,
            block_gas_limit,
            transactions,
            difficulty,
            &mut *self.graph.consensus.inner.write(),
        )
    }

    /// Assemble a new block without nonce
    pub fn assemble_new_block(
        &self, num_txs: usize, block_size_limit: usize,
        additional_transactions: Vec<Arc<SignedTransaction>>,
    ) -> Block
    {
        // get the best block
        let (guarded, best_info) = self.graph.get_best_info().into();

        let best_block_hash = best_info.best_block_hash;
        let mut referee = best_info.terminal_block_hashes;
        referee.retain(|r| *r != best_block_hash);
        let block_gas_limit = DEFAULT_MAX_BLOCK_GAS_LIMIT.into();

        let transactions_from_pool = self.txpool.pack_transactions(
            num_txs,
            block_gas_limit,
            block_size_limit,
            self.txgen
                .get_best_state_at(&guarded.best_state_block_hash()),
        );
        let transactions = [
            additional_transactions.as_slice(),
            transactions_from_pool.as_slice(),
        ]
        .concat();

        self.assemble_new_block_impl(
            best_block_hash,
            referee,
            best_info.deferred_state_root,
            best_info.deferred_receipts_root,
            block_gas_limit,
            transactions,
            0,
            &mut *RwLockUpgradableReadGuard::upgrade(guarded),
        )
    }

    /// Update and sync a new block
    pub fn on_mined_block(&self, block: Block) {
        self.sync.on_mined_block(block);
    }

    /// Check if we need to mine on a new block
    pub fn is_mining_block_outdated(&self, block: Option<&Block>) -> bool {
        if block.is_none() {
            return true;
        }

        // 1st Check: if the parent block changed
        let best_block_hash =
            self.graph.get_best_info().as_ref().best_block_hash;
        if best_block_hash != *block.unwrap().block_header.parent_hash() {
            return true;
        }
        // TODO: 2nd check: if the referee hashes changed
        // TODO: 3rd check: if we want to pack a new set of transactions
        false
    }

    pub fn generate_special_transactions(
        &self, block_size_limit: &mut usize, num_txs_simple: usize,
        num_txs_erc20: usize,
    ) -> Vec<Arc<SignedTransaction>>
    {
        self.special_txgen.lock().generate_transactions(
            block_size_limit,
            num_txs_simple,
            num_txs_erc20,
        )
    }

    /// Generate a block with fake transactions
    pub fn generate_block_with_transactions(
        &self, num_txs: usize, block_size_limit: usize,
    ) -> H256 {
        let mut txs = Vec::new();
        for _ in 0..num_txs {
            let tx = self.txgen.generate_transaction();
            txs.push(tx);
        }
        self.generate_block(
            num_txs,
            block_size_limit,
            txs.into_iter().map(|tx| Arc::new(tx)).collect(),
        )
    }

    pub fn generate_fixed_block(
        &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize,
        difficulty: u64,
    ) -> H256
    {
        let block = self.assemble_new_fixed_block(
            parent_hash,
            referee,
            num_txs,
            difficulty,
        );
        self.generate_block_impl(block)
    }

    /// Generate a block with transactions in the pool
    pub fn generate_block(
        &self, num_txs: usize, block_size_limit: usize,
        additional_transactions: Vec<Arc<SignedTransaction>>,
    ) -> H256
    {
        let block = self.assemble_new_block(
            num_txs,
            block_size_limit,
            additional_transactions,
        );
        self.generate_block_impl(block)
    }

    pub fn generate_custom_block(
        &self, transactions: Vec<Arc<SignedTransaction>>,
    ) -> H256 {
        // get the best block
        let (consensus_guard, best_info) = self.graph.get_best_info().into();
        let best_block_hash = best_info.best_block_hash;
        let mut referee = best_info.terminal_block_hashes;
        referee.retain(|r| *r != best_block_hash);
        let block_gas_limit = DEFAULT_MAX_BLOCK_GAS_LIMIT.into();

        let block = self.assemble_new_block_impl(
            best_block_hash,
            referee,
            best_info.deferred_state_root,
            best_info.deferred_receipts_root,
            block_gas_limit,
            transactions,
            0,
            &mut *RwLockUpgradableReadGuard::upgrade(consensus_guard),
        );

        self.generate_block_impl(block)
    }

    pub fn generate_custom_block_with_parent(
        &self, parent_hash: H256, referee: Vec<H256>,
        transactions: Vec<Arc<SignedTransaction>>,
    ) -> H256
    {
        let (state_root, receipts_root) =
            self.graph.consensus.compute_deferred_state_for_block(
                &parent_hash,
                DEFERRED_STATE_EPOCH_COUNT as usize - 1,
            );

        let block = self.assemble_new_block_impl(
            parent_hash,
            referee,
            state_root,
            receipts_root,
            DEFAULT_MAX_BLOCK_GAS_LIMIT.into(),
            transactions,
            0,
            &mut *self.graph.consensus.inner.write(),
        );

        self.generate_block_impl(block)
    }

    fn generate_block_impl(&self, block_init: Block) -> H256 {
        let mut block = block_init;
        let difficulty = block.block_header.difficulty();
        let problem = ProofOfWorkProblem {
            block_hash: block.block_header.problem_hash(),
            difficulty: *difficulty,
            boundary: difficulty_to_boundary(difficulty),
        };
        loop {
            let nonce = rand::random();
            if validate(&problem, &ProofOfWorkSolution { nonce }) {
                block.block_header.set_nonce(nonce);
                break;
            }
        }
        let hash = block.block_header.compute_hash();
        info!(
            "generate_block with block header:{:?} tx_number:{}, block_size:{}",
            block.block_header,
            block.transactions.len(),
            block.size(),
        );
        self.on_mined_block(block);

        // Ensure that when `generate**` function returns, the block has been
        // handled by Consensus This order is assumed by some tests, and
        // this function is also only used in tests.
        self.graph.consensus.wait_for_best_state_block_execution();

        hash
    }

    pub fn pow_config(&self) -> ProofOfWorkConfig {
        return self.pow_config.clone();
    }

    /// Start num_worker new workers
    pub fn start_new_worker(
        num_worker: u32, bg: Arc<BlockGenerator>,
    ) -> mpsc::Receiver<ProofOfWorkSolution> {
        let (tx, rx) = mpsc::channel();
        let mut workers = bg.workers.lock();
        for _ in 0..num_worker {
            let (sender_handle, receiver_handle) = mpsc::channel();
            workers.push((
                Worker::new(bg.clone(), tx.clone(), receiver_handle),
                sender_handle,
            ));
        }
        rx
    }

    pub fn start_mining(bg: Arc<BlockGenerator>, _payload_len: u32) {
        let mut current_mining_block = None;
        let mut current_problem: Option<ProofOfWorkProblem> = None;
        // FIXME: change to notification.
        let sleep_duration = time::Duration::from_millis(50);

        let receiver: mpsc::Receiver<ProofOfWorkSolution> =
            BlockGenerator::start_new_worker(1, bg.clone());

        loop {
            match *bg.state.read() {
                MiningState::Stop => return,
                _ => {}
            }

            if bg.is_mining_block_outdated(current_mining_block.as_ref()) {
                // TODO: #transations TBD
                if bg.sync.catch_up_mode() {
                    thread::sleep(sleep_duration);
                    continue;
                }

                current_mining_block = Some(bg.assemble_new_block(
                    MAX_TRANSACTION_COUNT_PER_BLOCK,
                    MAX_BLOCK_SIZE_IN_BYTES,
                    vec![],
                ));

                // set a mining problem
                let current_difficulty = current_mining_block
                    .as_ref()
                    .unwrap()
                    .block_header
                    .difficulty();
                let problem = ProofOfWorkProblem {
                    block_hash: current_mining_block
                        .as_ref()
                        .unwrap()
                        .block_header
                        .problem_hash(),
                    difficulty: *current_difficulty,
                    boundary: difficulty_to_boundary(current_difficulty),
                };
                BlockGenerator::send_problem(bg.clone(), problem);
                current_problem = Some(problem);
            } else {
                // check if the problem solved
                let mut new_solution = receiver.try_recv();
                loop {
                    // check if the block received valid
                    if new_solution.is_ok()
                        && !validate(
                            &current_problem.unwrap(),
                            &new_solution.unwrap(),
                        )
                    {
                        new_solution = receiver.try_recv();
                    } else {
                        break;
                    }
                }
                if new_solution.is_ok() {
                    let solution = new_solution.unwrap();
                    current_mining_block
                        .as_mut()
                        .unwrap()
                        .block_header
                        .set_nonce(solution.nonce);
                    current_mining_block
                        .as_mut()
                        .unwrap()
                        .block_header
                        .compute_hash();
                    bg.on_mined_block(current_mining_block.unwrap());
                    current_mining_block = None;
                    current_problem = None;
                } else {
                    // wait a moment and check again
                    thread::sleep(sleep_duration);
                    continue;
                }
            }
        }
    }
}
