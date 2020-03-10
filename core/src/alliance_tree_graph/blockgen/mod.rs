// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    alliance_tree_graph::consensus::TreeGraphConsensus, block_parameters::*,
    pow::*, transaction_pool::DEFAULT_MAX_BLOCK_GAS_LIMIT, BlockDataManager,
    SharedSynchronizationService, SharedTransactionPool, Stopable,
};
use cfx_types::{Address, H256, U256};
use log::trace;
//use metrics::{Gauge, GaugeUsize};
use parking_lot::RwLock;
use primitives::*;
use rand::Rng;
use std::{cmp::max, sync::Arc, thread, time};
use time::{Duration, SystemTime, UNIX_EPOCH};

pub struct TGBlockGenerator {
    pub pow_config: ProofOfWorkConfig,
    mining_author: Address,
    data_man: Arc<BlockDataManager>,
    txpool: SharedTransactionPool,
    //txgen: SharedTransactionGenerator,
    sync: SharedSynchronizationService,
    stopped: RwLock<bool>,
    //workers: Mutex<Vec<(Worker, mpsc::Sender<ProofOfWorkProblem>)>>,
}

impl TGBlockGenerator {
    pub fn new(
        data_man: Arc<BlockDataManager>, txpool: SharedTransactionPool,
        sync: SharedSynchronizationService, pow_config: ProofOfWorkConfig,
        mining_author: Address,
    ) -> Self
    {
        TGBlockGenerator {
            pow_config,
            mining_author,
            data_man,
            txpool,
            sync,
            stopped: RwLock::new(false),
        }
    }

    pub fn stop(&self) { *self.stopped.write() = true; }

    pub fn start(&self) {}

    /// Update and sync a new block
    pub fn on_mined_block(&self, block: Block) {
        self.sync.on_mined_block(block);
    }

    pub fn assemble_new_block(
        data_man: &Arc<BlockDataManager>, txpool: &SharedTransactionPool,
        parent_hash: H256, referee: Vec<H256>, deferred_state_root: H256,
        deferred_receipts_root: H256, deferred_logs_bloom_hash: H256,
        num_txs: usize,
    ) -> Block
    {
        let block_gas_limit = DEFAULT_MAX_BLOCK_GAS_LIMIT.into();
        let block_size_limit = MAX_BLOCK_SIZE_IN_BYTES;

        let transactions = txpool.pack_transactions(
            num_txs,
            block_gas_limit,
            block_size_limit,
        );

        let mut rng = rand::thread_rng();
        let parent_header = data_man
            .block_header_by_hash(&parent_hash)
            .expect("parent header must exist");
        let parent_height = parent_header.height();
        let parent_timestamp = parent_header.timestamp();

        trace!("{} txs packed", transactions.len());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Adjust the timestamp of the currently mined block to be later
        // than or equal to its parent's.
        // See comments in verify_header_graph_ready_block()
        let my_timestamp = max(parent_timestamp, now);

        let block_header = BlockHeaderBuilder::new()
            .with_transactions_root(Block::compute_transaction_root(
                &transactions,
            ))
            .with_parent_hash(parent_hash)
            .with_height(parent_height + 1)
            .with_timestamp(my_timestamp)
            //.with_author(self.mining_author)
            .with_deferred_state_root(deferred_state_root)
            .with_deferred_receipts_root(deferred_receipts_root)
            .with_deferred_logs_bloom_hash(deferred_logs_bloom_hash)
            .with_referee_hashes(referee)
            .with_nonce(rng.gen())
            .with_gas_limit(block_gas_limit)
            .build();

        Block::new(block_header, transactions)
    }

    pub fn assemble_new_block_with_transaction(
        &self, parent_hash: H256, referee: Vec<H256>,
        deferred_state_root: H256, deferred_receipts_root: H256,
        deferred_logs_bloom_hash: H256, block_gas_limit: U256,
        transactions: Vec<Arc<SignedTransaction>>,
    ) -> Block
    {
        let mut rng = rand::thread_rng();
        let parent_header = self
            .data_man
            .block_header_by_hash(&parent_hash)
            .expect("parent header must exist");
        let parent_height = parent_header.height();
        let parent_timestamp = parent_header.timestamp();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Adjust the timestamp of the currently mined block to be later
        // than or equal to its parent's.
        // See comments in verify_header_graph_ready_block()
        let my_timestamp = max(parent_timestamp, now);

        let block_header = BlockHeaderBuilder::new()
            .with_transactions_root(Block::compute_transaction_root(
                &transactions,
            ))
            .with_parent_hash(parent_hash)
            .with_height(parent_height + 1)
            .with_timestamp(my_timestamp)
            .with_author(self.mining_author)
            .with_deferred_state_root(deferred_state_root)
            .with_deferred_receipts_root(deferred_receipts_root)
            .with_deferred_logs_bloom_hash(deferred_logs_bloom_hash)
            .with_referee_hashes(referee)
            .with_nonce(rng.gen())
            .with_gas_limit(block_gas_limit)
            .build();

        Block::new(block_header, transactions)
    }

    pub fn generate_fixed_block(
        &self, parent_hash: H256, referee: Vec<H256>,
        deferred_state_root: H256, deferred_receipts_root: H256,
        deferred_logs_bloom_hash: H256, num_txs: usize,
    ) -> H256
    {
        let block = Self::assemble_new_block(
            &self.data_man,
            &self.txpool,
            parent_hash,
            referee,
            deferred_state_root,
            deferred_receipts_root,
            deferred_logs_bloom_hash,
            num_txs,
        );
        let block_hash = block.hash();
        self.on_mined_block(block);

        block_hash
    }

    /// Generate a block with transactions in the pool
    pub fn generate_block(
        &self, num_txs: usize, block_size_limit: usize,
        additional_transactions: Vec<Arc<SignedTransaction>>,
    ) -> H256
    {
        let sync_graph = self.sync.get_synchronization_graph();
        let consensus_graph = sync_graph
            .consensus
            .as_any()
            .downcast_ref::<TreeGraphConsensus>()
            .expect("downcast should succeed");
        let block_gas_limit = DEFAULT_MAX_BLOCK_GAS_LIMIT.into();

        let (best_info, transactions) =
            self.txpool.get_best_info_with_packed_transactions(
                num_txs,
                block_size_limit,
                block_gas_limit,
                additional_transactions,
            );

        let deferred_exec_commitment = consensus_graph
            .get_deferred_state_for_generation(&best_info.best_block_hash);
        let deferred_state_root = deferred_exec_commitment
            .state_root_with_aux_info
            .state_root
            .compute_state_root_hash();
        let deferred_receipts_root = deferred_exec_commitment.receipts_root;
        let deferred_logs_bloom_hash = deferred_exec_commitment.logs_bloom_hash;

        let best_block_hash = best_info.best_block_hash.clone();
        let mut referee = best_info.bounded_terminal_block_hashes.clone();
        referee.retain(|r| *r != best_block_hash);

        let block = self.assemble_new_block_with_transaction(
            best_block_hash,
            referee,
            deferred_state_root,
            deferred_receipts_root,
            deferred_logs_bloom_hash,
            block_gas_limit,
            transactions,
        );

        let block_hash = block.hash();
        self.on_mined_block(block);

        block_hash
    }

    pub fn auto_block_generation(&self, interval_ms: u64) {
        let interval = Duration::from_millis(interval_ms);
        loop {
            if *self.stopped.read() {
                return;
            }
            if !self.sync.catch_up_mode() {
                self.generate_block(3000, MAX_BLOCK_SIZE_IN_BYTES, vec![]);
            }
            thread::sleep(interval);
        }
    }
}

impl Stopable for TGBlockGenerator {
    fn stop(&self) { Self::stop(self) }
}
