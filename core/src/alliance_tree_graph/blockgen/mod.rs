// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    alliance_tree_graph::consensus::TreeGraphConsensus,
    block_parameters::*,
    miner::{
        stratum::{Options as StratumOption, Stratum},
        work_notify::NotifyWork,
    },
    pow::*,
    transaction_pool::DEFAULT_MAX_BLOCK_GAS_LIMIT,
    BlockDataManager, ConsensusGraphTrait, SharedSynchronizationService,
    SharedTransactionPool,
};
use cfx_types::{Address, H256, U256};
use lazy_static::lazy_static;
use log::{debug, trace, warn};
use metrics::{Gauge, GaugeUsize};
use parking_lot::{Mutex, RwLock};
use primitives::*;
use std::{
    cmp::max,
    collections::HashSet,
    sync::{mpsc, Arc},
    thread, time,
};
use time::{Duration, SystemTime, UNIX_EPOCH};
//use txgen::{SharedTransactionGenerator, SpecialTransactionGenerator};

pub struct TGBlockGenerator {
    pub pow_config: ProofOfWorkConfig,
    mining_author: Address,
    data_man: Arc<BlockDataManager>,
    txpool: SharedTransactionPool,
    //txgen: SharedTransactionGenerator,
    //special_txgen: Arc<Mutex<SpecialTransactionGenerator>>,
    sync: SharedSynchronizationService,
    stopped: RwLock<bool>,
    //workers: Mutex<Vec<(Worker, mpsc::Sender<ProofOfWorkProblem>)>>,
}

impl TGBlockGenerator {
    pub fn new(
        data_man: Arc<BlockDataManager>, txpool: SharedTransactionPool,
        sync: SharedSynchronizationService, /* txgen: SharedTransactionGenerator, */
        /* special_txgen: Arc<Mutex<SpecialTransactionGenerator>>, */
        pow_config: ProofOfWorkConfig, mining_author: Address,
    ) -> Self
    {
        TGBlockGenerator {
            pow_config,
            mining_author,
            data_man,
            txpool,
            // txgen,
            // special_txgen,
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

    /// Assume that the consensus lock was hold for the caller.
    pub fn assemble_new_block(
        data_man: &Arc<BlockDataManager>, parent_hash: H256,
        referee: Vec<H256>, deferred_state_root: H256,
        deferred_receipts_root: H256, deferred_logs_bloom_hash: H256,
        block_gas_limit: U256, transactions: Vec<Arc<SignedTransaction>>,
    ) -> Block
    {
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
            .with_nonce(0)
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
        let block_gas_limit = DEFAULT_MAX_BLOCK_GAS_LIMIT.into();
        let block_size_limit = MAX_BLOCK_SIZE_IN_BYTES;

        let transactions = self.txpool.pack_transactions(
            num_txs,
            block_gas_limit,
            block_size_limit,
        );
        let block = Self::assemble_new_block(
            &self.data_man,
            parent_hash,
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

    /// Generate a block with transactions in the pool
    pub fn generate_block(
        &self, num_txs: usize, block_size_limit: usize,
        additional_transactions: Vec<Arc<SignedTransaction>>,
    ) -> H256
    {
        // TODO: finish this function
        H256::zero()
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
