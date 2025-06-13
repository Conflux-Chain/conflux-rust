use cfx_parameters::consensus::GENESIS_GAS_LIMIT;
use cfx_types::{H256, U256};

use cfxcore::pow::{ProofOfWorkProblem, ProofOfWorkSolution};
use log::debug;

use primitives::*;
use std::{ops::Deref, sync::Arc, thread, time::Duration};

use crate::BlockGenerator;

pub struct BlockGeneratorTestApi(Arc<BlockGenerator>);

// Generate Block APIs for test only
impl BlockGeneratorTestApi {
    pub(crate) fn new(bg: Arc<BlockGenerator>) -> Self {
        BlockGeneratorTestApi(bg)
    }

    pub fn auto_block_generation(&self, interval_ms: u64) {
        let interval = Duration::from_millis(interval_ms);
        while self.is_running() {
            if !self.sync.catch_up_mode() {
                let block =
                    self.assembler.assemble_new_mining_block(Some(3000));
                self.generate_block_impl(block);
            }
            thread::sleep(interval);
        }
    }

    // This function is used in test only to simulate attacker behavior.
    pub fn generate_fixed_block(
        &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize,
        difficulty: u64, adaptive: bool, pos_reference: Option<H256>,
    ) -> Result<H256, String> {
        let block = self.assembler.assemble_new_fixed_block(
            parent_hash,
            referee,
            num_txs,
            difficulty,
            adaptive,
            GENESIS_GAS_LIMIT,
            pos_reference,
        )?;
        Ok(self.generate_block_impl(block))
    }

    /// Generate a block with transactions in the pool
    /// This is used for testing only
    pub fn generate_block(
        &self, num_txs: usize, block_size_limit: usize,
        additional_transactions: Vec<Arc<SignedTransaction>>,
    ) -> H256 {
        let block = self.assembler.assemble_new_block(
            num_txs,
            block_size_limit,
            additional_transactions,
        );
        self.generate_block_impl(block)
    }

    /// Generate a block with transactions in the pool.
    /// This is used for testing only
    pub fn generate_block_with_blame_info(
        &self, num_txs: usize, block_size_limit: usize,
        additional_transactions: Vec<Arc<SignedTransaction>>,
        blame: Option<u32>, state_root: Option<H256>,
        receipts_root: Option<H256>, logs_bloom_hash: Option<H256>,
    ) -> H256 {
        let block = self.assembler.assemble_new_block_with_blame_info(
            num_txs,
            block_size_limit,
            additional_transactions,
            blame,
            state_root,
            receipts_root,
            logs_bloom_hash,
        );
        self.generate_block_impl(block)
    }

    pub fn generate_custom_block(
        &self, transactions: Vec<Arc<SignedTransaction>>,
        adaptive: Option<bool>,
    ) -> H256 {
        let block =
            self.assembler.assemble_custom_block(transactions, adaptive);

        self.generate_block_impl(block)
    }

    pub fn generate_custom_block_with_parent(
        &self, parent_hash: H256, referee: Vec<H256>,
        transactions: Vec<Arc<SignedTransaction>>, adaptive: bool,
        maybe_custom: Option<Vec<Vec<u8>>>,
    ) -> Result<H256, String> {
        let block = self.assembler.assemble_custom_block_with_parent(
            parent_hash,
            referee,
            transactions,
            adaptive,
            maybe_custom,
        )?;

        Ok(self.generate_block_impl(block))
    }

    pub fn generate_block_with_nonce_and_timestamp(
        &self, parent_hash: H256, referee: Vec<H256>,
        transactions: Vec<Arc<SignedTransaction>>, nonce: U256, timestamp: u64,
        adaptive: bool,
    ) -> Result<H256, String> {
        let block = self.assembler.assemble_block_with_nonce_and_timestamp(
            parent_hash,
            referee,
            transactions,
            nonce,
            timestamp,
            adaptive,
        )?;

        Ok(self.generate_block_impl(block))
    }

    fn generate_block_impl(&self, block_init: Block) -> H256 {
        let mut block = block_init;
        let difficulty = block.block_header.difficulty();
        let problem = ProofOfWorkProblem::new(
            block.block_header.height(),
            block.block_header.problem_hash(),
            *difficulty,
        );
        let mut nonce: u64 = rand::random();
        loop {
            if self.pow.validate(
                &problem,
                &ProofOfWorkSolution {
                    nonce: U256::from(nonce),
                },
            ) {
                block.block_header.set_nonce(U256::from(nonce));
                break;
            }
            nonce += 1;
        }
        let hash = block.block_header.compute_hash();
        debug!(
            "generate_block with block header:{:?} tx_number:{}, block_size:{}",
            block.block_header,
            block.transactions.len(),
            block.size(),
        );
        self.on_mined_block(block);

        debug!("generate_block finished on_mined_block()");
        // FIXME: We should add a flag to enable/disable this wait
        // Ensure that when `generate**` function returns, the block has been
        // handled by Consensus This order is assumed by some tests, and
        // this function is also only used in tests.
        self.consensus.wait_for_generation(&hash);
        debug!("generate_block finished wait_for_generation()");

        hash
    }
}

impl Deref for BlockGeneratorTestApi {
    type Target = BlockGenerator;

    fn deref(&self) -> &Self::Target { &*self.0 }
}
