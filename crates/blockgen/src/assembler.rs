use cfx_parameters::{
    block::MAX_TRANSACTION_COUNT_PER_BLOCK,
    consensus::{
        GENESIS_GAS_LIMIT, TESTNET_FIX_POS_HEIGHT,
        TESTNET_FIX_POS_POS_REFERENCE,
    },
    consensus_internal::ELASTICITY_MULTIPLIER,
};
use cfx_types::{Address, SpaceMap, H256, U256};
use cfxcore::{
    consensus::{consensus_inner::StateBlameInfo, pos_handler::PosVerifier},
    verification::compute_transaction_root,
    ConsensusGraph, SharedSynchronizationGraph, SharedTransactionPool,
};
use lazy_static::lazy_static;
use log::{debug, trace};
use metrics::{Gauge, GaugeUsize};
use primitives::{pos::PosBlockId, *};
use std::{cmp::max, collections::HashSet, str::FromStr, sync::Arc, time};
use time::{SystemTime, UNIX_EPOCH};
use txgen::SharedTransactionGenerator;

lazy_static! {
    static ref PACKED_ACCOUNT_SIZE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "packed_account_size");
}

/// The interface for a conflux block generator
pub struct BlockAssembler {
    graph: SharedSynchronizationGraph,
    txpool: SharedTransactionPool,
    maybe_txgen: Option<SharedTransactionGenerator>,
    pos_verifier: Arc<PosVerifier>,
    mining_author: Address,
    max_consensus_block_size_in_bytes: usize,
}

impl BlockAssembler {
    pub fn new(
        graph: SharedSynchronizationGraph, txpool: SharedTransactionPool,
        maybe_txgen: Option<SharedTransactionGenerator>,
        mining_author: Address, pos_verifier: Arc<PosVerifier>,
    ) -> Self {
        let max_consensus_block_size_in_bytes =
            graph.verification_config.max_block_size_in_bytes;
        BlockAssembler {
            graph,
            txpool,
            maybe_txgen,
            pos_verifier,
            mining_author,
            max_consensus_block_size_in_bytes,
        }
    }

    pub fn stop(&self) {
        if let Some(txgen) = &self.maybe_txgen {
            txgen.stop();
        }
    }

    fn consensus_graph(&self) -> &ConsensusGraph { &self.graph.consensus }

    // TODO: should not hold and pass write lock to consensus.
    fn assemble_new_block_impl(
        &self, mut parent_hash: H256, mut referees: Vec<H256>,
        mut blame_info: StateBlameInfo, block_gas_limit: U256,
        transactions: Vec<Arc<SignedTransaction>>, difficulty: u64,
        adaptive_opt: Option<bool>, maybe_pos_reference: Option<PosBlockId>,
        maybe_base_price: Option<SpaceMap<U256>>,
    ) -> Block {
        trace!("{} txs packed", transactions.len());
        let consensus_graph = self.consensus_graph();
        if adaptive_opt.is_none() {
            // This is the normal case for mining.
            consensus_graph.choose_correct_parent(
                &mut parent_hash,
                &mut referees,
                &mut blame_info,
                maybe_pos_reference,
            );
        }
        let mut consensus_inner = consensus_graph.inner.write();
        // referees are retrieved before locking inner, so we need to
        // filter out the blocks that should be removed by possible
        // checkpoint making that happens before we acquire the inner lock
        referees
            .retain(|h| consensus_inner.hash_to_arena_indices.contains_key(h));
        let mut expected_difficulty =
            consensus_inner.expected_difficulty(&parent_hash);
        let adaptive = if let Some(x) = adaptive_opt {
            x
        } else {
            consensus_graph.check_mining_adaptive_block(
                &mut *consensus_inner,
                &parent_hash,
                &referees,
                &expected_difficulty,
                maybe_pos_reference,
            )
        };

        let (parent_height, parent_timestamp) = {
            let parent_header = consensus_inner
                .data_man
                .block_header_by_hash(&parent_hash)
                .unwrap();
            (parent_header.height(), parent_header.timestamp())
        };

        if U256::from(difficulty) > expected_difficulty {
            expected_difficulty = U256::from(difficulty);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Adjust the timestamp of the currently mined block to be later
        // than or equal to its parent's.
        // See comments in verify_header_graph_ready_block()
        let my_timestamp = max(parent_timestamp, now);

        let custom = self
            .txpool
            .machine()
            .params()
            .custom_prefix(parent_height + 1)
            .unwrap_or(vec![]);
        let block_header = BlockHeaderBuilder::new()
            .with_transactions_root(compute_transaction_root(&transactions))
            .with_parent_hash(parent_hash)
            .with_height(parent_height + 1)
            .with_timestamp(my_timestamp)
            .with_author(self.mining_author)
            .with_blame(blame_info.blame)
            .with_deferred_state_root(blame_info.state_vec_root)
            .with_deferred_receipts_root(blame_info.receipts_vec_root)
            .with_deferred_logs_bloom_hash(blame_info.logs_bloom_vec_root)
            .with_difficulty(expected_difficulty)
            .with_adaptive(adaptive)
            .with_referee_hashes(referees)
            .with_nonce(U256::zero())
            .with_gas_limit(block_gas_limit)
            .with_custom(custom)
            .with_pos_reference(maybe_pos_reference)
            .with_base_price(maybe_base_price)
            .build();

        Block::new(block_header, transactions)
    }

    /// Assemble a new block with specified parent and referee, this is for test
    /// only
    pub fn assemble_new_fixed_block(
        &self, parent_hash: H256, referee: Vec<H256>, num_txs: usize,
        difficulty: u64, adaptive: bool, block_gas_target: u64,
        pos_reference: Option<PosBlockId>,
    ) -> Result<Block, String> {
        let consensus_graph = self.consensus_graph();
        let state_blame_info = consensus_graph
            .force_compute_blame_and_deferred_state_for_generation(
                &parent_hash,
            )?;

        let block_size_limit =
            self.graph.verification_config.max_block_size_in_bytes;
        let best_info = consensus_graph.best_info();

        let parent_block = self
            .txpool
            .data_man
            .block_header_by_hash(&best_info.best_block_hash)
            // The parent block must exists.
            .expect("Parent block not found");

        let machine = self.txpool.machine();
        let params = machine.params();
        let cip1559_height = params.transition_heights.cip1559;
        let pack_height = best_info.best_epoch_number + 1;

        let block_gas_limit = if pack_height >= cip1559_height {
            (block_gas_target * ELASTICITY_MULTIPLIER as u64).into()
        } else {
            block_gas_target.into()
        };

        let (transactions, maybe_base_price) = if pack_height < cip1559_height {
            let txs = self.txpool.pack_transactions(
                num_txs,
                block_gas_limit,
                U256::zero(),
                block_size_limit,
                best_info.best_epoch_number,
                best_info.best_block_number,
            );
            (txs, None)
        } else {
            let parent_base_price = if cip1559_height == pack_height {
                params.init_base_price()
            } else {
                parent_block.base_price().unwrap()
            };

            let (txs, base_price) = self.txpool.pack_transactions_1559(
                num_txs,
                block_gas_limit,
                parent_base_price,
                block_size_limit,
                best_info.best_epoch_number,
                best_info.best_block_number,
            );
            (txs, Some(base_price))
        };

        Ok(self.assemble_new_block_impl(
            parent_hash,
            referee,
            state_blame_info,
            block_gas_limit,
            transactions,
            difficulty,
            Some(adaptive),
            pos_reference.or_else(|| self.get_pos_reference(&parent_hash)),
            maybe_base_price,
        ))
    }

    /// Assemble a new block without nonce
    pub fn assemble_new_block(
        &self, num_txs: usize, block_size_limit: usize,
        additional_transactions: Vec<Arc<SignedTransaction>>,
    ) -> Block {
        let consensus_graph = self.consensus_graph();

        let (best_info, block_gas_limit, transactions, maybe_base_price) =
            self.txpool.get_best_info_with_packed_transactions(
                num_txs,
                block_size_limit,
                additional_transactions,
            );

        let mut sender_accounts = HashSet::new();
        for tx in &transactions {
            let tx_hash = tx.hash();
            if tx_hash[0] & 254 == 0 {
                debug!("Sampled transaction {:?} in packing block", tx_hash);
            }
            sender_accounts.insert(tx.sender);
        }
        PACKED_ACCOUNT_SIZE.update(sender_accounts.len());

        let state_blame_info = consensus_graph
            .get_blame_and_deferred_state_for_generation(
                &best_info.best_block_hash,
            )
            .unwrap();

        let best_block_hash = best_info.best_block_hash.clone();
        let mut referee = best_info.bounded_terminal_block_hashes.clone();
        let maybe_pos_reference = if self
            .pos_verifier
            .is_enabled_at_height(best_info.best_epoch_number + 1)
        {
            // parent is in consensus, so our PoS must have processed its
            // pos_reference, meaning this latest pos reference must
            // be valid.
            if best_info.best_epoch_number + 1 < TESTNET_FIX_POS_HEIGHT {
                // FIXME(lpl): Temp fix pos reference before fix hardfork.
                Some(H256::from_str(TESTNET_FIX_POS_POS_REFERENCE).unwrap())
            } else {
                Some(self.pos_verifier.get_latest_pos_reference())
            }
        } else {
            None
        };
        referee.retain(|r| *r != best_block_hash);

        self.assemble_new_block_impl(
            best_block_hash,
            referee,
            state_blame_info,
            block_gas_limit,
            transactions,
            0,
            None,
            maybe_pos_reference,
            maybe_base_price,
        )
    }

    pub fn assemble_new_mining_block(&self, num_txs: Option<usize>) -> Block {
        self.assemble_new_block(
            num_txs.unwrap_or(MAX_TRANSACTION_COUNT_PER_BLOCK),
            self.max_consensus_block_size_in_bytes,
            vec![],
        )
    }

    /// Assemble a new block without nonce and with options to override the
    /// states/blame. This function is used for testing only to generate
    /// incorrect blocks
    pub fn assemble_new_block_with_blame_info(
        &self, num_txs: usize, block_size_limit: usize,
        additional_transactions: Vec<Arc<SignedTransaction>>,
        blame_override: Option<u32>, state_root_override: Option<H256>,
        receipt_root_override: Option<H256>,
        logs_bloom_hash_override: Option<H256>,
    ) -> Block {
        let consensus_graph = self.consensus_graph();

        let (best_info, block_gas_limit, transactions, maybe_base_price) =
            self.txpool.get_best_info_with_packed_transactions(
                num_txs,
                block_size_limit,
                additional_transactions,
            );

        let mut state_blame_info = consensus_graph
            .get_blame_and_deferred_state_for_generation(
                &best_info.best_block_hash,
            )
            .unwrap();

        if let Some(x) = blame_override {
            state_blame_info.blame = x;
        }
        if let Some(x) = state_root_override {
            state_blame_info.state_vec_root = x;
        }
        if let Some(x) = receipt_root_override {
            state_blame_info.receipts_vec_root = x;
        }
        if let Some(x) = logs_bloom_hash_override {
            state_blame_info.logs_bloom_vec_root = x;
        }

        let best_block_hash = best_info.best_block_hash.clone();
        let mut referee = best_info.bounded_terminal_block_hashes.clone();
        referee.retain(|r| *r != best_block_hash);

        self.assemble_new_block_impl(
            best_block_hash,
            referee,
            state_blame_info,
            block_gas_limit,
            transactions,
            0,
            None,
            self.get_pos_reference(&best_block_hash),
            maybe_base_price,
        )
    }

    pub fn assemble_custom_block(
        &self, transactions: Vec<Arc<SignedTransaction>>,
        adaptive: Option<bool>,
    ) -> Block {
        let consensus_graph = self.consensus_graph();
        // get the best block
        let (best_info, _, _, _) = self
            .txpool
            .get_best_info_with_packed_transactions(0, 0, Vec::new());

        let parent_hash = best_info.best_block_hash;
        let maybe_base_price = self
            .txpool
            .compute_1559_base_price(
                &parent_hash,
                (GENESIS_GAS_LIMIT * ELASTICITY_MULTIPLIER as u64).into(),
                transactions.iter().map(|x| &**x),
            )
            .unwrap();
        let block_gas_limit = GENESIS_GAS_LIMIT
            * if maybe_base_price.is_some() {
                ELASTICITY_MULTIPLIER as u64
            } else {
                1
            };

        let state_blame_info = consensus_graph
            .get_blame_and_deferred_state_for_generation(
                &best_info.best_block_hash,
            )
            .unwrap();

        let best_block_hash = best_info.best_block_hash.clone();
        let mut referee = best_info.bounded_terminal_block_hashes.clone();
        referee.retain(|r| *r != best_block_hash);

        let block = self.assemble_new_block_impl(
            best_block_hash,
            referee,
            state_blame_info,
            block_gas_limit.into(),
            transactions,
            0,
            adaptive,
            self.get_pos_reference(&best_block_hash),
            maybe_base_price,
        );
        block
    }

    pub fn assemble_custom_block_with_parent(
        &self, parent_hash: H256, referee: Vec<H256>,
        transactions: Vec<Arc<SignedTransaction>>, adaptive: bool,
        maybe_custom: Option<Vec<Vec<u8>>>,
    ) -> Result<Block, String> {
        let consensus_graph = self.consensus_graph();
        let state_blame_info = consensus_graph
            .force_compute_blame_and_deferred_state_for_generation(
                &parent_hash,
            )?;

        let maybe_base_price = self
            .txpool
            .compute_1559_base_price(
                &parent_hash,
                (GENESIS_GAS_LIMIT * ELASTICITY_MULTIPLIER as u64).into(),
                transactions.iter().map(|x| &**x),
            )
            .expect("Cannot compute base price");

        let block_gas_limit = if maybe_base_price.is_some() {
            GENESIS_GAS_LIMIT * ELASTICITY_MULTIPLIER as u64
        } else {
            GENESIS_GAS_LIMIT
        };

        let mut block = self.assemble_new_block_impl(
            parent_hash,
            referee,
            state_blame_info,
            block_gas_limit.into(),
            transactions,
            0,
            Some(adaptive),
            self.get_pos_reference(&parent_hash),
            maybe_base_price,
        );
        if let Some(custom) = maybe_custom {
            block.block_header.set_custom(custom);
        }

        Ok(block)
    }

    pub fn assemble_block_with_nonce_and_timestamp(
        &self, parent_hash: H256, referee: Vec<H256>,
        transactions: Vec<Arc<SignedTransaction>>, nonce: U256, timestamp: u64,
        adaptive: bool,
    ) -> Result<Block, String> {
        let consensus_graph = self.consensus_graph();
        let state_blame_info = consensus_graph
            .force_compute_blame_and_deferred_state_for_generation(
                &parent_hash,
            )?;

        let maybe_base_price = self
            .txpool
            .compute_1559_base_price(
                &parent_hash,
                (GENESIS_GAS_LIMIT * ELASTICITY_MULTIPLIER as u64).into(),
                transactions.iter().map(|x| &**x),
            )
            .expect("Cannot compute base price");

        let block_gas_limit = if maybe_base_price.is_some() {
            GENESIS_GAS_LIMIT * ELASTICITY_MULTIPLIER as u64
        } else {
            GENESIS_GAS_LIMIT
        };

        let mut block = self.assemble_new_block_impl(
            parent_hash,
            referee,
            state_blame_info,
            block_gas_limit.into(),
            transactions,
            0,
            Some(adaptive),
            self.get_pos_reference(&parent_hash),
            maybe_base_price,
        );
        block.block_header.set_nonce(nonce);
        block.block_header.set_timestamp(timestamp);
        block.block_header.compute_hash();

        Ok(block)
    }

    /// Get the latest pos reference according to parent height.
    ///
    /// Return `None` if parent block is missing in `BlockDataManager`, but this
    /// should not happen in the current usage.
    fn get_pos_reference(&self, parent_hash: &H256) -> Option<PosBlockId> {
        let height = self.graph.data_man.block_height_by_hash(parent_hash)? + 1;
        if self.pos_verifier.is_enabled_at_height(height) {
            Some(self.pos_verifier.get_latest_pos_reference())
        } else {
            None
        }
    }
}
