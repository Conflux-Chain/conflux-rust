mod post_block_execution;

use crate::{
    statetest::{match_fail_single_reason, TestOutcome},
    suite_tester::UnitTester,
    util::{
        calc_blob_gasprice, check_tx_common, make_state, make_transact_options,
    },
    TestError, TestErrorKind,
};
use cfx_executor::{
    executive::{ExecutionOutcome, ExecutiveContext, TxDropError},
    machine::Machine,
    state::State,
};
use cfx_types::{AddressSpaceUtil, Space, SpaceMap, H256, U256};
use cfx_vm_types::Env;
use cfxcore::verification::VerificationConfig;
use eest_types::{Block as EestBlock, BlockchainTestUnit, TestBlock};
use log::trace;
use post_block_execution::check_expected_state;
use primitives::{
    transaction::TransactionError, Block, BlockHeaderBuilder, SignedTransaction,
};
use std::{collections::BTreeMap, sync::Arc};
use thiserror::Error;

pub struct BlockchainUnitTester {
    path: String,
    name: String,
    unit: BlockchainTestUnit,
}

impl BlockchainUnitTester {
    fn err(&self, kind: TestErrorKind) -> TestError {
        TestError {
            name: self.name.clone(),
            path: self.path.clone(),
            kind,
        }
    }

    // eip2935
    fn before_epoch_execution(
        &self, state: &mut State, machine: &Machine, pivot_block: &Block,
    ) -> Result<(), String> {
        let params = machine.params();

        let epoch_number = pivot_block.block_header.height();
        let parent_hash = pivot_block.block_header.parent_hash();

        if epoch_number >= params.transition_heights.eip2935 {
            state
                .set_eip2935_storage(epoch_number - 1, *parent_hash)
                .map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    fn process_epoch(
        &self, state: &mut State, machine: &Machine,
        verification: &VerificationConfig, block_index: usize,
        epoch_blocks: &Vec<Arc<Block>>, start_block_number: u64,
    ) -> Result<usize, EpochProcessError> {
        let pivot_block = epoch_blocks.last().expect("Epoch not empty");

        let base_gas_price =
            pivot_block.block_header.base_price().unwrap_or_default();
        let burnt_gas_price =
            base_gas_price.map_all(|x| state.burnt_gas_price(x));

        let epoch_height = pivot_block.block_header.height();
        let chain_id = machine.params().chain_id_map(epoch_height);

        let mut transact_cnt = 0;

        self.before_epoch_execution(state, machine, &pivot_block)
            .map_err(|e| EpochProcessError::Internal(e))?;

        for (i, block) in epoch_blocks.iter().enumerate() {
            // do the before_block_execution handling
            state.commit_cache(false);

            let block_number = start_block_number + i as u64;
            let blob_gas_fee = calc_blob_gasprice(
                self.unit.blocks[block_index]
                    .get_excess_blog_gas()
                    .unwrap_or_default()
                    .as_u64(),
            );
            let epoch_context = EpochContext {
                epoch_height,
                block_number,
                chain_id: chain_id.clone(),
                base_gas_price: base_gas_price.clone(),
                burnt_gas_price: burnt_gas_price.clone(),
                timestamp: block.block_header.timestamp(),
                transaction_epoch_bound: verification.transaction_epoch_bound,
                blob_gas_fee,
            };
            let mut env = self.make_block_env(epoch_context, block);
            let spec = machine.spec(env.number, env.epoch_height);

            // pre check common
            for transaction in &block.transactions {
                env.transaction_hash = transaction.hash();
                check_tx_common(machine, &env, &transaction, verification)?;
            }

            let mut miner_reward = U256::zero();
            for (idx, transaction) in block.transactions.iter().enumerate() {
                env.transaction_hash = transaction.hash();

                let check_base_price = true;
                let options = make_transact_options(check_base_price);

                let executive_context =
                    ExecutiveContext::new(state, &env, machine, &spec);
                let Ok(execution_outcome) =
                    executive_context.transact(transaction, options)
                else {
                    trace!(
                        "{} tx {} execution failed",
                        idx,
                        transaction.hash()
                    );
                    continue;
                };

                if let ExecutionOutcome::NotExecutedDrop(tx_drop_err) =
                    &execution_outcome
                {
                    return Err(EpochProcessError::NotExecutedDrop(
                        tx_drop_err.clone(),
                    ));
                }

                transact_cnt += 1;

                let to_add = match execution_outcome {
                    ExecutionOutcome::Finished(ref executed)
                    | ExecutionOutcome::ExecutionErrorBumpNonce(
                        _,
                        ref executed,
                    ) => match executed.burnt_fee {
                        Some(burnt_fee) => executed.fee - burnt_fee,
                        None => executed.fee,
                    },
                    _ => U256::zero(),
                };
                miner_reward = miner_reward.saturating_add(to_add);

                // do we need to check the execution outcome?

                state.update_state_post_tx_execution(!spec.cip645.fix_eip1153);
                if let Some(burnt_fee) = execution_outcome
                    .try_as_executed()
                    .and_then(|e| e.burnt_fee)
                {
                    state.burn_by_cip1559(burnt_fee);
                };
            }

            // distribute miner reward
            let miner = block.block_header.author().with_evm_space();
            state
                .add_balance(&miner, &miner_reward)
                .expect("should success");
        }

        Ok(transact_cnt)
    }

    fn make_block_env(
        &self, epoch_context: EpochContext, block: &Arc<Block>,
    ) -> Env {
        let EpochContext {
            epoch_height,
            block_number,
            chain_id,
            base_gas_price,
            burnt_gas_price,
            timestamp,
            transaction_epoch_bound,
            blob_gas_fee,
        } = epoch_context;
        let last_hash = block.block_header.parent_hash().clone();
        Env {
            chain_id,
            number: block_number,
            author: block.block_header.author().clone(),
            timestamp,
            difficulty: block.block_header.difficulty().clone(),
            accumulated_gas_used: U256::zero(),
            last_hash,
            gas_limit: U256::from(block.block_header.gas_limit()),
            epoch_height,
            pos_view: None,
            finalized_epoch: None,
            transaction_epoch_bound,
            base_gas_price,
            burnt_gas_price,
            transaction_hash: H256::zero(),
            blob_gas_fee,
            ..Default::default()
        }
    }

    fn to_primitive_block(b: &EestBlock) -> Result<Block, String> {
        let txs: Vec<Result<SignedTransaction, String>> = b
            .transactions
            .iter()
            .map(|tx| tx.clone().try_into())
            .collect();
        if txs.iter().any(|tx| tx.is_err()) {
            return Err("block have unsupported tx".into());
        }
        let txs = txs.into_iter().map(|tx| Arc::new(tx.unwrap())).collect();
        let mut builder = BlockHeaderBuilder::new();
        builder
            .with_parent_hash(b.block_header.parent_hash)
            .with_height(b.block_header.number.as_u64())
            .with_timestamp(b.block_header.timestamp.as_u64())
            .with_author(b.block_header.coinbase)
            .with_transactions_root(b.block_header.transactions_trie)
            .with_deferred_state_root(b.block_header.state_root)
            .with_deferred_receipts_root(b.block_header.receipt_trie)
            .with_deferred_logs_bloom_hash(keccak_hash::keccak(
                b.block_header.bloom.data(),
            ))
            .with_difficulty(b.block_header.difficulty)
            .with_gas_limit(b.block_header.gas_limit)
            // use uncle_hashes as referee_hashes
            .with_referee_hashes(
                b.uncle_headers.iter().map(|h| h.hash).collect(),
            )
            .with_nonce(U256::from(b.block_header.nonce.as_u64()))
            // todo: set pos_reference, blame, adaptive, custom
            .with_base_price(
                b.block_header.base_fee_per_gas.map(|x| SpaceMap::new(x, x)),
            );
        let header = builder.build();
        let block = Block::new(header, txs);
        Ok(block)
    }

    fn primitive_blocks(&self) -> Vec<Result<BlockWithException, String>> {
        self.unit
            .blocks
            .iter()
            .map(|block| match block {
                TestBlock::Block(b) => {
                    Self::to_primitive_block(b).map(|b| BlockWithException {
                        block: b,
                        exception: None,
                    })
                }
                TestBlock::InvalidBlock(invalid) => match invalid.rlp_decoded {
                    Some(ref b) => Self::to_primitive_block(b).map(|pb| {
                        BlockWithException {
                            block: pb,
                            exception: Some(invalid.expect_exception.clone()),
                        }
                    }),
                    None => Err("none block".into()),
                },
            })
            .collect()
    }
}

struct BlockWithException {
    block: Block,
    exception: Option<String>,
}

#[derive(Debug, Error)]
pub enum EpochProcessError {
    #[error("state mismatch: {0}")]
    TransactionError(#[from] TransactionError),
    #[error("execution error: NotExecutedDrop {0:?}")]
    NotExecutedDrop(TxDropError),
    #[error("internal error: {0}")]
    Internal(String),
}

struct EpochContext {
    epoch_height: u64,
    block_number: u64,
    timestamp: u64,
    transaction_epoch_bound: u64,
    blob_gas_fee: U256,
    chain_id: BTreeMap<Space, u32>,
    base_gas_price: SpaceMap<U256>,
    burnt_gas_price: SpaceMap<U256>,
}

impl UnitTester for BlockchainUnitTester {
    type TestUnit = BlockchainTestUnit;

    fn new(path: &String, name: String, unit: BlockchainTestUnit) -> Self {
        BlockchainUnitTester {
            path: path.clone(),
            name,
            unit,
        }
    }

    fn run(
        &self, machine: &Machine, verification: &VerificationConfig,
        matches: Option<&str>,
    ) -> Result<usize, TestError> {
        if !matches.map_or(true, |pat| {
            format!("{}::{}", &self.path, &self.name).contains(pat)
        }) {
            return Ok(0);
        }

        if matches.is_some() {
            info!("Running TestUnit: {}", self.name);
        } else {
            trace!("Running TestUnit: {}", self.name);
        }

        let mut state = make_state(&self.unit.pre);

        let blocks = self.primitive_blocks();

        if blocks.iter().any(|block| block.is_err()) {
            // if block is error, means it contain unsupported tx, we skip this
            // test
            return Ok(0);
        }

        let epochs: Vec<Vec<BlockWithException>> =
            blocks.into_iter().map(|b| vec![b.unwrap()]).collect();

        let mut transact_cnt = 0;

        for (i, epoch) in epochs.iter().enumerate() {
            if skip_test_according_to_exception(&epoch[0].exception) {
                continue;
            }

            let epoch_blocks =
                epoch.iter().map(|b| Arc::new(b.block.clone())).collect();
            let epoch_res = self.process_epoch(
                &mut state,
                machine,
                verification,
                i,
                &epoch_blocks,
                epoch[0].block.block_header.height(),
            );

            if epoch_res.is_ok() && epoch[0].exception.is_some() {
                trace!(
                    "execution should fail, but it is ok, exception: {:?}",
                    epoch[0].exception
                );
            }

            match epoch_res {
                Ok(cnt) => transact_cnt += cnt,
                Err(e) => {
                    if !match_expect_exception(&epoch[0].exception, &e) {
                        trace!(
                            "error mismatch: expected: {:?}, actual: {:?}",
                            epoch[0].exception,
                            e
                        );
                        return Err(
                            self.err(TestErrorKind::Internal(e.to_string()))
                        );
                    } else {
                        return Ok(transact_cnt);
                    }
                }
            }
        }

        check_expected_state(&state, &self.unit.post_state)
            .map_err(|e| self.err(e))?;

        Ok(transact_cnt)
    }
}

fn match_expect_exception(
    expect: &Option<String>, epoch_process_error: &EpochProcessError,
) -> bool {
    if expect.is_none() {
        return false;
    }
    match epoch_process_error {
        EpochProcessError::TransactionError(e) => match_fail_single_reason(
            expect.as_ref().unwrap(),
            TestOutcome::Consensus(e),
        ),
        EpochProcessError::NotExecutedDrop(e) => match_fail_single_reason(
            expect.as_ref().unwrap(),
            TestOutcome::Execution(&ExecutionOutcome::NotExecutedDrop(
                e.clone(),
            )),
        ),
        EpochProcessError::Internal(_e) => false,
    }
}

fn skip_test_according_to_exception(exception: &Option<String>) -> bool {
    if exception.is_none() {
        return false;
    }

    matches!(
        exception.as_ref().unwrap().as_str(),
        "BlockException.INVALID_REQUESTS"
            | "BlockException.INCORRECT_BLOB_GAS_USED"
            | "BlockException.INCORRECT_BLOCK_FORMAT"
            | "TransactionException.INVALID_DEPOSIT_EVENT_LAYOUT"
            // | "TransactionException.TYPE_4_TX_PRE_FORK" // type 4 tx before fork
            | "TransactionException.TYPE_4_TX_CONTRACT_CREATION" // empty to
            // we don't support type 3 (4844)tx
            | "TransactionException.TYPE_3_TX_PRE_FORK"
            | "TransactionException.TYPE_3_TX_ZERO_BLOBS_PRE_FORK"
            | "TransactionException.TYPE_3_TX_INVALID_BLOB_VERSIONED_HASH"
            | "TransactionException.TYPE_3_TX_WITH_FULL_BLOBS"
            | "TransactionException.TYPE_3_TX_BLOB_COUNT_EXCEEDED"
            | "TransactionException.TYPE_3_TX_CONTRACT_CREATION"
            | "TransactionException.TYPE_3_TX_MAX_BLOB_GAS_ALLOWANCE_EXCEEDED"
            | "TransactionException.TYPE_3_TX_ZERO_BLOBS"
            // consensus level error
            | "TransactionException.GAS_ALLOWANCE_EXCEEDED"
    )
}
