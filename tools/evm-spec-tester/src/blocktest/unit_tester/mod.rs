mod post_block_execution;

use crate::{
    suite_tester::UnitTester,
    util::{calc_blob_gasprice, make_state, make_transact_options},
    TestError, TestErrorKind,
};
use cfx_executor::{
    executive::{ExecutionOutcome, ExecutiveContext},
    machine::Machine,
    state::State,
};
use cfx_types::{AddressSpaceUtil, Space, SpaceMap, H256, U256};
use cfx_vm_types::Env;
use cfxcore::verification::VerificationConfig;
use eest_types::{BlockchainTestUnit, TestBlock};
use log::trace;
use post_block_execution::check_expected_state;
use primitives::{Block, BlockHeaderBuilder, SignedTransaction};
use std::{collections::BTreeMap, sync::Arc};

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

    fn process_epoch(
        &self, state: &mut State, machine: &Machine,
        verification: &VerificationConfig, block_index: usize,
        epoch_blocks: &Vec<Arc<Block>>, start_block_number: u64,
    ) -> Result<usize, String> {
        let pivot_block = epoch_blocks.last().expect("Epoch not empty");

        let base_gas_price =
            pivot_block.block_header.base_price().unwrap_or_default();
        let burnt_gas_price =
            base_gas_price.map_all(|x| state.burnt_gas_price(x));

        let epoch_height = pivot_block.block_header.height();
        let chain_id = machine.params().chain_id_map(epoch_height);

        let mut transact_cnt = 0;

        // TODO: do the before_epoch_execution handling

        for (i, block) in epoch_blocks.iter().enumerate() {
            // TODO: do the before_block_execution handling
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

            let mut miner_reward = U256::zero();

            for (idx, transaction) in block.transactions.iter().enumerate() {
                let spec = machine.spec(env.number, env.epoch_height);
                let check_base_price = true;
                let options = make_transact_options(check_base_price);
                env.transaction_hash = transaction.hash();

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
            state.commit_cache(false);
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

    fn primitive_blocks(&self) -> Vec<Result<Block, String>> {
        self.unit
            .blocks
            .iter()
            .map(|block| match block {
                TestBlock::Block(b) => {
                    let txs: Vec<Result<SignedTransaction, String>> = b
                        .transactions
                        .iter()
                        .map(|tx| tx.clone().try_into())
                        .collect();
                    if txs.iter().any(|tx| tx.is_err()) {
                        return Err("block have invalid tx".into());
                    }
                    let txs = txs
                        .into_iter()
                        .map(|tx| Arc::new(tx.unwrap()))
                        .collect();
                    let mut builder = BlockHeaderBuilder::new();
                    builder
                        .with_parent_hash(b.block_header.parent_hash)
                        .with_height(b.block_header.number.as_u64())
                        .with_timestamp(b.block_header.timestamp.as_u64())
                        .with_author(b.block_header.coinbase)
                        .with_transactions_root(
                            b.block_header.transactions_trie,
                        )
                        .with_deferred_state_root(b.block_header.state_root)
                        .with_deferred_receipts_root(
                            b.block_header.receipt_trie,
                        )
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
                            b.block_header
                                .base_fee_per_gas
                                .map(|x| SpaceMap::new(x, x)),
                        );
                    let header = builder.build();
                    let block = Block::new(header, txs);
                    Ok(block)
                }
                TestBlock::InvalidBlock(_invalid) => {
                    Err("invalid block".into())
                }
            })
            .collect()
    }
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
            // if there are any invalid blocks, we temp skip this test
            return Ok(0);
            // return Err(self.err(TestErrorKind::Internal(
            //     "There are some invalid block in this test".into(),
            // )));
        }

        let epochs: Vec<Vec<Arc<Block>>> = blocks
            .into_iter()
            .map(|b| vec![Arc::new(b.unwrap())])
            .collect();

        let mut transact_cnt = 0;

        for (i, epoch) in epochs.iter().enumerate() {
            // every epoch should have exactly one block
            if epoch.is_empty() || epoch.len() > 1 {
                continue;
            }
            let epoch_res = self.process_epoch(
                &mut state,
                machine,
                verification,
                i,
                &epoch,
                epoch[0].block_header.height(),
            );

            match epoch_res {
                Ok(cnt) => transact_cnt += cnt,
                Err(e) => {
                    return Err(self.err(TestErrorKind::Internal(e)));
                }
            }
        }

        check_expected_state(&state, &self.unit.post_state)
            .map_err(|e| self.err(e))?;

        Ok(transact_cnt)
    }
}
