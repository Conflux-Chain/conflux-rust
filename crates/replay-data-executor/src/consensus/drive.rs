//! Per-epoch and per-block EVM execution: run each executed block's
//! transactions, apply the pre-execution chain hooks, recompute the epoch's
//! roots, and compare them against the chain.

use super::commitment::{compare_commitment, deferred_commitment_height, finalized_epoch};
use super::{EpochCommitment, EpochReport, ExecutedEpoch, Replayer};
use anyhow::{anyhow, Context, Result};
use cfxpack::packet::Block;
use cfx_execute_helper::{observer::Observer, tx_outcome::make_process_tx_outcome};
use cfx_executor::{
    executive::{ExecutiveContext, TransactOptions, TransactSettings},
    internal_contract::{
        block_hash_slot, epoch_hash_slot, initialize_internal_contract_accounts,
    },
    state::{initialize_cip107, initialize_cip137, State},
};
use cfx_statedb::StateDb;
#[cfg(not(feature = "backend-minimal-mpt"))]
use cfx_storage::{StateIndex, StorageManagerTrait};
use cfx_types::{SpaceMap, H256, U256};
use cfx_vm_types::Env;
use cfxcore::verification::compute_receipts_root;
use primitives::{receipt::BlockReceipts, BlockHeaderBuilder};
use std::sync::Arc;

impl Replayer {
    pub(super) fn execute_epoch(
        &mut self, blocks: &[&Block], start_block_number: u64,
    ) -> Result<EpochReport> {
        // `blocks` is the epoch's executed set only (skipped-set blocks were
        // stripped at the input boundary), so every block here is executed,
        // numbered, and contributes to the deferred receipts root.
        let pivot = *blocks.last().expect("non-empty epoch");
        let pivot_hash = pivot.hash;
        let debug_epoch = (30361150..=30361170).contains(&pivot.height);
        let mut state = self.open_next_state(pivot)?;
        self.before_epoch_execution(&mut state, pivot)?;

        let mut receipts = Vec::with_capacity(blocks.len());
        let mut block_number = start_block_number;
        let mut last_hash = self.previous_epoch_hash;
        for &block in blocks {
            if debug_epoch {
                eprintln!(
                    "[DBG] h={} blk_num={} blk_hash={:?} author={:?} txs={} base_reward={} flags=0x{:x} gas_limit={} blame={} finalized_epoch={} blk_height={} blk_epoch={}",
                    pivot.height, block_number, block.hash, block.author,
                    block.transactions.len(), block.base_reward, block.flags, block.gas_limit,
                    block.blame, block.finalized_epoch, block.height, block.epoch,
                );
                for (i, tx) in block.transactions.iter().enumerate() {
                    let action = match tx.action() {
                        primitives::Action::Create => "CREATE".to_string(),
                        primitives::Action::Call(addr) => format!("CALL({:?})", addr),
                    };
                    eprintln!(
                        "[DBG]   tx[{}] hash={:?} nonce={} gas_price={} gas={} value={} action={}",
                        i, tx.hash(), tx.nonce(), tx.gas_price(), tx.gas(), tx.value(), action,
                    );
                }
            }
            let block_receipts = self.execute_block(
                block,
                pivot,
                block_number,
                last_hash,
                &mut state,
            )?;
            if debug_epoch {
                for (i, r) in block_receipts.receipts.iter().enumerate() {
                    eprintln!(
                        "[DBG]   receipt[{}] outcome={:?} gas_fee={} burnt_gas_fee={:?} gas_sponsored={} storage_sponsored={} storage_collateralized={} storage_released={} logs={}",
                        i, r.outcome_status, r.gas_fee, r.burnt_gas_fee,
                        r.gas_sponsor_paid, r.storage_sponsor_paid,
                        r.storage_collateralized.len(), r.storage_released.len(),
                        r.logs.len(),
                    );
                }
                eprintln!(
                    "[DBG]   block_receipts secondary_reward={} block_number={}",
                    block_receipts.secondary_reward, block_receipts.block_number,
                );
            }
            receipts.push(Arc::new(block_receipts));
            last_hash = block.hash;
            block_number += 1;
        }

        let computed_receipts_root = compute_receipts_root(&receipts);
        let computed_logs_bloom_hash =
            BlockHeaderBuilder::compute_block_logs_bloom_hash(&receipts);
        let end_block_number = block_number.saturating_sub(1);
        if debug_epoch {
            eprintln!(
                "[DBG] h={} computed_receipts={:?} computed_logs={:?} end_block_number={} reward_for={}",
                pivot.height, computed_receipts_root, computed_logs_bloom_hash,
                end_block_number,
                if pivot.height > 12 { pivot.height - 12 } else { 0 },
            );
        }
        self.apply_due_rewards(&mut state, end_block_number, pivot)?;

        let state_root = state
            .commit(pivot_hash, None)
            .context("commit replay epoch state")?
            .state_root;
        let computed_state_root = state_root.aux_info.state_root_hash;
        if debug_epoch {
            eprintln!(
                "[DBG] h={} state_root_hash={:?} snapshot={:?} intermediate_delta={:?} delta={:?}",
                pivot.height, computed_state_root,
                state_root.state_root.snapshot_root,
                state_root.state_root.intermediate_delta_root,
                state_root.state_root.delta_root,
            );
        }
        self.previous_epoch_hash = pivot_hash;
        self.previous_state_root = state_root;

        let current_commitment = EpochCommitment {
            state_root: computed_state_root,
            receipts_root: computed_receipts_root,
            logs_bloom_hash: computed_logs_bloom_hash,
        };
        let deferred_height = deferred_commitment_height(pivot.height);
        let deferred_commitment = self
            .commitments_by_height
            .get(&deferred_height)
            .ok_or_else(|| {
                anyhow!(
                    "missing deferred execution commitment for height {} \
                     (pivot.height={}, pivot.epoch={})",
                    deferred_height,
                    pivot.height,
                    pivot.epoch,
                )
            })?;
        let checks = compare_commitment(deferred_commitment, pivot);

        self.commitments_by_height
            .insert(pivot.height, current_commitment);
        self.executed_epochs_by_height.insert(
            pivot.height,
            ExecutedEpoch {
                blocks: blocks.iter().map(|b| (*b).clone()).collect(),
                receipts: receipts.clone(),
            },
        );
        self.prune_old_state(pivot.height);

        Ok(EpochReport {
            pivot_height: pivot.height,
            deferred_height,
            pivot_hash,
            pivot_timestamp: pivot.timestamp,
            block_count: blocks.len(),
            transaction_count: blocks
                .iter()
                .map(|b| b.transactions.len())
                .sum(),
            computed_state_root,
            expected_state_root_prefix: checks.expected_state_root_prefix,
            state_root_prefix_match: checks.state_root_prefix_match,
            computed_receipts_root,
            expected_receipts_root_prefix: checks.expected_receipts_root_prefix,
            receipts_root_prefix_match: checks.receipts_root_prefix_match,
            computed_logs_bloom_hash,
            expected_logs_bloom_hash_prefix: checks.expected_logs_bloom_hash_prefix,
            logs_bloom_prefix_match: checks.logs_bloom_prefix_match,
        })
    }

    fn open_next_state(&self, pivot: &Block) -> Result<State> {
        // The minimal-mpt backend keeps only the latest state and is advanced
        // in place each epoch, so there is no `StateIndex` history to consult —
        // every epoch just wraps a fresh adapter over the same shared state.
        #[cfg(feature = "backend-minimal-mpt")]
        {
            let _ = pivot;
            return State::new(StateDb::new(Box::new(
                self.minimal_backend.open(),
            )))
            .context("create replay execution state (minimal-mpt)");
        }
        #[cfg(not(feature = "backend-minimal-mpt"))]
        {
            let state_index = StateIndex::new_for_next_epoch(
                &self.previous_epoch_hash,
                &self.previous_state_root,
                pivot.epoch.saturating_sub(1),
                self.snapshot_epoch_count,
            );
            let storage = self
                .storage_manager
                .get_state_for_next_epoch(state_index, false)
                .context("open replay state for next epoch")?
                .ok_or_else(|| anyhow!("replay state for next epoch missing"))?;
            State::new(StateDb::new(storage))
                .context("create replay execution state")
        }
    }

    fn execute_block(
        &self, block: &Block, pivot: &Block, block_number: u64,
        last_hash: H256, state: &mut State,
    ) -> Result<BlockReceipts> {
        let secondary_reward =
            self.before_block_execution(state, block_number, block)?;
        let mut env =
            self.make_env(block, pivot, block_number, last_hash, state);
        let mut accumulated_gas_used = U256::zero();
        let mut block_receipts = Vec::with_capacity(block.transactions.len());
        let mut errors = Vec::with_capacity(block.transactions.len());
        for tx in &block.transactions {
            let spec = self.machine.spec(env.number, env.epoch_height);
            let options = TransactOptions {
                observer: Observer::with_no_tracing(),
                settings: TransactSettings::all_checks(),
            };
            env.transaction_hash = tx.hash();
            let outcome =
                ExecutiveContext::new(state, &env, &self.machine, &spec)
                    .transact(tx, options)
                    .context("execute replay transaction")?;
            state.update_state_post_tx_execution(!spec.cip645.fix_eip1153);
            if let Some(burnt_fee) =
                outcome.try_as_executed().and_then(|e| e.burnt_fee)
            {
                state.burn_by_cip1559(burnt_fee);
            }
            let processed = make_process_tx_outcome(
                outcome,
                &mut accumulated_gas_used,
                tx.hash(),
                &spec,
            );
            block_receipts.push(processed.receipt);
            errors.push(processed.tx_exec_error_msg);
        }
        Ok(BlockReceipts {
            receipts: block_receipts,
            block_number: block_number + 1,
            secondary_reward,
            tx_execution_error_messages: errors,
        })
    }

    fn make_env(
        &self, block: &Block, pivot: &Block, block_number: u64,
        last_hash: H256, state: &mut State,
    ) -> Env {
        let base_gas_price =
            SpaceMap::new(block.base_price_core, block.base_price_espace);
        let burnt_gas_price =
            base_gas_price.map_all(|x| state.burnt_gas_price(x));
        Env {
            chain_id: self.machine.params().chain_id_map(pivot.epoch),
            number: block_number,
            author: block.author,
            timestamp: pivot.timestamp,
            difficulty: block.difficulty,
            accumulated_gas_used: U256::zero(),
            last_hash,
            gas_limit: block.gas_limit,
            epoch_height: pivot.epoch,
            pos_view: None,
            finalized_epoch: finalized_epoch(
                pivot.epoch,
                block.finalized_epoch,
            ),
            transaction_epoch_bound: self.conf.raw_conf.transaction_epoch_bound,
            base_gas_price,
            burnt_gas_price,
            transaction_hash: H256::zero(),
        }
    }

    fn before_epoch_execution(
        &self, state: &mut State, pivot: &Block,
    ) -> Result<()> {
        let params = self.machine.params();
        if pivot.epoch >= params.transition_heights.cip133e {
            state
                .set_system_storage(
                    epoch_hash_slot(pivot.epoch).into(),
                    U256::from_big_endian(pivot.hash.as_bytes()),
                )
                .context("set epoch hash slot")?;
        }
        if pivot.epoch >= params.transition_heights.eip2935 {
            state
                .set_eip2935_storage(pivot.epoch - 1, self.previous_epoch_hash)
                .context("set eip2935 parent hash")?;
        }
        Ok(())
    }

    fn before_block_execution(
        &self, state: &mut State, block_number: u64, block: &Block,
    ) -> Result<U256> {
        let params = self.machine.params();
        let transition_numbers = &params.transition_numbers;

        let cip94_start = transition_numbers.cip94n;
        let period = params.params_dao_vote_period;
        if block_number >= cip94_start
            && (block_number - cip94_start).is_multiple_of(period)
        {
            let set_pos_staking = block_number > transition_numbers.cip105;
            cfx_executor::state::initialize_or_update_dao_voted_params(
                state,
                set_pos_staking,
            )
            .context("initialize/update DAO voted params")?;
        }

        if block_number == transition_numbers.cip107 {
            initialize_cip107(state).context("initialize cip107")?;
        }

        if block_number >= transition_numbers.cip133b {
            state
                .set_system_storage(
                    block_hash_slot(block_number).into(),
                    U256::from_big_endian(block.hash.as_bytes()),
                )
                .context("set block hash slot")?;
        }

        if block_number == transition_numbers.cip137 {
            initialize_cip137(state);
        }

        if block_number < transition_numbers.cip43a {
            state.bump_block_number_accumulate_interest();
        }

        let secondary_reward = state.secondary_reward();
        state
            .inc_distributable_pos_interest(block_number)
            .context("increase distributable PoS interest")?;
        initialize_internal_contract_accounts(
            state,
            self.machine
                .internal_contracts()
                .initialized_at(block_number),
        )
        .context("initialize internal contract accounts")?;
        state.commit_cache(false);
        Ok(secondary_reward)
    }
}
