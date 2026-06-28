//! Per-epoch and per-block EVM execution: run each executed block's
//! transactions, apply the pre-execution chain hooks, recompute the epoch's
//! roots, and compare them against the chain.

use super::commitment::{compare_commitment, deferred_commitment_height};
use super::{EpochCommitment, EpochReport, ExecutedEpoch, Replayer};
use anyhow::{anyhow, Context, Result};
use cfxpack::packet::Block;
use cfx_execute_helper::{observer::Observer, tx_outcome::make_process_tx_outcome};
use cfx_executor::{
    executive::{ExecutiveContext, TransactOptions, TransactSettings},
    internal_contract::{
        block_hash_slot, epoch_hash_slot, initialize_internal_contract_accounts,
    },
    state::{initialize_cip107, initialize_cip137, update_pos_status, State},
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
        let mut state = self.open_next_state(pivot)?;
        self.before_epoch_execution(&mut state, pivot)?;

        let mut receipts = Vec::with_capacity(blocks.len());
        let mut block_number = start_block_number;
        let mut last_hash = self.previous_epoch_hash;
        let mut last_pos_view = self.previous_epoch_pos_view;
        let mut last_finalized_epoch = self.previous_epoch_finalized_epoch;
        for &block in blocks {
            let block_receipts = self.execute_block(
                block,
                pivot,
                block_number,
                last_hash,
                last_pos_view,
                last_finalized_epoch,
                &mut state,
            )?;
            receipts.push(Arc::new(block_receipts));
            last_hash = block.hash;
            last_pos_view = block.pos_view;
            last_finalized_epoch = if block.finalized_epoch > 0 {
                Some(block.epoch.saturating_sub(block.finalized_epoch))
            } else {
                None
            };
            block_number += 1;
        }

        let computed_receipts_root = compute_receipts_root(&receipts);
        let computed_logs_bloom_hash =
            BlockHeaderBuilder::compute_block_logs_bloom_hash(&receipts);
        let end_block_number = block_number.saturating_sub(1);
        self.apply_due_rewards(&mut state, end_block_number, pivot)?;

        // PoS unlock + interest distribution (DESIGN §8.8): mirror production
        // `process_pos_interest` which first processes unlock events (adjusting
        // TotalPosStaking), then distributes interest. Order matters because
        // inc_distributable_pos_interest (called per-block) reads TotalPosStaking.
        for entry in &pivot.unlock_events {
            update_pos_status(&mut state, entry.identifier, entry.unlocked)
                .context("apply pos unlock")?;
        }
        for entry in &pivot.pos_rewards {
            debug_assert_eq!(entry.execution_epoch_hash, pivot_hash);
            let distributable = state.distributable_pos_interest();
            let packed_total: U256 = entry
                .account_rewards
                .iter()
                .fold(U256::zero(), |acc, a| acc + a.reward);
            for account in &entry.account_rewards {
                // The packed reward was computed from a (possibly stale)
                // distributable_pos_interest snapshot. Re-derive each
                // validator's share from the live state value using the same
                // proportional formula the production code uses:
                //   interest = distributable * points / MAX_TERM_POINTS
                // Since points/MAX_TERM_POINTS == packed_reward/packed_total,
                // we get: interest = distributable * packed_reward / packed_total
                let interest = if packed_total.is_zero() {
                    U256::zero()
                } else {
                    distributable * account.reward / packed_total
                };
                state
                    .add_pos_interest(&account.address, &interest)
                    .context("apply pos interest")?;
            }
            state.reset_pos_distribute_info(end_block_number);
        }

        let state_root = state
            .commit(pivot_hash, None)
            .context("commit replay epoch state")?
            .state_root;
        let computed_state_root = state_root.aux_info.state_root_hash;
        self.previous_epoch_hash = pivot_hash;
        self.previous_epoch_pos_view = last_pos_view;
        self.previous_epoch_finalized_epoch = last_finalized_epoch;
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
        last_hash: H256, last_pos_view: Option<u64>,
        last_finalized_epoch: Option<u64>, state: &mut State,
    ) -> Result<BlockReceipts> {
        let secondary_reward =
            self.before_block_execution(state, block_number, block)?;
        let mut env =
            self.make_env(block, pivot, block_number, last_hash, last_pos_view, last_finalized_epoch, state);
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
        last_hash: H256, last_pos_view: Option<u64>,
        last_finalized_epoch: Option<u64>, state: &mut State,
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
            pos_view: last_pos_view,
            finalized_epoch: last_finalized_epoch,
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
