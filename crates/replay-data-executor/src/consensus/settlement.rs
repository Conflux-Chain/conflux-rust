//! Block and transaction-fee reward settlement.
//!
//! Conflux settles an epoch's rewards `REWARD_EPOCH_COUNT` epochs after it
//! executes, so this runs while committing a later pivot, against the retained
//! [`ExecutedEpoch`](super::ExecutedEpoch) of the epoch being settled.

use super::Replayer;
use anyhow::{anyhow, ensure, Context, Result};
use cfxpack::packet::{Block, FLAG_ZERO_TOTAL_REWARD};
use cfx_executor::state::State;
use cfx_parameters::consensus_internal::REWARD_EPOCH_COUNT;
use cfx_types::{Address, AddressSpaceUtil, H256, U256};
use primitives::receipt::BlockReceipts;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TxIdentity {
    block_index: usize,
    tx_index: usize,
}

#[derive(Default)]
struct TxExecutionInfo {
    fee: U256,
    packing_blocks: BTreeSet<H256>,
}

impl Replayer {
    /// Apply the block/fee reward settled at this epoch, if one is due.
    pub(super) fn apply_due_rewards(
        &mut self, state: &mut State, end_block_number: u64, pivot: &Block,
    ) -> Result<()> {
        let Some(reward_height) = reward_commitment_height(pivot.height) else {
            return Ok(());
        };
        let reward_epoch = self
            .executed_epochs_by_height
            .get(&reward_height)
            .ok_or_else(|| {
                anyhow!("missing reward execution data for height {}", reward_height)
            })?;
        self.process_rewards_and_fees(
            state,
            &reward_epoch.blocks,
            &reward_epoch.receipts,
            end_block_number,
            pivot,
        )
    }

    fn process_rewards_and_fees(
        &self, state: &mut State, blocks: &[Block],
        receipts: &[Arc<BlockReceipts>], end_block_number: u64,
        pivot: &Block,
    ) -> Result<()> {
        let debug_reward = (30361150..=30361170).contains(&pivot.height);
        let spec = self.machine.spec(end_block_number, pivot.height);
        let mut total_base_reward = U256::zero();
        let mut block_base_rewards = Vec::with_capacity(blocks.len());
        for block in blocks {
            let reward = block.base_reward;
            if !reward.is_zero() {
                total_base_reward += reward;
            }
            block_base_rewards.push(reward);
        }
        if debug_reward {
            let reward_height = if pivot.height > 12 { pivot.height - 12 } else { 0 };
            eprintln!(
                "[DBG-REWARD] pivot_h={} settling_h={} blocks={} total_base_reward={} receipts={}",
                pivot.height, reward_height, blocks.len(), total_base_reward, receipts.len(),
            );
            for (i, block) in blocks.iter().enumerate() {
                let zero_total = block.flags & FLAG_ZERO_TOTAL_REWARD != 0;
                eprintln!(
                    "[DBG-REWARD]   blk[{}] hash={:?} base_reward={} zero_total_reward={} author={:?} txs={} tx_refs={:?}",
                    i, block.hash, block.base_reward, zero_total, block.author,
                    block.transactions.len(), block.transaction_refs,
                );
            }
        }

        let mut tx_fee = HashMap::<TxIdentity, TxExecutionInfo>::new();
        let mut secondary_reward = U256::zero();
        for (block, block_receipts) in blocks.iter().zip(receipts.iter()) {
            secondary_reward += block_receipts.secondary_reward;
            ensure!(
                block.transactions.len() == block_receipts.receipts.len(),
                "transaction and receipt count mismatch for block {:?}",
                block.hash
            );
            for (tx_index, receipt) in
                block_receipts.receipts.iter().enumerate()
            {
                let fee =
                    receipt.gas_fee - receipt.burnt_gas_fee.unwrap_or_default();
                let info = tx_fee
                    .entry(transaction_identity(block, tx_index))
                    .or_default();
                if !fee.is_zero() && info.fee.is_zero() {
                    info.fee = fee;
                }
                // A block shares this tx's fee iff its full settlement reward
                // (total_reward) is non-zero. `base_reward == 0` is NOT the
                // right signal: a valid (non-penalized) weak block can have
                // base_reward == 0 yet still participate in fee distribution.
                // blame is orthogonal (a deferred-root verification concern)
                // and plays no role here.
                if block.flags & FLAG_ZERO_TOTAL_REWARD == 0 {
                    info.packing_blocks.insert(block.hash);
                }
            }
        }

        let mut block_tx_fees = HashMap::<H256, U256>::new();
        let mut burnt_fee = U256::zero();
        for info in tx_fee.values() {
            if info.packing_blocks.is_empty() {
                burnt_fee += info.fee;
                continue;
            }
            let block_count = U256::from(info.packing_blocks.len());
            let quotient = info.fee / block_count;
            let mut remainder = info.fee - block_count * quotient;
            for block_hash in &info.packing_blocks {
                let reward =
                    block_tx_fees.entry(*block_hash).or_insert(U256::zero());
                *reward += quotient;
                if !remainder.is_zero() {
                    *reward += U256::one();
                    remainder -= U256::one();
                }
            }
        }

        let mut merged_rewards = BTreeMap::<Address, U256>::new();
        let mut allocated_secondary_reward = U256::zero();
        for (block, base_reward) in blocks.iter().zip(block_base_rewards) {
            let fee = block_tx_fees
                .get(&block.hash)
                .copied()
                .unwrap_or_else(U256::zero);
            let total_reward =
                if !base_reward.is_zero() && !total_base_reward.is_zero() {
                    let block_secondary_reward =
                        base_reward * secondary_reward / total_base_reward;
                    allocated_secondary_reward += block_secondary_reward;
                    base_reward + fee + block_secondary_reward
                } else {
                    base_reward + fee
                };
            *merged_rewards.entry(block.author).or_insert(U256::zero()) +=
                total_reward;
        }

        for (address, reward) in merged_rewards {
            if spec.is_valid_address(&address) {
                state
                    .add_balance(&address.with_native_space(), &reward)
                    .context("apply block reward")?;
            }
        }

        let new_mint = total_base_reward + allocated_secondary_reward;
        if new_mint >= burnt_fee {
            state.add_total_issued(new_mint - burnt_fee);
        } else {
            state.sub_total_issued(burnt_fee - new_mint);
        }
        Ok(())
    }
}

/// The committed height whose reward a pivot at `height` settles, or `None`
/// before the first settleable height.
fn reward_commitment_height(height: u64) -> Option<u64> {
    if height <= REWARD_EPOCH_COUNT {
        None
    } else {
        Some(height - REWARD_EPOCH_COUNT)
    }
}

fn transaction_identity(block: &Block, tx_index: usize) -> TxIdentity {
    let (block_index, tx_index) = block
        .transaction_refs
        .get(tx_index)
        .copied()
        .flatten()
        .unwrap_or((block.index, tx_index));
    TxIdentity {
        block_index,
        tx_index,
    }
}
