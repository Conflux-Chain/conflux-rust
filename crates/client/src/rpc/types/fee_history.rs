use cfx_types::{Space, SpaceMap, H256, U256};
use primitives::{transaction::SignedTransaction, BlockHeader};
use std::collections::VecDeque;

use super::CfxFeeHistory;

#[derive(Serialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FeeHistory {
    /// Oldest Block
    oldest_block: U256,
    /// An array of block base fees per gas. This includes one block earlier
    /// than the oldest block. Zeroes are returned for pre-EIP-1559 blocks.
    base_fee_per_gas: VecDeque<U256>,
    /// In Conflux, 1559 is adjusted by the current block's gas limit of total
    /// transactions, instead of parent's gas used
    gas_used_ratio: VecDeque<f64>,
    /// A two-dimensional array of effective priority fees per gas at the
    /// requested block percentiles.
    reward: VecDeque<Vec<U256>>,
}

impl FeeHistory {
    pub fn new() -> Self { Default::default() }

    pub fn reward(&self) -> &VecDeque<Vec<U256>> { &self.reward }

    pub fn to_cfx_fee_history(self) -> CfxFeeHistory {
        CfxFeeHistory::new(
            self.oldest_block,
            self.base_fee_per_gas,
            self.gas_used_ratio,
            self.reward,
        )
    }

    pub fn push_front_block<'a, I>(
        &mut self, space: Space, percentiles: &Vec<f64>,
        pivot_header: &BlockHeader, transactions: I,
    ) -> Result<(), String>
    where
        I: Clone + Iterator<Item = &'a SignedTransaction>,
    {
        let base_price =
            if let Some(base_price) = pivot_header.space_base_price(space) {
                base_price
            } else {
                self.base_fee_per_gas.push_front(U256::zero());
                self.gas_used_ratio.push_front(0.0);
                self.reward
                    .push_front(vec![U256::zero(); percentiles.len()]);
                return Ok(());
            };
        self.base_fee_per_gas.push_front(base_price);

        let gas_limit = pivot_header.space_gas_limit(space);
        let gas_used = transactions
            .clone()
            .map(|x| *x.gas_limit())
            .reduce(|x, y| x + y)
            .unwrap_or_default();
        let gas_used_ratio = if gas_limit >= U256::from(u128::MAX)
            || gas_used >= U256::from(u128::MAX)
        {
            // Impossible path.
            1.0
        } else {
            gas_used.as_u128() as f64 / gas_limit.as_u128() as f64
        };
        self.gas_used_ratio.push_front(gas_used_ratio);

        let mut rewards: Vec<_> = transactions
            .map(|tx| {
                if *tx.gas_price() < base_price {
                    U256::zero()
                } else {
                    tx.effective_gas_price(&base_price)
                }
            })
            .collect();
        rewards.sort_unstable();
        self.reward
            .push_front(compute_reward(percentiles, &rewards));

        Ok(())
    }

    pub fn push_front_entry(
        &mut self, entry: &FeeHistoryEntry, percentiles: &Vec<f64>,
    ) -> Result<(), String> {
        self.base_fee_per_gas
            .push_front(U256::from(entry.base_fee_per_gas));
        self.gas_used_ratio.push_front(entry.gas_used_ratio);

        let rewards: Vec<U256> =
            entry.rewards.iter().map(|x| U256::from(*x)).collect();
        self.reward
            .push_front(compute_reward(percentiles, &rewards));

        Ok(())
    }

    pub fn finish(
        &mut self, oldest_block: u64, last_base_price: Option<&SpaceMap<U256>>,
        space: Space,
    ) {
        self.oldest_block = oldest_block.into();
        self.base_fee_per_gas
            .push_back(last_base_price.map_or(U256::zero(), |x| x[space]));
    }
}

// note rewards is required to be sorted
fn compute_reward(percentiles: &Vec<f64>, rewards: &Vec<U256>) -> Vec<U256> {
    if rewards.is_empty() {
        return vec![U256::zero(); percentiles.len()];
    }

    let n = rewards.len();
    percentiles
        .into_iter()
        .map(|per| {
            let mut index = ((*per) * (n as f64) / 100f64) as usize;
            if index >= n {
                index = n - 1;
            }
            rewards[index]
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct FeeHistoryEntry {
    /// The base fee per gas for this block.
    pub base_fee_per_gas: u64,
    /// Gas used ratio this block.
    pub gas_used_ratio: f64,
    /// Gas used by this block.
    pub gas_used: u64,
    /// Gas limit by this block.
    pub gas_limit: u64,
    /// Hash of the block.
    pub header_hash: H256,
    ///
    pub parent_hash: H256,
    /// Approximated rewards for the configured percentiles.
    pub rewards: Vec<u128>,
    /// The timestamp of the block.
    pub timestamp: u64,
}

impl FeeHistoryEntry {
    pub fn from_block<'a, I>(
        space: Space, pivot_header: &BlockHeader, transactions: I,
    ) -> Self
    where I: Clone + Iterator<Item = &'a SignedTransaction> {
        let gas_limit: u64 = pivot_header.space_gas_limit(space).as_u64();

        let gas_used = transactions
            .clone()
            .map(|x| *x.gas_limit())
            .reduce(|x, y| x + y)
            .unwrap_or_default()
            .as_u64();

        let gas_used_ratio = gas_used as f64 / gas_limit as f64;

        let base_fee_per_gas =
            pivot_header.space_base_price(space).unwrap_or_default();

        let mut rewards: Vec<_> = transactions
            .map(|tx| {
                if *tx.gas_price() < base_fee_per_gas {
                    U256::zero()
                } else {
                    tx.effective_gas_price(&base_fee_per_gas)
                }
            })
            .map(|x| x.as_u128())
            .collect();

        rewards.sort_unstable();

        Self {
            base_fee_per_gas: base_fee_per_gas.as_u64(),
            gas_used_ratio,
            gas_used,
            gas_limit,
            header_hash: pivot_header.hash(),
            parent_hash: *pivot_header.parent_hash(),
            rewards,
            timestamp: pivot_header.timestamp(),
        }
    }
}
