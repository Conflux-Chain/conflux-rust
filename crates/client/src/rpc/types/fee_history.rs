use std::collections::VecDeque;

use cfx_types::{Space, SpaceMap, U256};
use primitives::{transaction::SignedTransaction, BlockHeader};

#[derive(Serialize, Debug, Default)]
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

    pub fn push_back_block<'a, I>(
        &mut self, space: Space, percentiles: &Vec<f64>,
        pivot_header: &BlockHeader, transactions: I,
    ) -> Result<(), String>
    where
        I: Clone + Iterator<Item = &'a SignedTransaction>,
    {
        let base_price = if let Some(base_price) = pivot_header.base_price() {
            base_price[space]
        } else {
            self.base_fee_per_gas.push_back(U256::zero());
            self.gas_used_ratio.push_back(0.0);
            self.reward.push_back(vec![U256::zero(); percentiles.len()]);
            return Ok(());
        };

        self.base_fee_per_gas.push_back(
            pivot_header.base_price().map_or(U256::zero(), |x| x[space]),
        );

        let gas_limit: U256 = match space {
            Space::Native => pivot_header.gas_limit() * 9 / 10,
            Space::Ethereum => pivot_header.gas_limit() * 5 / 10,
        };

        let gas_used = transactions
            .clone()
            .map(|x| *x.gas_limit())
            .reduce(|x, y| x + y)
            .unwrap_or_default()
            / gas_limit;

        let gas_used_ratio = if gas_limit >= U256::from(u128::MAX)
            || gas_used >= U256::from(u128::MAX)
        {
            // Impossible path.
            1.0
        } else {
            gas_used.as_u128() as f64 / gas_limit.as_u128() as f64
        };

        self.gas_used_ratio.push_back(gas_used_ratio);

        let reward = compute_reward(percentiles, transactions, base_price);
        self.reward.push_back(reward);

        Ok(())
    }

    pub fn finish(
        &mut self, oldest_block: u64,
        parent_base_price: Option<&SpaceMap<U256>>, space: Space,
    ) {
        self.oldest_block = oldest_block.into();
        self.base_fee_per_gas
            .push_back(parent_base_price.map_or(U256::zero(), |x| x[space]));
    }
}

fn compute_reward<'a, I>(
    percentiles: &Vec<f64>, transactions: I, base_price: U256,
) -> Vec<U256>
where I: Iterator<Item = &'a SignedTransaction> {
    let mut rewards: Vec<_> = transactions
        .map(|tx| {
            if *tx.gas_price() < base_price {
                U256::zero()
            } else {
                tx.effective_gas_price(&base_price)
            }
        })
        .collect();

    if rewards.is_empty() {
        return vec![U256::zero(); percentiles.len()];
    }

    rewards.sort_unstable();
    let n = rewards.len();
    percentiles
        .into_iter()
        .map(|per| {
            let mut index = (*per) as usize * n / 100;
            if index >= n {
                index = n - 1;
            }
            rewards[index]
        })
        .collect()
}
