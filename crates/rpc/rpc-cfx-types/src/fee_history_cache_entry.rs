use cfx_types::{Space, H256, U256};
use primitives::{transaction::SignedTransaction, BlockHeader};

#[derive(Debug, Clone)]
pub struct FeeHistoryCacheEntry {
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

impl FeeHistoryCacheEntry {
    pub fn from_block<'a, I>(
        space: Space, pivot_header: &BlockHeader, transactions: I,
    ) -> Self
    where I: Clone + Iterator<Item = &'a SignedTransaction> {
        let gas_limit: u64 = if space == Space::Native {
            pivot_header.core_space_gas_limit().as_u64()
        } else {
            pivot_header.espace_gas_limit(true).as_u64()
        };

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
