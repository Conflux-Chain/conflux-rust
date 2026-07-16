use cfx_types::{U256, U64};
use serde::Serialize;
use std::collections::VecDeque;

#[derive(Serialize, Debug, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CfxFeeHistory {
    /// Oldest epoch
    oldest_epoch: U64,
    /// Pivot-block base fees per gas for the returned epochs, plus one
    /// additional base fee for the pivot block immediately after the newest
    /// returned epoch. Zeroes are returned for pre-EIP-1559 blocks.
    base_fee_per_gas: VecDeque<U256>,
    /// In Conflux, 1559 is adjusted by the current block's gas limit of total
    /// transactions, instead of parent's gas used
    gas_used_ratio: VecDeque<f64>,
    /// Effective gas prices at the requested pivot-block percentiles. Nonzero
    /// values include the pivot block's base fee.
    reward: VecDeque<Vec<U256>>,
}

impl CfxFeeHistory {
    pub fn new(
        oldest_epoch: U64, base_fee_per_gas: VecDeque<U256>,
        gas_used_ratio: VecDeque<f64>, reward: VecDeque<Vec<U256>>,
    ) -> Self {
        CfxFeeHistory {
            oldest_epoch,
            base_fee_per_gas,
            gas_used_ratio,
            reward,
        }
    }

    pub fn reward(&self) -> &VecDeque<Vec<U256>> { &self.reward }
}
