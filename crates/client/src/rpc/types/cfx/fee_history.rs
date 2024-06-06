use crate::rpc::types::FeeHistory;
use cfx_types::U256;
use std::collections::VecDeque;

#[derive(Serialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct CfxFeeHistory {
    /// Oldest epoch
    oldest_epoch: U256,
    /// An array of pivot block base fees per gas. This includes one block
    /// earlier than the oldest block. Zeroes are returned for pre-EIP-1559
    /// blocks.
    base_fee_per_gas: VecDeque<U256>,
    /// In Conflux, 1559 is adjusted by the current block's gas limit of total
    /// transactions, instead of parent's gas used
    gas_used_ratio: VecDeque<f64>,
    /// A two-dimensional array of effective priority fees per gas at the
    /// requested block percentiles.
    reward: VecDeque<Vec<U256>>,
}

impl CfxFeeHistory {
    pub fn new(fee_history: FeeHistory) -> Self { fee_history.into() }

    pub fn reward(&self) -> &VecDeque<Vec<U256>> { &self.reward }
}

impl From<FeeHistory> for CfxFeeHistory {
    fn from(fee_history: FeeHistory) -> Self {
        Self {
            oldest_epoch: fee_history.oldest_block,
            base_fee_per_gas: fee_history.base_fee_per_gas,
            gas_used_ratio: fee_history.gas_used_ratio,
            reward: fee_history.reward,
        }
    }
}
