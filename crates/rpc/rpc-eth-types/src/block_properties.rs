use cfx_types::{Address, H256, U256, U64};
use serde::Serialize;

/// Block properties needed for transaction execution
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BlockProperties {
    pub tx_hash: Option<H256>,
    pub inner_block_hash: H256, // hash of the DAG block
    pub coinbase: Address,
    pub difficulty: U256,
    pub gas_limit: U256,
    pub timestamp: U64,
    pub base_fee_per_gas: Option<U256>,
}
