use crate::RpcAddress;
use cfx_types::{H256, U256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardInfo {
    pub block_hash: H256,
    pub author: RpcAddress,
    pub total_reward: U256,
    pub base_reward: U256,
    pub tx_fee: U256,
}
