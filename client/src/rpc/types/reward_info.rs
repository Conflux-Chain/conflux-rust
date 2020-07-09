use cfx_types::{H160, H256, U256};
use cfxcore::block_data_manager::BlockRewardResult;

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardInfo {
    block_hash: H256,
    author: H160,
    total_reward: U256,
    base_reward: U256,
    tx_fee: U256,
}

impl RewardInfo {
    pub fn new(
        block_hash: H256, author: H160, reward_result: BlockRewardResult,
    ) -> Self {
        RewardInfo {
            block_hash: block_hash.into(),
            author: author.into(),
            total_reward: reward_result.total_reward.into(),
            base_reward: reward_result.base_reward.into(),
            tx_fee: reward_result.tx_fee.into(),
        }
    }
}
