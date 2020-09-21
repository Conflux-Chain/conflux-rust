use cfx_types::{H160, H256, U256};
use cfxcore::block_data_manager::BlockRewardResult;

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
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

#[cfg(test)]
mod tests {
    use crate::rpc::types::RewardInfo;
    use cfx_types::{H160, H256, U256};
    use cfxcore::block_data_manager::BlockRewardResult;

    #[test]
    fn test_reward_info_serialize() {
        let reward_info = RewardInfo {
            block_hash: H256([0xff; 32]),
            author: H160([0xff; 20]),
            total_reward: U256::one(),
            base_reward: U256::one(),
            tx_fee: U256::one(),
        };
        let serialize = serde_json::to_string(&reward_info).unwrap();
        assert_eq!(serialize,"{\"blockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"author\":\"0xffffffffffffffffffffffffffffffffffffffff\",\"totalReward\":\"0x1\",\"baseReward\":\"0x1\",\"txFee\":\"0x1\"}");
    }
    #[test]
    fn test_reward_info_deserialize() {
        let serialize = "{\"blockHash\":\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"author\":\"0xffffffffffffffffffffffffffffffffffffffff\",\"totalReward\":\"0x1\",\"baseReward\":\"0x1\",\"txFee\":\"0x1\"}";
        let deserialize: RewardInfo = serde_json::from_str(serialize).unwrap();
        let reward_info = RewardInfo {
            block_hash: H256([0xff; 32]),
            author: H160([0xff; 20]),
            total_reward: U256::one(),
            base_reward: U256::one(),
            tx_fee: U256::one(),
        };
        assert_eq!(deserialize, reward_info);
    }
    #[test]
    fn test_reward_info_new() {
        let result = BlockRewardResult::default();
        let info = RewardInfo::new(H256([0xff; 32]), H160([0xff; 20]), result);
        let reward_info = serde_json::to_string(&info).unwrap();
        assert_eq!(reward_info,
        r#"{"blockHash":"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","author":"0xffffffffffffffffffffffffffffffffffffffff","totalReward":"0x0","baseReward":"0x0","txFee":"0x0"}"#);
    }
}
