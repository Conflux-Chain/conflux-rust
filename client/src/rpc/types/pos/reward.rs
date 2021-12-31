// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::RpcAddress;
use cfx_addr::Network;
use cfx_types::{H256, U256};
use cfxcore::block_data_manager::block_data_types::PosRewardInfo;
use std::collections::HashMap;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reward {
    //
    pub pos_address: H256,
    //
    pub pow_address: RpcAddress,
    //
    pub reward: U256,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PoSEpochReward {
    //
    pub pow_epoch_hash: H256,
    //
    pub account_rewards: Vec<Reward>,
}

impl PoSEpochReward {
    pub fn try_from(
        reward: PosRewardInfo, network_type: Network,
    ) -> Result<PoSEpochReward, String> {
        let default_value = U256::from(0);
        let mut account_reward_map = HashMap::new();
        let mut account_address_map = HashMap::new();
        for r in reward.account_rewards.iter() {
            let key = r.pos_identifier;
            let r1 = account_reward_map.get(&key).unwrap_or(&default_value);
            let merged_reward = r.reward + r1;
            account_reward_map.insert(key, merged_reward);

            let rpc_address =
                RpcAddress::try_from_h160(r.address, network_type)?;
            account_address_map.insert(key, rpc_address);
        }
        let account_rewards = account_reward_map
            .iter()
            .map(|(k, v)| Reward {
                pos_address: *k,
                pow_address: account_address_map.get(k).unwrap().clone(),
                reward: *v,
            })
            .filter(|r| r.reward > U256::from(0))
            .collect();
        Ok(PoSEpochReward {
            pow_epoch_hash: reward.execution_epoch_hash,
            account_rewards,
        })
    }
}
