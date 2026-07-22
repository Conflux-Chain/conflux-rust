use cfx_types::U256;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoteParamsInfo {
    pub pow_base_reward: U256,
    pub interest_rate: U256,
    pub storage_point_prop: U256,
    pub base_fee_share_prop: U256,
}
