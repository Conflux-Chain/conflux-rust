use cfx_types::U256;

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoteParamsInfo {
    pub(crate) pow_base_reward: U256,
    pub(crate) interest_rate: U256,
}
