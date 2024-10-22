use cfx_types::U256;

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VoteParamsInfo {
    pub(crate) pow_base_reward: U256,
    pub(crate) interest_rate: U256,
    pub(crate) storage_point_prop: U256,
    pub(crate) base_fee_share_prop: U256,
}
