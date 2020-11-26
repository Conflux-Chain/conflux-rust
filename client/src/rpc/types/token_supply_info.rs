use cfx_types::U256;

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenSupplyInfo {
    pub total_issued: U256,
    pub total_staking: U256,
    pub total_collateral: U256,
}
