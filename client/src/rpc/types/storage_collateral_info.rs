use cfx_types::U256;

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageCollateralInfo {
    pub total_storage_tokens: U256,
    pub converted_storage_points: U256,
    pub used_storage_points: U256,
}
