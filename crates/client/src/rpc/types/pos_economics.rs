use cfx_types::{U256, U64};

#[derive(Debug, Serialize, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PoSEconomics {
    // This is the total number of CFX used for pos staking.
    pub total_pos_staking_tokens: U256,
    // This is the total distributable interest.
    pub distributable_pos_interest: U256,
    // This is the block number of last .
    pub last_distribute_block: U64,
}
