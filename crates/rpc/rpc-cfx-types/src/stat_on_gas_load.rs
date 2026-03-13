use cfx_types::{SpaceMap, U256, U64};
use serde_derive::Serialize;

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatOnGasLoad {
    pub time_elapsed: U64,

    pub epoch_num: U64,
    pub total_block_num: U64,
    pub espace_block_num: U64,
    pub total_gas_limit: U256,
    pub espace_gas_limit: U256,

    pub skipped_tx_count: SpaceMap<U64>,
    pub confirmed_tx_count: SpaceMap<U64>,
    pub skipped_tx_gas_limit: SpaceMap<U256>,
    pub confirmed_tx_gas_limit: SpaceMap<U256>,
    pub tx_gas_charged: SpaceMap<U256>,
}
