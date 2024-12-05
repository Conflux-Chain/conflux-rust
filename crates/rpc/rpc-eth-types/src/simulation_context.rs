use crate::BlockNumber;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationContext {
    /// BlockNumber
    pub block_number: Option<BlockNumber>,
    // /// TransactionIndex
    // pub transaction_index: Option<U256>,
}