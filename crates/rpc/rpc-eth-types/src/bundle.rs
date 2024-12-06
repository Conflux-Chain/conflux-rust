use crate::TransactionRequest;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bundle {
    /// Transactions
    pub transactions: Vec<TransactionRequest>,
    // /// BlockOverride
    // pub block_override: Option<StateOverride>,
}