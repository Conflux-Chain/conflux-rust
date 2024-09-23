use crate::Transaction;
use cfx_rpc_cfx_types::TransactionStatus;
use cfx_types::U64;
use serde::Serialize;

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountPendingTransactions {
    pub pending_transactions: Vec<Transaction>,
    pub first_tx_status: Option<TransactionStatus>,
    pub pending_count: U64,
}
