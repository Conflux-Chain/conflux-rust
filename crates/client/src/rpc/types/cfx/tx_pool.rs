use crate::rpc::types::Transaction;
use cfx_rpc_cfx_types::TransactionStatus;
use cfx_types::{H256, U256, U64};
use serde::Serialize;

#[derive(Default, Serialize)]
pub struct TxWithPoolInfo {
    pub exist: bool,
    pub packed: bool,
    pub local_nonce: U256,
    pub local_balance: U256,
    pub state_nonce: U256,
    pub state_balance: U256,
    pub local_balance_enough: bool,
    pub state_balance_enough: bool,
}

#[derive(Default, Serialize)]
pub struct TxPoolPendingNonceRange {
    pub min_nonce: U256,
    pub max_nonce: U256,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountPendingInfo {
    pub local_nonce: U256,
    pub pending_count: U256,
    pub pending_nonce: U256,
    pub next_pending_tx: H256,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountPendingTransactions {
    pub pending_transactions: Vec<Transaction>,
    pub first_tx_status: Option<TransactionStatus>,
    pub pending_count: U64,
}

#[derive(Default, Serialize)]
pub struct TxPoolStatus {
    pub deferred: U64,
    pub ready: U64,
    pub received: U64,
    pub unexecuted: U64,
}
