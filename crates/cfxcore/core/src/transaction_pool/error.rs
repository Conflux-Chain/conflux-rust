use cfx_types::{H256, U256};
use primitives::transaction::TransactionError;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum TransactionPoolError {
    ///
    #[error("{0:?}")]
    TransactionError(TransactionError),
    /// gas limit exceeded maximum value
    #[error("transaction gas {have} exceeds the maximum value {max:?}")]
    GasLimitExceeded { max: U256, have: U256 },

    #[error("transaction gas price {have} less than the minimum value {min}")]
    GasPriceLessThanMinimum { min: U256, have: U256 },

    #[error("{0}")]
    RlpDecodeError(String),

    #[error("Transaction {hash:?} is discarded due to in too distant future")]
    NonceTooDistant { hash: H256, nonce: U256 },

    #[error("Transaction {hash:?} is discarded due to a too stale nonce")]
    NonceTooStale { hash: H256, nonce: U256 },

    #[error("Transaction {hash:?} is discarded due to out of balance, needs {need:?} but account balance is {have:?}")]
    OutOfBalance { need: U256, have: U256, hash: H256 },

    #[error("txpool is full")]
    TxPoolFull,

    #[error("Tx with same nonce already inserted. To replace it, you need to specify a gas price > {expected:?}")]
    HigherGasPriceNeeded { expected: U256 },

    #[error("db error: {0}")]
    StateDbError(String),
}

impl From<cfx_statedb::Error> for TransactionPoolError {
    fn from(value: cfx_statedb::Error) -> Self {
        TransactionPoolError::StateDbError(format!(
            "Failed to read account_cache from storage: {}",
            value
        ))
    }
}
