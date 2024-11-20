use cfx_rpc_utils::error::errors::{
    EthApiError, RpcInvalidTransactionError, RpcPoolError,
};
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

impl From<TransactionPoolError> for EthApiError {
    fn from(err: TransactionPoolError) -> Self {
        match err {
            TransactionPoolError::TransactionError(tx_err) => match tx_err {
                TransactionError::AlreadyImported => Self::PoolError(RpcPoolError::ReplaceUnderpriced),
                TransactionError::ChainIdMismatch { .. } => Self::InvalidTransaction(RpcInvalidTransactionError::InvalidChainId),
                TransactionError::EpochHeightOutOfBound { .. } => Self::InvalidBlockRange,
                TransactionError::NotEnoughBaseGas { .. } => Self::InvalidTransaction(RpcInvalidTransactionError::GasTooLow),
                TransactionError::Stale => Self::InvalidTransaction(RpcInvalidTransactionError::NonceTooLow),
                TransactionError::TooCheapToReplace => Self::PoolError(RpcPoolError::ReplaceUnderpriced),
                TransactionError::LimitReached => Self::PoolError(RpcPoolError::TxPoolOverflow),
                TransactionError::InsufficientGasPrice { .. } => Self::PoolError(RpcPoolError::Underpriced),
                TransactionError::InsufficientGas { .. } => Self::InvalidTransaction(RpcInvalidTransactionError::GasTooLow),
                TransactionError::InsufficientBalance { .. } => Self::InvalidTransaction(RpcInvalidTransactionError::InsufficientFundsForTransfer),
                TransactionError::GasLimitExceeded { .. } => Self::InvalidTransaction(RpcInvalidTransactionError::GasTooHigh),
                TransactionError::InvalidGasLimit(_) => Self::InvalidTransaction(RpcInvalidTransactionError::GasUintOverflow),
                TransactionError::InvalidSignature(_) => Self::InvalidTransactionSignature,
                TransactionError::TooBig => Self::InvalidTransaction(RpcInvalidTransactionError::MaxInitCodeSizeExceeded),
                TransactionError::InvalidRlp(_) => Self::FailedToDecodeSignedTransaction,
                TransactionError::ZeroGasPrice => Self::PoolError(RpcPoolError::Underpriced),
                TransactionError::FutureTransactionType => Self::InvalidTransaction(RpcInvalidTransactionError::TxTypeNotSupported),
                TransactionError::InvalidReceiver => Self::Other("Invalid receiver".to_string()),
                TransactionError::TooLargeNonce => Self::InvalidTransaction(RpcInvalidTransactionError::NonceMaxValue),
            },
            TransactionPoolError::GasLimitExceeded { .. } => Self::PoolError(RpcPoolError::ExceedsGasLimit),
            TransactionPoolError::GasPriceLessThanMinimum { .. } => Self::PoolError(RpcPoolError::Underpriced),
            TransactionPoolError::RlpDecodeError(_) => Self::FailedToDecodeSignedTransaction,
            TransactionPoolError::NonceTooDistant { .. } => Self::InvalidTransaction(RpcInvalidTransactionError::NonceTooHigh),
            TransactionPoolError::NonceTooStale { .. } => Self::InvalidTransaction(RpcInvalidTransactionError::NonceTooLow),
            TransactionPoolError::OutOfBalance { .. } => Self::InvalidTransaction(RpcInvalidTransactionError::InsufficientFundsForTransfer),
            TransactionPoolError::TxPoolFull => Self::PoolError(RpcPoolError::TxPoolOverflow),
            TransactionPoolError::HigherGasPriceNeeded {..} => Self::PoolError(RpcPoolError::ReplaceUnderpriced),
            TransactionPoolError::StateDbError(_) => Self::InternalEthError,
        }
    }
}
