// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::error::jsonrpc_error_helpers::*;
use alloy_primitives::{hex, Address, Bytes};
use alloy_rpc_types::error::EthRpcErrorCode;
use alloy_sol_types::decode_revert_reason;
use jsonrpc_core::{Error as JsonRpcError, ErrorCode};
use revm::primitives::{HaltReason, OutOfGasError};
use std::time::Duration;

// The key point is the error code and message.

/// Result alias
pub type EthResult<T> = Result<T, EthApiError>;

/// Errors that can occur when interacting with the `eth_` namespace
#[derive(Debug, thiserror::Error)]
pub enum EthApiError {
    /// When a raw transaction is empty
    #[error("empty transaction data")]
    EmptyRawTransactionData,
    /// When decoding a signed transaction fails
    #[error("failed to decode signed transaction")]
    FailedToDecodeSignedTransaction,
    /// When the transaction signature is invalid
    #[error("invalid transaction signature")]
    InvalidTransactionSignature,
    /// Errors related to the transaction pool
    #[error(transparent)]
    PoolError(RpcPoolError),
    /// When an unknown block number is encountered
    #[error("unknown block number")]
    UnknownBlockNumber,
    /// Thrown when querying for `finalized` or `safe` block before the merge
    /// transition is finalized, <https://github.com/ethereum/execution-apis/blob/6d17705a875e52c26826124c2a8a15ed542aeca2/src/schemas/block.yaml#L109>
    ///
    /// op-node now checks for either `Unknown block` OR `unknown block`:
    /// <https://github.com/ethereum-optimism/optimism/blob/3b374c292e2b05cc51b52212ba68dd88ffce2a3b/op-service/sources/l2_client.go#L105>
    ///
    /// TODO(#8045): Temporary, until a version of <https://github.com/ethereum-optimism/optimism/pull/10071> is pushed through that doesn't require this to figure out the EL sync status.
    #[error("unknown block")]
    UnknownSafeOrFinalizedBlock,
    /// Thrown when an unknown block or transaction index is encountered
    #[error("unknown block or tx index")]
    UnknownBlockOrTxIndex,
    /// When an invalid block range is provided
    #[error("invalid block range")]
    InvalidBlockRange,
    /// An internal error where prevrandao is not set in the evm's environment
    #[error("prevrandao not in the EVM's environment after merge")]
    PrevrandaoNotSet,
    /// `excess_blob_gas` is not set for Cancun and above
    #[error("excess blob gas missing in the EVM's environment after Cancun")]
    ExcessBlobGasNotSet,
    /// Thrown when a call or transaction request (`eth_call`,
    /// `eth_estimateGas`, `eth_sendTransaction`) contains conflicting
    /// fields (legacy, EIP-1559)
    #[error(
        "both gasPrice and (maxFeePerGas or maxPriorityFeePerGas) specified"
    )]
    ConflictingFeeFieldsInRequest,
    /// Errors related to invalid transactions
    #[error(transparent)]
    InvalidTransaction(#[from] RpcInvalidTransactionError),
    /// Thrown when constructing an RPC block from primitive block data fails
    // #[error(transparent)]
    // InvalidBlockData(#[from] BlockError),
    /// Thrown when an `AccountOverride` contains conflicting `state` and
    /// `stateDiff` fields
    #[error("account {0:?} has both 'state' and 'stateDiff'")]
    BothStateAndStateDiffInOverride(Address),
    /// Other internal error
    // #[error(transparent)]
    // Internal(RethError),
    /// Error related to signing
    // #[error(transparent)]
    // Signing(#[from] SignError),
    /// Thrown when a requested transaction is not found
    #[error("transaction not found")]
    TransactionNotFound,
    /// Some feature is unsupported
    #[error("unsupported")]
    Unsupported(&'static str),
    /// General purpose error for invalid params
    #[error("{0}")]
    InvalidParams(String),
    /// When the tracer config does not match the tracer
    #[error("invalid tracer config")]
    InvalidTracerConfig,
    /// When the percentile array is invalid
    #[error("invalid reward percentiles")]
    InvalidRewardPercentiles,
    /// Error thrown when a spawned blocking task failed to deliver an
    /// anticipated response.
    ///
    /// This only happens if the blocking task panics and is aborted before it
    /// can return a response back to the request handler.
    #[error("internal blocking task error")]
    InternalBlockingTaskError,
    /// Error thrown when a spawned blocking task failed to deliver an
    /// anticipated response
    #[error("internal eth error")]
    InternalEthError,
    /// Error thrown when a (tracing) call exceeds the configured timeout
    #[error("execution aborted (timeout = {0:?})")]
    ExecutionTimedOut(Duration),
    /// Internal Error thrown by the javascript tracer
    #[error("{0}")]
    InternalJsTracerError(String),
    /// Call Input error when both `data` and `input` fields are set and not
    /// equal.
    #[error(transparent)]
    TransactionInputError(#[from] TransactionInputError),
    /// Evm generic purpose error.
    #[error("Revm error: {0}")]
    EvmCustom(String),
    /// Error encountered when converting a transaction type
    #[error("Transaction conversion error")]
    TransactionConversionError,
    /// Error thrown when tracing with a muxTracer fails
    // #[error(transparent)]
    // MuxTracerError(#[from] MuxError),
    /// Any other error
    #[error("{0}")]
    Other(String),
}

impl From<EthApiError> for JsonRpcError {
    fn from(error: EthApiError) -> Self {
        match error {
            EthApiError::FailedToDecodeSignedTransaction |
            EthApiError::InvalidTransactionSignature |
            EthApiError::EmptyRawTransactionData |
            EthApiError::InvalidBlockRange |
            EthApiError::ConflictingFeeFieldsInRequest |
            // EthApiError::Signing(_) |
            EthApiError::BothStateAndStateDiffInOverride(_) |
            EthApiError::InvalidTracerConfig |
            EthApiError::TransactionConversionError => invalid_params_rpc_err(error.to_string()),
            EthApiError::InvalidTransaction(err) => err.into(),
            EthApiError::PoolError(err) => err.into(),
            EthApiError::PrevrandaoNotSet |
            EthApiError::ExcessBlobGasNotSet |
            // EthApiError::InvalidBlockData(_) |
            // EthApiError::Internal(_) |
            EthApiError::TransactionNotFound |
            EthApiError::EvmCustom(_) |
            EthApiError::InvalidRewardPercentiles => internal_rpc_err(error.to_string()),
            EthApiError::UnknownBlockNumber | EthApiError::UnknownBlockOrTxIndex => {
                build_rpc_server_error(EthRpcErrorCode::ResourceNotFound.code() as i64, error.to_string())
            }
            EthApiError::UnknownSafeOrFinalizedBlock => {
                build_rpc_server_error(EthRpcErrorCode::UnknownBlock.code() as i64, error.to_string())
            }
            EthApiError::Unsupported(msg) => internal_rpc_err(msg),
            EthApiError::InternalJsTracerError(msg) => internal_rpc_err(msg),
            EthApiError::InvalidParams(msg) => invalid_params_rpc_err(msg),
            err @ EthApiError::ExecutionTimedOut(_) => {
                build_rpc_server_error(-32000, err.to_string()) // CALL_EXECUTION_FAILED_CODE = -32000
            }
            err @ EthApiError::InternalBlockingTaskError | err @ EthApiError::InternalEthError => {
                internal_rpc_err(err.to_string())
            }
            err @ EthApiError::TransactionInputError(_) => invalid_params_rpc_err(err.to_string()),
            EthApiError::Other(err) => internal_rpc_err(err),
            // EthApiError::MuxTracerError(msg) => internal_rpc_err(msg.to_string()),
        }
    }
}

/// An error due to invalid transaction.
///
/// The only reason this exists is to maintain compatibility with other clients
/// de-facto standard error messages.
///
/// These error variants can be thrown when the transaction is checked prior to
/// execution.
///
/// These variants also cover all errors that can be thrown by revm.
///
/// ## Nomenclature
///
/// This type is explicitly modeled after geth's error variants and uses
///   `fee cap` for `max_fee_per_gas`
///   `tip` for `max_priority_fee_per_gas`
#[derive(thiserror::Error, Debug)]
pub enum RpcInvalidTransactionError {
    /// returned if the nonce of a transaction is lower than the one present in
    /// the local chain.
    #[error("nonce too low")]
    NonceTooLow,
    /// returned if the nonce of a transaction is higher than the next one
    /// expected based on the local chain.
    #[error("nonce too high")]
    NonceTooHigh,
    /// Returned if the nonce of a transaction is too high
    /// Incrementing the nonce would lead to invalid state (overflow)
    #[error("nonce has max value")]
    NonceMaxValue,
    /// thrown if the transaction sender doesn't have enough funds for a
    /// transfer
    #[error("insufficient funds for transfer")]
    InsufficientFundsForTransfer,
    /// thrown if creation transaction provides the init code bigger than init
    /// code size limit.
    #[error("max initcode size exceeded")]
    MaxInitCodeSizeExceeded,
    /// Represents the inability to cover max cost + value (account balance too
    /// low).
    #[error("insufficient funds for gas * price + value")]
    InsufficientFunds,
    /// Thrown when calculating gas usage
    #[error("gas uint64 overflow")]
    GasUintOverflow,
    /// Thrown if the transaction is specified to use less gas than required to
    /// start the invocation.
    #[error("intrinsic gas too low")]
    GasTooLow,
    /// Thrown if the transaction gas exceeds the limit
    #[error("intrinsic gas too high")]
    GasTooHigh,
    /// Thrown if a transaction is not supported in the current network
    /// configuration.
    #[error("transaction type not supported")]
    TxTypeNotSupported,
    /// Thrown to ensure no one is able to specify a transaction with a tip
    /// higher than the total fee cap.
    #[error("max priority fee per gas higher than max fee per gas")]
    TipAboveFeeCap,
    /// A sanity error to avoid huge numbers specified in the tip field.
    #[error("max priority fee per gas higher than 2^256-1")]
    TipVeryHigh,
    /// A sanity error to avoid huge numbers specified in the fee cap field.
    #[error("max fee per gas higher than 2^256-1")]
    FeeCapVeryHigh,
    /// Thrown post London if the transaction's fee is less than the base fee
    /// of the block
    #[error("max fee per gas less than block base fee")]
    FeeCapTooLow,
    /// Thrown if the sender of a transaction is a contract.
    #[error("sender is not an EOA")]
    SenderNoEOA,
    /// Gas limit was exceeded during execution.
    /// Contains the gas limit.
    #[error("out of gas: gas required exceeds allowance: {0}")]
    BasicOutOfGas(u64),
    /// Gas limit was exceeded during memory expansion.
    /// Contains the gas limit.
    #[error("out of gas: gas exhausted during memory expansion: {0}")]
    MemoryOutOfGas(u64),
    /// Gas limit was exceeded during precompile execution.
    /// Contains the gas limit.
    #[error(
        "out of gas: gas exhausted during precompiled contract execution: {0}"
    )]
    PrecompileOutOfGas(u64),
    /// An operand to an opcode was invalid or out of range.
    /// Contains the gas limit.
    #[error("out of gas: invalid operand to an opcode; {0}")]
    InvalidOperandOutOfGas(u64),
    /// Thrown if executing a transaction failed during estimate/call
    #[error(transparent)]
    Revert(RevertError),
    /// Unspecific EVM halt error.
    #[error("EVM error: {0:?}")]
    EvmHalt(HaltReason),
    /// Invalid chain id set for the transaction.
    #[error("invalid chain ID")]
    InvalidChainId,
    /// The transaction is before Spurious Dragon and has a chain ID
    #[error("transactions before Spurious Dragon should not have a chain ID")]
    OldLegacyChainId,
    /// The transitions is before Berlin and has access list
    #[error("transactions before Berlin should not have access list")]
    AccessListNotSupported,
    /// `max_fee_per_blob_gas` is not supported for blocks before the Cancun
    /// hardfork.
    #[error("max_fee_per_blob_gas is not supported for blocks before the Cancun hardfork")]
    MaxFeePerBlobGasNotSupported,
    /// `blob_hashes`/`blob_versioned_hashes` is not supported for blocks
    /// before the Cancun hardfork.
    #[error("blob_versioned_hashes is not supported for blocks before the Cancun hardfork")]
    BlobVersionedHashesNotSupported,
    /// Block `blob_base_fee` is greater than tx-specified
    /// `max_fee_per_blob_gas` after Cancun.
    #[error("max fee per blob gas less than block blob gas fee")]
    BlobFeeCapTooLow,
    /// Blob transaction has a versioned hash with an invalid blob
    #[error("blob hash version mismatch")]
    BlobHashVersionMismatch,
    /// Blob transaction has no versioned hashes
    #[error("blob transaction missing blob hashes")]
    BlobTransactionMissingBlobHashes,
    /// Blob transaction has too many blobs
    #[error(
        "blob transaction exceeds max blobs per block; got {have}, max {max}"
    )]
    TooManyBlobs {
        /// The maximum number of blobs allowed.
        max: usize,
        /// The number of blobs in the transaction.
        have: usize,
    },
    /// Blob transaction is a create transaction
    #[error("blob transaction is a create transaction")]
    BlobTransactionIsCreate,
}

impl RpcInvalidTransactionError {
    /// Returns the rpc error code for this error.
    const fn error_code(&self) -> i32 {
        match self {
            Self::InvalidChainId | Self::GasTooLow | Self::GasTooHigh => {
                EthRpcErrorCode::InvalidInput.code()
            }
            Self::Revert(_) => EthRpcErrorCode::ExecutionError.code(),
            _ => EthRpcErrorCode::TransactionRejected.code(),
        }
    }

    /// Converts the halt error
    ///
    /// Takes the configured gas limit of the transaction which is attached to
    /// the error
    #[allow(dead_code)]
    pub(crate) const fn halt(reason: HaltReason, gas_limit: u64) -> Self {
        match reason {
            HaltReason::OutOfGas(err) => Self::out_of_gas(err, gas_limit),
            HaltReason::NonceOverflow => Self::NonceMaxValue,
            err => Self::EvmHalt(err),
        }
    }

    /// Converts the out of gas error
    #[allow(dead_code)]
    pub(crate) const fn out_of_gas(
        reason: OutOfGasError, gas_limit: u64,
    ) -> Self {
        match reason {
            OutOfGasError::Basic => Self::BasicOutOfGas(gas_limit),
            OutOfGasError::Memory | OutOfGasError::MemoryLimit => {
                Self::MemoryOutOfGas(gas_limit)
            }
            OutOfGasError::Precompile => Self::PrecompileOutOfGas(gas_limit),
            OutOfGasError::InvalidOperand => {
                Self::InvalidOperandOutOfGas(gas_limit)
            }
        }
    }
}

impl From<RpcInvalidTransactionError> for JsonRpcError {
    fn from(e: RpcInvalidTransactionError) -> Self {
        match e {
            RpcInvalidTransactionError::Revert(revert) => JsonRpcError {
                code: ErrorCode::ServerError(revert.error_code() as i64),
                message: revert.to_string(),
                data: revert.output.as_ref().map(|out| out.as_ref()).map(|v| {
                    serde_json::Value::String(hex::encode_prefixed(v))
                }),
            },
            err => JsonRpcError {
                code: ErrorCode::ServerError(err.error_code() as i64),
                message: err.to_string(),
                data: None,
            },
        }
    }
}

/// Error thrown when both `data` and `input` fields are set and not equal.
#[derive(Debug, Default, thiserror::Error)]
#[error("both \"data\" and \"input\" are set and not equal. Please use \"input\" to pass transaction call data")]
#[non_exhaustive]
pub struct TransactionInputError;
/// Represents a reverted transaction and its output data.
///
/// Displays "execution reverted(: reason)?" if the reason is a string.
#[derive(Debug, Clone)]
pub struct RevertError {
    /// The transaction output data
    ///
    /// Note: this is `None` if output was empty
    output: Option<Bytes>,
}

// === impl RevertError ==

impl RevertError {
    /// Wraps the output bytes
    ///
    /// Note: this is intended to wrap an revm output
    pub fn new(output: Bytes) -> Self {
        if output.is_empty() {
            Self { output: None }
        } else {
            Self {
                output: Some(output),
            }
        }
    }

    const fn error_code(&self) -> i32 { EthRpcErrorCode::ExecutionError.code() }
}

impl std::fmt::Display for RevertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("execution reverted")?;
        if let Some(reason) = self
            .output
            .as_ref()
            .and_then(|bytes| decode_revert_reason(bytes))
        {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RevertError {}

/// A helper error type that's mainly used to mirror `geth` Txpool's error
/// messages
#[derive(Debug, thiserror::Error)]
pub enum RpcPoolError {
    /// When the transaction is already known
    #[error("already known")]
    AlreadyKnown,
    /// When the sender is invalid
    #[error("invalid sender")]
    InvalidSender,
    /// When the transaction is underpriced
    #[error("transaction underpriced")]
    Underpriced,
    /// When the transaction pool is full
    #[error("txpool is full")]
    TxPoolOverflow,
    /// When the replacement transaction is underpriced
    #[error("replacement transaction underpriced")]
    ReplaceUnderpriced,
    /// When the transaction exceeds the block gas limit
    #[error("exceeds block gas limit")]
    ExceedsGasLimit,
    /// When a negative value is encountered
    #[error("negative value")]
    NegativeValue,
    /// When oversized data is encountered
    #[error("oversized data")]
    OversizedData,
    /// When the max initcode size is exceeded
    #[error("max initcode size exceeded")]
    ExceedsMaxInitCodeSize,
    /// Errors related to invalid transactions
    #[error(transparent)]
    Invalid(#[from] RpcInvalidTransactionError),
    /// Custom pool error
    // #[error(transparent)]
    // PoolTransactionError(Box<dyn PoolTransactionError>),
    /// Eip-4844 related error
    // #[error(transparent)]
    // Eip4844(#[from] Eip4844PoolTransactionError),
    /// Thrown if a conflicting transaction type is already in the pool
    ///
    /// In other words, thrown if a transaction with the same sender that
    /// violates the exclusivity constraint (blob vs normal tx)
    #[error("address already reserved")]
    AddressAlreadyReserved,
    /// Other unspecified error
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl From<RpcPoolError> for JsonRpcError {
    fn from(e: RpcPoolError) -> Self {
        match e {
            RpcPoolError::Invalid(err) => err.into(),
            error => JsonRpcError {
                code: ErrorCode::InternalError,
                message: error.to_string(),
                data: None,
            },
        }
    }
}
