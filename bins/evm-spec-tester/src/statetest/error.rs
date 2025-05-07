use cfx_bytes::Bytes;
use cfx_executor::executive::ExecutionOutcome;
use cfx_types::{H256, U256};
use cfxkey::Address;
use primitives::transaction::TransactionError;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Path: {path}\nName: {name}\nError: {kind}")]
pub struct TestError {
    pub name: String,
    pub path: String,
    pub kind: TestErrorKind,
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum TestErrorKind {
    #[error("state mismatch: {0}")]
    StateMismatch(#[from] StateMismatch),
    #[error("consensus check fail: {0}")]
    ConsensusCheckFail(#[from] TransactionError),
    #[error("unknown private key: {0:?}")]
    UnknownPrivateKey(H256),
    #[error("execution error: {outcome:?}")]
    ExecutionError { outcome: ExecutionOutcome },
    #[error("common check error: {tx_error:?}")]
    CommonCheckError { tx_error: TransactionError },
    #[error("should fail but success: {fail_reason}")]
    ShouldFail { fail_reason: String },
    #[error(
        "inconsistent fail_reason (execution): expect: {fail_reason}, actual: {outcome:?}"
    )]
    InconsistentError {
        outcome: ExecutionOutcome,
        fail_reason: String,
    },
    #[error(
        "inconsistent fail_reason (consensus): expect: {fail_reason}, actual: {error:?}"
    )]
    InconsistentErrorConsensus {
        error: TransactionError,
        fail_reason: String,
    },
    #[error(
        "unexpected output: got {got_output:?}, expected {expected_output:?}"
    )]
    UnexpectedOutput {
        expected_output: Option<Bytes>,
        got_output: Option<Bytes>,
    },
    #[error(transparent)]
    SerdeDeserialize(#[from] serde_json::Error),
    #[error("thread panicked")]
    Panic,
    #[error("path does not exist")]
    InvalidPath,
    #[error("no JSON test files found in path")]
    NoJsonFiles,
    #[error("internal error: {0}")]
    Internal(String),
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum StateMismatch {
    #[error("logs root mismatch: got {got}, expected {expected}")]
    LogsRootMismatch { got: H256, expected: H256 },
    #[error("state root mismatch: got {got}, expected {expected}")]
    StateRootMismatch { got: H256, expected: H256 },
    #[error(
        "balance mismatch: address {address}, got {got}, expected {expected}"
    )]
    BalanceMismatch {
        address: Address,
        got: U256,
        expected: U256,
    },
    #[error("gas mismatch: got {got}, expected {expected}")]
    GasMismatch { got: U256, expected: U256 },
    #[error(
        "nonce mismatch: address {address}, got {got}, expected {expected}"
    )]
    NonceMismatch {
        address: Address,
        got: U256,
        expected: U256,
    },
    #[error("code mismatch: got {got}, expected {expected}")]
    CodeMismatch { got: String, expected: String },
    #[error("storage mismatch (key {key}): got {got}, expected {expected}")]
    StorageMismatch {
        key: U256,
        got: U256,
        expected: U256,
    },
}
