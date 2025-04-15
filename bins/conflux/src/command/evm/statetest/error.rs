use cfx_bytes::Bytes;
use cfx_types::{H256, U256};
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
    #[error("unknown private key: {0:?}")]
    UnknownPrivateKey(H256),
    #[error("unexpected exception: got {got_exception:?}, expected {expected_exception:?}")]
    UnexpectedException {
        expected_exception: Option<String>,
        got_exception: Option<String>,
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
    #[error("custom error: {0}")]
    Custom(String),
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum StateMismatch {
    #[error("logs root mismatch: got {got}, expected {expected}")]
    LogsRootMismatch { got: H256, expected: H256 },
    #[error("state root mismatch: got {got}, expected {expected}")]
    StateRootMismatch { got: H256, expected: H256 },
    #[error("balance mismatch: got {got}, expected {expected}")]
    BalanceMismatch { got: U256, expected: U256 },
    #[error("nonce mismatch: got {got}, expected {expected}")]
    NonceMismatch { got: U256, expected: U256 },
    #[error("code mismatch: got {got}, expected {expected}")]
    CodeMismatch { got: String, expected: String },
    #[error("state mismatch: key {key} got {got}, expected {expected}")]
    StorageMismatch {
        key: U256,
        got: U256,
        expected: U256,
    },
}
