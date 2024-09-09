use cfxcore::rpc_errors::Error as CfxCoreError;
use jsonrpc_core::{Error as JsonRpcError, ErrorCode, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid params {0} {1}")]
    InvalidParams(String, String),
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl From<Error> for JsonRpcError {
    fn from(e: Error) -> JsonRpcError {
        match e {
            Error::InvalidParams(msg, details) => JsonRpcError {
                code: ErrorCode::InvalidParams,
                message: msg,
                data: Some(Value::String(details)),
            },
            Error::InternalError(msg) => JsonRpcError {
                code: ErrorCode::InternalError,
                message: msg,
                data: None,
            },
        }
    }
}

impl From<Error> for CfxCoreError {
    fn from(e: Error) -> cfxcore::rpc_errors::Error {
        let e: JsonRpcError = e.into();
        e.into()
    }
}
