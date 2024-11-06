use jsonrpc_core::{Error as JsonRpcError, ErrorCode, Value};
use jsonrpsee::types::ErrorObjectOwned;
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

impl From<Error> for ErrorObjectOwned {
    fn from(e: Error) -> ErrorObjectOwned {
        let err: JsonRpcError = e.into();
        ErrorObjectOwned::owned(err.code.code() as i32, err.message, err.data)
    }
}
