// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
use crate::light_protocol::Error as LightProtocolError;
use cfx_rpc_eth_types::Error as EthRpcError;
pub use cfx_rpc_utils::error::error_codes::EXCEPTION_ERROR;
use cfx_statedb::Error as StateDbError;
use cfx_storage::Error as StorageError;
use jsonrpc_core::{futures::future, Error as JsonRpcError, ErrorCode};
use jsonrpsee::types::ErrorObjectOwned;
use primitives::{account::AccountError, filter::FilterError};
use rlp::DecoderError;
use serde_json::Value;
use std::{
    fmt::{Debug, Display},
    pin::Pin,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    FilterError(#[from] FilterError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    StateDb(#[from] StateDbError),
    #[error(transparent)]
    Decoder(#[from] DecoderError),
    #[error(transparent)]
    LightProtocol(#[from] LightProtocolError),
    #[error(
        "JsonRpcError directly constructed to return to Rpc peer. Error: {0}"
    )]
    JsonRpcError(#[from] JsonRpcError),
    #[error("Jsonrpc error InvalidParam {0}: {1}.")]
    InvalidParam(String, String),
    #[error("Custom error detail: {0}")]
    Custom(String),
    #[error("Msg error detail: {0}")]
    Msg(String),
}

pub type BoxFuture<T> = Pin<Box<dyn future::Future<Output = Result<T>> + Send>>;

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for JsonRpcError {
    fn from(e: Error) -> JsonRpcError {
        match e {
            Error::JsonRpcError(j) => j,
            Error::InvalidParam(param, details) => {
                JsonRpcError {
                    code: ErrorCode::InvalidParams,
                    message: format!("Invalid parameters: {}", param),
                    data: Some(Value::String(format!("{:?}", details))),
                }
            }
            Error::Msg(_)
            | Error::Decoder(_)

            // TODO(thegaram): consider returning InvalidParams instead
            | Error::FilterError(_)

            // TODO(thegaram): make error conversion more fine-grained here
            | Error::LightProtocol(_)
            | Error::StateDb(_)
            | Error::Storage(_)
            | Error::Custom(_) => JsonRpcError {
                code: ErrorCode::ServerError(EXCEPTION_ERROR),
                message: format!("Error processing request: {}", e),
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

impl From<&str> for Error {
    fn from(s: &str) -> Error { Error::Msg(s.into()) }
}

impl From<String> for Error {
    fn from(s: String) -> Error { Error::Msg(s) }
}

impl From<EthRpcError> for Error {
    fn from(e: EthRpcError) -> Error {
        let e: JsonRpcError = e.into();
        e.into()
    }
}

pub(crate) fn invalid_params<T: Debug>(param: &str, details: T) -> Error {
    Error::JsonRpcError(JsonRpcError {
        code: ErrorCode::InvalidParams,
        message: format!("Invalid parameters: {}", param),
        data: Some(Value::String(format!("{:?}", details))),
    })
    .into()
}

pub(crate) fn invalid_params_check<T, E: Display>(
    param: &str, r: std::result::Result<T, E>,
) -> Result<T> {
    match r {
        Ok(t) => Ok(t),
        Err(e) => {
            Err(Error::InvalidParam(param.into(), format!("{}", e)).into())
        }
    }
}

pub fn account_result_to_rpc_result<T>(
    param: &str, result: std::result::Result<T, AccountError>,
) -> Result<T> {
    match result {
        Ok(t) => Ok(t),
        Err(AccountError::InvalidRlp(decoder_error)) => {
            Err(decoder_error.into())
        }
        Err(e) => Err(invalid_params(param, format!("{}", e))),
    }
}
