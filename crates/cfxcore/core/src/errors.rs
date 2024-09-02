// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
use thiserror::Error;

pub const EXCEPTION_ERROR: i64 = -32016;

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

pub type BoxFuture<T> = Box<
    dyn jsonrpc_core::futures::future::Future<Item = T, Error = Error> + Send,
>;

pub type Result<T> = std::result::Result<T, Error>;

impl From<Error> for JsonRpcError {
    fn from(e: Error) -> JsonRpcError {
        match e {
            Error::JsonRpcError(j) => j,
            Error::InvalidParam(param, details) => {
                JsonRpcError {
                    code: jsonrpc_core::ErrorCode::InvalidParams,
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
                code: jsonrpc_core::ErrorCode::ServerError(EXCEPTION_ERROR),
                message: format!("Error processing request: {}", e),
                data: None,
            },
        }
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Error { Error::Msg(s.into()) }
}

impl From<String> for Error {
    fn from(s: String) -> Error { Error::Msg(s) }
}

pub(crate) fn invalid_params<T: Debug>(param: &str, details: T) -> Error {
    Error::JsonRpcError(JsonRpcError {
        code: jsonrpc_core::ErrorCode::InvalidParams,
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
        Err(AccountError::AddressSpaceMismatch(_, _)) => {
            invalid_params_check(param, result)
        }
        Err(AccountError::ReservedAddressSpace(_)) => {
            invalid_params_check(param, result)
        }
    }
}

use crate::light_protocol::Error as LightProtocolError;
use cfx_statedb::Error as StateDbError;
use cfx_storage::Error as StorageError;
use jsonrpc_core::Error as JsonRpcError;
use primitives::{account::AccountError, filter::FilterError};
use rlp::DecoderError;
use serde_json::Value;
use std::fmt::{Debug, Display};
