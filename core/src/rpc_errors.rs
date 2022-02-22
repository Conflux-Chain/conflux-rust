// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub const EXCEPTION_ERROR: i64 = -32016;

error_chain! {
    links {
    }

    foreign_links {
        FilterError(FilterError);
        Storage(StorageError);
        StateDb(StateDbError);
        Decoder(DecoderError);
        LightProtocol(LightProtocolError);
    }

    errors {
        JsonRpcError(e: JsonRpcError) {
            description("JsonRpcError directly constructed to return to Rpc peer.")
            display("JsonRpcError directly constructed to return to Rpc peer. Error: {}", e)
        }

        InvalidParam(param: String, details: String) {
            description("Error as jsonrpc error InvalidParam.")
            display("Jsonrpc error InvalidParam {}: {}.", param, details)
        }

        Custom(details: String) {
            description("Server custom error")
            display("error detail: {}", details)
        }
    }
}

pub type BoxFuture<T> = Box<
    dyn jsonrpc_core::futures::future::Future<Item = T, Error = Error> + Send,
>;

impl From<JsonRpcError> for Error {
    fn from(j: JsonRpcError) -> Self { ErrorKind::JsonRpcError(j).into() }
}

impl From<Error> for JsonRpcError {
    fn from(e: Error) -> JsonRpcError {
        match e.0 {
            ErrorKind::JsonRpcError(j) => j,
            ErrorKind::InvalidParam(param, details) => {
                invalid_params(&param, details)
            }
            ErrorKind::Msg(_)
            | ErrorKind::Decoder(_)

            // TODO(thegaram): consider returning InvalidParams instead
            | ErrorKind::FilterError(_)

            // TODO(thegaram): make error conversion more fine-grained here
            | ErrorKind::LightProtocol(_)
            | ErrorKind::StateDb(_)
            | ErrorKind::Storage(_)
            | ErrorKind::Custom(_) => JsonRpcError {
                code: jsonrpc_core::ErrorCode::ServerError(EXCEPTION_ERROR),
                message: format!("Error processing request: {}", e),
                data: None,
            },
            // We exhausted all possible ErrorKinds here, however
            // https://stackoverflow.com/questions/36440021/whats-purpose-of-errorkind-nonexhaustive
            ErrorKind::__Nonexhaustive {} => unsafe {
                std::hint::unreachable_unchecked()
            },
        }
    }
}

pub fn invalid_params<T: Debug>(param: &str, details: T) -> JsonRpcError {
    JsonRpcError {
        code: jsonrpc_core::ErrorCode::InvalidParams,
        message: format!("Invalid parameters: {}", param),
        data: Some(Value::String(format!("{:?}", details))),
    }
}

pub fn invalid_params_check<T, E: Display>(
    param: &str, r: std::result::Result<T, E>,
) -> Result<T> {
    match r {
        Ok(t) => Ok(t),
        Err(e) => {
            Err(ErrorKind::InvalidParam(param.into(), format!("{}", e)).into())
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
