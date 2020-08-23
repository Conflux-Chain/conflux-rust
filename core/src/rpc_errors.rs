// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

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
    }
}

pub type BoxFuture<T> = Box<
    dyn jsonrpc_core::futures::future::Future<Item = T, Error = Error> + Send,
>;

impl From<JsonRpcError> for Error {
    fn from(j: JsonRpcError) -> Self { ErrorKind::JsonRpcError(j).into() }
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
use std::fmt::Display;
