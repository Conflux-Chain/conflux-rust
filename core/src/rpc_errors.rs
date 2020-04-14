// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

error_chain! {
    links {
    }

    foreign_links {
        FilterError(FilterError);
        Storage(StorageError);
        Decoder(DecoderError);
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

use crate::storage::Error as StorageError;
use jsonrpc_core::Error as JsonRpcError;
use primitives::filter::FilterError;
use rlp::DecoderError;
use std::fmt::Display;
