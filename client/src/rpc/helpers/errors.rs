#![allow(dead_code)]

// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

//! RPC Error codes and error objects

use std::fmt;

use crate::rpc::types::Bytes;
use jsonrpc_core::{Error, ErrorCode, Value};

mod codes {
    // NOTE [ToDr] Codes from [-32099, -32000]
    pub const UNSUPPORTED_REQUEST: i64 = -32000;
    pub const NO_WORK: i64 = -32001;
    pub const NO_AUTHOR: i64 = -32002;
    pub const NO_NEW_WORK: i64 = -32003;
    pub const NO_WORK_REQUIRED: i64 = -32004;
    pub const CANNOT_SUBMIT_WORK: i64 = -32005;
    pub const CANNOT_SUBMIT_BLOCK: i64 = -32006;
    pub const UNKNOWN_ERROR: i64 = -32009;
    pub const TRANSACTION_ERROR: i64 = -32010;
    pub const EXECUTION_ERROR: i64 = -32015;
    pub const EXCEPTION_ERROR: i64 = -32016;
    pub const DATABASE_ERROR: i64 = -32017;
    #[cfg(any(test, feature = "accounts"))]
    pub const ACCOUNT_LOCKED: i64 = -32020;
    #[cfg(any(test, feature = "accounts"))]
    pub const PASSWORD_INVALID: i64 = -32021;
    pub const ACCOUNT_ERROR: i64 = -32023;
    pub const PRIVATE_ERROR: i64 = -32024;
    pub const REQUEST_REJECTED: i64 = -32040;
    pub const REQUEST_REJECTED_LIMIT: i64 = -32041;
    pub const REQUEST_NOT_FOUND: i64 = -32042;
    pub const ENCRYPTION_ERROR: i64 = -32055;
    pub const ENCODING_ERROR: i64 = -32058;
    pub const FETCH_ERROR: i64 = -32060;
    pub const NO_LIGHT_PEERS: i64 = -32065;
    pub const NO_PEERS: i64 = -32066;
    pub const DEPRECATED: i64 = -32070;
    pub const EXPERIMENTAL_RPC: i64 = -32071;
    pub const CANNOT_RESTART: i64 = -32080;
}

pub fn unimplemented(details: Option<String>) -> Error {
    Error {
        code: ErrorCode::ServerError(codes::UNSUPPORTED_REQUEST),
        message: "This request is not implemented yet. Please create an issue on Github repo.".into(),
        data: details.map(Value::String),
    }
}

pub fn invalid_params<T: fmt::Debug>(param: &str, details: T) -> Error {
    Error {
        code: ErrorCode::InvalidParams,
        message: format!("Couldn't parse parameters: {}", param),
        data: Some(Value::String(format!("{:?}", details))),
    }
}

pub fn execution_error(message: String, output: Vec<u8>) -> Error {
    let output_bytes = Bytes::new(output);
    Error {
        code: ErrorCode::ServerError(codes::EXECUTION_ERROR),
        message,
        data: Some(Value::String(
            serde_json::to_string(&output_bytes)
                .expect("Bytes serialization cannot fail"),
        )),
    }
}
