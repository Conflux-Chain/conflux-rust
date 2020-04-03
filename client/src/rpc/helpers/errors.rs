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

pub mod codes {
    // NOTE [ToDr] Codes from [-32099, -32000]

    /* Rpc related error codes. */
    /// The requested rpc is not supported.
    pub const UNSUPPORTED_REQUEST: i64 = -32000;
    pub const DEPRECATED: i64 = -32070;
    pub const EXPERIMENTAL_RPC: i64 = -32071;

    // FIXME: I think transaction related rpc should consider if they want to
    // FIXME: return this error code under certain conditions.
    /// Mining isn't possible.
    pub const NO_WORK: i64 = -32001;

    // FIXME: Used in Parity for all Transaction related errors.
    // FIXME: We may process it as general invalid_params with error message?
    // FIXME: How do rpc clients handle errors from send_raw_transaction?
    pub const TRANSACTION_ERROR: i64 = -32010;

    /// Transaction execution error, For call()
    pub const EXECUTION_ERROR: i64 = -32015;

    pub const EXCEPTION_ERROR: i64 = -32016;

    /* Wallet/secret-store related. */
    // FIXME: why didn't we use this error code?
    #[cfg(any(test, feature = "accounts"))]
    pub const ACCOUNT_LOCKED: i64 = -32020;
    // FIXME: why didn't we use this error code?
    #[cfg(any(test, feature = "accounts"))]
    pub const PASSWORD_INVALID: i64 = -32021;
    // FIXME: why didn't we use this error code?
    pub const ACCOUNT_ERROR: i64 = -32023;
    // FIXME: do we have related rpc? It seems mostly used around secret-store.
    pub const ENCRYPTION_ERROR: i64 = -32055;

    // FIXME: used by parity in light node.
    pub const REQUEST_REJECTED: i64 = -32040;
    // FIXME: used by parity to indicate that any kind of limit about the
    // FIXME: request is exceeded. When data is too large, or there are already
    // too FIXME: many active requests to serve.
    //
    // FIXME: We should separate request rejection due to too many requests
    // FIXME: (attack prevention) from handshake or acl related (data limit)
    // reasons.
    pub const REQUEST_REJECTED_LIMIT: i64 = -32041;
    // FIXME: check request, parity's comment:
    // "Checks the progress of a previously posted request (transaction/sign).
    // Should be given a valid send_transaction ID."
    // FIXME: we should give a better name to both the rpc and the error.
    pub const REQUEST_NOT_FOUND: i64 = -32042;

    // FIXME: used by parity for invalid_call_data related to EIP712.
    pub const ENCODING_ERROR: i64 = -32058;

    /// Unable to serve a query from light node due to network connectivity.
    // FIXME: I don't think we must separate if from NO_PEERS.
    pub const NO_LIGHT_PEERS: i64 = -32065;

    // FIXME: used by parity to report the status. if there is no peers we can
    // FIXME: not retrieve any information about the blockchain. I suggest
    // FIXME: that we give it a better name and make it general.
    // FIXME:
    // FIXME: I think it's a bit different than the "stage" of the full node.
    // FIXME: a node can be disconnected from the blockchain at any time
    // FIXME: regardless of its type (full node / archive node / light node).
    // FIXME:
    // FIXME: There are different ways to detect network isolation. We may run
    // FIXME: out of trusted peer connections, run out of peer connections;
    // FIXME: we may see a suspicious FIXME: drop of total mining power; we may
    // FIXME: see an unanticipated drop in average block FIXME: generation
    // FIXME: rate. We may find that the current pivot chain is unstable.
    pub const NO_PEERS: i64 = -32066;
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
        message: format!("Invalid parameters: {}", param),
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
