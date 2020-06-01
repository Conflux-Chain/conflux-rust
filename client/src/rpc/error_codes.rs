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
    /// JsonRPC spec reserved from and including -32768 to -32000 for
    /// pre-defined errors. The reminder of the space is available for
    /// application defined errors.
    ///
    /// -32000 to -32099 is defined for "(JsonRPC) Server Error".
    ///
    /// We use the same error code number as in Parity Ethereum wherever
    /// possible. Since the error code is almost used up by Parity, we
    /// further reserve [-31999, -31000] for Conflux's extra server error
    /// codes, in the range of "application defined errors" as defined by
    /// JsonRPC.

    /// When the number on the right is -32100, check the next variable below.
    ///
    /// Please use the number on the right for new error code, then decrease it
    /// by 1.
    ///
    /// Do not recycle deprecated error codes.
    const NEXT_SERVER_ERROR_CODE: i64 = -32073;
    /// When the above number is equal to -32100, take the number below on the
    /// right for new error code, then increase it by 1.
    const CFX_EXTRA_SERVER_ERROR_CODE: i64 = -31999;

    /// We reserve [-30999, 30000] for application error code. i.e. Error code
    /// which is defined specifically for a particular rpc.
    const CFX_EXTRA_APP_ERROR_CODE: i64 = -30999;

    /* Rpc functional related error codes. */
    /// The request is not supported (yet) at this version.
    pub const UNSUPPORTED: i64 = -32000;
    /// The requested feature is deprecated.
    pub const DEPRECATED: i64 = -32070;
    /// The requested feature is experimental.
    pub const EXPERIMENTAL: i64 = -32071;
    /// The node is not able to serve the request due to configuration. e.g. Not
    /// mining, light node, not archive node.
    pub const INCAPABLE: i64 = -32703;

    /* Rpc usage related error codes */
    /// When there are too many rpc requests. We limt the number of allowed rpc
    /// requests for attack prevention.
    pub const REQUEST_REJECTED_TOO_MANY_REQUESTS: i64 = -32072;
    /// When the request is considered too much for the rpc function.
    /// The consideration is set individually per rpc. It can be data too large,
    /// or it can be that some performance/security related parameter is outside
    /// the accepted range.
    ///
    /// This is mostly an application error but it's generic enough to define it
    /// here.
    pub const REQUEST_REJECTED_LIMIT_DATA: i64 = -32041;

    /* Conflux node status related error codes
     *
     * When the node is not well-connected to the Conflux network, or when an
     * ongoing attack is detected, the rpc server should stop providing
     * on-chain information, and instead return a relevant error code.
     */
    /// No connection to trusted peers.
    pub const NO_TRUSTED_PEERS: i64 = -32074;
    /// No peers are currently connected or there is insufficient amount of
    /// peers connected.
    pub const NO_PEERS: i64 = -32066;
    pub const CONFLUX_PIVOT_CHAIN_UNSTABLE: i64 = -32075;
    /// The node see a suspicious total mining power or block rate.
    /// It's likely that the node is under attack or the whole Conflux network
    /// enters an abnormal state.
    pub const SUSPICIOUS_MINING_RATE: i64 = -32076;

    /* Other server error codes */
    /// Any exception happened while processing the transaction. Mostly likely
    /// there is an internal error within the server state.
    ///
    /// When the server can detect an error with the request itself, it should
    /// return another error code such as invalid params, or for example
    /// CALL_EXECUTION_ERROR.
    pub const EXCEPTION_ERROR: i64 = -32016;
    /// The error can be given to a request about a previous related request
    /// which we can not associate with.
    ///
    /// In Parity it was used for rpc check_request(). In parity's comment:
    /// "Checks the progress of a previously posted request (transaction/sign).
    /// Should be given a valid send_transaction ID."
    pub const PREVIOUS_REQUEST_NOT_FOUND: i64 = -32042;

    // FIXME: Used in Parity for all Transaction related errors.
    // FIXME: We may process it as general invalid_params with error message?
    // FIXME: How do rpc clients handle errors from send_raw_transaction?

    /* Wallet/secret-store/signing related. */
    // FIXME: why didn't we use this error code?
    #[cfg(any(test, feature = "accounts"))]
    pub const ACCOUNT_LOCKED: i64 = -32020;
    // FIXME: why didn't we use this error code?
    #[cfg(any(test, feature = "accounts"))]
    pub const PASSWORD_INVALID: i64 = -32021;
    // FIXME: why didn't we use this error code?
    pub const ACCOUNT_ERROR: i64 = -32023;
    /// Encoding error happened in signing structured data. Related to EIP712.
    pub const ENCODING_ERROR: i64 = -32058;

    /* Other application error codes */
    /// Call() execution error. This is clearly an application level error code,
    /// but we keep the error code to be ethereum rpc client compatible.
    pub const CALL_EXECUTION_ERROR: i64 = -32015;

}

pub fn unimplemented(details: Option<String>) -> Error {
    Error {
        code: ErrorCode::ServerError(codes::UNSUPPORTED),
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

pub fn call_execution_error(message: String, output: Vec<u8>) -> Error {
    let output_bytes = Bytes::new(output);
    Error {
        code: ErrorCode::ServerError(codes::CALL_EXECUTION_ERROR),
        message,
        data: Some(Value::String(
            serde_json::to_string(&output_bytes)
                .expect("Bytes serialization cannot fail"),
        )),
    }
}

pub fn request_rejected_too_many_request_error(
    details: Option<String>,
) -> Error {
    Error {
        code: ErrorCode::ServerError(codes::REQUEST_REJECTED_TOO_MANY_REQUESTS),
        message: "Request rejected.".into(),
        data: details.map(Value::String),
    }
}
