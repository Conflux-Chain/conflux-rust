use crate::error::error_codes as codes;
use alloy_primitives::hex;
use alloy_rpc_types::error::EthRpcErrorCode;
use cfx_types::H256;
use jsonrpc_core::{Error, ErrorCode, Value};
use jsonrpsee::types::ErrorObjectOwned;
use std::fmt;

/// Constructs a JSON-RPC error, consisting of `code`, `message` and optional
/// `data`.
pub fn rpc_err(
    code: i32, msg: impl Into<String>, data: Option<&[u8]>,
) -> Error {
    Error {
        code: ErrorCode::from(code as i64),
        message: msg.into(),
        data: data.map(|v| serde_json::Value::String(hex::encode_prefixed(v))),
    }
}

pub fn build_rpc_server_error(code: i64, message: String) -> Error {
    Error {
        code: ErrorCode::ServerError(code),
        message,
        data: None,
    }
}

pub fn unimplemented(details: Option<String>) -> Error {
    Error {
        code: ErrorCode::ServerError(codes::UNSUPPORTED),
        message: "This API is not implemented yet".into(),
        data: details.map(Value::String),
    }
}

// code is -32000
pub fn invalid_input_rpc_err(msg: impl Into<String>) -> Error {
    rpc_err(EthRpcErrorCode::InvalidInput.code(), msg, None)
}

/// Constructs an invalid params JSON-RPC error.
pub fn invalid_params_rpc_err(msg: impl Into<String>) -> Error {
    rpc_err(ErrorCode::InvalidParams.code() as i32, msg, None)
}

pub fn invalid_params<T: fmt::Debug>(param: &str, details: T) -> Error {
    Error {
        code: ErrorCode::InvalidParams,
        message: format!("Invalid parameters: {}", param),
        data: Some(Value::String(format!("{:?}", details))),
    }
}

pub fn invalid_params_check<T, E: std::fmt::Display>(
    param: &str, r: std::result::Result<T, E>,
) -> Result<T, Error> {
    match r {
        Ok(t) => Ok(t),
        Err(e) => Err(invalid_params(param.into(), format!("{}", e)).into()),
    }
}

pub fn invalid_params_msg(param: &str) -> Error {
    invalid_params_rpc_err(format!("Invalid parameters: {}", param))
}

pub fn invalid_params_detail<T: fmt::Debug>(param: &str, details: T) -> Error {
    Error {
        code: ErrorCode::InvalidParams,
        message: format!("Invalid parameters: {} {:?}", param, details),
        data: Some(Value::String(format!("{:?}", details))),
    }
}

pub fn unknown_block() -> Error {
    Error {
        code: ErrorCode::InvalidParams,
        message: "Unknown block number".into(),
        data: None,
    }
}

/// Constructs an internal JSON-RPC error.
pub fn internal_rpc_err(msg: impl Into<String>) -> Error {
    rpc_err(ErrorCode::InternalError.code() as i32, msg, None)
}

/// Constructs an internal JSON-RPC error with data
pub fn internal_rpc_err_with_data(
    msg: impl Into<String>, data: &[u8],
) -> Error {
    rpc_err(ErrorCode::InternalError.code() as i32, msg, Some(data))
}

pub fn internal_error_msg(param: &str) -> Error {
    Error {
        code: ErrorCode::InternalError,
        message: format!("Internal error: {}", param),
        data: None,
    }
}

pub fn internal_error<T: fmt::Debug>(details: T) -> Error {
    Error {
        code: ErrorCode::InternalError,
        message: "Internal error".into(),
        data: Some(Value::String(format!("{:?}", details))),
    }
}

pub fn call_execution_error(message: String, data: String) -> Error {
    Error {
        code: ErrorCode::ServerError(codes::CALL_EXECUTION_ERROR),
        message,
        data: Some(Value::String(data)),
    }
}

pub fn geth_call_execution_error(message: String, data: String) -> Error {
    Error {
        code: ErrorCode::ServerError(
            EthRpcErrorCode::ExecutionError.code() as i64
        ),
        message,
        data: Some(Value::String(data)),
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

pub fn request_rejected_in_catch_up_mode(details: Option<String>) -> Error {
    Error {
        code: ErrorCode::ServerError(codes::REQUEST_REJECTED_IN_CATCH_UP),
        message: "Request rejected due to still in the catch up mode.".into(),
        data: details.map(Value::String),
    }
}

pub fn pivot_assumption_failed(expected: H256, got: H256) -> Error {
    Error {
        code: ErrorCode::ServerError(codes::CONFLUX_PIVOT_CHAIN_UNSTABLE),
        message: "pivot chain assumption failed".into(),
        data: Some(Value::String(format!(
            "pivot assumption: {:?}, actual pivot hash: {:?}",
            expected, got
        ))),
    }
}

pub fn error_object_owned_to_jsonrpc_error(e: ErrorObjectOwned) -> Error {
    Error {
        code: ErrorCode::from(e.code() as i64),
        message: e.message().into(),
        data: e.data().map(|v| Value::String(v.to_string())),
    }
}
