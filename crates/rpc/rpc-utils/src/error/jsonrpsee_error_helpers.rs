use crate::error::error_codes as codes;
use alloy_rpc_types::error::EthRpcErrorCode;
use cfx_types::H256;
use jsonrpsee::types::error::{
    ErrorObjectOwned, INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG,
    INVALID_PARAMS_CODE, INVALID_REQUEST_CODE,
};
use serde::Serialize;

pub fn invalid_params_msg(param: &str) -> ErrorObjectOwned {
    let data: Option<bool> = None;
    invalid_params_rpc_err(format!("Invalid parameters: {}", param), data)
}

pub fn invalid_params<S: Serialize>(
    param: &str, data: Option<S>,
) -> ErrorObjectOwned {
    invalid_params_rpc_err(format!("Invalid parameters: {}", param), data)
}

pub fn invalid_params_rpc_err<S: Serialize>(
    msg: impl Into<String>, data: Option<S>,
) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INVALID_PARAMS_CODE, msg, data)
}

// code is -32000
pub fn invalid_input_rpc_err(msg: impl Into<String>) -> ErrorObjectOwned {
    rpc_err(EthRpcErrorCode::InvalidInput.code(), msg, None::<()>)
}

pub fn invalid_params_check<T, E: std::fmt::Display>(
    param: &str, r: std::result::Result<T, E>,
) -> Result<T, ErrorObjectOwned> {
    match r {
        Ok(t) => Ok(t),
        Err(e) => {
            Err(invalid_params(param.into(), Some(format!("{}", e))).into())
        }
    }
}

pub fn invalid_request_msg(param: &str) -> ErrorObjectOwned {
    let data: Option<bool> = None;
    ErrorObjectOwned::owned(INVALID_REQUEST_CODE, param, data)
}

pub fn internal_error() -> ErrorObjectOwned {
    let data: Option<bool> = None;
    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG, data)
}

/// Constructs an internal JSON-RPC error.
pub fn internal_error_with_data<S: Serialize>(data: S) -> ErrorObjectOwned {
    rpc_err(INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG, Some(data))
}

pub fn call_execution_error(message: String, data: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        codes::CALL_EXECUTION_ERROR as i32,
        message,
        Some(data),
    )
}

pub fn geth_call_execution_error(
    message: String, data: String,
) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        EthRpcErrorCode::ExecutionError.code(),
        message,
        Some(data),
    )
}

pub fn request_rejected_in_catch_up_mode(
    details: Option<String>,
) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        codes::REQUEST_REJECTED_IN_CATCH_UP as i32,
        "Request rejected due to still in the catch up mode.",
        details,
    )
}

pub fn pivot_assumption_failed(expected: H256, got: H256) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        codes::CONFLUX_PIVOT_CHAIN_UNSTABLE as i32,
        "pivot chain assumption failed",
        Some(format!(
            "pivot assumption: {:?}, actual pivot hash: {:?}",
            expected, got
        )),
    )
}

/// Constructs an internal JSON-RPC error with code and message
pub fn rpc_error_with_code(
    code: i32, msg: impl Into<String>,
) -> ErrorObjectOwned {
    rpc_err(code, msg, None::<()>)
}

/// Constructs a JSON-RPC error, consisting of `code`, `message` and optional
/// `data`.
pub fn rpc_err<S: Serialize>(
    code: i32, msg: impl Into<String>, data: Option<S>,
) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, msg, data)
}
