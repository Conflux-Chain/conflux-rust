use jsonrpc_core::Error as JsonRpcError;
use jsonrpsee::types::{
    self as jsonrpsee_types,
    error::{
        ErrorObjectOwned, INTERNAL_ERROR_CODE, INVALID_PARAMS_CODE,
        INVALID_REQUEST_CODE,
    },
};

pub fn jsonrpc_error_to_error_object_owned(
    e: JsonRpcError,
) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(e.code.code() as i32, e.message, e.data)
}

pub fn invalid_params_msg(param: &str) -> ErrorObjectOwned {
    invalid_params_rpc_err(format!("Invalid parameters: {}", param))
}

pub fn invalid_request_msg(param: &str) -> ErrorObjectOwned {
    let data: Option<bool> = None;
    ErrorObjectOwned::owned(INVALID_REQUEST_CODE, param, data)
}

pub fn invalid_params_rpc_err(msg: impl Into<String>) -> ErrorObjectOwned {
    let data: Option<bool> = None;
    ErrorObjectOwned::owned(INVALID_PARAMS_CODE, msg, data)
}

pub fn internal_error(msg: impl Into<String>) -> ErrorObjectOwned {
    let data: Option<bool> = None;
    ErrorObjectOwned::owned(INTERNAL_ERROR_CODE, msg, data)
}

/// Constructs an internal JSON-RPC error.
pub fn internal_rpc_err(msg: impl Into<String>) -> ErrorObjectOwned {
    rpc_err(jsonrpsee_types::error::INTERNAL_ERROR_CODE, msg, None)
}

/// Constructs an internal JSON-RPC error with data
pub fn internal_rpc_err_with_data(
    msg: impl Into<String>, data: &[u8],
) -> ErrorObjectOwned {
    rpc_err(jsonrpsee_types::error::INTERNAL_ERROR_CODE, msg, Some(data))
}

/// Constructs an internal JSON-RPC error with code and message
pub fn rpc_error_with_code(
    code: i32, msg: impl Into<String>,
) -> ErrorObjectOwned {
    rpc_err(code, msg, None)
}

/// Constructs a JSON-RPC error, consisting of `code`, `message` and optional
/// `data`.
pub fn rpc_err(
    code: i32, msg: impl Into<String>, data: Option<&[u8]>,
) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(
        code,
        msg.into(),
        data.map(|data| {
            jsonrpsee_core::to_json_raw_value(
                &alloy_primitives::hex::encode_prefixed(data),
            )
            .expect("serializing String can't fail")
        }),
    )
}
