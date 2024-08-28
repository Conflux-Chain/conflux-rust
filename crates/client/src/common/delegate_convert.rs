use std::convert::Into as StdInto;

use jsonrpc_core::{
    futures::{future::IntoFuture, Future},
    BoxFuture, Error as JsonRpcError, Result as JsonRpcResult,
};

use crate::rpc::{RpcBoxFuture, RpcError, RpcResult};

pub trait Into<T> {
    fn into(x: Self) -> T;
}

impl<T> Into<JsonRpcResult<T>> for JsonRpcResult<T> {
    fn into(x: Self) -> JsonRpcResult<T> { x }
}

impl<T: Send + Sync + 'static> Into<BoxFuture<T>> for BoxFuture<T> {
    fn into(x: Self) -> BoxFuture<T> { x }
}

impl<T: Send + Sync + 'static> Into<BoxFuture<T>> for RpcBoxFuture<T> {
    fn into(x: Self) -> BoxFuture<T> {
        Box::new(x.map_err(|rpc_error| Into::into(rpc_error)))
    }
}

impl Into<JsonRpcError> for RpcError {
    fn into(e: Self) -> JsonRpcError { e.into() }
}

pub fn into_jsonrpc_result<T>(r: RpcResult<T>) -> JsonRpcResult<T> {
    match r {
        Ok(t) => Ok(t),
        Err(e) => Err(Into::into(e)),
    }
}

impl<T> Into<JsonRpcResult<T>> for RpcResult<T> {
    fn into(x: Self) -> JsonRpcResult<T> { into_jsonrpc_result(x) }
}

/// Sometimes an rpc method is implemented asynchronously, then the rpc
/// trait definition must use BoxFuture for the return type.
///
/// This into conversion allow non-async rpc implementation method to
/// return RpcResult straight-forward. The delegate! macro with  #\[into\]
/// attribute will automatically call this method to do the return type
/// conversion.
impl<T: Send + Sync + 'static> Into<BoxFuture<T>> for RpcResult<T> {
    fn into(x: Self) -> BoxFuture<T> {
        into_jsonrpc_result(x).into_future().boxed()
    }
}

/*
/// It's a bad idea to convert a BoxFuture return type to a JsonRpcResult
/// return type for rpc call. Simply imagine how the code below runs.
impl<T: Send + Sync + 'static> Into<JsonRpcResult<T>> for BoxFuture<T> {
    fn into(x: Self) -> JsonRpcResult<T> {
        thread::Builder::new()
            .name("rpc async waiter".into())
            .spawn(move || x.wait())
            .map_err(|e| {
                let mut rpc_err = JsonRpcError::internal_error();
                rpc_err.message = format!("thread creation error: {}", e);

                rpc_err
            })?
            .join()
            .map_err(|_| {
                let mut rpc_err = JsonRpcError::internal_error();
                rpc_err.message = format!("thread join error.");

                rpc_err
            })?
    }
}
*/
