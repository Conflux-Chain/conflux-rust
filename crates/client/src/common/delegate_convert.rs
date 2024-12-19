use std::convert::Into as StdInto;

use jsonrpc_core::{
    futures::{FutureExt, TryFutureExt},
    BoxFuture, Error as JsonRpcError, Result as JsonRpcResult,
};

use crate::rpc::{CoreBoxFuture, CoreError, CoreResult};

pub trait Into<T> {
    fn into(x: Self) -> T;
}

impl<T> Into<JsonRpcResult<T>> for JsonRpcResult<T> {
    fn into(x: Self) -> JsonRpcResult<T> { x }
}

impl<T: Send + Sync + 'static> Into<BoxFuture<T>> for BoxFuture<T> {
    fn into(x: Self) -> BoxFuture<T> { x }
}

impl<T: Send + Sync + 'static> Into<BoxFuture<JsonRpcResult<T>>>
    for CoreBoxFuture<T>
{
    fn into(x: Self) -> BoxFuture<JsonRpcResult<T>> {
        x.map_err(Into::into).boxed()
    }
}

impl Into<JsonRpcError> for CoreError {
    fn into(e: Self) -> JsonRpcError { e.into() }
}

pub fn into_jsonrpc_result<T>(r: CoreResult<T>) -> JsonRpcResult<T> {
    match r {
        Ok(t) => Ok(t),
        Err(e) => Err(Into::into(e)),
    }
}

impl<T> Into<JsonRpcResult<T>> for CoreResult<T> {
    fn into(x: Self) -> JsonRpcResult<T> { into_jsonrpc_result(x) }
}

/// Sometimes an rpc method is implemented asynchronously, then the rpc
/// trait definition must use BoxFuture for the return type.
///
/// This into conversion allow non-async rpc implementation method to
/// return RpcResult straight-forward. The delegate! macro with  #\[into\]
/// attribute will automatically call this method to do the return type
/// conversion.
impl<T: Send + Sync + 'static> Into<BoxFuture<JsonRpcResult<T>>>
    for CoreResult<T>
{
    fn into(x: Self) -> BoxFuture<JsonRpcResult<T>> {
        async { into_jsonrpc_result(x) }.boxed()
    }
}
