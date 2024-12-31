use cfx_rpc_utils::error::{
    jsonrpc_error_helpers::request_rejected_too_many_request_error,
    jsonrpsee_error_helpers::jsonrpc_error_to_error_object_owned,
};
use cfx_util_macros::bail;
use futures::FutureExt;
use futures_util::future::BoxFuture;
use jsonrpsee::{
    core::RpcResult,
    server::{middleware::rpc::RpcServiceT, MethodResponse},
};
use jsonrpsee_types::Request;
use log::debug;
use throttling::token_bucket::{ThrottleResult, TokenBucketManager};

#[derive(Clone)]
pub struct Throttle<S> {
    service: S,
    manager: TokenBucketManager,
}

impl<S> Throttle<S> {
    pub fn new(file: Option<&str>, section: &str, s: S) -> Self {
        let manager = match file {
            Some(file) => TokenBucketManager::load(file, Some(section))
                .expect("invalid throttling configuration file"),
            None => TokenBucketManager::default(),
        };

        Throttle {
            service: s,
            manager,
        }
    }

    pub fn before(&self, name: &String) -> RpcResult<()> {
        let bucket = match self.manager.get(name) {
            Some(bucket) => bucket,
            None => return Ok(()),
        };

        let result = bucket.lock().throttle_default();

        match result {
            ThrottleResult::Success => Ok(()),
            ThrottleResult::Throttled(wait_time) => {
                debug!("RPC {} throttled in {:?}", name, wait_time);
                let err = request_rejected_too_many_request_error(Some(
                    format!("throttled in {:?}", wait_time),
                ));
                bail!(jsonrpc_error_to_error_object_owned(err))
            }
            ThrottleResult::AlreadyThrottled => {
                debug!("RPC {} already throttled", name);
                let err = request_rejected_too_many_request_error(Some(
                    "already throttled, please try again later".into(),
                ));
                bail!(jsonrpc_error_to_error_object_owned(err))
            }
        }
    }
}

impl<'a, S> RpcServiceT<'a> for Throttle<S>
where S: RpcServiceT<'a> + Send + Sync + Clone + 'static
{
    type Future = BoxFuture<'a, MethodResponse>;

    fn call(&self, req: Request<'a>) -> Self::Future {
        let service = self.service.clone();
        let throlltle_result = self.before(&req.method_name().to_string());
        // Box::pin(async move { service.call(req).await })
        match throlltle_result {
            Ok(_) => {
                debug!("throttle interceptor: method `{}` success", req.method);
                Box::pin(async move { service.call(req).await }).boxed()
            }
            Err(e) => {
                debug!("throttle interceptor: method `{}` failed", req.method);
                Box::pin(async move { MethodResponse::error(req.id, e) })
                    .boxed()
            }
        }
    }
}
