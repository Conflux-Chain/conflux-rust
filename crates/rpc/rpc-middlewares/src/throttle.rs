use cfx_rpc_utils::error::{
    jsonrpc_error_helpers::request_rejected_too_many_request_error,
    jsonrpsee_error_helpers::jsonrpc_error_to_error_object_owned,
};
use cfx_util_macros::bail;
use futures::FutureExt;
use jsonrpsee::{
    core::RpcResult,
    server::{
        middleware::rpc::{Batch, Notification, RpcServiceT},
        MethodResponse,
    },
};
use jsonrpsee_types::Request;
use log::debug;
use std::future::Future;
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

impl<S> RpcServiceT for Throttle<S>
where S: RpcServiceT<MethodResponse = MethodResponse>
        + Send
        + Sync
        + Clone
        + 'static
{
    type BatchResponse = S::BatchResponse;
    type MethodResponse = S::MethodResponse;
    type NotificationResponse = S::NotificationResponse;

    fn call<'a>(
        &self, req: Request<'a>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let service = self.service.clone();
        let throlltle_result = self.before(&req.method_name().to_string());
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

    fn batch<'a>(
        &self, batch: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        // batch are not throtted
        self.service.batch(batch)
    }

    fn notification<'a>(
        &self, n: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        // notifications are not throtted
        self.service.notification(n)
    }
}
