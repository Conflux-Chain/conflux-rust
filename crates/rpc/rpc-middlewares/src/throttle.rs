use cfx_rpc_utils::error::jsonrpsee_error_helpers::request_rejected_too_many_request_error;
use cfx_util_macros::bail;
use jsonrpsee::{
    core::{
        middleware::{BatchEntry, BatchEntryErr, ResponseFuture},
        RpcResult,
    },
    server::{
        middleware::rpc::{Batch, Notification, RpcServiceT},
        MethodResponse,
    },
    types::Request,
};
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

    pub fn before(&self, name: &str) -> RpcResult<()> {
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
                bail!(err)
            }
            ThrottleResult::AlreadyThrottled => {
                debug!("RPC {} already throttled", name);
                let err = request_rejected_too_many_request_error(Some(
                    "already throttled, please try again later".into(),
                ));
                bail!(err)
            }
        }
    }
}

impl<S> RpcServiceT for Throttle<S>
where S: RpcServiceT<
            MethodResponse = MethodResponse,
            BatchResponse = MethodResponse,
            NotificationResponse = MethodResponse,
        > + Send
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
        let throttle_result = self.before(req.method_name());
        match throttle_result {
            Ok(_) => {
                debug!("throttle interceptor: method `{}` success", req.method);
                ResponseFuture::future(self.service.call(req))
            }
            Err(e) => {
                debug!("throttle interceptor: method `{}` failed", req.method);
                ResponseFuture::ready(MethodResponse::error(req.id, e))
            }
        }
    }

    fn batch<'a>(
        &self, mut batch: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        for entry in batch.iter_mut() {
            let (id, name) = match entry {
                Ok(BatchEntry::Call(req)) => {
                    (req.id.clone(), req.method_name())
                }
                Ok(BatchEntry::Notification(_)) => continue,
                Err(_) => continue,
            };

            let throttle_result = self.before(name);
            if let Err(e) = throttle_result {
                // This will create a new error response for batch and replace
                // the method call
                *entry = Err(BatchEntryErr::new(id, e));
            }
        }

        self.service.batch(batch)
    }

    fn notification<'a>(
        &self, n: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        let throttle_result = self.before(n.method_name());
        match throttle_result {
            Ok(_) => ResponseFuture::future(self.service.notification(n)),
            // Notifications are not expected to return a response so just
            // ignore if the rate limit is reached.
            Err(_e) => ResponseFuture::ready(MethodResponse::notification()),
        }
    }
}
