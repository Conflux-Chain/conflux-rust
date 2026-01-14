use futures::{future::lazy, FutureExt};
use jsonrpsee::{
    core::RpcResult,
    server::{
        middleware::rpc::{Batch, Notification, RpcServiceT},
        MethodResponse,
    },
};
use jsonrpsee_types::Request;
use lazy_static::lazy_static;
use log::debug;
use metrics::{register_timer_with_group, ScopeTimer, Timer};
use parking_lot::Mutex;
use std::{collections::HashMap, future::Future, sync::Arc};

lazy_static! {
    static ref METRICS_INTERCEPTOR_TIMERS: Mutex<HashMap<String, Arc<dyn Timer>>> =
        Default::default();
}
#[derive(Clone)]
pub struct Metrics<S> {
    service: S,
}

impl<S> Metrics<S> {
    pub fn new(service: S) -> Self { Self { service } }
}

impl<S> Metrics<S> {
    fn before(&self, name: &String) -> RpcResult<()> {
        // Use a global variable here because `http` and `web3` setup different
        // interceptors for the same RPC API.
        let mut timers = METRICS_INTERCEPTOR_TIMERS.lock();
        if !timers.contains_key(name) {
            let timer = register_timer_with_group("async_rpc", name.as_str());
            timers.insert(name.clone(), timer);
        }
        Ok(())
    }
}

impl<S> RpcServiceT for Metrics<S>
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
        let before_result = self.before(&req.method_name().to_string());

        debug!("run metrics interceptor before_result: {:?}", before_result);
        match before_result {
            Ok(_) => {
                let maybe_timer = METRICS_INTERCEPTOR_TIMERS
                    .lock()
                    .get(req.method_name())
                    .map(|timer| timer.clone());
                let setup = lazy(move |_| {
                    Ok(maybe_timer
                        .as_ref()
                        .map(|timer| ScopeTimer::time_scope(timer.clone())))
                });

                let service = self.service.clone();
                Box::pin(async move {
                    let timer: Result<_, ()> = setup.await;
                    let resp = service.call(req).await;
                    drop(timer);
                    resp
                })
                .boxed()
            }
            Err(e) => {
                return Box::pin(
                    async move { MethodResponse::error(req.id, e) },
                )
                .boxed()
            }
        }
    }

    fn batch<'a>(
        &self, batch: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        // batch are not timed
        self.service.batch(batch)
    }

    fn notification<'a>(
        &self, n: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        // notifications are not timed
        self.service.notification(n)
    }
}
