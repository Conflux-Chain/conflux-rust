use futures::{future::lazy, FutureExt};
use futures_util::future::BoxFuture;
// use jsonrpc_core::Result as RpcResult;
use jsonrpsee::{
    core::RpcResult,
    server::{middleware::rpc::RpcServiceT, MethodResponse},
};
use jsonrpsee_types::Request;
use lazy_static::lazy_static;
use log::debug;
use metrics::{register_timer_with_group, ScopeTimer, Timer};
use parking_lot::Mutex;
use std::{collections::HashMap, sync::Arc};

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

impl<'a, S> RpcServiceT<'a> for Metrics<S>
where S: RpcServiceT<'a> + Send + Sync + Clone + 'static
{
    type Future = BoxFuture<'a, MethodResponse>;

    fn call(&self, req: Request<'a>) -> Self::Future {
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
}
