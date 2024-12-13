// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::errors::request_rejected_too_many_request_error;
use cfx_util_macros::bail;
use futures::{future::lazy, FutureExt, TryFutureExt};
use jsonrpc_core::{
    BoxFuture, Metadata, Params, RemoteProcedure, Result as RpcResult,
    RpcMethod,
};
use lazy_static::lazy_static;
use log::debug;
use metrics::{register_timer_with_group, ScopeTimer, Timer};
use parking_lot::Mutex;
use serde_json::Value;
use std::{collections::HashMap, marker::PhantomData, sync::Arc};
use throttling::token_bucket::{ThrottleResult, TokenBucketManager};

lazy_static! {
    static ref METRICS_INTERCEPTOR_TIMERS: Mutex<HashMap<String, Arc<dyn Timer>>> =
        Default::default();
}

pub trait RpcInterceptor: Send + Sync + 'static {
    fn before(&self, _name: &String) -> RpcResult<()>;

    fn around(
        &self, _name: &String, method_call: BoxFuture<RpcResult<Value>>,
    ) -> BoxFuture<RpcResult<Value>> {
        method_call
    }
}

pub struct RpcProxy<M, T, I>
where
    M: Metadata,
    T: IntoIterator<Item = (String, RemoteProcedure<M>)>,
    I: RpcInterceptor,
{
    underlying: T,
    interceptor: Arc<I>,
    phantom: PhantomData<M>,
}

impl<M, T, I> RpcProxy<M, T, I>
where
    M: Metadata,
    T: IntoIterator<Item = (String, RemoteProcedure<M>)>,
    I: RpcInterceptor,
{
    pub fn new(underlying: T, interceptor: I) -> Self {
        RpcProxy {
            underlying,
            interceptor: Arc::new(interceptor),
            phantom: PhantomData,
        }
    }
}

impl<M, T, I> IntoIterator for RpcProxy<M, T, I>
where
    M: Metadata,
    T: IntoIterator<Item = (String, RemoteProcedure<M>)>,
    I: RpcInterceptor,
{
    type IntoIter =
        std::collections::hash_map::IntoIter<String, RemoteProcedure<M>>;
    type Item = (String, RemoteProcedure<M>);

    fn into_iter(self) -> Self::IntoIter {
        let mut intercepted = HashMap::new();

        for (name, mut rp) in self.underlying.into_iter() {
            if let RemoteProcedure::Method(method) = rp {
                let method = RpcMethodWithInterceptor::new(
                    name.clone(),
                    method,
                    self.interceptor.clone(),
                );
                rp = RemoteProcedure::Method(Arc::new(method));
            }

            intercepted.insert(name, rp);
        }

        intercepted.into_iter()
    }
}

struct RpcMethodWithInterceptor<M, I>
where
    M: Metadata,
    I: RpcInterceptor,
{
    name: String,
    method: Arc<dyn RpcMethod<M>>,
    interceptor: Arc<I>,
}

impl<M, I> RpcMethodWithInterceptor<M, I>
where
    M: Metadata,
    I: RpcInterceptor,
{
    pub fn new(
        name: String, method: Arc<dyn RpcMethod<M>>, interceptor: Arc<I>,
    ) -> Self {
        RpcMethodWithInterceptor {
            name,
            method,
            interceptor,
        }
    }
}

impl<M, I> RpcMethod<M> for RpcMethodWithInterceptor<M, I>
where
    M: Metadata,
    I: RpcInterceptor,
{
    fn call(&self, params: Params, meta: M) -> BoxFuture<RpcResult<Value>> {
        let name = self.name.clone();
        let interceptor = self.interceptor.clone();
        let before_future = lazy(move |_| interceptor.before(&name));

        let method = self.method.clone();
        let method_call = self.interceptor.around(
            &self.name,
            lazy(move |_| method.call(params, meta)).flatten().boxed(),
        );
        let method_future = before_future.and_then(move |_| method_call);

        method_future.boxed()
    }
}

pub struct ThrottleInterceptor {
    manager: TokenBucketManager,
}

impl ThrottleInterceptor {
    pub fn new(file: &Option<String>, section: &str) -> Self {
        let manager = match file {
            Some(file) => TokenBucketManager::load(file, Some(section))
                .expect("invalid throttling configuration file"),
            None => TokenBucketManager::default(),
        };

        ThrottleInterceptor { manager }
    }
}

impl RpcInterceptor for ThrottleInterceptor {
    fn before(&self, name: &String) -> RpcResult<()> {
        let bucket = match self.manager.get(name) {
            Some(bucket) => bucket,
            None => return Ok(()),
        };

        let result = bucket.lock().throttle_default();

        match result {
            ThrottleResult::Success => Ok(()),
            ThrottleResult::Throttled(wait_time) => {
                debug!("RPC {} throttled in {:?}", name, wait_time);
                bail!(request_rejected_too_many_request_error(Some(format!(
                    "throttled in {:?}",
                    wait_time
                ))))
            }
            ThrottleResult::AlreadyThrottled => {
                debug!("RPC {} already throttled", name);
                bail!(request_rejected_too_many_request_error(Some(
                    "already throttled, please try again later".into()
                )))
            }
        }
    }
}

pub struct MetricsInterceptor {
    // TODO: Chain interceptors instead of wrapping up.
    throttle_interceptor: ThrottleInterceptor,
}

impl MetricsInterceptor {
    pub fn new(throttle_interceptor: ThrottleInterceptor) -> Self {
        Self {
            throttle_interceptor,
        }
    }
}

impl RpcInterceptor for MetricsInterceptor {
    fn before(&self, name: &String) -> RpcResult<()> {
        self.throttle_interceptor.before(name)?;
        // Use a global variable here because `http` and `web3` setup different
        // interceptors for the same RPC API.
        let mut timers = METRICS_INTERCEPTOR_TIMERS.lock();
        if !timers.contains_key(name) {
            let timer = register_timer_with_group("rpc", name.as_str());
            timers.insert(name.clone(), timer);
        }
        Ok(())
    }

    fn around(
        &self, name: &String, method_call: BoxFuture<RpcResult<Value>>,
    ) -> BoxFuture<RpcResult<Value>> {
        let maybe_timer = METRICS_INTERCEPTOR_TIMERS
            .lock()
            .get(name)
            .map(|timer| timer.clone());
        let setup = lazy(move |_| {
            Ok(maybe_timer
                .as_ref()
                .map(|timer| ScopeTimer::time_scope(timer.clone())))
        });
        setup
            .then(|timer: Result<_, ()>| {
                method_call.then(|r| async {
                    drop(timer);
                    r
                })
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::interceptor::{RpcInterceptor, RpcProxy};
    use jsonrpc_core::{Error as RpcError, MetaIoHandler, Result as RpcResult};
    use jsonrpc_derive::rpc;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    #[rpc]
    pub trait Foo {
        #[rpc(name = "cfx_balance")]
        fn balance(&self, _id: usize) -> RpcResult<usize>;
    }

    struct FooImpl;

    impl Foo for FooImpl {
        fn balance(&self, id: usize) -> RpcResult<usize> { Ok(id) }
    }

    #[derive(Default)]
    struct Bar {
        handled: Arc<AtomicBool>,
        error: Option<RpcError>,
    }

    impl RpcInterceptor for Bar {
        fn before(&self, _name: &String) -> RpcResult<()> {
            self.handled.store(true, Ordering::SeqCst);
            match self.error {
                Some(ref err) => Err(err.clone()),
                None => Ok(()),
            }
        }
    }

    #[test]
    fn test_interceptor_success() {
        let foo = FooImpl.to_delegate();

        // interceptor not handled
        let bar = Bar::default();
        let interceptor_handled = bar.handled.clone();

        let mut handler: MetaIoHandler<()> = MetaIoHandler::default();
        handler.extend_with(RpcProxy::new(foo, bar));

        let request = r#"{"jsonrpc": "2.0", "method": "cfx_balance", "params": [8], "id": 1}"#;
        assert_eq!(
            handler.handle_request_sync(request, ()),
            Some(r#"{"jsonrpc":"2.0","result":8,"id":1}"#.to_string()),
        );
        assert_eq!(interceptor_handled.load(Ordering::SeqCst), true);
    }

    #[test]
    fn test_interceptor_failure() {
        let foo = FooImpl.to_delegate();

        // interceptor with RPC error
        let mut bar = Bar::default();
        bar.error = Some(RpcError::invalid_params("some test error"));

        let mut handler: MetaIoHandler<()> = MetaIoHandler::default();
        handler.extend_with(RpcProxy::new(foo, bar));

        let request = r#"{"jsonrpc": "2.0", "method": "cfx_balance", "params": [8], "id": 1}"#;
        assert_eq!(
            handler.handle_request_sync(request, ()),
            Some(r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"some test error"},"id":1}"#.to_string()),
        );
    }

    #[test]
    fn test_interceptor_embedded() {
        let foo = FooImpl.to_delegate();

        // interceptor 1
        let bar = Bar::default();
        let interceptor_1_handled = bar.handled.clone();
        let proxy_1 = RpcProxy::new(foo, bar);

        // interceptor 2
        let bar = Bar::default();
        let interceptor_2_handled = bar.handled.clone();
        let proxy_2 = RpcProxy::new(proxy_1, bar);

        let mut handler: MetaIoHandler<()> = MetaIoHandler::default();
        handler.extend_with(proxy_2);

        let request = r#"{"jsonrpc": "2.0", "method": "cfx_balance", "params": [8], "id": 1}"#;
        assert_eq!(
            handler.handle_request_sync(request, ()),
            Some(r#"{"jsonrpc":"2.0","result":8,"id":1}"#.to_string()),
        );
        assert_eq!(interceptor_1_handled.load(Ordering::SeqCst), true);
        assert_eq!(interceptor_2_handled.load(Ordering::SeqCst), true);
    }
}
