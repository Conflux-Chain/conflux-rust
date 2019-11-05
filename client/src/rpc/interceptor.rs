// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use futures::{future::poll_fn, Async, Future};
use jsonrpc_core::{
    BoxFuture, Metadata, Params, RemoteProcedure, Result as RpcResult,
    RpcMethod,
};
use serde_json::Value;
use std::{collections::HashMap, marker::PhantomData, sync::Arc};

pub trait RpcInterceptor: Send + Sync + 'static {
    fn before(&self, _name: &String) -> RpcResult<()>;
}

pub struct RpcProxy<M, T, I>
where
    M: Metadata,
    T: Into<HashMap<String, RemoteProcedure<M>>>,
    I: RpcInterceptor,
{
    underlying: T,
    interceptor: Arc<I>,
    phantom: PhantomData<M>,
}

impl<M, T, I> RpcProxy<M, T, I>
where
    M: Metadata,
    T: Into<HashMap<String, RemoteProcedure<M>>>,
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

impl<M, T, I> Into<HashMap<String, RemoteProcedure<M>>> for RpcProxy<M, T, I>
where
    M: Metadata,
    T: Into<HashMap<String, RemoteProcedure<M>>>,
    I: RpcInterceptor,
{
    fn into(self) -> HashMap<String, RemoteProcedure<M>> {
        let mut intercepted = HashMap::new();

        for (name, mut rp) in self.underlying.into() {
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

        intercepted
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
    fn call(&self, params: Params, meta: M) -> BoxFuture<Value> {
        let name = self.name.clone();
        let interceptor = self.interceptor.clone();
        let before_future = poll_fn(move || {
            interceptor.before(&name).map(|_| Async::Ready(()))
        });

        let method = self.method.clone();
        let method_future =
            before_future.and_then(move |_| method.call(params, meta));

        Box::new(method_future)
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
