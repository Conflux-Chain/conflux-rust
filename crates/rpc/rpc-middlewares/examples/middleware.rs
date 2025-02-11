// Copyright 2019-2021 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! jsonrpsee supports two kinds of middlewares `http_middleware` and
//! `rpc_middleware`.
//!
//! This example demonstrates how to use the `rpc_middleware` which applies for
//! each JSON-RPC method call and batch requests may call the middleware more
//! than once.
//!
//! A typical use-case for this is to implement rate-limiting based on the
//! actual number of JSON-RPC methods calls and a request could potentially be
//! made by HTTP or WebSocket which this middleware is agnostic to.
//!
//! Contrary the HTTP middleware does only apply per HTTP request and
//! may be handy in some scenarios such CORS but if you want to access
//! to the actual JSON-RPC details this is the middleware to use.

use std::net::SocketAddr;

use cfx_rpc_middlewares::{Metrics, Throttle};
use jsonrpsee::{
    core::client::ClientT,
    rpc_params,
    server::{
        middleware::rpc::{RpcServiceBuilder, RpcServiceT},
        RpcModule, Server,
    },
    types::Request,
    ws_client::WsClientBuilder,
};
use log::debug;

#[derive(Clone)]
pub struct Logger<S>(S);

impl<'a, S> RpcServiceT<'a> for Logger<S>
where S: RpcServiceT<'a> + Send + Sync
{
    type Future = S::Future;

    fn call(&self, req: Request<'a>) -> Self::Future {
        println!("logger middleware: method `{}`", req.method);
        self.0.call(req)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
        .expect("setting default subscriber failed");

    let addr = run_server().await?;
    let url = format!("ws://{}", addr);

    for _ in 0..10 {
        let client: jsonrpsee::ws_client::WsClient =
            WsClientBuilder::default().build(&url).await?;
        let response: String =
            client.request("say_hello", rpc_params![]).await?;
        println!("response: {:?}", response);
        let _response: Result<String, _> =
            client.request("unknown_method", rpc_params![]).await;
        let _: String = client.request("say_hello", rpc_params![]).await?;
        let _: String = client.request("thready", rpc_params![4]).await?;

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    Ok(())
}

async fn run_server() -> anyhow::Result<SocketAddr> {
    let config_path = std::env::current_dir()?.join("throttling.toml");

    debug!("throttling config path: {:?}", config_path);

    let rpc_middleware = RpcServiceBuilder::new()
        .layer_fn(move |s| {
            Throttle::new(Some(config_path.to_str().unwrap()), "test", s)
        })
        .layer_fn(|s| Metrics::new(s));

    let server = Server::builder()
        .set_rpc_middleware(rpc_middleware)
        .build("127.0.0.1:0")
        .await?;
    let mut module = RpcModule::new(());
    module.register_method("say_hello", |_, _, _| "lo")?;
    module.register_method("thready", |params, _, _| {
        let thread_count: usize = params.one().unwrap();
        for _ in 0..thread_count {
            std::thread::spawn(|| {
                std::thread::sleep(std::time::Duration::from_secs(1))
            });
        }
        ""
    })?;
    let addr = server.local_addr()?;
    let handle = server.start(module);

    // In this example we don't care about doing shutdown so let's it run
    // forever. You may use the `ServerHandle` to shut it down or manage it
    // yourself.
    tokio::spawn(handle.stopped());

    Ok(addr)
}
