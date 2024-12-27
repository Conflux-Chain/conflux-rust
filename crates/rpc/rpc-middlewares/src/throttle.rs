use cfx_rpc_utils::error::{
    jsonrpc_error_helpers::request_rejected_too_many_request_error,
    jsonrpsee_error_helpers::jsonrpc_error_to_error_object_owned,
};
use cfx_util_macros::bail;
use futures::FutureExt;
use futures_util::future::BoxFuture;
use jsonrpc_core::Result as RpcResult;
use jsonrpsee::server::{middleware::rpc::RpcServiceT, MethodResponse};
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
                Box::pin(async move {
                    MethodResponse::error(
                        req.id,
                        jsonrpc_error_to_error_object_owned(e),
                    )
                })
                .boxed()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use jsonrpsee::{
        core::client::ClientT,
        rpc_params,
        server::{RpcServiceBuilder, Server},
        tokio,
        ws_client::WsClientBuilder,
        RpcModule,
    };
    use std::net::SocketAddr;

    use super::*;

    async fn run_server() -> anyhow::Result<SocketAddr> {
        let m = RpcServiceBuilder::new().layer_fn(|s: jsonrpsee::server::middleware::rpc::RpcService| {
            Throttle::new(Some("/Users/dayong/myspace/mywork/conflux-rust/crates/rpc/rpc-middlewares/src/throttling.toml"), "test", s)
        });

        let server = Server::builder()
            .set_rpc_middleware(m)
            .build("127.0.0.1:0")
            .await
            .unwrap();

        let addr = server.local_addr()?;

        let mut module = RpcModule::new(());
        module.register_method("say_hello", |_, _, _| "lo").unwrap();
        module
            .register_method("say_goodbye", |_, _, _| "goodbye")
            .unwrap();

        let handle = server.start(module);
        tokio::spawn(handle.stopped());

        Ok(addr)
    }

    async fn call_rpc(addr: SocketAddr) {
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init()
            .expect("setting default subscriber failed");

        let url = format!("ws://{}", addr);
        let client = WsClientBuilder::default().build(url).await.unwrap();

        for _ in 0..30 {
            let resp_hello: String =
                client.request("say_hello", rpc_params![]).await.unwrap();
            println!("resp_hello: {:?}", resp_hello);
            let resp_goodbye: String =
                client.request("say_goodbye", rpc_params![]).await.unwrap();
            println!("resp_goodbye: {:?}", resp_goodbye);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn test_throttle() {
        let addr = run_server().await.unwrap();
        call_rpc(addr).await;
    }
}
