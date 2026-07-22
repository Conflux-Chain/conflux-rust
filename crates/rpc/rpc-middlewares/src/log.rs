use jsonrpsee::{
    server::middleware::rpc::{Batch, Notification, RpcServiceT},
    types::Request,
};
use log::debug;
use std::{future::Future, time::Instant};

#[derive(Clone)]
pub struct Logger<S> {
    service: S,
}

impl<S> Logger<S> {
    pub fn new(service: S) -> Self { Self { service } }
}

impl<S> RpcServiceT for Logger<S>
where S: RpcServiceT + Send + Sync + Clone + 'static
{
    type BatchResponse = S::BatchResponse;
    type MethodResponse = S::MethodResponse;
    type NotificationResponse = S::NotificationResponse;

    fn call<'a>(
        &self, req: Request<'a>,
    ) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let req_id = req.id.clone();
        debug!(
            "RPC request: method `{}` id {} params {:?}",
            req.method, req_id, req.params
        );

        let svc = self.service.clone();
        let start = Instant::now();

        async move {
            let res = svc.call(req).await;
            debug!("RPC request {} handled in {:?}", req_id, start.elapsed());
            res
        }
    }

    fn batch<'a>(
        &self, batch: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        debug!("RPC bactch requests: {batch}");
        self.service.batch(batch)
    }

    fn notification<'a>(
        &self, n: Notification<'a>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        self.service.notification(n)
    }
}
