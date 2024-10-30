use cfx_rpc_eth_api::EthPubSubApiServer;
use cfx_rpc_eth_types::eth_pubsub::{Kind as SubscriptionKind, Params};
use jsonrpsee::{core::SubscriptionResult, PendingSubscriptionSink};

pub struct PubSubApi;

impl PubSubApi {
    pub fn new() -> PubSubApi { PubSubApi }
}

#[async_trait::async_trait]
impl EthPubSubApiServer for PubSubApi {
    async fn subscribe(
        &self, pending: PendingSubscriptionSink, kind: SubscriptionKind,
        params: Option<Params>,
    ) -> SubscriptionResult {
        let _ = (pending, kind, params);
        todo!()
    }
}
