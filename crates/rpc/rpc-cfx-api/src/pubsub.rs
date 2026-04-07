//! `cfx_` RPC API for pubsub subscription.

use cfx_rpc_cfx_types::pubsub;
use jsonrpsee::{core::SubscriptionResult, proc_macros::rpc};

/// Cfx pub-sub rpc interface.
#[rpc(server, namespace = "cfx")]
pub trait PubSubApi {
    /// Create a cfx subscription for the given params
    #[subscription(
        name = "subscribe" => "subscription",
        unsubscribe = "unsubscribe",
        item = pubsub::Result,
    )]
    async fn subscribe(
        &self, kind: pubsub::Kind, params: Option<pubsub::Params>,
    ) -> SubscriptionResult;
}
