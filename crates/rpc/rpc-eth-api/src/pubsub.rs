//! `eth_` RPC API for pubsub subscription.

use cfx_rpc_eth_types::eth_pubsub::{Kind as SubscriptionKind, Params};
use jsonrpsee::proc_macros::rpc;

/// Ethereum pub-sub rpc interface.
#[rpc(server, namespace = "eth")]
pub trait EthPubSubApi {
    /// Create an ethereum subscription for the given params
    #[subscription(
        name = "subscribe" => "subscription",
        unsubscribe = "unsubscribe",
        item = cfx_rpc_eth_types::eth_pubsub::Result,
    )]
    async fn subscribe(
        &self, kind: SubscriptionKind, params: Option<Params>,
    ) -> jsonrpsee::core::SubscriptionResult;
}
