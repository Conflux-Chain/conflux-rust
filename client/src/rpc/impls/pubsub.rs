#![allow(dead_code, unused_imports, unused_variables)]

use jsonrpc_pubsub::{
    typed::{Sink, Subscriber},
    SubscriptionId,
};

use crate::rpc::{
    helpers::{errors, Subscribers},
    metadata::Metadata,
    traits::PubSub,
    types::{pubsub, Header, Log},
};
use jsonrpc_core::{
    futures::{self, sync::mpsc, Future, IntoFuture, Stream},
    BoxFuture, Error, Result,
};
use parking_lot::RwLock;
use runtime::Executor;
use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};

type Client = Sink<pubsub::Result>;

/// Cfx PubSub implementation.
pub struct PubSubClient {
    handler: Arc<ChainNotificationHandler>,
    heads_subscribers: Arc<RwLock<Subscribers<Client>>>,
}

impl PubSubClient {
    /// Creates new `PubSubClient`.
    pub fn new(executor: Executor) -> Self {
        let heads_subscribers = Arc::new(RwLock::new(Subscribers::default()));

        let handler = Arc::new(ChainNotificationHandler {
            executor,
            heads_subscribers: heads_subscribers.clone(),
        });

        PubSubClient {
            handler,
            heads_subscribers,
        }
    }

    /// Returns a chain notification handler.
    pub fn handler(&self) -> Weak<ChainNotificationHandler> {
        Arc::downgrade(&self.handler)
    }
}

/// PubSub notification handler.
pub struct ChainNotificationHandler {
    executor: Executor,
    heads_subscribers: Arc<RwLock<Subscribers<Client>>>,
}

impl ChainNotificationHandler {
    fn notify(
        executor: &Executor, subscriber: &Client, result: pubsub::Result,
    ) {
        executor.spawn(subscriber.notify(Ok(result)).map(|_| ()).map_err(
            |e| warn!(target: "rpc", "Unable to send notification: {}", e),
        ));
    }

    fn notify_heads(&self, headers: &[(Vec<u8>, BTreeMap<String, String>)]) {
        for subscriber in self.heads_subscribers.read().values() {}
    }
}

impl PubSub for PubSubClient {
    type Metadata = Metadata;

    fn subscribe(
        &self, _meta: Metadata, subscriber: Subscriber<pubsub::Result>,
        kind: pubsub::Kind, params: Option<pubsub::Params>,
    )
    {
        let error = match (kind, params) {
            (pubsub::Kind::NewHeads, None) => {
                self.heads_subscribers.write().push(subscriber);
                return;
            }
            (pubsub::Kind::NewHeads, _) => {
                errors::invalid_params("newHeads", "Expected no parameters.")
            }
            _ => errors::unimplemented(None),
        };

        let _ = subscriber.reject(error);
    }

    fn unsubscribe(
        &self, _: Option<Self::Metadata>, id: SubscriptionId,
    ) -> Result<bool> {
        let res = self.heads_subscribers.write().remove(&id).is_some();

        Ok(res)
    }
}
