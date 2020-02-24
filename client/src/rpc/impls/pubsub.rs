#![allow(dead_code, unused_imports, unused_variables)]

use jsonrpc_pubsub::{
    typed::{Sink, Subscriber},
    SubscriptionId,
};

use crate::rpc::{
    helpers::{errors, Subscribers},
    metadata::Metadata,
    traits::PubSub,
    types::{pubsub, Header as RpcHeader, Log as RpcLog, H256},
};

use jsonrpc_core::{
    futures::{sync::mpsc, Future, IntoFuture, Stream},
    BoxFuture, Error, Result,
};

use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};

use cfxcore::{
    BlockDataManager, ConsensusGraph, Notifications, SharedConsensusGraph,
    SynchronizationGraph,
};

use futures::future::{FutureExt, TryFutureExt};
use parking_lot::RwLock;
use primitives::{filter::Filter, log_entry::LocalizedLogEntry, BlockHeader};
use runtime::Executor;

type Client = Sink<pubsub::Result>;

/// Cfx PubSub implementation.
pub struct PubSubClient {
    handler: Arc<ChainNotificationHandler>,
    heads_subscribers: Arc<RwLock<Subscribers<Client>>>,
}

impl PubSubClient {
    /// Creates new `PubSubClient`.
    pub fn new(
        executor: Executor, consensus: SharedConsensusGraph,
        notifications: Arc<Notifications>,
    ) -> Self
    {
        let heads_subscribers = Arc::new(RwLock::new(Subscribers::default()));

        let handler = Arc::new(ChainNotificationHandler {
            executor,
            consensus: consensus.clone(),
            heads_subscribers: heads_subscribers.clone(),
        });

        // subscribe to the `new_block_hashes` channel
        let receiver = notifications.new_block_hashes.subscribe();

        // loop asynchronously
        let handler_clone = handler.clone();
        let data_man = consensus.get_data_manager().clone();

        let fut = receiver.for_each(move |(hash, _)| {
            let header = match data_man.block_header_by_hash(&hash) {
                Some(h) => handler_clone.notify_new_headers(&[(*h).clone()]),
                None => return error!("Header {:?} not found", hash),
            };
        });

        // run futures@0.3 future on tokio@0.1 executor
        handler.executor.spawn(fut.unit_error().boxed().compat());

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
    pub executor: Executor,
    consensus: SharedConsensusGraph,
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

    fn notify_new_headers(&self, headers: &[BlockHeader]) {
        for subscriber in self.heads_subscribers.read().values() {
            let convert = |h| RpcHeader::new(h, self.consensus.clone());

            for h in headers.iter().map(convert) {
                Self::notify(
                    &self.executor,
                    subscriber,
                    pubsub::Result::Header(h),
                );
            }
        }
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
            // newHeads
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
