#![allow(dead_code, unused_imports, unused_variables)]

use jsonrpc_pubsub::{
    typed::{Sink, Subscriber},
    SubscriptionId,
};

use crate::rpc::{
    error_codes,
    helpers::{SubscriberId, Subscribers},
    metadata::Metadata,
    traits::PubSub,
    types::{pubsub, Header as RpcHeader, Log as RpcLog, H256 as RpcH256},
};

use jsonrpc_core::{
    futures::{sync::mpsc, Future, IntoFuture, Stream},
    BoxFuture, Error, Result as RpcResult,
};

use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    time::Duration,
};

use cfxcore::{
    block_data_manager::BlockExecutionResult, channel::Channel,
    BlockDataManager, Notifications, SharedConsensusGraph,
    SynchronizationGraph,
};

use cfx_types::H256;
use futures::{
    compat::Future01CompatExt,
    future::{join_all, FutureExt, TryFutureExt},
};
use itertools::zip;
use parking_lot::RwLock;
use primitives::{
    filter::Filter,
    log_entry::{LocalizedLogEntry, LogEntry},
    BlockHeader, BlockReceipts,
};
use runtime::Executor;
use tokio_timer::sleep;

type Client = Sink<pubsub::Result>;

/// Cfx PubSub implementation.
#[derive(Clone)]
pub struct PubSubClient {
    handler: Arc<ChainNotificationHandler>,
    heads_subscribers: Arc<RwLock<Subscribers<Client>>>,
    epochs_subscribers: Arc<RwLock<Subscribers<Client>>>,
    logs_subscribers: Arc<RwLock<Subscribers<(Client, Filter)>>>,
    epochs_ordered: Arc<Channel<(u64, Vec<H256>)>>,
}

impl PubSubClient {
    /// Creates new `PubSubClient`.
    pub fn new(
        executor: Executor, consensus: SharedConsensusGraph,
        notifications: Arc<Notifications>,
    ) -> Self
    {
        let heads_subscribers = Arc::new(RwLock::new(Subscribers::default()));
        let epochs_subscribers = Arc::new(RwLock::new(Subscribers::default()));
        let logs_subscribers = Arc::new(RwLock::new(Subscribers::default()));

        let handler = Arc::new(ChainNotificationHandler {
            executor,
            consensus: consensus.clone(),
            data_man: consensus.get_data_manager().clone(),
            heads_subscribers: heads_subscribers.clone(),
            epochs_subscribers: epochs_subscribers.clone(),
            logs_subscribers: logs_subscribers.clone(),
        });

        // --------- newHeads ---------
        // subscribe to the `new_block_hashes` channel
        let receiver = notifications.new_block_hashes.subscribe();

        // loop asynchronously
        let handler_clone = handler.clone();

        let fut = receiver.for_each(move |(hash, _)| {
            handler_clone.notify_header(&hash);
        });

        // run futures@0.3 future on tokio@0.1 executor
        handler.executor.spawn(fut.unit_error().boxed().compat());

        PubSubClient {
            handler,
            heads_subscribers,
            epochs_subscribers,
            logs_subscribers,
            epochs_ordered: notifications.epochs_ordered.clone(),
        }
    }

    /// Returns a chain notification handler.
    pub fn handler(&self) -> Weak<ChainNotificationHandler> {
        Arc::downgrade(&self.handler)
    }

    // Start an async loop that continuously receives epoch notifications and
    // publishes the corresponding epochs to subscriber `id`, keeping their
    // original order. The loop terminates when subscriber `id` unsubscribes.
    fn start_epoch_loop(&self, id: SubscriberId) {
        trace!("start_epoch_loop({:?})", id);

        // clone everything we use in our async loop
        let subscribers = self.epochs_subscribers.clone();
        let epochs_ordered = self.epochs_ordered.clone();
        let handler = self.handler.clone();

        // subscribe to the `epochs_ordered` channel
        let mut receiver = epochs_ordered.subscribe();

        // loop asynchronously
        let fut = async move {
            while let Some(epoch) = receiver.recv().await {
                trace!("epoch_loop({:?}): {:?}", id, epoch);

                // retrieve subscriber
                let sub = match subscribers.read().get(&id) {
                    Some(sub) => sub.clone(),
                    None => {
                        // unsubscribed, terminate loop
                        epochs_ordered.unsubscribe(receiver.id);
                        return;
                    }
                };

                // publish epochs
                handler.notify_epoch(sub, epoch).await;
            }
        };

        // run futures@0.3 future on tokio@0.1 executor
        let fut = fut.unit_error().boxed().compat();
        self.handler.executor.spawn(fut);
    }

    // Start an async loop that continuously receives epoch notifications and
    // publishes the corresponding logs to subscriber `id`, keeping their
    // original order. The loop terminates when subscriber `id` unsubscribes.
    fn start_logs_loop(&self, id: SubscriberId) {
        trace!("start_logs_loop({:?})", id);

        // clone everything we use in our async loop
        let subscribers = self.logs_subscribers.clone();
        let epochs_ordered = self.epochs_ordered.clone();
        let handler = self.handler.clone();

        // subscribe to the `epochs_ordered` channel
        let mut receiver = epochs_ordered.subscribe();

        // loop asynchronously
        let fut = async move {
            let mut last_epoch = 0;

            while let Some(epoch) = receiver.recv().await {
                trace!("logs_loop({:?}): {:?}", id, epoch);

                // retrieve subscriber
                let (sub, filter) = match subscribers.read().get(&id) {
                    Some(sub) => sub.clone(),
                    None => {
                        // unsubscribed, terminate loop
                        epochs_ordered.unsubscribe(receiver.id);
                        return;
                    }
                };

                // publish pivot chain reorg if necessary
                if epoch.0 <= last_epoch {
                    debug!("pivot chain reorg: {} -> {}", last_epoch, epoch.0);
                    assert!(epoch.0 > 0, "Unexpected epoch number received.");
                    handler.notify_revert(&sub, epoch.0 - 1).await;
                }

                last_epoch = epoch.0;

                // publish matching logs
                handler.notify_logs(&sub, filter, epoch).await;
            }
        };

        // run futures@0.3 future on tokio@0.1 executor
        let fut = fut.unit_error().boxed().compat();
        self.handler.executor.spawn(fut);
    }
}

/// PubSub notification handler.
pub struct ChainNotificationHandler {
    pub executor: Executor,
    consensus: SharedConsensusGraph,
    data_man: Arc<BlockDataManager>,
    heads_subscribers: Arc<RwLock<Subscribers<Client>>>,
    epochs_subscribers: Arc<RwLock<Subscribers<Client>>>,
    logs_subscribers: Arc<RwLock<Subscribers<(Client, Filter)>>>,
}

impl ChainNotificationHandler {
    // notify `subscriber` about `result` in a separate task
    fn notify(exec: &Executor, subscriber: &Client, result: pubsub::Result) {
        let fut = subscriber.notify(Ok(result)).map(|_| ()).map_err(
            |e| warn!(target: "rpc", "Unable to send notification: {}", e),
        );

        exec.spawn(fut)
    }

    // notify `subscriber` about `result` asynchronously
    async fn notify_async(subscriber: &Client, result: pubsub::Result) {
        let fut = subscriber.notify(Ok(result)).map(|_| ()).map_err(
            |e| warn!(target: "rpc", "Unable to send notification: {}", e),
        );

        // convert futures01::Future into std::Future so that we can await
        let _ = fut.compat().await;
    }

    // notify each subscriber about header `hash` concurrently
    // NOTE: multiple calls to this method will result in concurrent
    // notifications, so the headers published might be reordered.
    fn notify_header(&self, hash: &H256) {
        trace!("notify_header({:?})", hash);

        let subscribers = self.heads_subscribers.read();

        // do not retrieve anything unnecessarily
        if subscribers.is_empty() {
            return;
        }

        let header = match self.data_man.block_header_by_hash(hash) {
            Some(h) => RpcHeader::new(&*h, self.consensus.clone()),
            None => return warn!("Unable to retrieve header for {:?}", hash),
        };

        for subscriber in subscribers.values() {
            Self::notify(
                &self.executor,
                subscriber,
                pubsub::Result::Header(header.clone()),
            );
        }
    }

    async fn notify_epoch(&self, subscriber: Client, epoch: (u64, Vec<H256>)) {
        trace!("notify_epoch({:?})", epoch);

        let (epoch, hashes) = epoch;
        let hashes = hashes.into_iter().map(RpcH256::from).collect();

        Self::notify_async(
            &subscriber,
            pubsub::Result::Epoch {
                epoch_number: epoch.into(),
                epoch_hashes_ordered: hashes,
            },
        )
        .await
    }

    async fn notify_revert(&self, subscriber: &Client, epoch: u64) {
        trace!("notify_revert({:?})", epoch);

        Self::notify_async(
            subscriber,
            pubsub::Result::ChainReorg {
                revert_to: epoch.into(),
            },
        )
        .await
    }

    async fn notify_logs(
        &self, subscriber: &Client, filter: Filter, epoch: (u64, Vec<H256>),
    ) {
        trace!("notify_logs({:?})", epoch);

        let epoch_number = epoch.0;

        // NOTE: calls to DbManager are supposed to be cached
        // FIXME(thegaram): what is the perf impact of calling this for each
        // subscriber? would it be better to do this once for each epoch?
        let logs = match self.retrieve_epoch_logs(epoch).await {
            Some(logs) => logs,
            None => return,
        };

        // apply filter to logs
        let logs = logs
            .iter()
            .filter(|l| filter.matches(&l.entry))
            .cloned()
            .map(RpcLog::from);

        // send logs in order
        // FIXME(thegaram): Sink::notify flushes after each item.
        // consider sending them in a batch.
        for log in logs {
            Self::notify_async(subscriber, pubsub::Result::Log(log)).await
        }
    }

    // attempt to retrieve block receipts from BlockDataManager
    // on failure, wait and retry a few times, then fail
    // NOTE: we do this because we might get epoch notifications
    // before the corresponding execution results are computed
    async fn retrieve_block_receipts(
        &self, block: &H256, pivot: &H256,
    ) -> Option<Arc<BlockReceipts>> {
        const NUM_POLLS: i8 = 10;
        const POLL_INTERVAL_MS: Duration = Duration::from_millis(100);

        for iter in 0..NUM_POLLS {
            match self.data_man.block_execution_result_by_hash_with_epoch(
                &block, &pivot, true, /* update_cache */
            ) {
                Some(res) => return Some(res.block_receipts.clone()),
                None => {
                    trace!("Cannot find receipts with {:?}/{:?}", block, pivot);
                    let _ = sleep(POLL_INTERVAL_MS).compat().await;
                }
            }
        }

        warn!("Cannot find receipts with {:?}/{:?}", block, pivot);
        None
    }

    async fn retrieve_epoch_logs(
        &self, epoch: (u64, Vec<H256>),
    ) -> Option<Vec<LocalizedLogEntry>> {
        let (epoch_number, hashes) = epoch;
        let pivot = hashes.last().cloned().expect("epoch should not be empty");

        // retrieve epoch receipts
        let fut = hashes
            .iter()
            .map(|h| self.retrieve_block_receipts(&h, &pivot));

        let receipts = join_all(fut)
            .await
            .into_iter()
            .collect::<Option<Vec<_>>>()?;

        let mut logs = vec![];
        let mut log_index = 0;

        for (block_hash, block_receipts) in zip(hashes, receipts) {
            // retrieve block transactions
            let block = match self
                .data_man
                .block_by_hash(&block_hash, true /* update_cache */)
            {
                Some(b) => b,
                None => {
                    warn!("Unable to retrieve block {:?}", block_hash);
                    return None;
                }
            };

            let txs = &block.transactions;
            assert_eq!(block_receipts.receipts.len(), txs.len());

            // construct logs
            for (txid, (receipt, tx)) in
                zip(&block_receipts.receipts, txs).enumerate()
            {
                for (logid, entry) in receipt.logs.iter().cloned().enumerate() {
                    logs.push(LocalizedLogEntry {
                        entry,
                        block_hash,
                        epoch_number,
                        transaction_hash: tx.hash,
                        transaction_index: txid,
                        log_index,
                        transaction_log_index: logid,
                    });

                    log_index += 1;
                }
            }
        }

        Some(logs)
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
            // --------- newHeads ---------
            (pubsub::Kind::NewHeads, None) => {
                self.heads_subscribers.write().push(subscriber);
                return;
            }
            (pubsub::Kind::NewHeads, _) => error_codes::invalid_params(
                "newHeads",
                "Expected no parameters.",
            ),
            // --------- epochs ---------
            (pubsub::Kind::Epochs, None) => {
                let id = self.epochs_subscribers.write().push(subscriber);
                self.start_epoch_loop(id);
                return;
            }
            (pubsub::Kind::Epochs, _) => {
                error_codes::invalid_params("epochs", "Expected no parameters.")
            }
            // --------- logs ---------
            (pubsub::Kind::Logs, None) => {
                let id = self
                    .logs_subscribers
                    .write()
                    .push(subscriber, Filter::default());

                self.start_logs_loop(id);
                return;
            }
            (pubsub::Kind::Logs, Some(pubsub::Params::Logs(filter))) => {
                let id = self
                    .logs_subscribers
                    .write()
                    .push(subscriber, filter.into());

                self.start_logs_loop(id);
                return;
            }
            (pubsub::Kind::Logs, _) => error_codes::invalid_params(
                "logs",
                "Expected filter parameter.",
            ),
            _ => error_codes::unimplemented(None),
        };

        let _ = subscriber.reject(error);
    }

    fn unsubscribe(
        &self, _: Option<Self::Metadata>, id: SubscriptionId,
    ) -> RpcResult<bool> {
        let res0 = self.heads_subscribers.write().remove(&id).is_some();
        let res1 = self.epochs_subscribers.write().remove(&id).is_some();
        let res2 = self.logs_subscribers.write().remove(&id).is_some();

        Ok(res0 || res1 || res2)
    }
}
