// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    error_codes,
    helpers::{EpochQueue, SubscriberId, Subscribers},
    metadata::Metadata,
    traits::PubSub,
    types::{pubsub, Header as RpcHeader, Log as RpcLog},
};
use cfx_addr::Network;
use cfx_parameters::consensus::DEFERRED_STATE_EPOCH_COUNT;
use cfx_types::H256;
use cfxcore::{
    channel::Channel, BlockDataManager, Notifications, SharedConsensusGraph,
};
use futures::{
    compat::Future01CompatExt,
    future::{join_all, FutureExt, TryFutureExt},
};
use itertools::zip;
use jsonrpc_core::{futures::Future, Result as RpcResult};
use jsonrpc_pubsub::{
    typed::{Sink, Subscriber},
    SubscriptionId,
};
use parking_lot::RwLock;
use primitives::{filter::Filter, log_entry::LocalizedLogEntry, BlockReceipts};
use runtime::Executor;
use std::{
    sync::{Arc, Weak},
    time::Duration,
};
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
        notifications: Arc<Notifications>, network: Network,
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
            network,
        });

        // --------- newHeads ---------
        // subscribe to the `new_block_hashes` channel
        let receiver = notifications.new_block_hashes.subscribe();

        // loop asynchronously
        let handler_clone = handler.clone();

        let fut = receiver.for_each(move |hash| {
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

        // use a queue to make sure we only process an epoch once it has been
        // executed for sure
        let mut queue = EpochQueue::<Vec<H256>>::with_capacity(
            (DEFERRED_STATE_EPOCH_COUNT - 1) as usize,
        );

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

                let epoch = match queue.push(epoch) {
                    None => continue,
                    Some(e) => e,
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
    network: Network,
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
            Some(h) => {
                RpcHeader::new(&*h, self.network, self.consensus.clone())
            }
            None => return warn!("Unable to retrieve header for {:?}", hash),
        };

        let header = match header {
            Ok(h) => h,
            Err(e) => {
                error!(
                    "Unexpected error while constructing RpcHeader: {:?}",
                    e
                );
                return;
            }
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
        let hashes = hashes.into_iter().map(H256::from).collect();

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
            .map(|l| RpcLog::try_from_localized(l, self.network));

        // send logs in order
        // FIXME(thegaram): Sink::notify flushes after each item.
        // consider sending them in a batch.
        for log in logs {
            match log {
                Ok(l) => {
                    Self::notify_async(subscriber, pubsub::Result::Log(l)).await
                }
                Err(e) => {
                    error!(
                        "Unexpected error while constructing RpcLog: {:?}",
                        e
                    );
                }
            }
        }
    }

    // attempt to retrieve block receipts from BlockDataManager
    // on failure, wait and retry a few times, then fail
    // NOTE: we do this because we might get epoch notifications
    // before the corresponding execution results are computed
    async fn retrieve_block_receipts(
        &self, block: &H256, pivot: &H256,
    ) -> Option<Arc<BlockReceipts>> {
        const POLL_INTERVAL_MS: Duration = Duration::from_millis(100);

        // we assume that all epochs we receive (with a distance of at least
        // `DEFERRED_STATE_EPOCH_COUNT` from the tip of the pivot chain) are
        // eventually executed, i.e. epochs are not dropped from the execution
        // queue on pivot chain reorgs. moreover, multiple execution results
        // might be stored for the same block for all epochs it was executed in.
        // if these assumptions hold, we will eventually successfully read these
        // execution results, even if they are outdated.
        for ii in 0.. {
            match self.data_man.block_execution_result_by_hash_with_epoch(
                &block, &pivot, false, /* update_pivot_assumption */
                false, /* update_cache */
            ) {
                Some(res) => return Some(res.block_receipts.clone()),
                None => {
                    trace!("Cannot find receipts with {:?}/{:?}", block, pivot);
                    let _ = sleep(POLL_INTERVAL_MS).compat().await;
                }
            }

            // this should not happen
            if ii > 100 {
                error!("Cannot find receipts with {:?}/{:?}", block, pivot);
                return None;
            }
        }

        unreachable!()
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
                match filter.into_primitive() {
                    Err(e) => e,
                    Ok(filter) => {
                        let id = self
                            .logs_subscribers
                            .write()
                            .push(subscriber, filter);

                        self.start_logs_loop(id);
                        return;
                    }
                }
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
