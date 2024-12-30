// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    errors,
    helpers::{EpochQueue, SubscriberId, Subscribers},
    metadata::Metadata,
    traits::pubsub::PubSub,
    types::{
        pubsub::{self, SubscriptionEpoch},
        Header as RpcHeader, Log as RpcLog,
    },
};
use cfx_addr::Network;
use cfx_parameters::{
    consensus::DEFERRED_STATE_EPOCH_COUNT,
    consensus_internal::REWARD_EPOCH_COUNT,
};
use cfx_types::{Space, H256};
use cfxcore::{BlockDataManager, Notifications, SharedConsensusGraph};
use futures::future::join_all;
use itertools::zip;
use jsonrpc_core::Result as RpcResult;
use jsonrpc_pubsub::{
    typed::{Sink, Subscriber},
    SinkResult, SubscriptionId,
};
use log::{debug, error, trace, warn};
use parking_lot::RwLock;
use primitives::{
    filter::LogFilter, log_entry::LocalizedLogEntry, BlockReceipts,
};
use std::{
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::{runtime::Runtime, time::sleep};

type Client = Sink<pubsub::Result>;

/// Cfx PubSub implementation.
#[derive(Clone)]
pub struct PubSubClient {
    handler: Arc<ChainNotificationHandler>,
    heads_subscribers: Arc<RwLock<Subscribers<Client>>>,
    epochs_subscribers: Arc<RwLock<Subscribers<Client>>>,
    logs_subscribers: Arc<RwLock<Subscribers<(Client, LogFilter)>>>,
    heads_loop_started: Arc<RwLock<bool>>,
    notifications: Arc<Notifications>,
    pub executor: Arc<Runtime>,
}

impl PubSubClient {
    /// Creates new `PubSubClient`.
    pub fn new(
        executor: Arc<Runtime>, consensus: SharedConsensusGraph,
        notifications: Arc<Notifications>, network: Network,
    ) -> Self {
        let heads_subscribers = Arc::new(RwLock::new(Subscribers::default()));
        let epochs_subscribers = Arc::new(RwLock::new(Subscribers::default()));
        let logs_subscribers = Arc::new(RwLock::new(Subscribers::default()));

        let handler = Arc::new(ChainNotificationHandler {
            consensus: consensus.clone(),
            data_man: consensus.get_data_manager().clone(),
            network,
        });

        PubSubClient {
            handler,
            heads_subscribers,
            epochs_subscribers,
            logs_subscribers,
            heads_loop_started: Arc::new(RwLock::new(false)),
            notifications,
            executor,
        }
    }

    /// Returns a chain notification handler.
    pub fn handler(&self) -> Weak<ChainNotificationHandler> {
        Arc::downgrade(&self.handler)
    }

    fn start_head_loop(&self) {
        let mut loop_started = self.heads_loop_started.write();
        if *loop_started {
            return;
        }

        debug!("start_headers_loop");
        *loop_started = true;

        // --------- newHeads ---------
        // subscribe to the `new_block_hashes` channel
        let new_block_hashes = self.notifications.new_block_hashes.clone();
        let mut receiver = new_block_hashes.subscribe();

        // loop asynchronously
        let handler_clone = self.handler.clone();
        let this = self.clone();

        let fut = async move {
            while let Some(hash) = receiver.recv().await {
                // handler_clone.notify_header(&hash);
                let subscribers = this.heads_subscribers.read();

                // do not retrieve anything unnecessarily
                if subscribers.is_empty() {
                    new_block_hashes.unsubscribe(receiver.id);
                    let mut loop_started = this.heads_loop_started.write();
                    *loop_started = false;
                    break;
                }

                let header = match handler_clone.get_header_by_hash(&hash) {
                    Ok(h) => h,
                    Err(e) => {
                        error!(
                            "Unexpected error while constructing RpcHeader: {:?}",
                            e
                        );
                        continue;
                    }
                };

                let mut ids_to_remove = vec![];
                for (id, subscriber) in subscribers.iter() {
                    let send_res = notify(
                        subscriber,
                        pubsub::Result::Header(header.clone()),
                    );
                    if let Err(err) = send_res {
                        if err.is_disconnected() {
                            ids_to_remove.push(id.clone());
                        }
                    }
                }

                drop(subscribers);
                for id in ids_to_remove {
                    this.heads_subscribers
                        .write()
                        .remove(&SubscriptionId::String(id.as_string()));
                }
            }
        };

        self.executor.spawn(fut);
    }

    // Start an async loop that continuously receives epoch notifications and
    // publishes the corresponding epochs to subscriber `id`, keeping their
    // original order. The loop terminates when subscriber `id` unsubscribes.
    fn start_epoch_loop(&self, id: SubscriberId, sub_epoch: SubscriptionEpoch) {
        trace!("start_epoch_loop({:?})", id);

        // clone everything we use in our async loop
        let subscribers = self.epochs_subscribers.clone();
        let epochs_ordered = self.notifications.epochs_ordered.clone();
        let handler = self.handler.clone();

        // subscribe to the `epochs_ordered` channel
        let mut receiver = epochs_ordered.subscribe();

        // when subscribing to "latest_state", use a queue to make sure
        // we only process epochs once they have been executed
        let mut queue = EpochQueue::<Vec<H256>>::with_capacity(
            if sub_epoch == SubscriptionEpoch::LatestState {
                (DEFERRED_STATE_EPOCH_COUNT - 1) as usize
            } else {
                0
            },
        );

        // loop asynchronously
        let fut = async move {
            while let Some((epoch, hashes)) = receiver.recv().await {
                trace!("epoch_loop({:?}): {:?}", id, (epoch, &hashes));

                // retrieve subscriber
                let sub = match subscribers.read().get(&id) {
                    Some(sub) => sub.clone(),
                    None => {
                        // unsubscribed, terminate loop
                        epochs_ordered.unsubscribe(receiver.id);
                        return;
                    }
                };

                let (epoch, hashes) = match queue.push((epoch, hashes)) {
                    None => continue,
                    Some(e) => e,
                };

                // wait for epoch to be executed
                if sub_epoch == SubscriptionEpoch::LatestState {
                    let pivot = hashes.last().expect("empty epoch in pubsub");
                    handler.wait_for_epoch(&pivot).await;
                }

                // publish epochs
                let send_res = handler.notify_epoch(sub, (epoch, hashes)).await;
                if let Err(err) = send_res {
                    if err.is_disconnected() {
                        epochs_ordered.unsubscribe(receiver.id);
                        subscribers
                            .write()
                            .remove(&SubscriptionId::String(id.as_string()));
                        return;
                    }
                }
            }
        };

        self.executor.spawn(fut);
    }

    // Start an async loop that continuously receives epoch notifications and
    // publishes the corresponding logs to subscriber `id`, keeping their
    // original order. The loop terminates when subscriber `id` unsubscribes.
    fn start_logs_loop(&self, id: SubscriberId) {
        trace!("start_logs_loop({:?})", id);

        // clone everything we use in our async loop
        let subscribers = self.logs_subscribers.clone();
        let epochs_ordered = self.notifications.epochs_ordered.clone();
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
                let send_res = handler.notify_logs(&sub, filter, epoch).await;
                if let Err(err) = send_res {
                    if err.is_disconnected() {
                        epochs_ordered.unsubscribe(receiver.id);
                        subscribers
                            .write()
                            .remove(&SubscriptionId::String(id.as_string()));
                        return;
                    }
                }
            }
        };

        self.executor.spawn(fut);
    }
}

/// PubSub notification handler.
pub struct ChainNotificationHandler {
    consensus: SharedConsensusGraph,
    data_man: Arc<BlockDataManager>,
    pub network: Network,
}

impl ChainNotificationHandler {
    fn get_header_by_hash(&self, hash: &H256) -> Result<RpcHeader, String> {
        let header = match self.data_man.block_header_by_hash(hash) {
            Some(h) => {
                RpcHeader::new(&*h, self.network, self.consensus.clone())
            }
            None => return Err("Header not found".to_string()),
        };

        header
    }

    async fn notify_epoch(
        &self, subscriber: Client, epoch: (u64, Vec<H256>),
    ) -> SinkResult {
        trace!("notify_epoch({:?})", epoch);

        let (epoch, hashes) = epoch;
        let hashes = hashes.into_iter().map(H256::from).collect();

        notify(
            &subscriber,
            pubsub::Result::Epoch {
                epoch_number: epoch.into(),
                epoch_hashes_ordered: hashes,
            },
        )
    }

    async fn notify_revert(&self, subscriber: &Client, epoch: u64) {
        trace!("notify_revert({:?})", epoch);

        let _ = notify(
            subscriber,
            pubsub::Result::ChainReorg {
                revert_to: epoch.into(),
            },
        );
    }

    async fn notify_logs(
        &self, subscriber: &Client, filter: LogFilter, epoch: (u64, Vec<H256>),
    ) -> SinkResult {
        trace!("notify_logs({:?})", epoch);

        // NOTE: calls to DbManager are supposed to be cached
        // FIXME(thegaram): what is the perf impact of calling this for each
        // subscriber? would it be better to do this once for each epoch?
        let logs = match self.retrieve_epoch_logs(epoch).await {
            Some(logs) => logs,
            None => return Ok(()),
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
                    let send_res = notify(subscriber, pubsub::Result::Log(l));
                    if send_res.is_err() {
                        return send_res;
                    }
                }
                Err(e) => {
                    error!(
                        "Unexpected error while constructing RpcLog: {:?}",
                        e
                    );
                }
            }
        }
        Ok(())
    }

    // attempt to retrieve block receipts from BlockDataManager
    // on failure, wait and retry a few times, then fail
    // NOTE: we do this because we might get epoch notifications
    // before the corresponding execution results are computed
    async fn retrieve_block_receipts(
        &self, block: &H256, pivot: &H256,
    ) -> Option<Arc<BlockReceipts>> {
        const POLL_INTERVAL_MS: Duration = Duration::from_millis(100);
        let epoch = self.data_man.block_height_by_hash(pivot)?;

        // we assume that all epochs we receive (with a distance of at least
        // `DEFERRED_STATE_EPOCH_COUNT` from the tip of the pivot chain) are
        // eventually executed, i.e. epochs are not dropped from the execution
        // queue on pivot chain reorgs. moreover, multiple execution results
        // might be stored for the same block for all epochs it was executed in.
        // if these assumptions hold, we will eventually successfully read these
        // execution results, even if they are outdated.
        for ii in 0.. {
            let latest = self.consensus.best_epoch_number();
            match self.data_man.block_execution_result_by_hash_with_epoch(
                &block, &pivot, false, /* update_pivot_assumption */
                false, /* update_cache */
            ) {
                Some(res) => return Some(res.block_receipts.clone()),
                None => {
                    trace!("Cannot find receipts with {:?}/{:?}", block, pivot);
                    let _ = sleep(POLL_INTERVAL_MS).await;
                }
            }

            // we assume that an epoch gets executed within 100 seconds
            if ii > 1000 {
                error!("Cannot find receipts with {:?}/{:?}", block, pivot);
                return None;
            } else {
                if latest
                    > epoch + DEFERRED_STATE_EPOCH_COUNT + REWARD_EPOCH_COUNT
                {
                    // Even if the epoch was executed, the receipts on the fork
                    // should have been deleted and cannot
                    // be retrieved.
                    warn!(
                        "Cannot find receipts with {:?}/{:?}, latest_epoch={}",
                        block, pivot, latest
                    );
                    return None;
                }
            }
        }

        unreachable!()
    }

    // wait until the execution results corresponding to `pivot` become
    // available in the database.
    async fn wait_for_epoch(&self, pivot: &H256) -> () {
        let _ = self.retrieve_block_receipts(&pivot, &pivot).await;
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
                let native_logs: Vec<_> = receipt
                    .logs
                    .iter()
                    .cloned()
                    .filter(|l| l.space == Space::Native)
                    .collect();

                for (logid, entry) in native_logs.into_iter().enumerate() {
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
    ) {
        let error = match (kind, params) {
            // --------- newHeads ---------
            (pubsub::Kind::NewHeads, None) => {
                self.heads_subscribers.write().push(subscriber);
                self.start_head_loop();
                return;
            }
            (pubsub::Kind::NewHeads, _) => {
                errors::invalid_params("newHeads", "Expected no parameters.")
            }
            // --------- epochs ---------
            (pubsub::Kind::Epochs, None) => {
                let id = self.epochs_subscribers.write().push(subscriber);
                self.start_epoch_loop(id, SubscriptionEpoch::LatestMined);
                return;
            }
            (pubsub::Kind::Epochs, Some(pubsub::Params::Epochs(epoch))) => {
                let id = self.epochs_subscribers.write().push(subscriber);
                self.start_epoch_loop(id, epoch);
                return;
            }
            (pubsub::Kind::Epochs, _) => {
                errors::invalid_params("epochs", "Expected epoch parameter.")
            }
            // --------- logs ---------
            (pubsub::Kind::Logs, None) => {
                let id = self
                    .logs_subscribers
                    .write()
                    .push(subscriber, LogFilter::default());

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
            (pubsub::Kind::Logs, _) => {
                errors::invalid_params("logs", "Expected filter parameter.")
            }
            _ => errors::unimplemented(None),
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

fn notify(subscriber: &Client, result: pubsub::Result) -> SinkResult {
    subscriber.notify(Ok(result))
}
