// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    error_codes,
    helpers::{EpochQueue, SubscriberId, Subscribers},
    metadata::Metadata,
    traits::eth_space::eth_pubsub::EthPubSub as PubSub,
    types::eth::{eth_pubsub as pubsub, Header as RpcHeader, Log as RpcLog},
};
use cfx_parameters::consensus::DEFERRED_STATE_EPOCH_COUNT;
use cfx_types::{Space, H256};
use cfxcore::{
    channel::Channel, BlockDataManager, ConsensusGraph, Notifications,
    SharedConsensusGraph,
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
use primitives::{
    filter::LogFilter, log_entry::LocalizedLogEntry, BlockReceipts, EpochNumber,
};
use runtime::Executor;
use std::{
    collections::VecDeque,
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
    logs_subscribers: Arc<RwLock<Subscribers<(Client, LogFilter)>>>,
    epochs_ordered: Arc<Channel<(u64, Vec<H256>)>>,
    consensus: SharedConsensusGraph,
    heads_loop_started: Arc<RwLock<bool>>,
}

impl PubSubClient {
    /// Creates new `PubSubClient`.
    pub fn new(
        executor: Executor, consensus: SharedConsensusGraph,
        notifications: Arc<Notifications>,
    ) -> Self
    {
        let heads_subscribers = Arc::new(RwLock::new(Subscribers::default()));
        let logs_subscribers = Arc::new(RwLock::new(Subscribers::default()));

        let handler = Arc::new(ChainNotificationHandler {
            executor,
            consensus: consensus.clone(),
            data_man: consensus.get_data_manager().clone(),
            heads_subscribers: heads_subscribers.clone(),
        });

        PubSubClient {
            handler,
            heads_subscribers,
            logs_subscribers,
            epochs_ordered: notifications.epochs_ordered.clone(),
            consensus: consensus.clone(),
            heads_loop_started: Arc::new(RwLock::new(false)),
        }
    }

    /// Returns a chain notification handler.
    pub fn handler(&self) -> Weak<ChainNotificationHandler> {
        Arc::downgrade(&self.handler)
    }

    pub fn epochs_ordered(&self) -> Arc<Channel<(u64, Vec<H256>)>> {
        self.epochs_ordered.clone()
    }

    fn start_heads_loop(&self) {
        let mut loop_started = self.heads_loop_started.write();
        if *loop_started {
            return;
        }

        debug!("start_headers_loop");
        *loop_started = true;
        let epochs_ordered = self.epochs_ordered.clone();
        let handler_clone = self.handler.clone();

        // subscribe to the `epochs_ordered` channel
        let mut receiver = epochs_ordered.subscribe();

        // use queue to make sure we only process epochs once they have been
        // executed
        let mut queue = EpochQueue::<Vec<H256>>::with_capacity(
            (DEFERRED_STATE_EPOCH_COUNT - 1) as usize,
        );

        // loop asynchronously
        let fut = async move {
            while let Some((epoch, hashes)) = receiver.recv().await {
                debug!("epoch_loop: {:?}", (epoch, &hashes));

                let (epoch, hashes) = match queue.push((epoch, hashes)) {
                    None => continue,
                    Some(e) => e,
                };

                // wait for epoch to be executed
                let pivot = hashes.last().expect("empty epoch in pubsub");
                handler_clone.wait_for_epoch(&pivot).await;

                // publish epochs
                handler_clone.notify_header(epoch);
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

        let consensus = self.consensus.clone();

        // loop asynchronously
        let fut = async move {
            let mut last_epoch = 0;
            let mut epochs: VecDeque<(u64, Vec<H256>)> = VecDeque::new();

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

                    let mut reverted = vec![];
                    while let Some(e) = epochs.back() {
                        if e.0 >= epoch.0 {
                            reverted.push(epochs.pop_back().unwrap());
                        } else {
                            break;
                        }
                    }

                    for e in reverted.into_iter() {
                        handler
                            .notify_logs(&sub, filter.clone(), e, true)
                            .await;
                    }
                }

                last_epoch = epoch.0;
                epochs.push_back(epoch.clone());

                let latest_finalized_epoch_number =
                    consensus.latest_finalized_epoch_number();
                while let Some(e) = epochs.front() {
                    if e.0 < latest_finalized_epoch_number {
                        epochs.pop_front();
                    } else {
                        break;
                    }
                }

                // publish matching logs
                handler.notify_logs(&sub, filter, epoch, false).await;
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
    fn notify_header(&self, epoch: u64) {
        info!("notifnotify_epochy_header({:?})", epoch);

        let subscribers = self.heads_subscribers.read();

        // do not retrieve anything unnecessarily
        if subscribers.is_empty() {
            debug!("subscribers is empty");
            return;
        }

        let phantom_block = {
            // keep read lock to ensure consistent view
            let _inner = self.consensus_graph().inner.read();
            let block = self.consensus_graph().get_phantom_block_by_number(
                EpochNumber::Number(epoch),
                None,
                false,
            );

            let pb = match block {
                Err(e) => {
                    debug!("Invalid params {:?}", e);
                    return;
                }
                Ok(pb) => pb,
            };

            pb
        };

        let header: Result<RpcHeader, String> = match phantom_block {
            None => {
                debug!("Phantom block is none");
                return;
            }
            Some(pb) => Ok(RpcHeader::from_phantom(&pb)),
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

        debug!("Notify {}", epoch);
        for subscriber in subscribers.values() {
            Self::notify(
                &self.executor,
                subscriber,
                pubsub::Result::Header(header.clone()),
            );
        }
    }

    async fn notify_logs(
        &self, subscriber: &Client, filter: LogFilter, epoch: (u64, Vec<H256>),
        removed: bool,
    )
    {
        debug!("notify_logs({:?})", epoch);

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
            .map(|l| {
                RpcLog::try_from_localized(l, self.consensus.clone(), removed)
            });

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
        info!("eth pubsub retrieve_block_receipts");
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

            // we assume that an epoch gets executed within 100 seconds
            if ii > 1000 {
                error!("Cannot find receipts with {:?}/{:?}", block, pivot);
                return None;
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
        info!("eth pubsub retrieve_epoch_logs");
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

    fn consensus_graph(&self) -> &ConsensusGraph {
        self.consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
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
                info!("eth pubsub newheads");
                self.heads_subscribers.write().push(subscriber);
                self.start_heads_loop();
                return;
            }
            (pubsub::Kind::NewHeads, _) => error_codes::invalid_params(
                "newHeads",
                "Expected no parameters.",
            ),
            // --------- logs ---------
            (pubsub::Kind::Logs, None) => {
                info!("eth pubsub logs");
                let mut log_filter = LogFilter::default();
                log_filter.space = Space::Ethereum;

                let id =
                    self.logs_subscribers.write().push(subscriber, log_filter);

                self.start_logs_loop(id);
                return;
            }
            (pubsub::Kind::Logs, Some(pubsub::Params::Logs(filter))) => {
                info!("eth pubsub logs with filter");
                match filter.into_primitive(self.consensus.clone()) {
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
        let res1 = self.logs_subscribers.write().remove(&id).is_some();

        Ok(res0 || res1)
    }
}
