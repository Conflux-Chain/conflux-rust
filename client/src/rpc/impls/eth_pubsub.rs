// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::rpc::{
    error_codes,
    helpers::{EpochQueue, SubscriberId, Subscribers},
    metadata::Metadata,
    traits::eth_space::eth_pubsub::EthPubSub as PubSub,
    types::eth::{
        eth_pubsub as pubsub, Header as RpcHeader, Log as RpcLog, Log,
    },
};
use cfx_parameters::{
    consensus::DEFERRED_STATE_EPOCH_COUNT,
    consensus_internal::REWARD_EPOCH_COUNT,
};
use cfx_types::{Space, H256};
use cfxcore::{
    channel::Channel, consensus::PhantomBlock, BlockDataManager,
    ConsensusGraph, Notifications, SharedConsensusGraph,
};
use futures::{
    compat::Future01CompatExt,
    future::{FutureExt, TryFutureExt},
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
    pending_transactions_subscribers: Arc<RwLock<Subscribers<Client>>>,
    epochs_ordered: Arc<Channel<(u64, Vec<H256>)>>,
    consensus: SharedConsensusGraph,
    heads_loop_started: Arc<RwLock<bool>>,
    pending_transactions_loop_started: Arc<RwLock<bool>>,
    new_pending_transactions: Arc<Channel<H256>>,
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
        let pending_transactions_subscribers     = Arc::new(RwLock::new(Subscribers::default()));

        let handler = Arc::new(ChainNotificationHandler {
            executor,
            consensus: consensus.clone(),
            data_man: consensus.get_data_manager().clone(),
            heads_subscribers: heads_subscribers.clone(),
            pending_transactions_subscribers: pending_transactions_subscribers.clone()
        });

        PubSubClient {
            handler,
            heads_subscribers,
            logs_subscribers,
            pending_transactions_subscribers,
            epochs_ordered: notifications.epochs_ordered.clone(),
            consensus: consensus.clone(),
            new_pending_transactions: notifications.new_pending_transactions.clone(),
            heads_loop_started: Arc::new(RwLock::new(false)),
            pending_transactions_loop_started: Arc::new(RwLock::new(false)),
        }
    }

    /// Returns a chain notification handler.
    pub fn handler(&self) -> Weak<ChainNotificationHandler> {
        Arc::downgrade(&self.handler)
    }

    pub fn epochs_ordered(&self) -> Arc<Channel<(u64, Vec<H256>)>> {
        self.epochs_ordered.clone()
    }

    fn start_new_pending_transactions_loop(&self) {
        let mut loop_started = self.pending_transactions_loop_started.write();
        if *loop_started {
            return;
        }
    
        debug!("start_pending_transactions_loop");
        *loop_started = true;
    
        let mut receiver = self.new_pending_transactions.subscribe();
    
        let handler_clone = self.handler.clone();

        let fut = async move {
            while let Some(new_tx) = receiver.recv().await {
                debug!("new_pending_transactions_loop: {:?}", new_tx);
    
                handler_clone.notify_new_pending_transaction(new_tx);
            }
        };
    
        let fut = fut.unit_error().boxed().compat();
        self.handler.executor.spawn(fut);
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
            let mut epochs: VecDeque<(u64, Vec<H256>, Vec<Log>)> =
                VecDeque::new();

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

                    for (_, _, logs) in reverted.into_iter() {
                        handler.notify_removed_logs(&sub, logs).await;
                    }
                }

                last_epoch = epoch.0;

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
                let logs = handler
                    .notify_logs(&sub, filter, epoch.clone(), false)
                    .await;
                epochs.push_back((epoch.0, epoch.1, logs));
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
    pending_transactions_subscribers: Arc<RwLock<Subscribers<Client>>>,
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

    // notify each subscriber about new pending transaction `hash` concurrently
    fn notify_new_pending_transaction(&self, hash: H256) {
        info!("notify_new_pending_transaction({:?})", hash);

        let subscribers = self.pending_transactions_subscribers.read();

        // do not retrieve anything unnecessarily
        if subscribers.is_empty() {
            debug!("No subscribers for pending transactions");
            return;
        }

        debug!("Notify {}", hash);
        for subscriber in subscribers.values() {
            Self::notify(
                &self.executor,
                subscriber,
                pubsub::Result::TransactionHash(hash),
            );
        }
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

    async fn notify_removed_logs(&self, subscriber: &Client, logs: Vec<Log>) {
        // send logs in order
        for mut log in logs.into_iter() {
            log.removed = true;
            Self::notify_async(subscriber, pubsub::Result::Log(log)).await;
        }
    }

    async fn notify_logs(
        &self, subscriber: &Client, filter: LogFilter, epoch: (u64, Vec<H256>),
        removed: bool,
    ) -> Vec<Log>
    {
        debug!("notify_logs({:?})", epoch);

        // NOTE: calls to DbManager are supposed to be cached
        // FIXME(thegaram): what is the perf impact of calling this for each
        // subscriber? would it be better to do this once for each epoch?
        let logs = match self.retrieve_epoch_logs(epoch).await {
            Some(logs) => logs,
            None => return vec![],
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
        let mut ret = vec![];
        for log in logs {
            match log {
                Ok(l) => {
                    Self::notify_async(
                        subscriber,
                        pubsub::Result::Log(l.clone()),
                    )
                    .await;
                    ret.push(l);
                }
                Err(e) => {
                    error!(
                        "Unexpected error while constructing RpcLog: {:?}",
                        e
                    );
                }
            }
        }

        ret
    }

    async fn get_phantom_block(
        &self, epoch_number: u64, pivot: H256,
    ) -> Option<PhantomBlock> {
        debug!("eth pubsub get_phantom_block");
        const POLL_INTERVAL_MS: Duration = Duration::from_millis(100);

        for ii in 0.. {
            let latest = self.consensus.best_epoch_number();
            match self.consensus_graph().get_phantom_block_by_number(
                EpochNumber::Number(epoch_number),
                Some(pivot),
                false, /* include_traces */
            ) {
                Ok(Some(b)) => return Some(b),
                Ok(None) => {
                    error!("Block not executed yet {:?}", pivot);
                    let _ = sleep(POLL_INTERVAL_MS).compat().await;
                }
                Err(e) => {
                    error!("get_phantom_block_by_number failed {}", e);
                    return None;
                }
            };

            // we assume that an epoch gets executed within 100 seconds
            if ii > 1000 {
                error!("Cannot construct phantom block for {:?}", pivot);
                return None;
            } else {
                if latest
                    > epoch_number
                        + DEFERRED_STATE_EPOCH_COUNT
                        + REWARD_EPOCH_COUNT
                {
                    // Even if the epoch was executed, the phantom block on the
                    // fork should be unable to constructed.
                    warn!(
                        "Cannot onstruct phantom block for {:?}, latest_epoch={}",
                        pivot, latest
                    );
                    return None;
                }
            }
        }

        unreachable!()
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
                    let _ = sleep(POLL_INTERVAL_MS).compat().await;
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
        info!("eth pubsub retrieve_epoch_logs");
        let (epoch_number, hashes) = epoch;
        let pivot = hashes.last().cloned().expect("epoch should not be empty");

        let pb = self.get_phantom_block(epoch_number, pivot).await?;

        let mut logs = vec![];
        let mut log_index = 0;

        let txs = &pb.transactions;
        assert_eq!(pb.receipts.len(), txs.len());

        // construct logs
        for (txid, (receipt, tx)) in zip(&pb.receipts, txs).enumerate() {
            let eth_logs: Vec<_> = receipt
                .logs
                .iter()
                .cloned()
                .filter(|l| l.space == Space::Ethereum)
                .collect();

            for (logid, entry) in eth_logs.into_iter().enumerate() {
                logs.push(LocalizedLogEntry {
                    entry,
                    block_hash: pivot,
                    epoch_number,
                    transaction_hash: tx.hash,
                    transaction_index: txid,
                    log_index,
                    transaction_log_index: logid,
                });

                log_index += 1;
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
             // --------- newPendingTransactions ---------
            (pubsub::Kind::NewPendingTransactions, None) => {
                info!("eth pubsub newPendingTransactions");
                self.pending_transactions_subscribers.write().push(subscriber);
                self.start_new_pending_transactions_loop();
                return;
            }
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
