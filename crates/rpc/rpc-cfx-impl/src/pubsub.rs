use crate::helpers::{
    block_provider::build_header, subscribers::pipe_from_stream, EpochQueue,
};
use cfx_addr::Network;
use cfx_parameters::{
    consensus::DEFERRED_STATE_EPOCH_COUNT,
    consensus_internal::REWARD_EPOCH_COUNT,
};
use cfx_rpc_cfx_api::PubSubApiServer;
use cfx_rpc_cfx_types::{
    pubsub::{self, Kind, Params, SubscriptionEpoch},
    Header, Log,
};
use cfx_tasks::TaskExecutor;
use cfx_types::{Space, H256};
use cfxcore::{
    channel::Channel, BlockDataManager, Notifications, SharedConsensusGraph,
};
use futures::{future::join_all, StreamExt};
use jsonrpsee::{
    core::{async_trait, SubscriptionResult},
    server::PendingSubscriptionSink,
};
use log::{debug, error, trace, warn};
use parking_lot::RwLock;
use primitives::{
    filter::LogFilter, log_entry::LocalizedLogEntry, receipt::BlockReceipts,
};
use std::{collections::HashMap, iter::zip, sync::Arc, time::Duration};
use tokio::{sync::broadcast, time::sleep};
use tokio_stream::{wrappers::BroadcastStream, Stream};

const BROADCAST_CHANNEL_SIZE: usize = 1000;

pub struct PubSubHandler {
    handler: Arc<ChainNotificationHandler>,
    heads_loop_started: Arc<RwLock<bool>>,
    notifications: Arc<Notifications>,
    executor: TaskExecutor,
    head_sender: Arc<broadcast::Sender<Header>>,
    latest_state_epoch_task: EpochTask,
    latest_mined_epoch_task: EpochTask,
    log_loop_started: Arc<RwLock<HashMap<LogFilter, bool>>>,
    log_senders:
        Arc<RwLock<HashMap<LogFilter, broadcast::Sender<pubsub::Result>>>>,
}

impl PubSubHandler {
    pub fn new(
        notifications: Arc<Notifications>, executor: TaskExecutor,
        consensus: SharedConsensusGraph, network: Network,
    ) -> Self {
        let (head_sender, _) = broadcast::channel(BROADCAST_CHANNEL_SIZE);
        let handler = Arc::new(ChainNotificationHandler {
            consensus: consensus.clone(),
            data_man: consensus.data_manager().clone(),
            network,
        });
        let log_senders = Arc::new(RwLock::new(HashMap::new()));
        Self {
            latest_state_epoch_task: EpochTask::new(
                SubscriptionEpoch::LatestState,
                executor.clone(),
                handler.clone(),
            ),
            latest_mined_epoch_task: EpochTask::new(
                SubscriptionEpoch::LatestMined,
                executor.clone(),
                handler.clone(),
            ),
            handler,
            heads_loop_started: Arc::new(RwLock::new(false)),
            notifications,
            executor,
            head_sender: Arc::new(head_sender),
            log_loop_started: Arc::new(RwLock::new(HashMap::new())),
            log_senders,
        }
    }

    fn new_headers_stream(&self) -> impl Stream<Item = Header> {
        let receiver = self.head_sender.subscribe();
        BroadcastStream::new(receiver)
            .filter(|item| {
                let res = match item {
                    Ok(_) => true,
                    Err(_) => false, /* there are two types of errors: closed
                                      * and lagged, mainly lagged */
                };
                futures::future::ready(res)
            })
            .map(|item| item.expect("should not be an error"))
    }

    fn new_epoch_stream(
        &self, epoch: SubscriptionEpoch,
    ) -> impl Stream<Item = pubsub::Result> {
        let receiver = match epoch {
            SubscriptionEpoch::LatestState => {
                self.latest_state_epoch_task.sender.subscribe()
            }
            SubscriptionEpoch::LatestMined => {
                self.latest_mined_epoch_task.sender.subscribe()
            }
        };
        BroadcastStream::new(receiver)
            .filter(|item| {
                let res = match item {
                    Ok(_) => true,
                    Err(_) => false,
                };
                futures::future::ready(res)
            })
            .map(|item| {
                let (epoch, hashes) = item.expect("should not be an error");
                pubsub::Result::Epoch {
                    epoch_number: epoch.into(),
                    epoch_hashes_ordered: hashes,
                }
            })
    }

    fn new_logs_stream(
        &self, filter: LogFilter,
    ) -> impl Stream<Item = pubsub::Result> {
        let receiver;
        let senders = self.log_senders.read();
        if !senders.contains_key(&filter) {
            drop(senders);
            let mut senders = self.log_senders.write();
            let (tx, rx) = broadcast::channel(BROADCAST_CHANNEL_SIZE);
            senders.insert(filter, tx);
            receiver = rx;
        } else {
            receiver = senders.get(&filter).unwrap().subscribe();
        }

        BroadcastStream::new(receiver)
            .filter(|item| {
                let res = match item {
                    Ok(_) => true,
                    Err(_) => false,
                };
                futures::future::ready(res)
            })
            .map(|item| item.expect("should not be an error"))
    }

    fn start_logs_loop(&self, filter: LogFilter) {
        let mut loop_started = self.log_loop_started.write();
        if loop_started.contains_key(&filter) {
            return;
        }
        loop_started.insert(filter.clone(), true);

        let mut receiver = self.notifications.epochs_ordered.subscribe();
        let senders = self.log_senders.read();
        let tx = senders.get(&filter).unwrap().clone();

        // clone everything we use in our async loop
        let loop_started = self.log_loop_started.clone();
        let handler = self.handler.clone();

        // use a queue to make sure we only process an epoch once it has been
        // executed for sure
        let mut queue = EpochQueue::<Vec<H256>>::with_capacity(
            (DEFERRED_STATE_EPOCH_COUNT - 1) as usize,
        );

        let fut = async move {
            let mut last_epoch = 0;

            while let Some(epoch) = receiver.recv().await {
                trace!("logs_loop: {:?}", epoch);

                let epoch = match queue.push(epoch) {
                    None => continue,
                    Some(e) => e,
                };

                // publish pivot chain reorg if necessary
                if epoch.0 <= last_epoch {
                    debug!("pivot chain reorg: {} -> {}", last_epoch, epoch.0);
                    assert!(epoch.0 > 0, "Unexpected epoch number received.");
                    let revert = pubsub::Result::ChainReorg {
                        revert_to: (epoch.0 - 1).into(),
                    };
                    let _ = tx.send(revert);
                }

                last_epoch = epoch.0;

                let send_res =
                    handler.notify_logs(&tx, filter.clone(), epoch).await;
                if send_res.is_err() {
                    let mut loop_started = loop_started.write();
                    loop_started.remove(&filter);
                    return;
                }
            }
        };

        self.executor.spawn(fut);
    }

    fn start_epoch_loop(&self, epoch: SubscriptionEpoch) {
        let epochs_ordered = self.notifications.epochs_ordered.clone();
        match epoch {
            SubscriptionEpoch::LatestState => {
                self.latest_state_epoch_task.start_loop(epochs_ordered)
            }
            SubscriptionEpoch::LatestMined => {
                self.latest_mined_epoch_task.start_loop(epochs_ordered)
            }
        }
    }

    fn start_heads_loop(&self) {
        let mut loop_started = self.heads_loop_started.write();
        if *loop_started {
            return;
        }
        *loop_started = true;

        debug!("async start_headers_loop");
        let handler_clone = self.handler.clone();
        let head_sender = self.head_sender.clone();
        let heads_loop_started = self.heads_loop_started.clone();
        let new_block_hashes = self.notifications.new_block_hashes.clone();
        let mut receiver = new_block_hashes.subscribe();

        let fut = async move {
            while let Some(hash) = receiver.recv().await {
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

                let send_res = head_sender.send(header);
                if send_res.is_err() {
                    // stop the loop
                    let mut loop_started = heads_loop_started.write();
                    *loop_started = false;
                    return;
                }
            }
        };

        self.executor.spawn(fut);
    }
}

#[async_trait]
impl PubSubApiServer for PubSubHandler {
    async fn subscribe(
        &self, pending: PendingSubscriptionSink, kind: Kind,
        params: Option<pubsub::Params>,
    ) -> SubscriptionResult {
        match (kind, params) {
            (Kind::NewHeads, None) => {
                let sink = pending.accept().await?;
                let stream = self
                    .new_headers_stream()
                    .map(|header| pubsub::Result::Header(header));
                self.executor.spawn(async move {
                    let _ = pipe_from_stream(sink, stream).await;
                });

                // start the head stream
                self.start_heads_loop();
            }
            (Kind::NewHeads, _) => {
                return Err("Expected no parameters.".into());
            }
            (Kind::Epochs, None) => {
                let sink = pending.accept().await?;
                let epoch = SubscriptionEpoch::LatestMined;
                let stream = self.new_epoch_stream(epoch);
                self.executor.spawn(async move {
                    let _ = pipe_from_stream(sink, stream).await;
                });
                self.start_epoch_loop(epoch);
            }
            (Kind::Epochs, Some(Params::Epochs(epoch))) => {
                let sink = pending.accept().await?;
                let stream = self.new_epoch_stream(epoch);
                self.executor.spawn(async move {
                    let _ = pipe_from_stream(sink, stream).await;
                });
                self.start_epoch_loop(epoch);
            }
            (Kind::Epochs, _) => {
                return Err("Expected epoch parameter.".into());
            }
            (Kind::Logs, None) => {
                let sink = pending.accept().await?;
                let filter = LogFilter::default();
                let stream = self.new_logs_stream(filter.clone());
                self.executor.spawn(async move {
                    let _ = pipe_from_stream(sink, stream).await;
                });
                self.start_logs_loop(filter);
            }
            (Kind::Logs, Some(Params::Logs(filter))) => {
                let sink = pending.accept().await?;
                let filter =
                    filter.into_primitive().map_err(|e| e.to_string())?;
                let stream = self.new_logs_stream(filter.clone());
                self.executor.spawn(async move {
                    let _ = pipe_from_stream(sink, stream).await;
                });
                self.start_logs_loop(filter);
            }
            (Kind::Logs, _) => {
                return Err("Expected filter parameter.".into());
            }
            _ => {
                return Err("Unsupported subscription kind.".into());
            }
        };
        Ok(())
    }
}

pub struct EpochTask {
    epoch_type: SubscriptionEpoch,
    loop_started: Arc<RwLock<bool>>,
    sender: Arc<broadcast::Sender<(u64, Vec<H256>)>>,
    executor: TaskExecutor,
    chain_handler: Arc<ChainNotificationHandler>,
}

impl EpochTask {
    fn new(
        epoch_type: SubscriptionEpoch, executor: TaskExecutor,
        chain_handler: Arc<ChainNotificationHandler>,
    ) -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CHANNEL_SIZE);

        Self {
            epoch_type,
            loop_started: Arc::new(RwLock::new(false)),
            sender: Arc::new(sender),
            executor,
            chain_handler,
        }
    }

    fn start_loop(&self, epochs_ordered: Arc<Channel<(u64, Vec<H256>)>>) {
        let mut loop_started = self.loop_started.write();
        if *loop_started {
            return;
        }
        *loop_started = true;

        let mut receiver = epochs_ordered.subscribe();
        let sender = self.sender.clone();
        let loop_started = self.loop_started.clone();
        let queue_size = if self.epoch_type == SubscriptionEpoch::LatestState {
            (DEFERRED_STATE_EPOCH_COUNT - 1) as usize
        } else {
            0
        };
        let mut queue = EpochQueue::<Vec<H256>>::with_capacity(queue_size);
        let epoch_type = self.epoch_type;
        let chain_handler = self.chain_handler.clone();

        let fut = async move {
            while let Some((epoch, hashes)) = receiver.recv().await {
                trace!("epoch_loop: {:?}", (epoch, &hashes));

                let (epoch, hashes) = match queue.push((epoch, hashes)) {
                    None => continue,
                    Some(e) => e,
                };

                // wait for epoch to be executed
                if epoch_type == pubsub::SubscriptionEpoch::LatestState {
                    let pivot = hashes.last().expect("empty epoch in pubsub");
                    chain_handler.wait_for_epoch(&pivot).await;
                }

                // publish epochs
                let send_res = sender.send((epoch, hashes));
                if send_res.is_err() {
                    // stop the loop
                    let mut loop_started = loop_started.write();
                    *loop_started = false;
                    return;
                }
            }
        };

        self.executor.spawn(fut);
    }
}

#[derive(Clone)]
pub struct ChainNotificationHandler {
    consensus: SharedConsensusGraph,
    data_man: Arc<BlockDataManager>,
    pub network: Network,
}

impl ChainNotificationHandler {
    fn get_header_by_hash(&self, hash: &H256) -> Result<Header, String> {
        let header = match self.data_man.block_header_by_hash(hash) {
            Some(h) => build_header(&*h, self.network, self.consensus.clone()),
            None => return Err("Header not found".to_string()),
        };

        header
    }

    // wait until the execution results corresponding to `pivot` become
    // available in the database.
    async fn wait_for_epoch(&self, pivot: &H256) -> () {
        let _ = self.retrieve_block_receipts(&pivot, &pivot).await;
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
                        block_timestamp: Some(block.block_header.timestamp()),
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

    async fn notify_logs(
        &self, subscriber: &broadcast::Sender<pubsub::Result>,
        filter: LogFilter, epoch: (u64, Vec<H256>),
    ) -> Result<usize, String> {
        trace!("notify_logs({:?})", epoch);

        // NOTE: calls to DbManager are supposed to be cached
        // FIXME(thegaram): what is the perf impact of calling this for each
        // subscriber? would it be better to do this once for each epoch?
        let logs = match self.retrieve_epoch_logs(epoch).await {
            Some(logs) => logs,
            None => return Ok(0),
        };

        let logs_len = logs.len();
        trace!("notify_logs: retrieved {} logs", logs_len);

        // apply filter to logs
        let logs = logs
            .iter()
            .filter(|l| filter.matches(&l.entry))
            .cloned()
            .map(|l| Log::try_from_localized(l, self.network));

        // send logs in order
        // FIXME(thegaram): Sink::notify flushes after each item.
        // consider sending them in a batch.
        for log in logs {
            match log {
                Ok(l) => {
                    let send_res = subscriber.send(pubsub::Result::Log(l));
                    if send_res.is_err() {
                        return send_res.map_err(|e| e.to_string());
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
        Ok(logs_len)
    }
}
