use crate::helpers::EpochQueue;
use cfx_parameters::{
    consensus::DEFERRED_STATE_EPOCH_COUNT,
    consensus_internal::REWARD_EPOCH_COUNT,
};
use cfx_rpc_cfx_types::{traits::BlockProvider, PhantomBlock};
use cfx_rpc_eth_api::EthPubSubApiServer;
use cfx_rpc_eth_types::{
    eth_pubsub::{Kind as SubscriptionKind, Params, Result as PubSubResult},
    Header, Log,
};
use cfx_rpc_utils::error::jsonrpsee_error_helpers::internal_rpc_err;
use cfx_types::{Space, H256};
use cfxcore::{
    BlockDataManager, ConsensusGraph, Notifications, SharedConsensusGraph,
};
use futures::StreamExt;
use jsonrpsee::{
    core::SubscriptionResult, server::SubscriptionMessage, types::ErrorObject,
    PendingSubscriptionSink, SubscriptionSink,
};
use log::{debug, error, info, trace, warn};
use parking_lot::RwLock;
use primitives::{
    filter::LogFilter, log_entry::LocalizedLogEntry, BlockReceipts, EpochNumber,
};
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    iter::zip,
    sync::Arc,
    time::Duration,
};
use tokio::{runtime::Runtime, sync::broadcast, time::sleep};
use tokio_stream::{wrappers::BroadcastStream, Stream};

const BROADCAST_CHANNEL_SIZE: usize = 1000;

#[derive(Clone)]
pub struct PubSubApi {
    executor: Arc<Runtime>,
    chain_data_provider: Arc<ChainDataProvider>,
    notifications: Arc<Notifications>,
    heads_loop_started: Arc<RwLock<bool>>,
    head_sender: Arc<broadcast::Sender<Header>>,
    log_loop_started: Arc<RwLock<HashMap<LogFilter, bool>>>,
    log_senders: Arc<RwLock<HashMap<LogFilter, broadcast::Sender<Log>>>>,
}

impl PubSubApi {
    pub fn new(
        consensus: SharedConsensusGraph, notifications: Arc<Notifications>,
        executor: Arc<Runtime>,
    ) -> PubSubApi {
        let (head_sender, _) = broadcast::channel(BROADCAST_CHANNEL_SIZE);
        let log_senders = Arc::new(RwLock::new(HashMap::new()));
        let chain_data_provider =
            Arc::new(ChainDataProvider::new(consensus.clone()));

        PubSubApi {
            executor,
            notifications,
            heads_loop_started: Arc::new(RwLock::new(false)),
            head_sender: Arc::new(head_sender),
            log_senders,
            chain_data_provider,
            log_loop_started: Arc::new(RwLock::new(HashMap::new())),
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

    fn new_logs_stream(&self, filter: LogFilter) -> impl Stream<Item = Log> {
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

    fn start_heads_loop(&self) {
        let mut loop_started = self.heads_loop_started.write();
        if *loop_started {
            return;
        }
        *loop_started = true;

        debug!("async start_headers_loop");

        // subscribe to the `epochs_ordered` channel
        let mut receiver = self.notifications.epochs_ordered.subscribe();
        let head_sender = self.head_sender.clone();
        // clone everything we use in our async loop
        let chain_data_provider = self.chain_data_provider.clone();
        let heads_loop_started = self.heads_loop_started.clone();

        // loop asynchronously
        let fut = async move {
            // use queue to make sure we only process epochs once they have been
            // executed
            let mut queue = EpochQueue::<Vec<H256>>::with_capacity(
                (DEFERRED_STATE_EPOCH_COUNT - 1) as usize,
            );

            while let Some((epoch, hashes)) = receiver.recv().await {
                debug!("epoch_loop: {:?}", (epoch, &hashes));
                let (epoch, hashes) = match queue.push((epoch, hashes)) {
                    None => continue,
                    Some(e) => e,
                };

                // wait for epoch to be executed
                let pivot = hashes.last().expect("empty epoch in pubsub");
                chain_data_provider.wait_for_epoch(&pivot).await;

                // publish epochs
                let header = chain_data_provider.get_pivot_block_header(epoch);
                if let Some(header) = header {
                    let send_res = head_sender.send(header);
                    if send_res.is_err() {
                        // stop the loop
                        let mut loop_started = heads_loop_started.write();
                        *loop_started = false;
                        return;
                    }
                }
            }
        };

        self.executor.spawn(fut);
    }

    fn start_logs_loop(&self, filter: LogFilter) {
        let mut loop_started = self.log_loop_started.write();
        if loop_started.contains_key(&filter) {
            return;
        }
        loop_started.insert(filter.clone(), true);

        // subscribe to the `epochs_ordered` channel
        let mut receiver = self.notifications.epochs_ordered.subscribe();
        let senders = self.log_senders.read();
        let tx = senders.get(&filter).unwrap().clone();

        // clone everything we use in our async loop
        let chain_data_provider = self.chain_data_provider.clone();
        let loop_started = self.log_loop_started.clone();

        // loop asynchronously
        let fut = async move {
            let mut last_epoch = 0;
            let mut epochs: VecDeque<(u64, Vec<H256>, Vec<Log>)> =
                VecDeque::new();
            // use a queue to make sure we only process an epoch once it has
            // been executed for sure
            let mut queue = EpochQueue::<Vec<H256>>::with_capacity(
                (DEFERRED_STATE_EPOCH_COUNT - 1) as usize,
            );

            while let Some(epoch) = receiver.recv().await {
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
                        for mut log in logs.into_iter() {
                            log.removed = true;
                            // send removed logs
                            let send_res = tx.send(log);
                            if send_res.is_err() {
                                let mut loop_started = loop_started.write();
                                loop_started.remove(&filter);
                                return;
                            }
                        }
                    }
                }

                last_epoch = epoch.0;

                let latest_finalized_epoch_number =
                    chain_data_provider.latest_finalized_epoch_number();
                while let Some(e) = epochs.front() {
                    if e.0 < latest_finalized_epoch_number {
                        epochs.pop_front();
                    } else {
                        break;
                    }
                }

                let logs = chain_data_provider
                    .get_epoch_logs(&filter, epoch.clone(), false)
                    .await;
                for log in logs.iter() {
                    let send_res = tx.send(log.clone());
                    // when send_res is an error, it means all the receiver has
                    // been dropped and we should stop the
                    // loop
                    if send_res.is_err() {
                        let mut loop_started = loop_started.write();
                        loop_started.remove(&filter);
                        return;
                    }
                }
                epochs.push_back((epoch.0, epoch.1, logs));
            }
        };

        self.executor.spawn(fut);
    }
}

#[async_trait::async_trait]
impl EthPubSubApiServer for PubSubApi {
    async fn subscribe(
        &self, pending: PendingSubscriptionSink, kind: SubscriptionKind,
        params: Option<Params>,
    ) -> SubscriptionResult {
        match (kind, params) {
            (SubscriptionKind::NewHeads, None) => {
                let sink = pending.accept().await?;
                let stream = self
                    .new_headers_stream()
                    .map(|header| PubSubResult::Header(header));
                self.executor.spawn(async move {
                    let _ = pipe_from_stream(sink, stream).await;
                });

                // start the head stream
                self.start_heads_loop();
                Ok(())
            }
            (SubscriptionKind::NewHeads, _) => {
                // reject
                Err("Params should be empty".into())
            }
            (SubscriptionKind::Logs, None) => {
                let mut filter = LogFilter::default();
                filter.space = Space::Ethereum;

                let sink = pending.accept().await?;
                let stream = self
                    .new_logs_stream(filter.clone())
                    .map(|log| PubSubResult::Log(log));
                self.executor.spawn(async {
                    let _ = pipe_from_stream(sink, stream).await;
                });

                // start the log loop
                self.start_logs_loop(filter);
                Ok(())
            }
            (SubscriptionKind::Logs, Some(Params::Logs(filter))) => {
                let filter = match filter
                    .into_primitive(self.chain_data_provider.as_ref())
                {
                    Err(_e) => return Err("Invalid filter params".into()),
                    Ok(filter) => filter,
                };
                let stream = self
                    .new_logs_stream(filter.clone())
                    .map(|log| PubSubResult::Log(log));
                let sink = pending.accept().await?;
                self.executor.spawn(async {
                    let _ = pipe_from_stream(sink, stream).await;
                });

                // start the log loop
                self.start_logs_loop(filter);
                Ok(())
            }
            (_, _) => {
                // reject
                Err("Not supported".into())
            }
        }
    }
}

pub struct ChainDataProvider {
    consensus: SharedConsensusGraph,
    data_man: Arc<BlockDataManager>,
}

impl ChainDataProvider {
    pub fn new(consensus: SharedConsensusGraph) -> ChainDataProvider {
        let data_man = consensus.get_data_manager().clone();
        ChainDataProvider {
            consensus,
            data_man,
        }
    }

    fn latest_finalized_epoch_number(&self) -> u64 {
        self.consensus.latest_finalized_epoch_number()
    }

    fn consensus_graph(&self) -> &ConsensusGraph {
        self.consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
    }

    async fn get_epoch_logs(
        &self, filter: &LogFilter, epoch: (u64, Vec<H256>), removed: bool,
    ) -> Vec<Log> {
        let logs = match self.retrieve_epoch_logs(epoch).await {
            Some(logs) => logs,
            None => return vec![],
        };

        // apply filter to logs
        let logs = logs
            .iter()
            .filter(|l| filter.matches(&l.entry))
            .cloned()
            .map(|l| Log::try_from_localized(l, self, removed))
            .filter(|l| l.is_ok())
            .map(|l| l.unwrap())
            .collect();

        return logs;
    }

    async fn wait_for_epoch(&self, pivot: &H256) -> Option<Arc<BlockReceipts>> {
        self.retrieve_block_receipts(&pivot, &pivot).await
    }

    fn get_pivot_block_header(&self, epoch: u64) -> Option<Header> {
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
                    None
                }
                Ok(pb) => pb,
            };

            pb
        };

        phantom_block.map(|b| Header::from_phantom(&b))
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

    async fn get_phantom_block(
        &self, epoch: u64, pivot: H256,
    ) -> Option<PhantomBlock> {
        debug!("eth pubsub get_phantom_block");
        const POLL_INTERVAL_MS: Duration = Duration::from_millis(100);

        for ii in 0.. {
            let latest = self.consensus.best_epoch_number();
            match self.consensus_graph().get_phantom_block_by_number(
                EpochNumber::Number(epoch),
                Some(pivot),
                false, /* include_traces */
            ) {
                Ok(Some(b)) => return Some(b),
                Ok(None) => {
                    error!("Block not executed yet {:?}", pivot);
                    let _ = sleep(POLL_INTERVAL_MS).await;
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
                    > epoch + DEFERRED_STATE_EPOCH_COUNT + REWARD_EPOCH_COUNT
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
}

impl BlockProvider for &ChainDataProvider {
    fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        self.consensus.get_block_epoch_number(hash)
    }

    fn get_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String> {
        self.consensus.get_block_hashes_by_epoch(epoch_number)
    }
}

/// Helper to convert a serde error into an [`ErrorObject`]
#[derive(Debug, thiserror::Error)]
#[error("Failed to serialize subscription item: {0}")]
pub struct SubscriptionSerializeError(#[from] serde_json::Error);

impl SubscriptionSerializeError {
    const fn new(err: serde_json::Error) -> Self { Self(err) }
}

impl From<SubscriptionSerializeError> for ErrorObject<'static> {
    fn from(value: SubscriptionSerializeError) -> Self {
        internal_rpc_err(value.to_string())
    }
}

/// Pipes all stream items to the subscription sink.
/// when the stream ends or the sink is closed, the function returns.
async fn pipe_from_stream<T, St>(
    sink: SubscriptionSink, mut stream: St,
) -> Result<(), ErrorObject<'static>>
where
    St: Stream<Item = T> + Unpin,
    T: Serialize,
{
    loop {
        tokio::select! {
            _ = sink.closed() => {
                // connection dropped: when user unsubscribes or network closed
                break Ok(())
            },
            maybe_item = stream.next() => {
                let item = match maybe_item {
                    Some(item) => item,
                    None => {
                        // stream ended
                        break  Ok(())
                    },
                };
                let msg = SubscriptionMessage::from_json(&item).map_err(SubscriptionSerializeError::new)?;
                if sink.send(msg).await.is_err() {
                    break Ok(());
                }
            }
        }
    }
}
