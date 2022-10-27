// Copyright 2022 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    sync::Arc,
    thread,
    time::Duration,
};

use cfx_types::{H256, U256};
use cfxcore::{
    channel::Channel, BlockDataManager, ConsensusGraph, ConsensusGraphTrait,
    SharedConsensusGraph, SharedTransactionPool,
};
use futures::{FutureExt, TryFutureExt};
use itertools::zip;
use parking_lot::{Mutex, RwLock};
use primitives::{
    filter::LogFilter, log_entry::LocalizedLogEntry, BlockReceipts, EpochNumber,
};
use runtime::Executor;

use crate::rpc::{
    error_codes::codes,
    helpers::{limit_logs, PollFilter, PollManager, SyncPollFilter},
    traits::eth_space::eth::EthFilter,
    types::{
        eth::{BlockNumber, EthRpcLogFilter, FilterChanges, Log},
        Index,
    },
};
use cfxcore::rpc_errors::Error as CfxRpcError;
use jsonrpc_core::{Error as RpcError, ErrorCode, Result as RpcResult};

/// Something which provides data that can be filtered over.
pub trait Filterable {
    /// Current best block number.
    fn best_executed_epoch_number(&self) -> u64;

    /// Get a block hash by block id.
    fn block_hashes(&self, epoch_num: EpochNumber) -> Option<Vec<H256>>;

    /// pending transaction hashes at the given block (unordered).
    fn pending_transaction_hashes(&self) -> BTreeSet<H256>;

    /// Get logs that match the given filter.
    fn logs(&self, filter: LogFilter) -> RpcResult<Vec<Log>>;

    /// Get logs that match the given filter for specific epoch
    fn logs_for_epoch(
        &self, filter: &LogFilter, epoch: (u64, Vec<H256>), removed: bool,
        data_man: &Arc<BlockDataManager>,
    ) -> RpcResult<Vec<Log>>;

    /// Get a reference to the poll manager.
    fn polls(&self) -> &Mutex<PollManager<SyncPollFilter>>;

    /// Get a reference to ConsensusGraph
    fn consensus_graph(&self) -> &ConsensusGraph;

    /// Get a clone of SharedConsensusGraph
    fn shared_consensus_graph(&self) -> SharedConsensusGraph;

    /// Get logs limitation
    fn get_logs_filter_max_limit(&self) -> Option<usize>;

    /// Get epochs since last query
    fn epochs_since_last_request(
        &self, last_block_number: u64,
        recent_reported_epochs: &VecDeque<(u64, Vec<H256>)>,
    ) -> RpcResult<(u64, Vec<(u64, Vec<H256>)>)>;
}

/// Eth filter rpc implementation for a full node.
pub struct EthFilterClient {
    consensus: SharedConsensusGraph,
    tx_pool: SharedTransactionPool,
    polls: Mutex<PollManager<SyncPollFilter>>,
    unfinalized_epochs: Arc<RwLock<VecDeque<(u64, Vec<H256>)>>>,
    logs_filter_max_limit: Option<usize>,
}

impl EthFilterClient {
    /// Creates new Eth filter client.
    pub fn new(
        consensus: SharedConsensusGraph, tx_pool: SharedTransactionPool,
        epochs_ordered: Arc<Channel<(u64, Vec<H256>)>>, executor: Executor,
        poll_lifetime: u32, logs_filter_max_limit: Option<usize>,
    ) -> Self
    {
        let filter_client = EthFilterClient {
            consensus,
            tx_pool,
            polls: Mutex::new(PollManager::new(poll_lifetime)),
            unfinalized_epochs: Default::default(),
            logs_filter_max_limit,
        };

        // start loop to receive epochs, to avoid re-org during filter query
        filter_client.start_epochs_loop(epochs_ordered, executor);
        filter_client
    }

    fn start_epochs_loop(
        &self, epochs_ordered: Arc<Channel<(u64, Vec<H256>)>>,
        executor: Executor,
    )
    {
        // subscribe to the `epochs_ordered` channel
        let mut receiver = epochs_ordered.subscribe();
        let consensus = self.consensus.clone();
        let epochs = self.unfinalized_epochs.clone();

        // loop asynchronously
        let fut = async move {
            while let Some(epoch) = receiver.recv().await {
                let mut epochs = epochs.write();
                epochs.push_back(epoch.clone());

                let latest_finalized_epoch_number =
                    consensus.latest_finalized_epoch_number();
                debug!(
                    "latest finalized epoch number: {}, received epochs: {:?}",
                    latest_finalized_epoch_number, epoch
                );

                // only keep epochs after finalized state
                while let Some(e) = epochs.front() {
                    if e.0 < latest_finalized_epoch_number {
                        epochs.pop_front();
                    } else {
                        break;
                    }
                }
            }
        };

        let fut = fut.unit_error().boxed().compat();
        executor.spawn(fut);
    }
}

impl Filterable for EthFilterClient {
    /// Current best block number.
    fn best_executed_epoch_number(&self) -> u64 {
        self.consensus_graph().best_executed_state_epoch_number()
    }

    /// Get a block hash by block id.
    fn block_hashes(&self, epoch_num: EpochNumber) -> Option<Vec<H256>> {
        // keep read lock to ensure consistent view
        let _inner = self.consensus_graph().inner.read();
        let hashes =
            self.consensus_graph().get_block_hashes_by_epoch(epoch_num);

        match hashes {
            Ok(v) => return Some(v),
            _ => return None,
        }
    }

    /// pending transaction hashes at the given block (unordered).
    fn pending_transaction_hashes(&self) -> BTreeSet<H256> {
        self.tx_pool.get_pending_transaction_hashes_in_evm_pool()
    }

    /// Get logs that match the given filter.
    fn logs(&self, filter: LogFilter) -> RpcResult<Vec<Log>> {
        let logs = self
            .consensus_graph()
            .logs(filter)
            .map_err(|err| CfxRpcError::from(err))?;

        Ok(logs
            .iter()
            .cloned()
            .map(|l| Log::try_from_localized(l, self.consensus.clone(), false))
            .collect::<Result<_, _>>()?)
    }

    fn logs_for_epoch(
        &self, filter: &LogFilter, epoch: (u64, Vec<H256>), removed: bool,
        data_man: &Arc<BlockDataManager>,
    ) -> RpcResult<Vec<Log>>
    {
        let mut result = vec![];
        let logs = match retrieve_epoch_logs(&data_man, epoch) {
            Some(logs) => logs,
            None => bail!(RpcError {
                code: ErrorCode::ServerError(codes::UNSUPPORTED),
                message: "Unable to retrieve logs for epoch".into(),
                data: None,
            }),
        };

        // apply filter to logs
        let logs: Vec<Log> = logs
            .iter()
            .filter(|l| filter.matches(&l.entry))
            .cloned()
            .map(|l| {
                Log::try_from_localized(l, self.consensus.clone(), removed)
            })
            .collect::<Result<_, _>>()?;
        result.extend(logs);

        Ok(result)
    }

    /// Get a reference to the poll manager.
    fn polls(&self) -> &Mutex<PollManager<SyncPollFilter>> { &self.polls }

    fn consensus_graph(&self) -> &ConsensusGraph {
        self.consensus
            .as_any()
            .downcast_ref::<ConsensusGraph>()
            .expect("downcast should succeed")
    }

    fn shared_consensus_graph(&self) -> SharedConsensusGraph {
        self.consensus.clone()
    }

    fn get_logs_filter_max_limit(&self) -> Option<usize> {
        self.logs_filter_max_limit
    }

    fn epochs_since_last_request(
        &self, last_block_number: u64,
        recent_reported_epochs: &VecDeque<(u64, Vec<H256>)>,
    ) -> RpcResult<(u64, Vec<(u64, Vec<H256>)>)>
    {
        let last_block = if let Some((num, hash)) =
            recent_reported_epochs.front().cloned()
        {
            if last_block_number != num {
                bail!(RpcError {
                    code: ErrorCode::ServerError(codes::UNSUPPORTED),
                    message: "Last block number does not match".into(),
                    data: None,
                });
            }
            Some(hash)
        } else {
            None
        };

        // retrive the current block number
        let current_epoch_number = self.best_executed_epoch_number();
        debug!("current epoch number {}", current_epoch_number);
        let latest_epochs = self.unfinalized_epochs.read();

        // the best executed epoch index
        let mut idx = latest_epochs.len() as i32 - 1;
        while idx >= 0 && latest_epochs[idx as usize].0 != current_epoch_number
        {
            idx -= 1;
        }

        // epochs between [max(last_block_number,
        // latest_finalized_epoch_number), best executed epoch]
        let mut end_epoch_number = current_epoch_number + 1;
        let mut new_epochs = vec![];
        let mut hm = HashMap::new();
        while idx >= 0 {
            let (num, blocks) = latest_epochs[idx as usize].clone();
            if num == last_block_number
                && (last_block.is_none() || last_block == Some(blocks.clone()))
            {
                break;
            }

            // only keep the last one
            if !hm.contains_key(&num) {
                hm.insert(num, blocks.clone());
                new_epochs.push((num, blocks));
                end_epoch_number = num;
            }

            idx -= 1;
        }
        new_epochs.reverse();

        // re-orged epochs
        // when last_block_number great than or equal to
        // latest_finalized_epoch_number, reorg_epochs should be empty
        // when last_block_number less than
        // latest_finalized_epoch_number, epochs between [fork point,
        // min(last_block_number, latest_finalized_epoch_number)]
        let mut reorg_epochs = vec![];
        let mut reorg_len = 0;
        for i in 0..recent_reported_epochs.len() {
            let (num, hash) = recent_reported_epochs[i].clone();
            let pivot_hash = if let Some(v) = hm.get(&num) {
                v.clone()
            } else {
                self.block_hashes(EpochNumber::Number(num))
                    .expect("Epoch should exist")
            };

            if pivot_hash == hash {
                // meet fork point
                break;
            }

            if num < end_epoch_number {
                debug!("reorg for {}, pivot hash {:?}", num, pivot_hash);
                reorg_epochs.push((num, pivot_hash));
            }
            reorg_len += 1;
        }
        reorg_epochs.reverse();

        // mid stable epochs, epochs in [last_block_number,
        // latest_finalized_epoch_number]
        debug!(
            "stable epochs from {} to {}",
            last_block_number + 1,
            end_epoch_number
        );
        for epoch_num in (last_block_number + 1)..end_epoch_number {
            let hash = self
                .block_hashes(EpochNumber::Number(epoch_num))
                .expect("Epoch should exist");
            reorg_epochs.push((epoch_num, hash));
        }
        reorg_epochs.append(&mut new_epochs);

        debug!(
            "Chain reorg len: {}, new epochs len: {}",
            reorg_len,
            reorg_epochs.len()
        );
        Ok((reorg_len, reorg_epochs))
    }
}

impl<T: Filterable + Send + Sync + 'static> EthFilter for T {
    /// Returns id of new filter.
    fn new_filter(&self, filter: EthRpcLogFilter) -> RpcResult<U256> {
        debug!("create filter: {:?}", filter);
        let mut polls = self.polls().lock();
        let block_number = self.best_executed_epoch_number();

        if filter.to_block == Some(BlockNumber::Pending) {
            bail!(RpcError {
                code: ErrorCode::InvalidRequest,
                message: "Filter logs from pending blocks is not supported"
                    .into(),
                data: None,
            })
        }

        let filter: LogFilter =
            filter.into_primitive(self.shared_consensus_graph())?;

        let id = polls.create_poll(SyncPollFilter::new(PollFilter::Logs {
            last_block_number: if block_number == 0 {
                0
            } else {
                block_number - 1
            },
            filter,
            include_pending: false,
            previous_logs: VecDeque::with_capacity(
                PollFilter::MAX_BLOCK_HISTORY_SIZE,
            ),
            recent_reported_epochs: VecDeque::with_capacity(
                PollFilter::MAX_BLOCK_HISTORY_SIZE,
            ),
        }));

        Ok(id.into())
    }

    /// Returns id of new block filter.
    fn new_block_filter(&self) -> RpcResult<U256> {
        debug!("create block filter");
        let mut polls = self.polls().lock();
        // +1, since we don't want to include the current block
        let id = polls.create_poll(SyncPollFilter::new(PollFilter::Block {
            last_block_number: self.best_executed_epoch_number(),
            recent_reported_epochs: VecDeque::with_capacity(
                PollFilter::MAX_BLOCK_HISTORY_SIZE,
            ),
        }));

        Ok(id.into())
    }

    /// Returns id of new block filter.
    fn new_pending_transaction_filter(&self) -> RpcResult<U256> {
        debug!("create pending transaction filter");
        let mut polls = self.polls().lock();
        let pending_transactions = self.pending_transaction_hashes();
        let id = polls.create_poll(SyncPollFilter::new(
            PollFilter::PendingTransaction(pending_transactions),
        ));
        Ok(id.into())
    }

    /// Returns filter changes since last poll.
    fn filter_changes(&self, index: Index) -> RpcResult<FilterChanges> {
        let filter = match self.polls().lock().poll_mut(&index.value()) {
            Some(filter) => filter.clone(),
            None => bail!(RpcError {
                code: ErrorCode::InvalidRequest,
                message: "Filter not found".into(),
                data: None,
            }),
        };

        filter.modify(|filter| match *filter {
            PollFilter::Block {
                ref mut last_block_number,
                ref mut recent_reported_epochs,
            } => {
                let (reorg_len, epochs) = self.epochs_since_last_request(
                    *last_block_number,
                    recent_reported_epochs,
                )?;

                // rewind block to last valid
                for _ in 0..reorg_len {
                    recent_reported_epochs.pop_front();
                }

                let mut hashes = Vec::new();
                for (num, blocks) in epochs.into_iter() {
                    *last_block_number = num;
                    hashes.push(
                        blocks
                            .last()
                            .cloned()
                            .expect("pivot block should exist"),
                    );
                    // Only keep the most recent history
                    if recent_reported_epochs.len()
                        >= PollFilter::MAX_BLOCK_HISTORY_SIZE
                    {
                        recent_reported_epochs.pop_back();
                    }
                    recent_reported_epochs.push_front((num, blocks));
                }

                Ok(FilterChanges::Hashes(hashes))
            }
            PollFilter::PendingTransaction(ref mut previous_hashes) => {
                // get hashes of pending transactions
                let current_hashes = self.pending_transaction_hashes();

                let new_hashes = {
                    // find all new hashes
                    current_hashes
                        .difference(previous_hashes)
                        .cloned()
                        .map(Into::into)
                        .collect()
                };

                // save all hashes of pending transactions
                *previous_hashes = current_hashes;

                // return new hashes
                Ok(FilterChanges::Hashes(new_hashes))
            }
            PollFilter::Logs {
                ref mut last_block_number,
                ref mut recent_reported_epochs,
                ref mut previous_logs,
                ref filter,
                include_pending: _,
            } => {
                let (reorg_len, epochs) = self.epochs_since_last_request(
                    *last_block_number,
                    recent_reported_epochs,
                )?;

                let mut logs = vec![];
                let data_man =
                    self.consensus_graph().get_data_manager().clone();

                // retrieve reorg logs
                for _ in 0..reorg_len {
                    recent_reported_epochs.pop_front().unwrap();
                    let mut log: Vec<Log> = previous_logs
                        .pop_front()
                        .unwrap()
                        .into_iter()
                        .map(|mut l| {
                            l.removed = true;
                            l
                        })
                        .collect();
                    logs.append(&mut log);
                }

                // logs from new epochs
                for (num, blocks) in epochs.into_iter() {
                    let log = self.logs_for_epoch(
                        &filter,
                        (num, blocks.clone()),
                        false,
                        &data_man,
                    )?;
                    logs.append(&mut log.clone());
                    *last_block_number = num;

                    // Only keep the most recent history
                    if recent_reported_epochs.len()
                        >= PollFilter::MAX_BLOCK_HISTORY_SIZE
                    {
                        recent_reported_epochs.pop_back();
                        previous_logs.pop_back();
                    }
                    recent_reported_epochs.push_front((num, blocks));
                    previous_logs.push_front(log);
                }

                Ok(FilterChanges::Logs(limit_logs(
                    logs,
                    self.get_logs_filter_max_limit(),
                )))
            }
        })
    }

    /// Returns all logs matching given filter (in a range 'from' - 'to').
    fn filter_logs(&self, index: Index) -> RpcResult<Vec<Log>> {
        let (filter, _) = {
            let mut polls = self.polls().lock();

            match polls.poll(&index.value()).and_then(|f| {
                f.modify(|filter| match *filter {
                    PollFilter::Logs {
                        ref filter,
                        include_pending,
                        ..
                    } => Some((filter.clone(), include_pending)),
                    _ => None,
                })
            }) {
                Some((filter, include_pending)) => (filter, include_pending),
                None => bail!(RpcError {
                    code: ErrorCode::InvalidRequest,
                    message: "Filter not found".into(),
                    data: None,
                }),
            }
        };

        // retrieve logs
        Ok(limit_logs(
            self.logs(filter)?,
            self.get_logs_filter_max_limit(),
        ))
    }

    /// Uninstalls filter.
    fn uninstall_filter(&self, index: Index) -> RpcResult<bool> {
        Ok(self.polls().lock().remove_poll(&index.value()))
    }
}

fn retrieve_epoch_logs(
    data_man: &Arc<BlockDataManager>, epoch: (u64, Vec<H256>),
) -> Option<Vec<LocalizedLogEntry>> {
    info!("retrieve_epoch_logs");
    let (epoch_number, hashes) = epoch;
    let pivot = hashes.last().cloned().expect("epoch should not be empty");

    // retrieve epoch receipts
    let fut = hashes
        .iter()
        .map(|h| retrieve_block_receipts(data_man, &h, &pivot));

    let receipts = fut.into_iter().collect::<Option<Vec<_>>>()?;

    let mut logs = vec![];
    let mut log_index = 0;

    for (block_hash, block_receipts) in zip(hashes, receipts) {
        // retrieve block transactions
        let block = match data_man
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

// attempt to retrieve block receipts from BlockDataManager
fn retrieve_block_receipts(
    data_man: &Arc<BlockDataManager>, block: &H256, pivot: &H256,
) -> Option<Arc<BlockReceipts>> {
    const POLL_INTERVAL_MS: Duration = Duration::from_millis(100);

    for ii in 0.. {
        match data_man.block_execution_result_by_hash_with_epoch(
            &block, &pivot, false, /* update_pivot_assumption */
            false, /* update_cache */
        ) {
            Some(res) => return Some(res.block_receipts.clone()),
            None => {
                error!("Cannot find receipts with {:?}/{:?}", block, pivot);
                thread::sleep(POLL_INTERVAL_MS);
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
