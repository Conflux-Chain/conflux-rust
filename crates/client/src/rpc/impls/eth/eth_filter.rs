// Copyright 2022 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    sync::Arc,
};

use cfx_types::{Space, H128, H256};
use cfxcore::{
    channel::Channel, ConsensusGraph, ConsensusGraphTrait,
    SharedConsensusGraph, SharedTransactionPool,
};
use futures::{FutureExt, TryFutureExt};
use itertools::zip;
use parking_lot::{Mutex, RwLock};
use primitives::{
    filter::LogFilter, log_entry::LocalizedLogEntry, EpochNumber,
};
use runtime::Executor;

use crate::rpc::{
    errors::codes,
    helpers::{
        limit_logs, PollFilter, PollManager, SyncPollFilter,
        MAX_BLOCK_HISTORY_SIZE,
    },
    traits::eth_space::eth_filter::EthFilter,
    types::eth::{BlockNumber, EthRpcLogFilter, FilterChanges, Log},
};
use cfx_rpc_cfx_types::traits::BlockProvider;
use cfx_rpc_eth_types::Error as EthRpcError;
use cfxcore::errors::Error as CfxRpcError;
use jsonrpc_core::{Error as RpcError, ErrorCode, Result as RpcResult};

/// Something which provides data that can be filtered over.
pub trait Filterable {
    /// Current best epoch number.
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
    ) -> RpcResult<Vec<Log>>;

    /// Get a reference to the poll manager.
    fn polls(&self) -> &Mutex<PollManager<SyncPollFilter<Log>>>;

    /// Get a reference to ConsensusGraph
    fn consensus_graph(&self) -> &ConsensusGraph;

    /// Get a clone of SharedConsensusGraph
    fn shared_consensus_graph(&self) -> SharedConsensusGraph;

    /// Get logs limitation
    fn get_logs_filter_max_limit(&self) -> Option<usize>;

    /// Get epochs since last query
    fn epochs_since_last_request(
        &self, last_epoch_number: u64,
        recent_reported_epochs: &VecDeque<(u64, Vec<H256>)>,
    ) -> RpcResult<(u64, Vec<(u64, Vec<H256>)>)>;

    fn into_primitive_filter(
        &self, filter: EthRpcLogFilter,
    ) -> Result<LogFilter, EthRpcError>;
}

/// Eth filter rpc implementation for a full node.
pub struct EthFilterClient {
    consensus: SharedConsensusGraph,
    tx_pool: SharedTransactionPool,
    polls: Mutex<PollManager<SyncPollFilter<Log>>>,
    unfinalized_epochs: Arc<RwLock<UnfinalizedEpochs>>,
    logs_filter_max_limit: Option<usize>,
}

pub struct UnfinalizedEpochs {
    epochs_queue: VecDeque<(u64, Vec<H256>)>,
    epochs_map: HashMap<u64, Vec<Vec<H256>>>,
}

impl Default for UnfinalizedEpochs {
    fn default() -> Self {
        UnfinalizedEpochs {
            epochs_queue: Default::default(),
            epochs_map: Default::default(),
        }
    }
}

impl EthFilterClient {
    /// Creates new Eth filter client.
    pub fn new(
        consensus: SharedConsensusGraph, tx_pool: SharedTransactionPool,
        epochs_ordered: Arc<Channel<(u64, Vec<H256>)>>, executor: Executor,
        poll_lifetime: u32, logs_filter_max_limit: Option<usize>,
    ) -> Self {
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
    ) {
        // subscribe to the `epochs_ordered` channel
        let mut receiver = epochs_ordered.subscribe();
        let consensus = self.consensus.clone();
        let epochs = self.unfinalized_epochs.clone();

        // loop asynchronously
        let fut = async move {
            while let Some(epoch) = receiver.recv().await {
                let mut epochs = epochs.write();

                epochs.epochs_queue.push_back(epoch.clone());
                epochs
                    .epochs_map
                    .entry(epoch.0)
                    .or_insert(vec![])
                    .push(epoch.1.clone());

                let latest_finalized_epoch_number =
                    consensus.latest_finalized_epoch_number();
                debug!(
                    "latest finalized epoch number: {}, received epochs: {:?}",
                    latest_finalized_epoch_number, epoch
                );

                // only keep epochs after finalized state
                while let Some(e) = epochs.epochs_queue.front() {
                    if e.0 < latest_finalized_epoch_number {
                        let (k, _) = epochs.epochs_queue.pop_front().unwrap();
                        if let Some(target) = epochs.epochs_map.get_mut(&k) {
                            if target.len() == 1 {
                                epochs.epochs_map.remove(&k);
                            } else {
                                target.remove(0);
                            }
                        }
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
    /// Current best epoch number.
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
            .map(|l| Log::try_from_localized(l, self, false))
            .collect::<Result<_, _>>()?)
    }

    fn logs_for_epoch(
        &self, filter: &LogFilter, epoch: (u64, Vec<H256>), removed: bool,
    ) -> RpcResult<Vec<Log>> {
        let mut result = vec![];
        let logs = match retrieve_epoch_logs(epoch, self.consensus_graph()) {
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
            .map(|l| Log::try_from_localized(l, self, removed))
            .collect::<Result<_, _>>()?;
        result.extend(logs);

        Ok(result)
    }

    /// Get a reference to the poll manager.
    fn polls(&self) -> &Mutex<PollManager<SyncPollFilter<Log>>> { &self.polls }

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
        &self, last_epoch_number: u64,
        recent_reported_epochs: &VecDeque<(u64, Vec<H256>)>,
    ) -> RpcResult<(u64, Vec<(u64, Vec<H256>)>)> {
        let last_block = if let Some((num, hash)) =
            recent_reported_epochs.front().cloned()
        {
            if last_epoch_number != num {
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

        // retrieve the current epoch number
        let current_epoch_number = self.best_executed_epoch_number();
        debug!("current epoch number {}", current_epoch_number);
        let latest_epochs = self.unfinalized_epochs.read();

        // the best executed epoch index
        let mut idx = latest_epochs.epochs_queue.len() as i32 - 1;
        while idx >= 0
            && latest_epochs.epochs_queue[idx as usize].0
                != current_epoch_number
        {
            // special case: best_executed_epoch_number rollback, so those
            // epoches before last_epoch_number can be considered to have be
            // processed.
            if latest_epochs.epochs_queue[idx as usize].0 == last_epoch_number
                && last_block
                    == Some(latest_epochs.epochs_queue[idx as usize].1.clone())
            {
                return Ok((0, vec![]));
            }

            idx -= 1;
        }

        // epochs between [max(last_epoch_number,
        // latest_finalized_epoch_number), best executed epoch]
        let mut end_epoch_number = current_epoch_number + 1;
        let mut new_epochs = vec![];
        let mut hs = HashSet::new();
        while idx >= 0 {
            let (num, blocks) =
                latest_epochs.epochs_queue[idx as usize].clone();
            if num == last_epoch_number
                && (last_block.is_none() || last_block == Some(blocks.clone()))
            {
                break;
            }

            // only keep the last one
            if num < end_epoch_number && !hs.contains(&num) {
                hs.insert(num);
                new_epochs.push((num, blocks));
                end_epoch_number = num;
            }

            idx -= 1;
        }
        new_epochs.reverse();

        // re-orged epochs
        // when last_epoch_number great than or equal to
        // latest_finalized_epoch_number, reorg_epochs should be empty
        // when last_epoch_number less than
        // latest_finalized_epoch_number, epochs between [fork point,
        // min(last_epoch_number, latest_finalized_epoch_number)]
        let mut reorg_epochs = vec![];
        let mut reorg_len = 0;
        for i in 0..recent_reported_epochs.len() {
            let (num, hash) = recent_reported_epochs[i].clone();

            if num < end_epoch_number {
                let pivot_hash =
                    if let Some(v) = latest_epochs.epochs_map.get(&num) {
                        v.last().unwrap().clone()
                    } else {
                        self.block_hashes(EpochNumber::Number(num))
                            .expect("Epoch should exist")
                    };

                if pivot_hash == hash {
                    // meet fork point
                    break;
                }

                debug!("reorg for {}, pivot hash {:?}", num, pivot_hash);
                reorg_epochs.push((num, pivot_hash));
            }
            reorg_len += 1;
        }
        reorg_epochs.reverse();

        // mid stable epochs, epochs in [last_epoch_number,
        // latest_finalized_epoch_number]
        debug!(
            "stable epochs from {} to {}",
            last_epoch_number + 1,
            end_epoch_number
        );
        for epoch_num in (last_epoch_number + 1)..end_epoch_number {
            let hash = self
                .block_hashes(EpochNumber::Number(epoch_num))
                .expect("Epoch should exist");
            reorg_epochs.push((epoch_num, hash));
        }
        reorg_epochs.append(&mut new_epochs);

        info!(
            "Chain reorg len: {}, new epochs len: {}",
            reorg_len,
            reorg_epochs.len()
        );
        Ok((reorg_len, reorg_epochs))
    }

    fn into_primitive_filter(
        &self, filter: EthRpcLogFilter,
    ) -> Result<LogFilter, EthRpcError> {
        filter.into_primitive(self)
    }
}

impl BlockProvider for &EthFilterClient {
    fn get_block_epoch_number(&self, hash: &H256) -> Option<u64> {
        self.consensus.get_block_epoch_number(hash)
    }

    fn get_block_hashes_by_epoch(
        &self, epoch_number: EpochNumber,
    ) -> Result<Vec<H256>, String> {
        self.consensus.get_block_hashes_by_epoch(epoch_number)
    }
}

impl<T: Filterable + Send + Sync + 'static> EthFilter for T {
    /// Returns id of new filter.
    fn new_filter(&self, filter: EthRpcLogFilter) -> RpcResult<H128> {
        debug!("create filter: {:?}", filter);
        let mut polls = self.polls().lock();
        let epoch_number = self.best_executed_epoch_number();

        if filter.to_block == Some(BlockNumber::Pending) {
            bail!(RpcError {
                code: ErrorCode::InvalidRequest,
                message: "Filter logs from pending blocks is not supported"
                    .into(),
                data: None,
            })
        }

        let filter: LogFilter = self.into_primitive_filter(filter)?;

        let id = polls.create_poll(SyncPollFilter::new(PollFilter::Logs {
            last_epoch_number: if epoch_number == 0 {
                0
            } else {
                epoch_number - 1
            },
            filter,
            include_pending: false,
            previous_logs: VecDeque::with_capacity(MAX_BLOCK_HISTORY_SIZE),
            recent_reported_epochs: VecDeque::with_capacity(
                MAX_BLOCK_HISTORY_SIZE,
            ),
        }));

        Ok(id.into())
    }

    /// Returns id of new block filter.
    fn new_block_filter(&self) -> RpcResult<H128> {
        debug!("create block filter");
        let mut polls = self.polls().lock();
        // +1, since we don't want to include the current block
        let id = polls.create_poll(SyncPollFilter::new(PollFilter::Block {
            last_epoch_number: self.best_executed_epoch_number(),
            recent_reported_epochs: VecDeque::with_capacity(
                MAX_BLOCK_HISTORY_SIZE,
            ),
        }));

        Ok(id.into())
    }

    /// Returns id of new block filter.
    fn new_pending_transaction_filter(&self) -> RpcResult<H128> {
        debug!("create pending transaction filter");
        let mut polls = self.polls().lock();
        let pending_transactions = self.pending_transaction_hashes();
        let id = polls.create_poll(SyncPollFilter::new(
            PollFilter::PendingTransaction(pending_transactions),
        ));
        Ok(id.into())
    }

    /// Returns filter changes since last poll.
    fn filter_changes(&self, index: H128) -> RpcResult<FilterChanges> {
        info!("filter_changes id: {}", index);
        let filter = match self.polls().lock().poll_mut(&index) {
            Some(filter) => filter.clone(),
            None => bail!(RpcError {
                code: ErrorCode::InvalidRequest,
                message: "Filter not found".into(),
                data: None,
            }),
        };

        filter.modify(|filter| match *filter {
            PollFilter::Block {
                ref mut last_epoch_number,
                ref mut recent_reported_epochs,
            } => {
                let (reorg_len, epochs) = self.epochs_since_last_request(
                    *last_epoch_number,
                    recent_reported_epochs,
                )?;

                // rewind block to last valid
                for _ in 0..reorg_len {
                    recent_reported_epochs.pop_front();
                }

                let mut hashes = Vec::new();
                for (num, blocks) in epochs.into_iter() {
                    *last_epoch_number = num;
                    hashes.push(
                        blocks
                            .last()
                            .cloned()
                            .expect("pivot block should exist"),
                    );
                    // Only keep the most recent history
                    if recent_reported_epochs.len() >= MAX_BLOCK_HISTORY_SIZE {
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
                ref mut last_epoch_number,
                ref mut recent_reported_epochs,
                ref mut previous_logs,
                ref filter,
                include_pending: _,
            } => {
                let (reorg_len, epochs) = self.epochs_since_last_request(
                    *last_epoch_number,
                    recent_reported_epochs,
                )?;

                let mut logs = vec![];

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
                    let log = match self.logs_for_epoch(
                        &filter,
                        (num, blocks.clone()),
                        false,
                    ) {
                        Ok(l) => l,
                        _ => break,
                    };

                    logs.append(&mut log.clone());
                    *last_epoch_number = num;

                    // Only keep the most recent history
                    if recent_reported_epochs.len() >= MAX_BLOCK_HISTORY_SIZE {
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
    fn filter_logs(&self, index: H128) -> RpcResult<Vec<Log>> {
        let (filter, _) = {
            let mut polls = self.polls().lock();

            match polls.poll(&index).and_then(|f| {
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
    fn uninstall_filter(&self, index: H128) -> RpcResult<bool> {
        Ok(self.polls().lock().remove_poll(&index))
    }
}

fn retrieve_epoch_logs(
    epoch: (u64, Vec<H256>), consensus_graph: &ConsensusGraph,
) -> Option<Vec<LocalizedLogEntry>> {
    debug!("retrieve_epoch_logs {:?}", epoch);
    let (epoch_number, hashes) = epoch;
    let pivot = hashes.last().cloned().expect("epoch should not be empty");

    // construct phantom block
    let pb = match consensus_graph.get_phantom_block_by_number(
        EpochNumber::Number(epoch_number),
        Some(pivot),
        false, /* include_traces */
    ) {
        Ok(Some(b)) => b,
        Ok(None) => {
            error!("Block not executed yet {:?}", pivot);
            return None;
        }
        Err(e) => {
            error!("get_phantom_block_by_number failed with {}", e);
            return None;
        }
    };

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
