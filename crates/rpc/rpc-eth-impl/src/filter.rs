use crate::{
    helpers::{
        eth_filter::EthFilterHelper,
        poll_filter::{
            limit_logs, PollFilter, SyncPollFilter, MAX_BLOCK_HISTORY_SIZE,
        },
    },
    traits::Filterable,
};
use cfx_rpc_eth_api::EthFilterApiServer;
use cfx_rpc_eth_types::{
    BlockNumber, EthRpcLogFilter as Filter, FilterChanges, Log,
};
use cfx_rpc_utils::error::jsonrpsee_error_helpers::{
    invalid_request_msg, jsonrpc_error_to_error_object_owned,
};
use cfx_types::{H128 as FilterId, H256};
use cfx_util_macros::bail;
use cfxcore::{channel::Channel, SharedConsensusGraph, SharedTransactionPool};
use jsonrpsee::core::RpcResult;
use primitives::filter::LogFilter;
use std::{collections::VecDeque, sync::Arc};
use tokio::runtime::Runtime;

type PendingTransactionFilterKind = ();

pub struct EthFilterApi {
    inner: EthFilterHelper,
}

impl EthFilterApi {
    pub fn new(
        consensus: SharedConsensusGraph, tx_pool: SharedTransactionPool,
        epochs_ordered: Arc<Channel<(u64, Vec<H256>)>>, executor: Arc<Runtime>,
        poll_lifetime: u32, logs_filter_max_limit: Option<usize>,
    ) -> EthFilterApi {
        let eth_filter = EthFilterHelper::new(
            consensus,
            tx_pool,
            epochs_ordered,
            executor,
            poll_lifetime,
            logs_filter_max_limit,
        );
        EthFilterApi { inner: eth_filter }
    }
}

#[async_trait::async_trait]
impl EthFilterApiServer for EthFilterApi {
    async fn new_filter(&self, filter: Filter) -> RpcResult<FilterId> {
        let mut polls = self.inner.polls().lock();
        let epoch_number = self.inner.best_executed_epoch_number();

        if filter.to_block == Some(BlockNumber::Pending) {
            bail!(invalid_request_msg(
                "Filter logs from pending blocks is not supported"
            ))
        }

        let filter: LogFilter = self
            .inner
            .into_primitive_filter(filter)
            .map_err(|e| jsonrpc_error_to_error_object_owned(e.into()))?;

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

    async fn new_block_filter(&self) -> RpcResult<FilterId> {
        let mut polls = self.inner.polls().lock();
        // +1, since we don't want to include the current block
        let id = polls.create_poll(SyncPollFilter::new(PollFilter::Block {
            last_epoch_number: self.inner.best_executed_epoch_number(),
            recent_reported_epochs: VecDeque::with_capacity(
                MAX_BLOCK_HISTORY_SIZE,
            ),
        }));

        Ok(id.into())
    }

    async fn new_pending_transaction_filter(
        &self, kind: Option<PendingTransactionFilterKind>,
    ) -> RpcResult<FilterId> {
        let _ = kind;
        let mut polls = self.inner.polls().lock();
        let pending_transactions = self.inner.pending_transaction_hashes();
        let id = polls.create_poll(SyncPollFilter::new(
            PollFilter::PendingTransaction(pending_transactions),
        ));
        Ok(id.into())
    }

    async fn filter_changes(&self, id: FilterId) -> RpcResult<FilterChanges> {
        let filter = match self.inner.polls().lock().poll_mut(&id) {
            Some(filter) => filter.clone(),
            None => bail!(invalid_request_msg("Filter not found")),
        };

        filter.modify(|filter| match *filter {
            PollFilter::Block {
                ref mut last_epoch_number,
                ref mut recent_reported_epochs,
            } => {
                let (reorg_len, epochs) = self
                    .inner
                    .epochs_since_last_request(
                        *last_epoch_number,
                        recent_reported_epochs,
                    )
                    .map_err(|e| jsonrpc_error_to_error_object_owned(e))?;

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
                let current_hashes = self.inner.pending_transaction_hashes();

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
                let (reorg_len, epochs) = self
                    .inner
                    .epochs_since_last_request(
                        *last_epoch_number,
                        recent_reported_epochs,
                    )
                    .map_err(|e| jsonrpc_error_to_error_object_owned(e))?;

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
                    let log = match self.inner.logs_for_epoch(
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
                    self.inner.get_logs_filter_max_limit(),
                )))
            }
        })
    }

    async fn filter_logs(&self, id: FilterId) -> RpcResult<Vec<Log>> {
        let (filter, _) = {
            let mut polls = self.inner.polls().lock();

            match polls.poll(&id).and_then(|f| {
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
                None => bail!(invalid_request_msg("Filter not found")),
            }
        };

        // retrieve logs
        Ok(limit_logs(
            self.inner
                .logs(filter)
                .map_err(|e| jsonrpc_error_to_error_object_owned(e))?,
            self.inner.get_logs_filter_max_limit(),
        ))
    }

    async fn uninstall_filter(&self, id: FilterId) -> RpcResult<bool> {
        Ok(self.inner.polls().lock().remove_poll(&id))
    }
}
