// Copyright 2022 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::collections::VecDeque;

use cfx_types::H128;
use cfx_util_macros::bail;
use log::{debug, info};
use primitives::filter::LogFilter;

use crate::rpc::{
    helpers::{limit_logs, PollFilter, SyncPollFilter, MAX_BLOCK_HISTORY_SIZE},
    traits::eth_space::eth_filter::EthFilter,
    types::eth::{BlockNumber, EthRpcLogFilter, FilterChanges, Log},
};
pub use cfx_rpc::helpers::eth_filter::EthFilterHelper;
use cfx_rpc::traits::Filterable;
use jsonrpc_core::{Error as RpcError, ErrorCode, Result as RpcResult};

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
