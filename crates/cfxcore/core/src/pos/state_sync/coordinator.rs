// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::pos::{
    mempool::{CommitNotification, CommitResponse, CommittedTransaction},
    state_sync::{
        client::{CoordinatorMessage, SyncRequest},
        executor_proxy::{ExecutorProxyTrait, SyncState},
        logging::{LogEntry, LogEvent, LogSchema},
    },
};
use diem_config::config::{NodeConfig, RoleType, StateSyncConfig};
use diem_logger::prelude::*;
use diem_types::{contract_event::ContractEvent, transaction::Transaction};
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use std::time::{Duration, SystemTime};
use tokio::time::{interval, timeout};
use tokio_stream::wrappers::IntervalStream;

/// Coordination of the state sync process is driven by StateSyncCoordinator.
/// The `start()` function runs an infinite event loop and triggers actions
/// based on external and internal (local) requests.
pub(crate) struct StateSyncCoordinator<T> {
    client_events: mpsc::UnboundedReceiver<CoordinatorMessage>,
    state_sync_to_mempool_sender: mpsc::Sender<CommitNotification>,
    local_state: SyncState,
    config: StateSyncConfig,
    role: RoleType,
    sync_request: Option<SyncRequest>,
    executor_proxy: T,
}

impl<T: ExecutorProxyTrait> StateSyncCoordinator<T> {
    pub fn new(
        client_events: mpsc::UnboundedReceiver<CoordinatorMessage>,
        state_sync_to_mempool_sender: mpsc::Sender<CommitNotification>,
        node_config: &NodeConfig, executor_proxy: T, initial_state: SyncState,
    ) -> Result<Self, anyhow::Error> {
        let role = node_config.base.role;

        Ok(Self {
            client_events,
            state_sync_to_mempool_sender,
            local_state: initial_state,
            config: node_config.state_sync.clone(),
            role,
            sync_request: None,
            executor_proxy,
        })
    }

    /// main routine. starts sync coordinator that listens for CoordinatorMsg
    pub async fn start(mut self) {
        diem_info!(LogSchema::new(LogEntry::RuntimeStart));
        let mut interval = IntervalStream::new(interval(
            Duration::from_millis(self.config.tick_interval_ms),
        ))
        .fuse();

        loop {
            ::futures::select! {
                msg = self.client_events.select_next_some() => {
                    match msg {
                        CoordinatorMessage::SyncRequest(_request) => {
                            // Sync requests are no longer handled via
                            // the network state sync layer.
                        }
                        CoordinatorMessage::CommitNotification(notification) => {
                            if let Err(e) = self.process_commit_notification(
                                notification.committed_transactions,
                                Some(notification.callback),
                                notification.reconfiguration_events,
                            ).await {
                                diem_error!(
                                    LogSchema::event_log(
                                        LogEntry::ConsensusCommit,
                                        LogEvent::PostCommitFail
                                    ),
                                    "Failed to process commit notification: {:?}",
                                    e
                                );
                            }
                        }
                        CoordinatorMessage::WaitForInitialization(cb_sender) => {
                            // Always initialized (waypoint removed).
                            if let Err(e) = Self::send_initialization_callback(cb_sender) {
                                diem_error!(
                                    "Failed to send initialization callback: {:?}",
                                    e
                                );
                            }
                        }
                    };
                },
                _ = interval.select_next_some() => {
                    if let Err(e) = self.check_progress() {
                        diem_error!(
                            LogSchema::event_log(
                                LogEntry::ProgressCheck,
                                LogEvent::Fail
                            ),
                            "Progress check failed: {:?}",
                            e
                        );
                    }
                }
            }
        }
    }

    fn sync_state_with_local_storage(&mut self) -> Result<(), anyhow::Error> {
        let new_state = self.executor_proxy.get_local_storage_state()?;
        if new_state.trusted_epoch() > self.local_state.trusted_epoch() {
            diem_info!(LogSchema::new(LogEntry::EpochChange)
                .old_epoch(self.local_state.trusted_epoch())
                .new_epoch(new_state.trusted_epoch()));
        }
        self.local_state = new_state;
        Ok(())
    }

    /// This method updates state sync to process new transactions that have
    /// been committed to storage (e.g., through consensus).
    async fn process_commit_notification(
        &mut self, committed_transactions: Vec<Transaction>,
        commit_callback: Option<
            oneshot::Sender<Result<CommitResponse, anyhow::Error>>,
        >,
        reconfiguration_events: Vec<ContractEvent>,
    ) -> Result<(), anyhow::Error> {
        diem_debug!(
            "process_commit_notification: {} events",
            reconfiguration_events.len()
        );
        self.sync_state_with_local_storage()?;

        // Notify mempool of commit
        let commit_response = match self
            .notify_mempool_of_committed_transactions(committed_transactions)
            .await
        {
            Ok(()) => CommitResponse::success(),
            Err(error) => {
                diem_error!(
                    LogSchema::new(LogEntry::CommitFlow),
                    "Failed to notify mempool: {:?}",
                    error
                );
                CommitResponse::error(error.to_string())
            }
        };

        // Notify consensus of the commit response
        if let Err(error) = self.notify_consensus_of_commit_response(
            commit_response,
            commit_callback,
        ) {
            diem_error!(
                LogSchema::new(LogEntry::CommitFlow),
                "Failed to notify consensus: {:?}",
                error
            );
        }

        if let Some(req) = self.sync_request.as_mut() {
            req.last_commit_timestamp = SystemTime::now();
        }

        // Check if we hit the sync request target
        let synced_version = self.local_state.synced_version();
        self.check_sync_request_completed(synced_version)?;

        // Publish the on chain config updates
        if let Err(error) = self
            .executor_proxy
            .publish_on_chain_config_updates(reconfiguration_events)
        {
            diem_error!(
                LogSchema::event_log(LogEntry::Reconfig, LogEvent::Fail),
                "Failed to publish reconfig updates: {:?}",
                error
            );
        }

        Ok(())
    }

    fn check_sync_request_completed(
        &mut self, synced_version: u64,
    ) -> Result<(), anyhow::Error> {
        if let Some(sync_request) = self.sync_request.as_ref() {
            let sync_target_version =
                sync_request.target.ledger_info().version();
            if synced_version > sync_target_version {
                return Err(anyhow::anyhow!(
                    "Synced beyond the target version. Synced version: {}, target version: {}",
                    synced_version,
                    sync_target_version,
                ));
            }
            if synced_version == sync_target_version {
                let committed_version = self.local_state.committed_version();
                let local_epoch = self.local_state.trusted_epoch();
                diem_info!(LogSchema::event_log(
                    LogEntry::SyncRequest,
                    LogEvent::Complete
                )
                .local_li_version(committed_version)
                .local_synced_version(synced_version)
                .local_epoch(local_epoch));
                if let Some(sync_request) = self.sync_request.take() {
                    Self::send_sync_req_callback(sync_request, Ok(()))?;
                }
            }
        }

        Ok(())
    }

    fn notify_consensus_of_commit_response(
        &self, commit_response: CommitResponse,
        callback: Option<
            oneshot::Sender<Result<CommitResponse, anyhow::Error>>,
        >,
    ) -> Result<(), anyhow::Error> {
        if let Some(callback) = callback {
            if let Err(error) = callback.send(Ok(commit_response)) {
                return Err(anyhow::anyhow!(
                    "Failed to send commit ACK to consensus!: {:?}",
                    error
                ));
            }
        }
        Ok(())
    }

    async fn notify_mempool_of_committed_transactions(
        &mut self, committed_transactions: Vec<Transaction>,
    ) -> Result<(), anyhow::Error> {
        let user_transactions = committed_transactions
            .iter()
            .filter_map(|transaction| match transaction {
                Transaction::UserTransaction(signed_txn) => {
                    Some(CommittedTransaction {
                        sender: signed_txn.sender(),
                        hash: signed_txn.hash(),
                    })
                }
                _ => None,
            })
            .collect();

        let (callback_sender, callback_receiver) = oneshot::channel();
        let req = CommitNotification {
            transactions: user_transactions,
            block_timestamp_usecs: self
                .local_state
                .committed_ledger_info()
                .ledger_info()
                .timestamp_usecs(),
            callback: callback_sender,
        };

        if let Err(error) = self.state_sync_to_mempool_sender.try_send(req) {
            Err(anyhow::anyhow!(
                "Failed to notify mempool of committed transactions! Error: {:?}",
                error
            ))
        } else if let Err(error) = timeout(
            Duration::from_millis(self.config.mempool_commit_timeout_ms),
            callback_receiver,
        )
        .await
        {
            Err(anyhow::anyhow!(
                "Did not receive ACK for commit notification from mempool! Error: {:?}",
                error
            ))
        } else {
            Ok(())
        }
    }

    fn check_progress(&mut self) -> Result<(), anyhow::Error> {
        if self.role == RoleType::Validator && self.sync_request.is_none() {
            return Ok(());
        }

        // Check if the sync request has timed out
        if let Some(sync_request) = self.sync_request.as_ref() {
            let timeout_between_commits =
                Duration::from_millis(self.config.sync_request_timeout_ms);
            let commit_deadline = sync_request
                .last_commit_timestamp
                .checked_add(timeout_between_commits)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "The commit deadline timestamp has overflown!"
                    )
                })?;

            if SystemTime::now().duration_since(commit_deadline).is_ok() {
                diem_warn!(LogSchema::event_log(
                    LogEntry::SyncRequest,
                    LogEvent::Timeout
                ));

                if let Some(sync_request) = self.sync_request.take() {
                    if let Err(e) = Self::send_sync_req_callback(
                        sync_request,
                        Err(anyhow::anyhow!("Sync request timed out!")),
                    ) {
                        diem_error!(
                            LogSchema::event_log(
                                LogEntry::SyncRequest,
                                LogEvent::CallbackFail
                            ),
                            "Failed to send sync request callback: {:?}",
                            e
                        );
                    }
                }
            }
        }

        Ok(())
    }

    fn send_sync_req_callback(
        sync_req: SyncRequest, msg: Result<(), anyhow::Error>,
    ) -> Result<(), anyhow::Error> {
        sync_req.callback.send(msg).map_err(|failed_msg| {
            anyhow::anyhow!(
                "Consensus sync request callback error - failed to send: {:?}",
                failed_msg
            )
        })
    }

    fn send_initialization_callback(
        callback: oneshot::Sender<Result<(), anyhow::Error>>,
    ) -> Result<(), anyhow::Error> {
        callback.send(Ok(())).map_err(|error| {
            anyhow::anyhow!(
                "Initialization callback error - failed to send: {:?}",
                error
            )
        })
    }
}
