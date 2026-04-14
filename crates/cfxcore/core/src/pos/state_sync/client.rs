// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::pos::mempool::CommitResponse;
use diem_logger::prelude::*;
use diem_types::{
    contract_event::ContractEvent, ledger_info::LedgerInfoWithSignatures,
    transaction::Transaction,
};
use futures::{
    channel::{mpsc, oneshot},
    future::Future,
    SinkExt,
};
use std::time::{Duration, SystemTime};
use tokio::time::timeout;

/// A sync request for a specified target ledger info.
pub struct SyncRequest {
    pub callback: oneshot::Sender<Result<(), anyhow::Error>>,
    pub last_commit_timestamp: SystemTime,
    pub target: LedgerInfoWithSignatures,
}

/// A commit notification to notify state sync of new commits.
pub struct CommitNotification {
    pub callback: oneshot::Sender<Result<CommitResponse, anyhow::Error>>,
    pub committed_transactions: Vec<Transaction>,
    pub reconfiguration_events: Vec<ContractEvent>,
}

/// Messages used by the StateSyncClient for communication with the
/// StateSyncCoordinator.
pub enum CoordinatorMessage {
    SyncRequest(Box<SyncRequest>),
    CommitNotification(Box<CommitNotification>),
    WaitForInitialization(oneshot::Sender<Result<(), anyhow::Error>>),
}

/// A client used for communicating with a StateSyncCoordinator.
pub struct StateSyncClient {
    coordinator_sender: mpsc::UnboundedSender<CoordinatorMessage>,

    /// Timeout for the StateSyncClient to receive an ack when executing
    /// commit().
    commit_timeout_ms: u64,
}

impl StateSyncClient {
    pub fn new(
        coordinator_sender: mpsc::UnboundedSender<CoordinatorMessage>,
        commit_timeout_ms: u64,
    ) -> Self {
        Self {
            coordinator_sender,
            commit_timeout_ms,
        }
    }

    /// Notifies state sync about newly committed transactions.
    pub fn commit(
        &self, committed_txns: Vec<Transaction>,
        reconfig_events: Vec<ContractEvent>,
    ) -> impl Future<Output = Result<(), anyhow::Error>> {
        let mut sender = self.coordinator_sender.clone();
        let (cb_sender, cb_receiver) = oneshot::channel();

        let commit_timeout_ms = self.commit_timeout_ms;
        let notification = CommitNotification {
            callback: cb_sender,
            committed_transactions: committed_txns,
            reconfiguration_events: reconfig_events,
        };
        diem_debug!(
            "state_sync::commit: {} reconfig events",
            notification.reconfiguration_events.len()
        );

        async move {
            sender
                .send(CoordinatorMessage::CommitNotification(Box::new(
                    notification,
                )))
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to send commit notification: {}", e)
                })?;

            match timeout(
                Duration::from_millis(commit_timeout_ms),
                cb_receiver,
            )
            .await
            {
                Err(_) => Err(anyhow::anyhow!(
                    "State sync client timeout: failed to receive commit() ack in time!"
                )),
                Ok(response) => {
                    let response = response??;
                    if response.success {
                        Ok(())
                    } else {
                        Err(anyhow::anyhow!(
                            "State sync client failed: commit() returned an error: {:?}",
                            response.error_message
                        ))
                    }
                }
            }
        }
    }

    /// Waits until state sync is caught up with the waypoint specified in the
    /// local config.
    pub fn wait_until_initialized(
        &self,
    ) -> impl Future<Output = Result<(), anyhow::Error>> {
        let mut sender = self.coordinator_sender.clone();
        let (cb_sender, cb_receiver) = oneshot::channel();

        async move {
            sender
                .send(CoordinatorMessage::WaitForInitialization(cb_sender))
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to send wait for initialization: {}",
                        e
                    )
                })?;
            cb_receiver.await?
        }
    }
}
