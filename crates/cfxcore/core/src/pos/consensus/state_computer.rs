// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{error::StateSyncError, state_replication::StateComputer};
use crate::pos::mempool::{CommitNotification, CommittedTransaction};
use anyhow::Result;
use consensus_types::block::Block;
use diem_crypto::HashValue;
use diem_logger::prelude::*;
use diem_types::{
    ledger_info::LedgerInfoWithSignatures, transaction::Transaction,
};
use executor_types::{
    BlockExecutor, Error as ExecutionError, StateComputeResult,
};
use fail::fail_point;
use futures::channel::{mpsc, oneshot};
use parking_lot::Mutex;
use std::boxed::Box;

/// Basic communication with the Execution module;
/// implements StateComputer traits.
pub struct ExecutionProxy {
    executor: Mutex<Box<dyn BlockExecutor>>,
    mempool_commit_sender: mpsc::Sender<CommitNotification>,
    mempool_commit_timeout_ms: u64,
}

impl ExecutionProxy {
    pub fn new(
        executor: Box<dyn BlockExecutor>,
        mempool_commit_sender: mpsc::Sender<CommitNotification>,
        mempool_commit_timeout_ms: u64,
    ) -> Self {
        Self {
            executor: Mutex::new(executor),
            mempool_commit_sender,
            mempool_commit_timeout_ms,
        }
    }

    /// Notify mempool of committed transactions so it can prune them.
    async fn notify_mempool(&self, committed_txns: Vec<Transaction>) {
        let user_txns: Vec<CommittedTransaction> = committed_txns
            .iter()
            .filter_map(|txn| match txn {
                Transaction::UserTransaction(signed_txn) => {
                    Some(CommittedTransaction {
                        sender: signed_txn.sender(),
                        hash: signed_txn.hash(),
                    })
                }
                _ => None,
            })
            .collect();

        if user_txns.is_empty() {
            return;
        }

        let (callback, cb_receiver) = oneshot::channel();
        let notification = CommitNotification {
            transactions: user_txns,
            callback,
        };

        if let Err(e) =
            self.mempool_commit_sender.clone().try_send(notification)
        {
            diem_error!(
                error = ?e,
                "Failed to send commit notification to mempool"
            );
            return;
        }

        match tokio::time::timeout(
            std::time::Duration::from_millis(self.mempool_commit_timeout_ms),
            cb_receiver,
        )
        .await
        {
            Ok(Ok(Ok(response))) => {
                if !response.success {
                    diem_error!(
                        "Mempool commit failed: {:?}",
                        response.error_message
                    );
                }
            }
            Ok(Ok(Err(e))) => {
                diem_error!(
                    error = ?e,
                    "Mempool commit returned error"
                );
            }
            Ok(Err(_)) => {
                diem_error!("Mempool commit callback dropped");
            }
            Err(_) => {
                diem_error!(
                    "Mempool commit notification timed out after {} ms",
                    self.mempool_commit_timeout_ms
                );
            }
        }
    }
}

#[async_trait::async_trait]
impl StateComputer for ExecutionProxy {
    fn compute(
        &self,
        // The block to be executed.
        block: &Block,
        // The parent block id.
        parent_block_id: HashValue,
        catch_up_mode: bool,
    ) -> Result<StateComputeResult, ExecutionError> {
        fail_point!("consensus::compute", |_| {
            Err(ExecutionError::InternalError {
                error: "Injected error in compute".into(),
            })
        });
        diem_debug!(
            block_id = block.id(),
            parent_id = block.parent_id(),
            "Executing block",
        );

        self.executor.lock().execute_block(
            id_and_transactions_from_block(block),
            parent_block_id,
            catch_up_mode,
        )
    }

    async fn commit(
        &self, block_ids: Vec<HashValue>,
        finality_proof: LedgerInfoWithSignatures,
    ) -> Result<(), ExecutionError> {
        let committed_txns = self
            .executor
            .lock()
            .commit_blocks(block_ids, finality_proof)?;
        self.notify_mempool(committed_txns).await;
        Ok(())
    }

    /// No-op: state sync via chunk execution is not supported in
    /// Conflux PoS.
    async fn sync_to(
        &self, _target: LedgerInfoWithSignatures,
    ) -> Result<(), StateSyncError> {
        fail_point!("consensus::sync_to", |_| {
            Err(anyhow::anyhow!("Injected error in sync_to").into())
        });
        Ok(())
    }
}

fn id_and_transactions_from_block(
    block: &Block,
) -> (HashValue, Vec<Transaction>) {
    let id = block.id();
    let mut transactions = vec![Transaction::BlockMetadata(block.into())];
    transactions.extend(
        block
            .payload()
            .unwrap_or(&vec![])
            .iter()
            .map(|txn| Transaction::UserTransaction(txn.clone())),
    );
    (id, transactions)
}
