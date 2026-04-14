// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::pos::state_sync::client::StateSyncClient;

use super::{error::StateSyncError, state_replication::StateComputer};
use anyhow::Result;
use consensus_types::block::Block;
use diem_crypto::HashValue;
use diem_infallible::Mutex;
use diem_logger::prelude::*;
use diem_metrics::monitor;
use diem_types::{
    ledger_info::LedgerInfoWithSignatures, transaction::Transaction,
};
use executor_types::{
    BlockExecutor, Error as ExecutionError, StateComputeResult,
};
use fail::fail_point;
use std::boxed::Box;

/// Basic communication with the Execution module;
/// implements StateComputer traits.
pub struct ExecutionProxy {
    //execution_correctness_client:
    //    Mutex<Box<dyn ExecutionCorrectness + Send + Sync>>,
    synchronizer: StateSyncClient,
    // TODO(lpl): Use Mutex or Arc?
    executor: Mutex<Box<dyn BlockExecutor>>,
}

impl ExecutionProxy {
    pub fn new(
        executor: Box<dyn BlockExecutor>, synchronizer: StateSyncClient,
    ) -> Self {
        Self {
            /*execution_correctness_client: Mutex::new(
                execution_correctness_client,
            ),*/
            synchronizer,
            executor: Mutex::new(executor),
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

        // TODO: figure out error handling for the prologue txn
        monitor!(
            "execute_block",
            self.executor.lock().execute_block(
                id_and_transactions_from_block(block),
                parent_block_id,
                catch_up_mode
            )
        )
    }

    /// Send a successful commit. A future is fulfilled when the state is
    /// finalized.
    async fn commit(
        &self, block_ids: Vec<HashValue>,
        finality_proof: LedgerInfoWithSignatures,
    ) -> Result<(), ExecutionError> {
        let (committed_txns, reconfig_events) = monitor!(
            "commit_block",
            self.executor
                .lock()
                .commit_blocks(block_ids, finality_proof)?
        );
        if let Err(e) = monitor!(
            "notify_state_sync",
            self.synchronizer
                .commit(committed_txns, reconfig_events)
                .await
        ) {
            diem_error!(error = ?e, "Failed to notify state synchronizer");
        }
        Ok(())
    }

    /// Synchronize to a commit that not present locally.
    /// State sync via chunk execution has been removed; this is now a no-op.
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
    // TODO(lpl): Do we need BlockMetadata?
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
