// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    consensus_types::{block::Block, executed_block::ExecutedBlock},
    counters,
    state_replication::StateComputer,
};
use anyhow::{ensure, Result};
use cfx_types::H256;
use libra_logger::prelude::*;
use libra_types::{
    account_config,
    crypto_proxies::{
        LedgerInfoWithSignatures, ValidatorChangeProof, ValidatorSet,
    },
    transaction::{SignedTransaction, Transaction},
};
//use state_synchronizer::StateSyncClient;
use super::super::executor::{Executor, ProcessedVMOutput};
use crate::alliance_tree_graph::consensus::TreeGraphConsensus;
use libra_types::event::EventKey;
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PivotBlockDecision {
    height: u64,
    block_hash: H256,
    parent_hash: H256,
}

impl PivotBlockDecision {
    pub fn pivot_select_event_key() -> EventKey {
        EventKey::new_from_address(
            &account_config::pivot_chain_select_address(),
            2,
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        lcs::from_bytes(bytes).map_err(Into::into)
    }
}

/// Basic communication with the Execution module;
/// implements StateComputer traits.
pub struct ExecutionProxy {
    executor: Arc<Executor>,
    //synchronizer: Arc<StateSyncClient>,
    tg_consensus: Arc<TreeGraphConsensus>,
}

impl ExecutionProxy {
    pub fn new(
        executor: Arc<Executor>, /* , synchronizer: Arc<StateSyncClient> */
        tg_consensus: Arc<TreeGraphConsensus>,
    ) -> Self
    {
        Self {
            executor,
            //synchronizer,
            tg_consensus,
        }
    }

    fn transactions_from_block(
        block: &Block<Vec<SignedTransaction>>,
    ) -> Vec<Transaction> {
        let mut transactions = vec![Transaction::BlockMetadata(block.into())];
        transactions.extend(
            block
                .payload()
                .unwrap_or(&vec![])
                .iter()
                .map(|txn| Transaction::UserTransaction(txn.clone())),
        );
        transactions
    }
}

#[async_trait::async_trait]
impl StateComputer for ExecutionProxy {
    type Payload = Vec<SignedTransaction>;

    fn compute(
        &self,
        // The block to be executed.
        block: &Block<Self::Payload>,
    ) -> Result<ProcessedVMOutput>
    {
        // TODO: figure out error handling for the prologue txn
        self.executor
            .execute_block(
                Self::transactions_from_block(block),
                //parent_executed_trees,
                //committed_trees,
                block.parent_id(),
                block.id(),
            )
            .and_then(|output| {
                // Check whether pivot block selection is valid.
                if let Some(p) = output.pivot_block.as_ref() {
                    let mut inner = self.tg_consensus.inner.write();
                    ensure!(
                        inner.on_new_candidate_pivot(
                            &p.block_hash,
                            &p.parent_hash,
                            p.height
                        ),
                        "Invalid pivot block proposal!"
                    );
                }
                // FIXME: Check whether new membership is valid.
                Ok(output)
            })
    }

    /// Send a successful commit. A future is fulfilled when the state is
    /// finalized.
    async fn commit(
        &self, blocks: Vec<&ExecutedBlock<Self::Payload>>,
        finality_proof: LedgerInfoWithSignatures,
    ) -> Result<()>
    {
        let version = finality_proof.ledger_info().version();
        counters::LAST_COMMITTED_VERSION.set(version as i64);

        let pre_commit_instant = Instant::now();

        let committable_blocks: Vec<(
            Vec<Transaction>,
            Arc<ProcessedVMOutput>,
        )> = blocks
            .into_iter()
            .map(|executed_block| {
                (
                    Self::transactions_from_block(executed_block.block()),
                    Arc::clone(executed_block.output()),
                )
            })
            .collect();

        let mut committed_blocks = Vec::new();
        for (_, output) in &committable_blocks {
            if let Some(p) = output.pivot_block.as_ref() {
                committed_blocks.push(p.block_hash);
            }
        }
        self.tg_consensus.inner.write().commit(&committed_blocks);

        self.executor
            .commit_blocks(committable_blocks, finality_proof)?;
        counters::BLOCK_COMMIT_DURATION_S
            .observe_duration(pre_commit_instant.elapsed());
        /*
        if let Err(e) = self.synchronizer.commit().await {
            error!("failed to notify state synchronizer: {:?}", e);
        }
        */
        Ok(())
    }

    /// Synchronize to a commit that not present locally.
    async fn sync_to(&self, target: LedgerInfoWithSignatures) -> Result<()> {
        /*
        counters::STATE_SYNC_COUNT.inc();
        self.synchronizer.sync_to(target).await
        */
        Ok(())
    }

    async fn get_epoch_proof(
        &self, start_epoch: u64, end_epoch: u64,
    ) -> Result<ValidatorChangeProof> {
        /*
        self.synchronizer
            .get_epoch_proof(start_epoch, end_epoch)
            .await
            */
        Ok(ValidatorChangeProof::new(Vec::new(), false))
    }
}
