// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    consensus_types::{block::Block, executed_block::ExecutedBlock},
    counters,
    state_replication::StateComputer,
};
use anyhow::{ensure, Result};
use cfx_types::H256;
use libra_types::{
    crypto_proxies::{LedgerInfoWithSignatures, ValidatorChangeProof},
    transaction::{SignedTransaction, Transaction},
};
//use state_synchronizer::StateSyncClient;
use super::super::executor::{Executor, ProcessedVMOutput};
use crate::{
    alliance_tree_graph::{
        consensus::SetPivotChainCallbackType,
        hsb_sync_protocol::sync_protocol::{PeerState, Peers},
    },
    sync::SharedSynchronizationService,
};
use futures::{channel::oneshot, executor::block_on};
use libra_types::block_info::PivotBlockDecision;
use std::{sync::Arc, time::Instant};

/// Basic communication with the Execution module;
/// implements StateComputer traits.
pub struct ExecutionProxy {
    executor: Arc<Executor>,
    //synchronizer: Arc<StateSyncClient>,
    tg_sync: SharedSynchronizationService,
    peers: Arc<Peers<PeerState, H256>>,
}

impl ExecutionProxy {
    pub fn new(
        executor: Arc<Executor>, /* , synchronizer: Arc<StateSyncClient> */
        tg_sync: SharedSynchronizationService,
    ) -> Self
    {
        Self {
            executor,
            //synchronizer,
            tg_sync,
            peers: Arc::new(Peers::default()),
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
        // The last pivot selection after executing the parent block.
        last_pivot: Option<PivotBlockDecision>,
        ignore_db: bool,
        verify_admin_transaction: bool,
    ) -> Result<ProcessedVMOutput>
    {
        // TODO: figure out error handling for the prologue txn
        let output = self.executor.execute_block(
            Self::transactions_from_block(block),
            last_pivot,
            block.parent_id(),
            block.id(),
            block.epoch(),
            verify_admin_transaction,
        )?;

        // Check whether pivot block selection is valid.
        if output.pivot_updated {
            ensure!(
                output.pivot_block.is_some(),
                "There must be pivot selection if updated."
            );
            let p = output.pivot_block.as_ref().unwrap();
            let peer_hash =
                H256::from_slice(block.author().unwrap().to_vec().as_slice());
            let peer_id = self
                .peers
                .get(&peer_hash)
                .map(|peer_state| peer_state.read().get_id());
            let (callback, cb_receiver) = oneshot::channel();
            debug!("tg_sync.on_new_candidate_pivot");
            self.tg_sync
                .on_new_candidate_pivot(p, peer_id, callback, ignore_db);
            let valid_pivot_decision =
                block_on(async move { cb_receiver.await? })?;
            debug!("on_new_candidate_pivot returned in time");
            ensure!(valid_pivot_decision, "Invalid pivot block proposal!");
        }

        Ok(output)
    }

    fn recover_tree_graph_from_pivot_block(
        &self, block_hash: &H256, callback: SetPivotChainCallbackType,
    ) {
        debug!("recover_tree_graph_from_pivot_block: {:?}", block_hash);
        self.tg_sync.set_pivot_chain(block_hash, callback);
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
            if output.pivot_updated {
                let p = output.pivot_block.as_ref().unwrap();
                committed_blocks.push(p.block_hash);
            }
        }

        self.tg_sync.on_commit_blocks(&committed_blocks);

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
    async fn sync_to(&self, _target: LedgerInfoWithSignatures) -> Result<()> {
        /*
        counters::STATE_SYNC_COUNT.inc();
        self.synchronizer.sync_to(target).await
        */
        Ok(())
    }

    async fn get_epoch_proof(
        &self, start_epoch: u64, end_epoch: u64,
    ) -> Result<ValidatorChangeProof> {
        let (ledger_infos, more) = self
            .executor
            .get_epoch_change_ledger_infos(start_epoch, end_epoch)?;
        Ok(ValidatorChangeProof::new(ledger_infos, more))
        /*
        self.synchronizer
            .get_epoch_proof(start_epoch, end_epoch)
            .await
            */
    }

    fn get_peers(&self) -> Arc<Peers<PeerState, H256>> { self.peers.clone() }

    fn get_executor(&self) -> Arc<Executor> { self.executor.clone() }
}
