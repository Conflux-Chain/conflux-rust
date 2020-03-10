// Copyright (c) The Libra Core Contributors
// SPDX-License-Identifier: Apache-2.0

use super::{
    super::executor::ProcessedVMOutput,
    consensus_types::{block::Block, executed_block::ExecutedBlock},
};
use crate::alliance_tree_graph::hsb_sync_protocol::sync_protocol::{
    PeerState, Peers,
};
use anyhow::Result;
//use executor::{ExecutedTrees, ProcessedVMOutput, StateComputeResult};
use crate::{
    alliance_tree_graph::{
        bft::executor::Executor, consensus::SetPivotChainCallbackType,
    },
    sync::{ProtocolConfiguration, SharedSynchronizationService},
};
use cfx_types::H256;
use libra_types::{
    block_info::PivotBlockDecision,
    crypto_proxies::{LedgerInfoWithSignatures, ValidatorChangeProof},
    transaction::SignedTransaction,
};
use network::NetworkService;
use parking_lot::RwLock;
use std::sync::Arc;

pub trait TxnTransformer: Send + Sync + Clone + 'static {
    type Payload;

    fn convert(&self, tx: SignedTransaction) -> Self::Payload;
}

#[derive(Default, Clone)]
pub struct TxnTransformerProxy {}

impl TxnTransformer for TxnTransformerProxy {
    type Payload = Vec<SignedTransaction>;

    fn convert(&self, tx: SignedTransaction) -> Self::Payload { vec![tx] }
}

/// Retrieves and updates the status of transactions on demand (e.g., via
/// talking with Mempool)
#[async_trait::async_trait]
pub trait TxnManager: Send + Sync + Clone + 'static {
    type Payload;

    /// Brings new transactions to be applied.
    /// The `exclude_txns` list includes the transactions that are already
    /// pending in the branch of blocks consensus is trying to extend.
    async fn pull_txns(
        &mut self, max_size: u64, exclude_txns: Vec<&Self::Payload>,
    ) -> Result<Self::Payload>;

    /// Notifies TxnManager about the payload of the committed block including
    /// the state compute result, which includes the specifics of what
    /// transactions succeeded and failed.
    async fn commit_txns(
        &mut self,
        txns: &Self::Payload,
        //compute_result: &StateComputeResult,
        // Monotonic timestamp_usecs of committed blocks is used to GC expired
        // transactions.
        timestamp_usecs: u64,
    ) -> Result<()>;
}

/// While Consensus is managing proposed blocks, `StateComputer` is managing the
/// results of the (speculative) execution of their payload.
/// StateComputer is using proposed block ids for identifying the transactions.
#[async_trait::async_trait]
pub trait StateComputer: Send + Sync {
    type Payload;

    /// How to execute a sequence of transactions and obtain the next state.
    /// While some of the transactions succeed, some of them can fail.
    /// In case all the transactions are failed, new_state_id is equal to the
    /// previous state id.
    fn compute(
        &self,
        // The block that will be computed.
        block: &Block<Self::Payload>,
        // The last pivot selection after executing the parent block.
        last_pivot: Option<PivotBlockDecision>,
        // Whether when requesting the block from peer if missed in
        // consensus graph it can ignore checking on local disk first.
        // During the recovery phase, it is possible to execute a block
        // (in the subtree of root) that is proposed by the node itself.
        // And any other peer does not see this block, and it is only
        // stored in the local storage of this node. In this case, it
        // has to check the local storage first.
        ignore_db: bool,
        verify_admin_transaction: bool,
    ) -> Result<ProcessedVMOutput>;

    /// Send a successful commit. A future is fulfilled when the state is
    /// finalized.
    async fn commit(
        &self,
        blocks: Vec<&ExecutedBlock<Self::Payload>>,
        finality_proof: LedgerInfoWithSignatures,
        //synced_trees: &ExecutedTrees,
    ) -> Result<()>;

    fn recover_tree_graph_from_pivot_block(
        &self, block_hash: &H256, callback: SetPivotChainCallbackType,
    );

    /// Best effort state synchronization to the given target LedgerInfo.
    /// In case of success (`Result::Ok`) the LI of storage is at the given
    /// target. In case of failure (`Result::Error`) the LI of storage
    /// remains unchanged, and the validator can assume there were no
    /// modifications to the storage made.
    async fn sync_to(&self, target: LedgerInfoWithSignatures) -> Result<()>;

    /// Generate the epoch change proof from start_epoch to the latest epoch.
    async fn get_epoch_proof(
        &self, start_epoch: u64, end_epoch: u64,
    ) -> Result<ValidatorChangeProof>;

    fn get_peers(&self) -> Arc<Peers<PeerState, H256>>;
    fn get_executor(&self) -> Arc<Executor>;
}

pub trait StateMachineReplication {
    type Payload;
    /// The function is synchronous: it returns when the state is initialized /
    /// recovered from persisted storage and all the threads have been
    /// started.
    fn start<TT: TxnTransformer<Payload = Self::Payload>>(
        &mut self, txn_transformer: TT,
        state_computer: Arc<dyn StateComputer<Payload = Self::Payload>>,
        network: Arc<NetworkService>, own_node_hash: H256,
        protocol_config: ProtocolConfiguration,
        tg_sync: SharedSynchronizationService,
        admin_transaction: Arc<RwLock<Option<SignedTransaction>>>,
    ) -> Result<()>;

    /// Stop is synchronous: returns when all the threads are shutdown and the
    /// state is persisted.
    fn stop(&mut self);
}
