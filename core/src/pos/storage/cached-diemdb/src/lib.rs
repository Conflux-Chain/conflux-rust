// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod logging;
mod speculation_cache;

use anyhow::{anyhow, bail, ensure, format_err, Result};
use diem_crypto::HashValue;
use diem_infallible::Mutex;
use diem_types::{
    account_address::{AccountAddress, HashAccountAddress},
    account_state::AccountState,
    account_state_blob::AccountStateBlob,
    block_info::PivotBlockDecision,
    contract_event::ContractEvent,
    epoch_state::EpochState,
    ledger_info::{LedgerInfo, LedgerInfoWithSignatures},
    on_chain_config,
    proof::accumulator::InMemoryAccumulator,
    term_state::{
        ElectionEvent, NodeID, PosState, RegisterEvent, RetireEvent,
        UpdateVotingPowerEvent,
    },
    transaction::{
        Transaction, TransactionInfo, TransactionListWithProof,
        TransactionOutput, TransactionPayload, TransactionStatus,
        TransactionToCommit, Version,
    },
    write_set::{WriteOp, WriteSet},
};

use executor_types::{
    BlockExecutor, ChunkExecutor, Error, ExecutedTrees, ProcessedVMOutput,
    ProofReader, StateComputeResult, TransactionReplayer,
};
use storage_interface::{
    state_view::VerifiedStateView, DbReaderWriter, TreeState,
};

use std::sync::Arc;

pub use speculation_cache::{SpeculationBlock, SpeculationCache};

pub struct CachedDiemDB {
    pub db: DbReaderWriter,
    pub cache: Mutex<SpeculationCache>,
}

impl CachedDiemDB {
    pub fn new(db: DbReaderWriter) -> Self {
        let startup_info = db
            .reader
            .get_startup_info()
            .expect("Shouldn't fail")
            .expect("DB not bootstrapped.");

        Self {
            db,
            cache: Mutex::new(SpeculationCache::new_with_startup_info(
                startup_info,
            )),
        }
    }

    pub fn reset_cache(&self) -> Result<(), Error> {
        let startup_info = self
            .db
            .reader
            .get_startup_info()?
            .ok_or_else(|| format_err!("DB not bootstrapped."))?;
        *(self.cache.lock()) =
            SpeculationCache::new_with_startup_info(startup_info);
        Ok(())
    }

    pub fn new_on_unbootstrapped_db(
        db: DbReaderWriter, tree_state: TreeState,
        initial_nodes: Vec<(NodeID, u64)>,
        genesis_pivot_decision: Option<PivotBlockDecision>,
    ) -> Self
    {
        // if initial_nodes.is_empty() {
        //     let access_paths = ON_CHAIN_CONFIG_REGISTRY
        //         .iter()
        //         .map(|config_id| config_id.access_path())
        //         .collect();
        //     let configs = db
        //         .reader
        //         .as_ref()
        //         .batch_fetch_resources_by_version(access_paths, 0)
        //         .unwrap();
        //     let validators: ValidatorSet = OnChainConfigPayload::new(
        //         0,
        //         Arc::new(
        //             ON_CHAIN_CONFIG_REGISTRY
        //                 .iter()
        //                 .cloned()
        //                 .zip_eq(configs)
        //                 .collect(),
        //         ),
        //     )
        //     .get()
        //     .unwrap();
        //     for node in validators {
        //         let node_id = NodeID::new(
        //             node.consensus_public_key().clone(),
        //             node.vrf_public_key().clone().unwrap(),
        //         );
        //         initial_nodes.push((node_id, node.consensus_voting_power()));
        //     }
        // }
        // TODO(lpl): The default value is only for pos-tool.
        let genesis_pivot_decision =
            genesis_pivot_decision.unwrap_or(PivotBlockDecision {
                block_hash: Default::default(),
                height: 0,
            });
        let pos_state =
            PosState::new(vec![], initial_nodes, genesis_pivot_decision, true);
        Self {
            db,
            cache: Mutex::new(SpeculationCache::new_for_db_bootstrapping(
                tree_state, pos_state,
            )),
        }
    }

    pub fn committed_block_id(&self) -> HashValue {
        return self.cache.lock().committed_block_id();
    }

    pub fn update_block_tree_root(
        &self, committed_trees: ExecutedTrees,
        committed_ledger_info: &LedgerInfo, committed_txns: Vec<Transaction>,
        reconfig_events: Vec<ContractEvent>,
    )
    {
        self.cache.lock().update_block_tree_root(
            committed_trees,
            committed_ledger_info,
            committed_txns,
            reconfig_events,
        )
    }

    pub fn update_synced_trees(&self, new_trees: ExecutedTrees) {
        self.cache.lock().update_synced_trees(new_trees)
    }

    pub fn add_block(
        &self, parent_block_id: HashValue,
        block: (
            HashValue,         /* block id */
            Vec<Transaction>,  /* block transactions */
            ProcessedVMOutput, /* block execution output */
        ),
    ) -> Result<(), Error>
    {
        self.cache.lock().add_block(parent_block_id, block)
    }

    pub fn reset(&self) { self.cache.lock().reset() }

    pub fn prune(
        &self, committed_ledger_info: &LedgerInfo,
        committed_txns: Vec<Transaction>, reconfig_events: Vec<ContractEvent>,
    ) -> Result<(), Error>
    {
        self.cache.lock().prune(
            committed_ledger_info,
            committed_txns,
            reconfig_events,
        )
    }

    pub fn get_block(
        &self, block_id: &HashValue,
    ) -> Result<Arc<Mutex<SpeculationBlock>>, Error> {
        self.cache.lock().get_block(block_id)
    }
}
