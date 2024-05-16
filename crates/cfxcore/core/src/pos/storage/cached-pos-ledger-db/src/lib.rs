// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use std::sync::Arc;

use anyhow::{format_err, Result};

use diem_crypto::HashValue;
use diem_infallible::Mutex;
use diem_logger::prelude::*;
use diem_types::{
    account_address::AccountAddress,
    block_info::PivotBlockDecision,
    contract_event::ContractEvent,
    ledger_info::LedgerInfo,
    term_state::{NodeID, PosState},
    transaction::Transaction,
};
use executor_types::{Error, ExecutedTrees, ProcessedVMOutput};
pub use speculation_cache::{SpeculationBlock, SpeculationCache};
use storage_interface::{DbReaderWriter, TreeState};

mod logging;
mod speculation_cache;

pub struct CachedPosLedgerDB {
    pub db: DbReaderWriter,
    pub cache: Mutex<SpeculationCache>,
}

impl CachedPosLedgerDB {
    pub fn new(db: DbReaderWriter) -> Self {
        let startup_info = db
            .reader
            .get_startup_info(true)
            .expect("Shouldn't fail")
            .expect("DB not bootstrapped.");

        Self {
            db,
            cache: Mutex::new(SpeculationCache::new_with_startup_info(
                startup_info,
            )),
        }
    }

    fn get_executed_trees(
        &self, block_id: HashValue,
    ) -> Result<ExecutedTrees, Error> {
        diem_debug!(
            "get_executed_trees:{} {}",
            block_id,
            self.cache.lock().committed_block_id()
        );
        let executed_trees =
            if block_id == self.cache.lock().committed_block_id() {
                self.cache.lock().committed_trees().clone()
            } else {
                self.get_block(&block_id)?
                    .lock()
                    .output()
                    .executed_trees()
                    .clone()
            };

        Ok(executed_trees)
    }

    pub fn get_pos_state(
        &self, block_id: &HashValue,
    ) -> Result<PosState, Error> {
        if let Ok(executed_tree) = self.get_executed_trees(*block_id) {
            Ok(executed_tree.pos_state().clone())
        } else {
            self.db.reader.get_pos_state(block_id).map_err(|_| {
                Error::InternalError {
                    error: "pos state not found".to_string(),
                }
            })
        }
    }

    pub fn reset_cache(&self) -> Result<(), Error> {
        let startup_info = self
            .db
            .reader
            .get_startup_info(true)?
            .ok_or_else(|| format_err!("DB not bootstrapped."))?;
        *(self.cache.lock()) =
            SpeculationCache::new_with_startup_info(startup_info);
        Ok(())
    }

    pub fn new_on_unbootstrapped_db(
        db: DbReaderWriter, tree_state: TreeState, initial_seed: Vec<u8>,
        initial_nodes: Vec<(NodeID, u64)>,
        initial_committee: Vec<(AccountAddress, u64)>,
        genesis_pivot_decision: Option<PivotBlockDecision>,
    ) -> Self {
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
        let pos_state = PosState::new(
            initial_seed,
            initial_nodes,
            initial_committee,
            genesis_pivot_decision,
        );
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
    ) {
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
    ) -> Result<(), Error> {
        self.cache.lock().add_block(parent_block_id, block)
    }

    pub fn reset(&self) { self.cache.lock().reset() }

    pub fn prune(
        &self, committed_ledger_info: &LedgerInfo,
        committed_txns: Vec<Transaction>, reconfig_events: Vec<ContractEvent>,
    ) -> Result<HashValue, Error> {
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
