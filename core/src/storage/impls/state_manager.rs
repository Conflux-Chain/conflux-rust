// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub use super::super::super::db::COL_DELTA_TRIE;

// TODO: Set the parameter large enough because we haven't implement background
// snapshotting.
/// The rule should be somewhat friendly to new miners so that they know which
/// block starts a new snapshot by looking at consensus graph.
pub const SNAPSHOT_EPOCHS_CAPACITY: u64 = 1_000_000_000_000_000;

pub type DeltaDbManager = DeltaDbManagerRocksdb;
pub type SnapshotDbManager = SnapshotDbManagerSqlite;
pub type SnapshotDb = <SnapshotDbManager as SnapshotDbManagerTrait>::SnapshotDb;

// TODO: remove option on intermediate tree.
pub type StateTrees = (
    Arc<SnapshotDb>,
    Option<Arc<DeltaMpt>>,
    Option<NodeRefDeltaMpt>,
    Arc<DeltaMpt>,
    Option<NodeRefDeltaMpt>,
);

pub struct StateManager {
    delta_trie: Arc<DeltaMpt>,
    pub db: Arc<SystemDB>,
    storage_manager: Arc<StorageManager>,
    pub number_committed_nodes: AtomicUsize,
}

impl StateManager {
    // TODO(ming): Should prevent from committing at existing epoch because
    // otherwise the overwritten trie nodes can not be reachable from db.
    // The current codebase overwrites because it didn't check if the state
    // root is already computed, which should eventually be optimized out.
    // TODO(ming): Use self.get_state_root_node_ref(epoch_id).
    pub(super) fn mpt_commit_state_root(
        &self, epoch_id: EpochId, root_node: Option<NodeRefDeltaMpt>,
    ) {
        match root_node {
            None => {}
            Some(node) => {
                // Debugging log.
                info!("State root committed for epoch {:?}", epoch_id);
                self.delta_trie.set_epoch_root(epoch_id, node.clone())
            }
        }
    }

    // FIXME: change the parameter.
    pub fn new(db: Arc<SystemDB>, conf: StorageConfiguration) -> Self {
        debug!("Storage conf {:?}", conf);

        let storage_manager = Arc::new(StorageManager::new(
            DeltaDbManagerRocksdb::new(db.clone()),
        ));

        // FIXME: move the commit_lock into delta_mpt, along with the row_number
        // FIXME: reading into the new_delta_mpt method.
        Self {
            delta_trie: StorageManager::new_delta_mpt(
                storage_manager.clone(),
                &MERKLE_NULL_NODE,
                &MERKLE_NULL_NODE,
                conf,
            )
            // It's fine to unwrap in initialization.
            .unwrap(),
            db,
            storage_manager,
            number_committed_nodes: Default::default(),
        }
    }

    /// ` test_net_version` is used to update the genesis author so that after
    /// resetting, the chain of the older version will be discarded
    pub fn initialize(
        &self, genesis_accounts: HashMap<Address, U256>,
        genesis_gas_limit: U256, test_net_version: Address,
        initial_difficulty: U256,
    ) -> Block
    {
        let mut state = StateDb::new(self.get_state_for_genesis_write());

        for (addr, balance) in genesis_accounts {
            let account =
                Account::new_empty_with_balance(&addr, &balance, &0.into());
            state.set(&state.account_key(&addr), &account).unwrap();
        }

        let state_root = state.compute_state_root().unwrap();
        let mut genesis = Block::new(
            BlockHeaderBuilder::new()
                .with_deferred_state_root(
                    state_root.state_root.compute_state_root_hash(),
                )
                .with_deferred_state_root_with_aux_info(state_root)
                .with_gas_limit(genesis_gas_limit)
                .with_author(test_net_version)
                .with_difficulty(initial_difficulty)
                .build(),
            Vec::new(),
        );
        genesis.block_header.compute_hash();
        debug!("Genesis Block:{:?} hash={:?}", genesis, genesis.hash());
        state.commit(genesis.block_header.hash()).unwrap();
        genesis
    }

    pub fn log_usage(&self) {
        self.delta_trie.log_usage();
        info!(
            "number of nodes committed to db {}",
            self.number_committed_nodes.load(Ordering::Relaxed),
        );
    }

    /// This is unsafe because if state for `epoch_id` does not exist, it'll
    /// panic.
    pub unsafe fn get_state_readonly_assumed_existence(
        &self, epoch_id: EpochId,
    ) -> Result<State> {
        Ok(self
            .get_state_no_commit(SnapshotAndEpochIdRef::new(&epoch_id, None))?
            .unwrap())
    }

    // FIXME: Fix implementation.
    // Empty Snapshot is a Snapshot. Empty intermediate delta mpt should be a
    // DeltaMpt.
    pub fn get_state_trees(
        &self, epoch_id: &SnapshotAndEpochIdRef,
    ) -> Result<Option<StateTrees>> {
        let maybe_snapshot =
            self.storage_manager.get_snapshot(&epoch_id.snapshot_root)?;
        let maybe_intermediate_mpt = None;
        // FIXME: delta_mpt is determined by snapshot.
        let delta_mpt = self.delta_trie.clone();

        match maybe_snapshot {
            None => Ok(None),
            Some(snapshot) => {
                let intermediate_root = None;
                let maybe_delta_root =
                    delta_mpt.get_state_root_node_ref(epoch_id.epoch_id)?;
                if maybe_delta_root.is_none() {
                    Ok(None)
                } else {
                    Ok(Some((
                        snapshot,
                        maybe_intermediate_mpt,
                        intermediate_root,
                        delta_mpt,
                        maybe_delta_root,
                    )))
                }
            }
        }
    }

    pub fn get_state_trees_for_next_epoch(
        &self, parent_epoch_id: &SnapshotAndEpochIdRef,
    ) -> Result<Option<StateTrees>> {
        let maybe_snapshot;
        // TODO: implement shift logic for intermediate and delta mpt as well.
        let maybe_intermediate_mpt = None;
        let delta_mpt = self.delta_trie.clone();
        let intermediate_root = None;
        let delta_root;

        // Should shift to a new snapshot
        // When the delta_height is set to None (e.g. in tests), we assume that
        // the snapshot shift check is disabled.
        if parent_epoch_id.delta_height.unwrap_or_default()
            == SNAPSHOT_EPOCHS_CAPACITY
        {
            maybe_snapshot = self.storage_manager.get_snapshot_by_epoch_id(
                parent_epoch_id.intermediate_delta_epoch_id,
            )?;
            delta_root = None;
        } else {
            maybe_snapshot = self
                .storage_manager
                .get_snapshot(&parent_epoch_id.snapshot_root)?;
            delta_root =
                delta_mpt.get_state_root_node_ref(parent_epoch_id.epoch_id)?;
            if delta_root.is_none() {
                return Ok(None);
            }
        }

        match maybe_snapshot {
            None => Ok(None),
            Some(snapshot) => Ok(Some((
                snapshot,
                maybe_intermediate_mpt,
                intermediate_root,
                delta_mpt,
                delta_root,
            ))),
        }
    }
}

impl StateManagerTrait for StateManager {
    fn get_state_no_commit(
        &self, epoch_id: SnapshotAndEpochIdRef,
    ) -> Result<Option<State>> {
        let maybe_state_trees = self.get_state_trees(&epoch_id)?;
        match maybe_state_trees {
            None => Ok(None),
            Some(state_trees) => Ok(Some(State::new(self, state_trees))),
        }
    }

    fn get_state_for_genesis_write(&self) -> State {
        State::new(
            self,
            (
                self.storage_manager
                    .get_snapshot(&MERKLE_NULL_NODE)
                    .unwrap()
                    .unwrap(),
                None,
                None,
                self.delta_trie.clone(),
                None,
            ),
        )
    }

    fn get_state_for_next_epoch(
        &self, parent_epoch_id: SnapshotAndEpochIdRef,
    ) -> Result<Option<State>> {
        let maybe_state_trees =
            self.get_state_trees_for_next_epoch(&parent_epoch_id)?;
        match maybe_state_trees {
            None => Ok(None),
            Some(state_trees) => Ok(Some(State::new(self, state_trees))),
        }
    }

    fn contains_state(&self, epoch_id: SnapshotAndEpochIdRef) -> Result<bool> {
        let maybe_state_trees = self.get_state_trees(&epoch_id)?;
        Ok(match maybe_state_trees {
            None => {
                warn!("Failed to load state for epoch {:?}", epoch_id);
                false
            }
            Some(_) => true,
        })
    }

    // FIXME: split into 2 methods.
    fn drop_state_outside(&self, _epoch_id: EpochId) { unimplemented!() }

    fn get_snapshot_wire_format(
        &self, _snapshot_root: MerkleHash,
    ) -> Result<Option<Snapshot>> {
        unimplemented!()
    }
}

use super::{
    super::{
        snapshot_manager::SnapshotManagerTrait, state::*, state_manager::*,
        storage_db::*,
    },
    errors::*,
    multi_version_merkle_patricia_trie::{
        merkle_patricia_trie::NodeRefDeltaMpt, *,
    },
    storage_db::{
        delta_db_manager_rocksdb::DeltaDbManagerRocksdb,
        snapshot_db_manager_sqlite::SnapshotDbManagerSqlite,
    },
    storage_manager::storage_manager::StorageManager,
};
use crate::{ext_db::SystemDB, snapshot::snapshot::Snapshot, statedb::StateDb};
use cfx_types::{Address, U256};
use primitives::{
    Account, Block, BlockHeaderBuilder, EpochId, MerkleHash, MERKLE_NULL_NODE,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
