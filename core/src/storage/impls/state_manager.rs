// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type DeltaDbManager = DeltaDbManagerRocksdb;
pub type SnapshotDbManager = SnapshotDbManagerSqlite;
pub type SnapshotDb = <SnapshotDbManager as SnapshotDbManagerTrait>::SnapshotDb;

pub struct StateTrees {
    pub snapshot_db: SnapshotDb,
    /// None means that the intermediate_trie is empty, or in a special
    /// situation that we use the snapshot at intermediate epoch directly,
    /// so we don't need to look up intermediate trie.
    pub maybe_intermediate_trie: Option<Arc<DeltaMpt>>,
    pub intermediate_trie_root: Option<NodeRefDeltaMpt>,
    /// Delta trie can't be none since we may commit into it.
    pub delta_trie: Arc<DeltaMpt>,
    pub delta_trie_root: Option<NodeRefDeltaMpt>,
    /// Information for making new snapshot when necessary.
    pub delta_trie_height: Option<u32>,
    pub height: Option<u64>,
    pub intermediate_epoch_id: EpochId,

    // FIXME: this field is added only for the hack to get pivot chain from a
    // FIXME: snapshot to its parent snapshot.
    pub epoch_id: EpochId,
}

pub struct StateManager {
    storage_manager: Arc<StorageManager>,
    pub number_committed_nodes: AtomicUsize,
}

impl StateManager {
    // FIXME: leave this method here or not?
    // FIXME: fix the TODO.
    // TODO(ming): Should prevent from committing at existing epoch because
    // otherwise the overwritten trie nodes can not be reachable from db.
    // The current codebase overwrites because it didn't check if the state
    // root is already computed, which should eventually be optimized out.
    // TODO(ming): Use self.get_state_root_node_ref(epoch_id).
    pub(super) fn mpt_commit_state_root(
        delta_trie: &DeltaMpt, epoch_id: EpochId, merkle_root: &MerkleHash,
        parent_epoch_id: EpochId, root_node: Option<NodeRefDeltaMpt>,
    )
    {
        match root_node {
            None => {}
            Some(node) => {
                // Debugging log.
                info!("State root committed for epoch {:?}", epoch_id);
                delta_trie.set_parent_epoch(parent_epoch_id, epoch_id.clone());
                delta_trie.set_epoch_root(epoch_id, node.clone());
                delta_trie.set_root_node_ref(merkle_root.clone(), node.clone());
            }
        }
    }

    // FIXME: change the parameter.
    pub fn new(db: Arc<SystemDB>, conf: StorageConfiguration) -> Self {
        debug!("Storage conf {:?}", conf);

        let storage_manager =
            Arc::new(StorageManager::new(DeltaDbManager::new(db), conf));

        // FIXME: move the commit_lock into delta_mpt, along with the row_number
        // FIXME: reading into the new_or_delta_mpt method.
        Self {
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
        self.storage_manager.log_usage();
        info!(
            "number of nodes committed to db {}",
            self.number_committed_nodes.load(Ordering::Relaxed),
        );
    }

    pub fn get_storage_manager(&self) -> &StorageManager {
        &*self.storage_manager
    }

    // FIXME: Fix implementation.
    // Empty Snapshot is a Snapshot. Empty intermediate delta mpt should be a
    // DeltaMpt.
    pub fn get_state_trees(
        &self, epoch_id: &SnapshotAndEpochIdRef,
    ) -> Result<Option<StateTrees>> {
        let maybe_snapshot = self
            .storage_manager
            .get_snapshot_manager()
            .get_snapshot_by_epoch_id(&epoch_id.snapshot_epoch_id)?;

        match maybe_snapshot {
            None => {
                // TODO: there is a special case when the snapshot_root isn't
                // TODO: available but the snapshot at the intermediate epoch
                // TODO: exists.
                Ok(None)
            }
            Some(snapshot) => {
                let maybe_intermediate_mpt = self
                    .storage_manager
                    .get_intermediate_mpt(&epoch_id.snapshot_epoch_id)?;
                let delta_mpt = self
                    .storage_manager
                    .get_delta_mpt(&epoch_id.snapshot_epoch_id)?;
                let intermediate_root = None;
                let maybe_delta_root =
                    delta_mpt.get_root_node_ref_by_epoch(epoch_id.epoch_id)?;
                if maybe_delta_root.is_none() {
                    Ok(None)
                } else {
                    Ok(Some(StateTrees {
                        snapshot_db: snapshot,
                        maybe_intermediate_trie: maybe_intermediate_mpt,
                        intermediate_trie_root: intermediate_root,
                        delta_trie: delta_mpt,
                        delta_trie_root: maybe_delta_root,
                        delta_trie_height: epoch_id.delta_trie_height,
                        height: epoch_id.height,
                        intermediate_epoch_id: epoch_id
                            .intermediate_epoch_id
                            .clone(),
                        epoch_id: epoch_id.epoch_id.clone(),
                    }))
                }
            }
        }
    }

    pub fn get_state_trees_for_next_epoch(
        &self, parent_epoch_id: &SnapshotAndEpochIdRef,
    ) -> Result<Option<StateTrees>> {
        let snapshot;
        let maybe_intermediate_mpt;
        let delta_mpt;
        let delta_root;

        // Should shift to a new snapshot
        // When the delta_height is set to None (e.g. in tests), we assume that
        // the snapshot shift check is disabled.
        let delta_trie_height;
        let height;
        let intermediate_epoch_id;
        if parent_epoch_id.delta_trie_height.unwrap_or_default() as u64
            == SNAPSHOT_EPOCHS_CAPACITY
        {
            let maybe_snapshot = self
                .storage_manager
                .get_snapshot_manager()
                .get_snapshot_by_epoch_id(
                    parent_epoch_id.intermediate_epoch_id,
                )?;
            if maybe_snapshot.is_none() {
                return Ok(None);
            }
            snapshot = maybe_snapshot.unwrap();

            delta_mpt = self.storage_manager.get_delta_mpt(
                &snapshot.get_snapshot_info().get_snapshot_epoch_id(),
            )?;

            delta_root = None;
            height = Some(1);
            delta_trie_height = Some(1);
            maybe_intermediate_mpt = Some(
                self.storage_manager
                    .get_delta_mpt(&parent_epoch_id.snapshot_epoch_id)?,
            );
            intermediate_epoch_id = parent_epoch_id.epoch_id.clone();
        } else {
            height = parent_epoch_id.height.map(|x| x + 1);
            delta_trie_height =
                parent_epoch_id.delta_trie_height.map(|x| x + 1);
            intermediate_epoch_id =
                parent_epoch_id.intermediate_epoch_id.clone();
            let maybe_snapshot = self
                .storage_manager
                .get_snapshot_manager()
                .get_snapshot_by_epoch_id(&parent_epoch_id.snapshot_epoch_id)?;
            if maybe_snapshot.is_none() {
                return Ok(None);
                // TODO: there is a special case when the snapshot_root isn't
                // TODO: available but the snapshot at the intermediate epoch
                // TODO: exists.
            };
            snapshot = maybe_snapshot.unwrap();

            delta_mpt = self
                .storage_manager
                .get_delta_mpt(&parent_epoch_id.snapshot_epoch_id)?;
            delta_root = delta_mpt
                .get_root_node_ref_by_epoch(parent_epoch_id.epoch_id)?;
            if delta_root.is_none() {
                return Ok(None);
            }
            maybe_intermediate_mpt = self
                .storage_manager
                .get_intermediate_mpt(&parent_epoch_id.snapshot_epoch_id)?;
        }

        let intermediate_trie_root =
            if parent_epoch_id.intermediate_epoch_id.eq(&NULL_EPOCH)
                || maybe_intermediate_mpt.is_none()
            {
                None
            } else {
                maybe_intermediate_mpt
                    .as_ref()
                    .unwrap()
                    .get_root_node_ref_by_epoch(
                        &parent_epoch_id.intermediate_epoch_id,
                    )?
            };

        Ok(Some(StateTrees {
            snapshot_db: snapshot,
            maybe_intermediate_trie: maybe_intermediate_mpt,
            intermediate_trie_root,
            delta_trie: delta_mpt,
            delta_trie_root: delta_root,
            delta_trie_height,
            height,
            intermediate_epoch_id,
            epoch_id: parent_epoch_id.epoch_id.clone(),
        }))
    }

    /// Check if we can make a new snapshot, and if so, make it in background.
    pub(super) fn check_make_snapshot(
        &self, intermediate_trie: Option<Arc<DeltaMpt>>,
        intermediate_trie_root: Option<NodeRefDeltaMpt>,
        intermediate_epoch_id: &EpochId, new_height: u64,
    ) -> Result<()>
    {
        StorageManager::check_make_register_snapshot_background(
            self.storage_manager.clone(),
            intermediate_epoch_id.clone(),
            new_height,
            DeltaMptInserter {
                maybe_mpt: intermediate_trie,
                maybe_root_node: intermediate_trie_root,
            },
        )
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
            StateTrees {
                snapshot_db: self
                    .storage_manager
                    .get_snapshot_manager()
                    .get_snapshot_by_epoch_id(&NULL_EPOCH)
                    .unwrap()
                    .unwrap(),
                maybe_intermediate_trie: None,
                intermediate_trie_root: None,
                delta_trie: self
                    .storage_manager
                    .get_delta_mpt(&NULL_EPOCH)
                    .unwrap(),
                delta_trie_root: None,
                delta_trie_height: Some(1),
                height: Some(1),
                intermediate_epoch_id: NULL_EPOCH,
                epoch_id: NULL_EPOCH,
            },
        )
    }

    // Currently we use epoch number to decide whether or not to
    // start a new delta trie. The value of parent_epoch_id is only
    // known after the computation is done.
    //
    // If we use delta trie size upper bound to decide whether or not
    // to start a new delta trie, then the computation about whether
    // or not start a new delta trie, can only be done at the time
    // of committing. In this scenario, the execution engine should
    // first get the state assuming that the delta trie won't change,
    // then check if committing fails due to over size, and if so,
    // start a new delta trie and re-apply the change.
    //
    // Due to the complexity of the latter approach, we stay with the
    // simple approach.
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
}

// FIXME This is a quick fix for the ref loop of storage_manager. We should
// eliminate this loop. Arc<StorageManager> -> snapshot_associated_mpts_by_epoch
// contains -> Arc<DeltaMpt> -> delta_mpts_releaser -> storage_manager ->
// Arc<StorageManager>
impl Drop for StateManager {
    fn drop(&mut self) {
        self.storage_manager
            .snapshot_associated_mpts_by_epoch
            .write()
            .clear();
    }
}

use super::{
    super::{state::*, state_manager::*, storage_db::*},
    errors::*,
    multi_version_merkle_patricia_trie::{
        merkle_patricia_trie::NodeRefDeltaMpt, *,
    },
    storage_db::{
        delta_db_manager_rocksdb::DeltaDbManagerRocksdb,
        snapshot_db_manager_sqlite::SnapshotDbManagerSqlite,
    },
    storage_manager::storage_manager::{DeltaMptInserter, StorageManager},
};
use crate::{ext_db::SystemDB, statedb::StateDb};
use cfx_types::{Address, U256};
use primitives::{
    Account, Block, BlockHeaderBuilder, EpochId, MerkleHash, NULL_EPOCH,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
