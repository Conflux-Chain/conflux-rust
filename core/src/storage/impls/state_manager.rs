// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// TODO: Set the parameter large enough because we haven't implement background
// snapshotting.
// FIXME: move to the right place.
/// The rule should be somewhat friendly to new miners so that they know which
/// block starts a new snapshot by looking at consensus graph.
// FIXME: u32.
pub const SNAPSHOT_EPOCHS_CAPACITY: u64 = 1_000_000_000_000_000;

pub type DeltaDbManager = DeltaDbManagerRocksdb;
pub type SnapshotDbManager = SnapshotDbManagerSqlite;
pub type SnapshotDb = <SnapshotDbManager as SnapshotDbManagerTrait>::SnapshotDb;

pub struct StateTrees {
    pub snapshot_db: SnapshotDb,
    /// None means that the intermediate_trie is empty.
    pub intermediate_trie: Option<Arc<DeltaMpt>>,
    pub intermediate_trie_root: Option<NodeRefDeltaMpt>,
    /// Delta trie can't be none since we may commit into it.
    pub delta_trie: Arc<DeltaMpt>,
    pub delta_trie_root: Option<NodeRefDeltaMpt>,
    /// Information for making new snapshot when necessary.
    pub delta_trie_height: Option<u32>,
    pub height: Option<u64>,
    pub intermediate_epoch_id: EpochId,

    // FIXME: this field is added only for the hack to get pivot chain from a
    // snapshot FIXME: to its parent snapshot.
    pub epoch_id: EpochId,
}

pub struct StateManager {
    delta_trie: Arc<DeltaMpt>,
    pub db: Arc<SystemDB>,
    storage_manager: Arc<StorageManager>,
    pub number_committed_nodes: AtomicUsize,
}

impl StateManager {
    // FIXME: fix the TODO.
    // TODO(ming): Should prevent from committing at existing epoch because
    // otherwise the overwritten trie nodes can not be reachable from db.
    // The current codebase overwrites because it didn't check if the state
    // root is already computed, which should eventually be optimized out.
    // TODO(ming): Use self.get_state_root_node_ref(epoch_id).
    pub(super) fn mpt_commit_state_root(
        &self, epoch_id: EpochId, merkle_root: &MerkleHash,
        root_node: Option<NodeRefDeltaMpt>,
    )
    {
        match root_node {
            None => {}
            Some(node) => {
                // Debugging log.
                info!("State root committed for epoch {:?}", epoch_id);
                self.delta_trie.set_epoch_root(epoch_id, node.clone());
                self.delta_trie
                    .set_root_node_ref(merkle_root.clone(), node.clone());
            }
        }
    }

    // FIXME: change the parameter.
    pub fn new(db: Arc<SystemDB>, conf: StorageConfiguration) -> Self {
        debug!("Storage conf {:?}", conf);

        let storage_manager =
            Arc::new(StorageManager::new(DeltaDbManager::new(db.clone())));

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

    pub fn get_storage_manager(&self) -> &StorageManager {
        &*self.storage_manager
    }

    /*
    pub fn get_snapshot_manager(
        &self,
    ) -> &(dyn SnapshotManagerTrait<
        SnapshotDb = SnapshotDb,
        SnapshotDbManager = SnapshotDbManager,
    > + Send
                   + Sync) {
        self.storage_manager.get_snapshot_manager()
    }
    */

    // FIXME: Fix implementation.
    // Empty Snapshot is a Snapshot. Empty intermediate delta mpt should be a
    // DeltaMpt.
    pub fn get_state_trees(
        &self, epoch_id: &SnapshotAndEpochIdRef,
    ) -> Result<Option<StateTrees>> {
        let maybe_snapshot = self
            .storage_manager
            .get_snapshot_manager()
            .get_snapshot(&epoch_id.snapshot_root)?;
        let maybe_intermediate_mpt = None;
        // FIXME: delta_mpt is determined by snapshot.
        let delta_mpt = self.delta_trie.clone();

        match maybe_snapshot {
            None => Ok(None),
            Some(snapshot) => {
                let intermediate_root = None;
                let maybe_delta_root =
                    delta_mpt.get_root_node_ref_by_epoch(epoch_id.epoch_id)?;
                if maybe_delta_root.is_none() {
                    Ok(None)
                } else {
                    Ok(Some(StateTrees {
                        snapshot_db: snapshot,
                        intermediate_trie: maybe_intermediate_mpt,
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
        let maybe_snapshot;
        // TODO: implement shift logic for intermediate and delta mpt as well.
        let maybe_intermediate_mpt = None;
        let delta_mpt = self.delta_trie.clone();
        let intermediate_root = None;
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
            // FIXME: get snapshot by epoch id or by delta root?
            maybe_snapshot = self
                .storage_manager
                .get_snapshot_manager()
                .get_snapshot_by_epoch_id(
                    parent_epoch_id.intermediate_epoch_id,
                )?;
            delta_root = None;
            height = Some(1);
            delta_trie_height = Some(1);
            intermediate_epoch_id = parent_epoch_id.epoch_id.clone();
        } else {
            height = parent_epoch_id.height.map(|x| x + 1);
            delta_trie_height =
                parent_epoch_id.delta_trie_height.map(|x| x + 1);
            intermediate_epoch_id =
                parent_epoch_id.intermediate_epoch_id.clone();
            maybe_snapshot = self
                .storage_manager
                .get_snapshot_manager()
                .get_snapshot(&parent_epoch_id.snapshot_root)?;
            delta_root = delta_mpt
                .get_root_node_ref_by_epoch(parent_epoch_id.epoch_id)?;
            if delta_root.is_none() {
                return Ok(None);
            }
        }

        match maybe_snapshot {
            None => Ok(None),
            Some(snapshot) => Ok(Some(StateTrees {
                snapshot_db: snapshot,
                intermediate_trie: maybe_intermediate_mpt,
                intermediate_trie_root: intermediate_root,
                delta_trie: delta_mpt,
                delta_trie_root: delta_root,
                delta_trie_height,
                height,
                intermediate_epoch_id,
                epoch_id: parent_epoch_id.epoch_id.clone(),
            })),
        }
    }

    /// Check if we can make a new snapshot, and if so, make it in background.
    pub(super) fn check_make_snapshot(
        &self, snapshot_root: &MerkleHash, intermediate_trie: Arc<DeltaMpt>,
        intermediate_trie_root: Option<NodeRefDeltaMpt>,
        intermediate_epoch_id: &EpochId, new_height: u64,
    ) -> Result<()>
    {
        StorageManager::check_make_register_snapshot_background(
            self.storage_manager.clone(),
            snapshot_root,
            intermediate_epoch_id.clone(),
            new_height,
            DeltaMptInserter {
                mpt: intermediate_trie,
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
                    .get_snapshot(&MERKLE_NULL_NODE)
                    .unwrap()
                    .unwrap(),
                intermediate_trie: None,
                intermediate_trie_root: None,
                delta_trie: self.delta_trie.clone(),
                delta_trie_root: None,
                delta_trie_height: Some(1),
                height: Some(1),
                intermediate_epoch_id: MERKLE_NULL_NODE,
                epoch_id: MERKLE_NULL_NODE,
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

    // FIXME: split into 2 methods.
    fn drop_state_outside(&self, _epoch_id: EpochId) { unimplemented!() }

    // FIXME: why?
    fn get_snapshot_wire_format(
        &self, _snapshot_root: MerkleHash,
    ) -> Result<Option<Snapshot>> {
        unimplemented!()
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
