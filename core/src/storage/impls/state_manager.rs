// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub type DeltaDbManager = DeltaDbManagerRocksdb;
pub type SnapshotDbManager = SnapshotDbManagerSqlite;
pub type SnapshotDb = <SnapshotDbManager as SnapshotDbManagerTrait>::SnapshotDb;

pub struct StateTrees {
    pub snapshot_db: SnapshotDb,
    pub snapshot_epoch_id: EpochId,
    pub snapshot_merkle_root: MerkleHash,
    /// None means that the intermediate_trie is empty, or in a special
    /// situation that we use the snapshot at intermediate epoch directly,
    /// so we don't need to look up intermediate trie.
    pub maybe_intermediate_trie: Option<Arc<DeltaMpt>>,
    pub intermediate_trie_root: Option<NodeRefDeltaMpt>,
    pub intermediate_trie_root_merkle: MerkleHash,
    pub maybe_intermediate_trie_key_padding: Option<DeltaMptKeyPadding>,
    /// Delta trie can't be none since we may commit into it.
    pub delta_trie: Arc<DeltaMpt>,
    pub delta_trie_root: Option<NodeRefDeltaMpt>,
    pub delta_trie_key_padding: DeltaMptKeyPadding,
    /// Information for making new snapshot when necessary.
    pub maybe_delta_trie_height: Option<u32>,
    pub maybe_height: Option<u64>,
    pub intermediate_epoch_id: EpochId,

    // TODO: this field is added only for the hack to get pivot chain from a
    // TODO: snapshot to its parent snapshot.
    pub parent_epoch_id: EpochId,
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
                delta_trie.set_parent_epoch(epoch_id, parent_epoch_id.clone());
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
            let account = Account::new_empty_with_balance(
                &addr,
                &balance,
                &0.into(), /* nonce */
            );
            state
                .set(StorageKey::new_account_key(&addr), &account)
                .unwrap();
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

    /// delta_mpt_key_padding is required. When None is passed,
    /// it's calculated for the state_trees.
    #[inline]
    pub fn get_state_trees_internal(
        snapshot_db: SnapshotDb, snapshot_epoch_id: &EpochId,
        snapshot_merkle_root: MerkleHash,
        maybe_intermediate_trie: Option<Arc<DeltaMpt>>,
        maybe_intermediate_trie_key_padding: Option<&DeltaMptKeyPadding>,
        delta_mpt: Arc<DeltaMpt>,
        maybe_delta_mpt_key_padding: Option<&DeltaMptKeyPadding>,
        intermediate_epoch_id: &EpochId, epoch_id: &EpochId,
        maybe_delta_root: Option<NodeRefDeltaMpt>, maybe_height: Option<u64>,
        maybe_delta_trie_height: Option<u32>,
    ) -> Result<Option<StateTrees>>
    {
        let intermediate_trie_root_merkle;
        let intermediate_trie_root;
        if maybe_intermediate_trie.is_none() {
            intermediate_trie_root_merkle = MERKLE_NULL_NODE;
            intermediate_trie_root = None;
        } else {
            intermediate_trie_root_merkle = match maybe_intermediate_trie
                .as_ref()
                .unwrap()
                .get_merkle_root_by_epoch_id(intermediate_epoch_id)?
            {
                None => MERKLE_NULL_NODE,
                Some(merkle_root) => merkle_root,
            };
            intermediate_trie_root =
                maybe_intermediate_trie
                    .as_ref()
                    .unwrap()
                    .get_root_node_ref_by_epoch(intermediate_epoch_id)?
        };
        let delta_trie_key_padding = match maybe_delta_mpt_key_padding {
            Some(x) => x.clone(),
            None => {
                // TODO: maybe we can move the calculation to a central place
                // and cache the result?
                StorageKey::delta_mpt_padding(
                    &snapshot_merkle_root,
                    &intermediate_trie_root_merkle,
                )
            }
        };

        Ok(Some(StateTrees {
            snapshot_db,
            snapshot_merkle_root,
            snapshot_epoch_id: *snapshot_epoch_id,
            maybe_intermediate_trie,
            intermediate_trie_root,
            intermediate_trie_root_merkle,
            maybe_intermediate_trie_key_padding:
                maybe_intermediate_trie_key_padding.cloned(),
            delta_trie: delta_mpt,
            delta_trie_root: maybe_delta_root,
            delta_trie_key_padding,
            maybe_delta_trie_height,
            maybe_height,
            intermediate_epoch_id: intermediate_epoch_id.clone(),
            parent_epoch_id: epoch_id.clone(),
        }))
    }

    // FIXME: Fix implementation.
    pub fn get_state_trees(
        &self, state_index: &StateIndex,
    ) -> Result<Option<StateTrees>> {
        let maybe_snapshot = self
            .storage_manager
            .get_snapshot_manager()
            .get_snapshot_by_epoch_id(&state_index.snapshot_epoch_id)?;

        match maybe_snapshot {
            None => {
                // TODO: there is a special case when the snapshot_root isn't
                // TODO: available but the snapshot at the intermediate epoch
                // TODO: exists.
                Ok(None)
            }
            Some(mut snapshot) => {
                // FIXME: move snapshot_merkle_root into StateIndex.
                // FIXME: But if the snapshot_merkle_root is only used to
                // FIXME: compute padding, do it differently.
                let snapshot_merkle_root =
                    snapshot.open_snapshot_mpt_read_only()?.get_merkle_root();
                let maybe_intermediate_mpt = self
                    .storage_manager
                    .get_intermediate_mpt(&state_index.snapshot_epoch_id)?;
                let delta_mpt = self
                    .storage_manager
                    .get_delta_mpt(&state_index.snapshot_epoch_id)?;
                let maybe_delta_root = delta_mpt
                    .get_root_node_ref_by_epoch(state_index.epoch_id)?;

                Self::get_state_trees_internal(
                    snapshot,
                    state_index.snapshot_epoch_id,
                    snapshot_merkle_root,
                    maybe_intermediate_mpt,
                    state_index.maybe_intermediate_mpt_key_padding,
                    delta_mpt,
                    Some(state_index.delta_mpt_key_padding),
                    state_index.intermediate_epoch_id,
                    state_index.epoch_id,
                    maybe_delta_root,
                    state_index.maybe_height,
                    state_index.maybe_delta_trie_height,
                )
            }
        }
    }

    pub fn get_state_trees_for_next_epoch(
        &self, parent_state_index: &StateIndex,
    ) -> Result<Option<StateTrees>> {
        let maybe_height = parent_state_index.maybe_height.map(|x| x + 1);

        let (
            snapshot_epoch_id,
            maybe_delta_trie_height,
            maybe_intermediate_trie_key_padding,
            maybe_delta_mpt_key_padding,
            intermediate_epoch_id,
            new_delta_root,
        ) = if parent_state_index
            .maybe_delta_trie_height
            .unwrap_or_default()
            == self.storage_manager.get_snapshot_epoch_count()
        {
            // Should shift to a new snapshot
            // When the delta_height is set to None (e.g. in tests), we
            // assume that the snapshot shift check is
            // disabled.

            (
                parent_state_index.intermediate_epoch_id,
                Some(1),
                // This is only used for the case of genesis
                Some(parent_state_index.delta_mpt_key_padding),
                None,
                parent_state_index.epoch_id,
                true,
            )
        } else {
            // The special case for the epochs in the snapshot (except the first
            // one) after a full sync will also fall into this case,
            // because parent_state_index.snapshot_epoch_id is from
            // ExecutionCommitment and set to the same as the
            // previous snapshot_epoch_id
            (
                parent_state_index.snapshot_epoch_id,
                parent_state_index.maybe_delta_trie_height.map(|x| x + 1),
                parent_state_index.maybe_intermediate_mpt_key_padding,
                Some(parent_state_index.delta_mpt_key_padding),
                parent_state_index.intermediate_epoch_id,
                false,
            )
        };

        let mut maybe_snapshot = self
            .storage_manager
            .get_snapshot_manager()
            .get_snapshot_by_epoch_id(snapshot_epoch_id)?;
        let snapshot_merkle_root = match maybe_snapshot.as_mut() {
            None => {
                return Ok(None);
            }
            Some(snapshot) => {
                snapshot.open_snapshot_mpt_read_only()?.get_merkle_root()
            }
        };
        let delta_mpt =
            self.storage_manager.get_delta_mpt(snapshot_epoch_id)?;
        delta_mpt.update_row_number()?;
        let maybe_delta_root = if new_delta_root {
            None
        } else {
            delta_mpt.get_root_node_ref_by_epoch(parent_state_index.epoch_id)?
        };
        Self::get_state_trees_internal(
            maybe_snapshot.unwrap(),
            snapshot_epoch_id,
            snapshot_merkle_root,
            self.storage_manager
                .get_intermediate_mpt(snapshot_epoch_id)?,
            maybe_intermediate_trie_key_padding,
            delta_mpt,
            maybe_delta_mpt_key_padding,
            intermediate_epoch_id,
            parent_state_index.epoch_id,
            maybe_delta_root,
            maybe_height,
            maybe_delta_trie_height,
        )
    }

    /// Check if we can make a new snapshot, and if so, make it in background.
    pub fn check_make_snapshot(
        &self, maybe_intermediate_trie: Option<Arc<DeltaMpt>>,
        intermediate_trie_root: Option<NodeRefDeltaMpt>,
        intermediate_epoch_id: &EpochId, new_height: u64,
    ) -> Result<()>
    {
        debug!(
            "check_make_snapshot called for {:?} at height {}",
            intermediate_epoch_id, new_height
        );
        StorageManager::check_make_register_snapshot_background(
            self.storage_manager.clone(),
            intermediate_epoch_id.clone(),
            new_height,
            maybe_intermediate_trie.map(|intermediate_trie| DeltaMptIterator {
                mpt: intermediate_trie,
                maybe_root_node: intermediate_trie_root,
            }),
        )
    }
}

impl StateManagerTrait for StateManager {
    fn get_state_no_commit(
        &self, epoch_id: StateIndex,
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
                snapshot_epoch_id: NULL_EPOCH,
                snapshot_merkle_root: MERKLE_NULL_NODE,
                maybe_intermediate_trie: None,
                intermediate_trie_root: None,
                intermediate_trie_root_merkle: MERKLE_NULL_NODE,
                maybe_intermediate_trie_key_padding: None,
                delta_trie: self
                    .storage_manager
                    .get_delta_mpt(&NULL_EPOCH)
                    .unwrap(),
                delta_trie_root: None,
                delta_trie_key_padding: GENESIS_DELTA_MPT_KEY_PADDING.clone(),
                maybe_delta_trie_height: Some(1),
                maybe_height: Some(1),
                intermediate_epoch_id: NULL_EPOCH,
                parent_epoch_id: NULL_EPOCH,
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
        &self, parent_epoch_id: StateIndex,
    ) -> Result<Option<State>> {
        let maybe_state_trees =
            self.get_state_trees_for_next_epoch(&parent_epoch_id)?;
        match maybe_state_trees {
            None => Ok(None),
            Some(state_trees) => Ok(Some(State::new(self, state_trees))),
        }
    }
}

use super::{
    super::{state::*, state_manager::*, storage_db::*},
    delta_mpt::*,
    errors::*,
    storage_db::{
        delta_db_manager_rocksdb::DeltaDbManagerRocksdb,
        snapshot_db_manager_sqlite::SnapshotDbManagerSqlite,
    },
    storage_manager::storage_manager::{DeltaMptIterator, StorageManager},
};
use crate::{
    ext_db::SystemDB, statedb::StateDb, storage::StorageConfiguration,
};
use cfx_types::{Address, U256};
use primitives::{
    Account, Block, BlockHeaderBuilder, DeltaMptKeyPadding, EpochId,
    MerkleHash, StorageKey, GENESIS_DELTA_MPT_KEY_PADDING, MERKLE_NULL_NODE,
    NULL_EPOCH,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
