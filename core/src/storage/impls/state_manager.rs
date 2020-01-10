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
    /// A None value indicate the special case when snapshot_db is actually the
    /// snapshot_db from the intermediate_epoch_id.
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

impl Drop for StateManager {
    fn drop(&mut self) { self.storage_manager.graceful_shutdown(); }
}

impl StateManager {
    pub fn new(conf: StorageConfiguration) -> Result<Self> {
        debug!("Storage conf {:?}", conf);

        let storage_manager = StorageManager::new_arc(conf)?;

        Ok(Self {
            storage_manager,
            number_committed_nodes: Default::default(),
        })
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
        intermediate_epoch_id: &EpochId,
        intermediate_trie_root_merkle: MerkleHash, delta_mpt: Arc<DeltaMpt>,
        maybe_delta_mpt_key_padding: Option<&DeltaMptKeyPadding>,
        epoch_id: &EpochId, delta_root: Option<NodeRefDeltaMpt>,
        maybe_height: Option<u64>, maybe_delta_trie_height: Option<u32>,
    ) -> Result<Option<StateTrees>>
    {
        let intermediate_trie_root = match &maybe_intermediate_trie {
            None => None,
            Some(mpt) => {
                match mpt.get_root_node_ref_by_epoch(intermediate_epoch_id)? {
                    None => {
                        warn!(
                            "get_state_trees_internal, intermediate_mpt root not found \
                             for epoch {:?}.",
                            intermediate_epoch_id,
                        );
                        return Ok(None);
                    }
                    Some(root) => root,
                }
            }
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
            delta_trie_root: delta_root,
            delta_trie_key_padding,
            maybe_delta_trie_height,
            maybe_height,
            intermediate_epoch_id: intermediate_epoch_id.clone(),
            parent_epoch_id: epoch_id.clone(),
        }))
    }

    pub fn get_state_trees(
        &self, state_index: &StateIndex,
    ) -> Result<Option<StateTrees>> {
        let maybe_intermediate_mpt;
        let maybe_intermediate_mpt_key_padding;
        let delta_mpt;
        let snapshot;

        match self
            .storage_manager
            .wait_for_snapshot(&state_index.snapshot_epoch_id)?
        {
            None => {
                // This is the special scenario when the snapshot isn't
                // available but the snapshot at the intermediate epoch exists.
                if let Some(snapshot_got) = self
                    .storage_manager
                    .wait_for_snapshot(&state_index.intermediate_epoch_id)?
                {
                    snapshot = snapshot_got;
                    maybe_intermediate_mpt = None;
                    maybe_intermediate_mpt_key_padding = None;
                    delta_mpt = match self
                        .storage_manager
                        .get_intermediate_mpt(
                            &state_index.intermediate_epoch_id,
                        )? {
                        None => {
                            warn!(
                                    "get_state_trees, special case, \
                                    intermediate_mpt not found for epoch {:?}. StateIndex: {:?}.",
                                    state_index.intermediate_epoch_id,
                                    state_index,
                                );
                            return Ok(None);
                        }
                        Some(delta_mpt) => delta_mpt,
                    };
                } else {
                    warn!(
                        "get_state_trees, special case, \
                         snapshot not found for epoch {:?}. StateIndex: {:?}.",
                        state_index.intermediate_epoch_id, state_index,
                    );
                    return Ok(None);
                }
            }
            Some(snapshot_got) => {
                snapshot = snapshot_got;
                maybe_intermediate_mpt_key_padding =
                    state_index.maybe_intermediate_mpt_key_padding;
                maybe_intermediate_mpt = if maybe_intermediate_mpt_key_padding
                    .is_some()
                {
                    self.storage_manager
                        .get_intermediate_mpt(&state_index.snapshot_epoch_id)?
                } else {
                    None
                };
                delta_mpt = self
                    .storage_manager
                    .get_delta_mpt(&state_index.snapshot_epoch_id)?;
            }
        }

        let delta_root = match delta_mpt
            .get_root_node_ref_by_epoch(state_index.epoch_id)?
        {
            None => {
                warn!(
                    "get_state_trees, \
                    delta_root not found for epoch {:?}. mpt_id {}, StateIndex: {:?}.",
                    state_index.epoch_id, delta_mpt.get_mpt_id(), state_index,
                );
                return Ok(None);
            }
            Some(root) => root,
        };

        Self::get_state_trees_internal(
            snapshot,
            state_index.snapshot_epoch_id,
            *state_index.snapshot_merkle_root,
            maybe_intermediate_mpt,
            maybe_intermediate_mpt_key_padding,
            state_index.intermediate_epoch_id,
            *state_index.intermediate_trie_root_merkle,
            delta_mpt,
            Some(state_index.delta_mpt_key_padding),
            state_index.epoch_id,
            delta_root,
            state_index.maybe_height,
            state_index.maybe_delta_trie_height,
        )
    }

    pub fn get_state_trees_for_next_epoch(
        &self, parent_state_index: &StateIndex,
    ) -> Result<Option<StateTrees>> {
        let maybe_height = parent_state_index.maybe_height.map(|x| x + 1);

        let snapshot;
        let snapshot_epoch_id;
        let snapshot_merkle_root;
        let maybe_delta_trie_height;
        let maybe_intermediate_mpt;
        let maybe_intermediate_mpt_key_padding;
        let intermediate_trie_root_merkle;
        let delta_mpt;
        let maybe_delta_mpt_key_padding;
        let intermediate_epoch_id;
        let new_delta_root;

        if parent_state_index
            .maybe_delta_trie_height
            .unwrap_or_default()
            == self.storage_manager.get_snapshot_epoch_count()
        {
            // Should shift to a new snapshot
            // When the delta_height is set to None (e.g. in tests), we
            // assume that the snapshot shift check is
            // disabled.

            snapshot_epoch_id = parent_state_index.intermediate_epoch_id;
            intermediate_epoch_id = parent_state_index.epoch_id;
            match self.storage_manager.wait_for_snapshot(snapshot_epoch_id)? {
                None => {
                    // This is the special scenario when the snapshot isn't
                    // available but the snapshot at the intermediate epoch
                    // exists.
                    //
                    // At the synced snapshot, the intermediate_epoch_id is
                    // its parent snapshot. We need to shift again.

                    // There is no snapshot_info for the parent snapshot,
                    // how can we find out the snapshot_merkle_root?
                    // See validate_blame_states().
                    snapshot_merkle_root =
                        *parent_state_index.snapshot_epoch_id;
                    match self
                        .storage_manager
                        .wait_for_snapshot(parent_state_index.epoch_id)?
                    {
                        None => {
                            warn!(
                                "get_state_trees_for_next_epoch, shift snapshot, special case, \
                                snapshot not found for snapshot {:?}. StateIndex: {:?}.",
                                parent_state_index.epoch_id,
                                parent_state_index,
                            );
                            return Ok(None);
                        }
                        Some(snapshot_got) => snapshot = snapshot_got,
                    }
                    maybe_intermediate_mpt = None;
                    maybe_intermediate_mpt_key_padding = None;
                    intermediate_trie_root_merkle = MERKLE_NULL_NODE;
                    match self
                        .storage_manager
                        .get_intermediate_mpt(parent_state_index.epoch_id)?
                    {
                        None => {
                            warn!(
                                "get_state_trees_for_next_epoch, shift snapshot, special case, \
                                intermediate_mpt not found for snapshot {:?}. StateIndex: {:?}.",
                                parent_state_index.epoch_id,
                                parent_state_index,
                            );
                            return Ok(None);
                        }
                        Some(mpt) => delta_mpt = mpt,
                    }
                }
                Some(snapshot_got) => {
                    snapshot = snapshot_got;

                    snapshot_merkle_root = match self
                        .storage_manager
                        .get_snapshot_info_at_epoch(snapshot_epoch_id)
                    {
                        None => {
                            warn!(
                                "get_state_trees_for_next_epoch, shift snapshot, normal case, \
                                snapshot info not found for snapshot {:?}. StateIndex: {:?}.",
                                snapshot_epoch_id,
                                parent_state_index,
                            );
                            return Ok(None);
                        }
                        Some(snapshot_info) => snapshot_info.merkle_root,
                    };
                    maybe_intermediate_mpt = self
                        .storage_manager
                        .get_intermediate_mpt(snapshot_epoch_id)?;
                    delta_mpt = self
                        .storage_manager
                        .get_delta_mpt(&snapshot_epoch_id)?;
                    intermediate_trie_root_merkle = match maybe_intermediate_mpt
                        .as_ref()
                    {
                        None => MERKLE_NULL_NODE,
                        Some(mpt) => match mpt.get_merkle_root_by_epoch_id(
                            &parent_state_index.epoch_id,
                        )? {
                            Some(merkle_root) => merkle_root,
                            None => {
                                warn!(
                                        "get_state_trees_for_next_epoch, shift snapshot, normal case, \
                                        intermediate_trie_root not found for epoch {:?}. StateIndex: {:?}.",
                                        parent_state_index.epoch_id,
                                        parent_state_index,
                                    );
                                return Ok(None);
                            }
                        },
                    };
                    maybe_intermediate_mpt_key_padding =
                        Some(parent_state_index.delta_mpt_key_padding);
                }
            };
            maybe_delta_trie_height = Some(1);
            maybe_delta_mpt_key_padding = None;
            new_delta_root = true;
        } else {
            snapshot_epoch_id = parent_state_index.snapshot_epoch_id;
            snapshot_merkle_root = *parent_state_index.snapshot_merkle_root;
            intermediate_epoch_id = parent_state_index.intermediate_epoch_id;
            intermediate_trie_root_merkle =
                *parent_state_index.intermediate_trie_root_merkle;
            match self.storage_manager.wait_for_snapshot(snapshot_epoch_id)? {
                None => {
                    // This is the special scenario when the snapshot isn't
                    // available but the snapshot at the intermediate epoch
                    // exists.
                    if let Some(snapshot_got) = self
                        .storage_manager
                        .wait_for_snapshot(&intermediate_epoch_id)?
                    {
                        snapshot = snapshot_got;
                        maybe_intermediate_mpt = None;
                        maybe_intermediate_mpt_key_padding = None;
                        delta_mpt = match self
                            .storage_manager
                            .get_intermediate_mpt(intermediate_epoch_id)?
                        {
                            None => {
                                return {
                                    warn!(
                                    "get_state_trees_for_next_epoch, special case, \
                                    intermediate_mpt not found for epoch {:?}. StateIndex: {:?}.",
                                    intermediate_epoch_id,
                                    parent_state_index,
                                );
                                    Ok(None)
                                }
                            }
                            Some(delta_mpt) => delta_mpt,
                        };
                    } else {
                        warn!(
                            "get_state_trees_for_next_epoch, special case, \
                            snapshot not found for epoch {:?}. StateIndex: {:?}.",
                            intermediate_epoch_id,
                            parent_state_index,
                        );
                        return Ok(None);
                    }
                }
                Some(snapshot_got) => {
                    snapshot = snapshot_got;
                    maybe_intermediate_mpt_key_padding =
                        parent_state_index.maybe_intermediate_mpt_key_padding;
                    maybe_intermediate_mpt =
                        if maybe_intermediate_mpt_key_padding.is_some() {
                            self.storage_manager
                                .get_intermediate_mpt(snapshot_epoch_id)?
                        } else {
                            None
                        };
                    delta_mpt = self
                        .storage_manager
                        .get_delta_mpt(snapshot_epoch_id)?;
                }
            };
            maybe_delta_trie_height =
                parent_state_index.maybe_delta_trie_height.map(|x| x + 1);
            maybe_delta_mpt_key_padding =
                Some(parent_state_index.delta_mpt_key_padding);
            new_delta_root = false;
        };

        let delta_root = if new_delta_root {
            None
        } else {
            match delta_mpt
                .get_root_node_ref_by_epoch(parent_state_index.epoch_id)?
            {
                None => {
                    warn!(
                        "get_state_trees_for_next_epoch, not shifting, \
                         delta_root not found for epoch {:?}. mpt_id {}, StateIndex: {:?}.",
                        parent_state_index.epoch_id,
                        delta_mpt.get_mpt_id(), parent_state_index
                    );
                    return Ok(None);
                }
                Some(root_node) => root_node,
            }
        };
        Self::get_state_trees_internal(
            snapshot,
            snapshot_epoch_id,
            snapshot_merkle_root,
            maybe_intermediate_mpt,
            maybe_intermediate_mpt_key_padding,
            intermediate_epoch_id,
            intermediate_trie_root_merkle,
            delta_mpt,
            maybe_delta_mpt_key_padding,
            parent_state_index.epoch_id,
            delta_root,
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
            Some(state_trees) => Ok(Some(State::new(
                // Safe because StateManager is always an Arc.
                unsafe { shared_from_this(self) },
                state_trees,
            ))),
        }
    }

    fn get_state_for_genesis_write(&self) -> State {
        State::new(
            // Safe because StateManager is always an Arc.
            unsafe { shared_from_this(self) },
            StateTrees {
                snapshot_db: self
                    .storage_manager
                    .wait_for_snapshot(&NULL_EPOCH)
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
            Some(state_trees) => Ok(Some(State::new(
                // Safe because StateManager is always an Arc.
                unsafe { shared_from_this(self) },
                state_trees,
            ))),
        }
    }
}

use crate::{
    statedb::StateDb,
    storage::{
        impls::{
            delta_mpt::*,
            errors::*,
            storage_db::{
                delta_db_manager_rocksdb::DeltaDbManagerRocksdb,
                snapshot_db_manager_sqlite::SnapshotDbManagerSqlite,
            },
            storage_manager::storage_manager::StorageManager,
        },
        state::*,
        state_manager::*,
        storage_db::*,
        utils::arc_ext::shared_from_this,
        StorageConfiguration,
    },
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
