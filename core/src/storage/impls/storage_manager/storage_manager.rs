// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// FIXME: correctly order code blocks.
pub struct StorageManager {
    delta_db_manager: DeltaDbManager,
    snapshot_manager: Box<
        dyn SnapshotManagerTrait<
                SnapshotDb = SnapshotDb,
                SnapshotDbManager = SnapshotDbManager,
            > + Send
            + Sync,
    >,
    maybe_db_destroy_errors: MaybeDbDestroyErrors,
    // FIXME: when do insertions happen?
    snapshot_associated_mpts:
        RwLock<HashMap<MerkleHash, (Arc<DeltaMpt>, Arc<DeltaMpt>)>>,
}

struct MaybeDbDestroyErrors {
    error_1: Cell<Option<Result<()>>>,
    error_2: Cell<Option<Result<()>>>,
}

// It's only used when relevant lock has been acquired.
unsafe impl Sync for MaybeDbDestroyErrors {}

impl StorageManager {
    // FIXME: should load persistent storage from disk.
    pub fn new(
        delta_db_manager: DeltaDbManager, /* , node type, full node or
                                          * archive node */
    ) -> Self
    {
        Self {
            delta_db_manager,
            snapshot_manager: Box::new(StorageManagerFullNode::<
                SnapshotDbManager,
            > {
                // FIXME: path from param.
                snapshot_db_manager: SnapshotDbManager::new(
                    "./storage_db/snapshot/".to_string(),
                ),
            }),
            maybe_db_destroy_errors: MaybeDbDestroyErrors {
                error_1: Cell::new(None),
                error_2: Cell::new(None),
            },
            snapshot_associated_mpts: RwLock::new(Default::default()),
        }
    }
}

/// Struct which makes sure that the delta mpt is properly ref-counted and
/// released.
pub struct DeltaDbReleaser {
    pub storage_manager: Arc<StorageManager>,
    pub snapshot_root: MerkleHash,
}

impl Drop for DeltaDbReleaser {
    fn drop(&mut self) {
        // FIXME: we must make sure that the latest delta db does not get
        // FIXME: destroyed at program exit. The current code is broken.

        // Note that when an error happens in db, the program should fail
        // gracefully, but not in destructor.
        self.storage_manager
            .release_delta_mpt_actions_in_drop(&self.snapshot_root);
    }
}

impl StorageManager {
    pub fn get_delta_mpt(
        &self, snapshot_root: &MerkleHash,
    ) -> Option<Arc<DeltaMpt>> {
        self.snapshot_associated_mpts
            .read()
            .get(snapshot_root)
            .map(|mpts| mpts.1.clone())
    }

    pub fn new_delta_mpt(
        storage_manager: Arc<StorageManager>, snapshot_root: &MerkleHash,
        intermediate_delta_root: &MerkleHash, conf: StorageConfiguration,
    ) -> Result<Arc<DeltaMpt>>
    {
        let db =
            Arc::new(storage_manager.delta_db_manager.new_empty_delta_db(
                &DeltaDbManager::delta_db_name(snapshot_root),
            )?);
        Ok(Arc::new(DeltaMpt::new(
            db,
            conf,
            DeltaMpt::padding(snapshot_root, intermediate_delta_root),
            snapshot_root.clone(),
            storage_manager.clone(),
        )))
    }

    /// The methods clean up Delta DB when dropping an Delta MPT.
    /// It silently finishes and in case of error, it keeps the error
    /// and raise it later on.
    fn release_delta_mpt_actions_in_drop(&self, snapshot_root: &MerkleHash) {
        let maybe_another_error = self.maybe_db_destroy_errors.error_1.replace(
            Some(self.delta_db_manager.destroy_delta_db(
                &DeltaDbManager::delta_db_name(snapshot_root),
            )),
        );
        self.maybe_db_destroy_errors
            .error_2
            .set(maybe_another_error);
    }

    fn release_delta_mpts_from_snapshot(
        &self, snapshot_root: &MerkleHash,
    ) -> Result<()> {
        let mut snapshot_associated_mpts_guard =
            self.snapshot_associated_mpts.write();
        // Release
        snapshot_associated_mpts_guard.remove(snapshot_root);
        self.check_db_destroy_errors()
    }

    fn check_db_destroy_errors(&self) -> Result<()> {
        let _maybe_error_1 = self.maybe_db_destroy_errors.error_1.take();
        let _maybe_error_2 = self.maybe_db_destroy_errors.error_2.take();
        // FIXME: Combine two errors, instruct users, and raise combined error.
        unimplemented!()
    }
}

impl GetSnapshotDbManager for StorageManager {
    type SnapshotDb = SnapshotDb;
    type SnapshotDbManager = SnapshotDbManager;

    fn get_snapshot_db_manager(&self) -> &Self::SnapshotDbManager {
        &self.snapshot_manager.get_snapshot_db_manager()
    }
}

impl SnapshotManagerTrait for StorageManager {
    fn remove_old_pivot_snapshot(
        &self, snapshot_root: &MerkleHash,
    ) -> Result<()> {
        self.release_delta_mpts_from_snapshot(snapshot_root)?;
        self.snapshot_manager
            .remove_old_pivot_snapshot(snapshot_root)
    }

    fn remove_non_pivot_snapshot(
        &self, snapshot_root: &MerkleHash,
    ) -> Result<()> {
        self.release_delta_mpts_from_snapshot(snapshot_root)?;
        self.snapshot_manager
            .remove_non_pivot_snapshot(snapshot_root)
    }
}

#[derive(Clone)]
pub struct DeltaMptInserter {
    pub mpt: Arc<DeltaMpt>,
    pub maybe_root_node: Option<NodeRefDeltaMpt>,
}

impl DeltaMptInserter {
    pub fn iterate<'a, DeltaMptDumper: KVInserter<(Vec<u8>, Box<[u8]>)>>(
        &self, dumper: &mut DeltaMptDumper,
    ) -> Result<()> {
        match &self.maybe_root_node {
            None => {}
            Some(root_node) => {
                let db = &mut *self.mpt.db_owned_read()?;
                let owned_node_set = Default::default();
                let mut cow_root_node =
                    CowNodeRef::new(root_node.clone(), &owned_node_set);
                let guarded_trie_node =
                    GuardedValue::take(cow_root_node.get_trie_node(
                        self.mpt.get_node_memory_manager(),
                        &self.mpt.get_node_memory_manager().get_allocator(),
                        db,
                    )?);
                cow_root_node.iterate_internal(
                    &owned_node_set,
                    &self.mpt,
                    guarded_trie_node,
                    CompressedPathRaw::new_zeroed(0, 0),
                    dumper,
                    db,
                )?;
            }
        }
        Ok(())
    }
}

use super::{
    super::{
        super::{
            snapshot_manager::*, state_manager::*,
            storage_db::delta_db_manager::*,
        },
        errors::*,
        multi_version_merkle_patricia_trie::{
            guarded_value::GuardedValue,
            merkle_patricia_trie::{
                cow_node_ref::KVInserter, CompressedPathRaw, CowNodeRef,
                NodeRefDeltaMpt,
            },
            DeltaMpt,
        },
        state_manager::*,
    },
    *,
};
use parking_lot::RwLock;
use primitives::MerkleHash;
use std::{cell::Cell, collections::HashMap, sync::Arc};
