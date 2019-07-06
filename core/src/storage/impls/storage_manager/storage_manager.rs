pub struct StorageManager {
    delta_db_manager: DeltaDbManager,
    snapshot_manager: Box<
        dyn SnapshotManagerTrait<
                DeltaMpt = DeltaMpt,
                SnapshotDb = SnapshotDb,
                SnapshotDbManager = SnapshotDbManager,
            > + Send
            + Sync,
    >,
    maybe_db_destroy_errors: MaybeDbDestroyErrors,
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
    pub fn new(delta_db_manager: DeltaDbManager, /* , node type */) -> Self {
        Self {
            delta_db_manager,
            snapshot_manager: Box::new(StorageManagerFullNode::<
                SnapshotDbManager,
            > {
                snapshot_db_manager: SnapshotDbManager::new(),
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
        let db = storage_manager.delta_db_manager.new_empty_delta_db(
            &DeltaDbManager::delta_db_name(snapshot_root),
        )?;
        Ok(Arc::new(DeltaMpt::new(
            Arc::new(db),
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

// FIXME: What is the best way to wrap around a storage manager?
// FIXME: this method basically chooses a storage manager based
// FIXME: on a FULL_NODE / ARCHIVE_NODE flag.
impl GetSnapshotDbManager for StorageManager {
    type DeltaMpt = DeltaMpt;
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

use super::{
    super::{
        super::{
            snapshot_manager::*, state_manager::*,
            storage_db::delta_db_manager::*,
        },
        errors::*,
        multi_version_merkle_patricia_trie::DeltaMpt,
        state_manager::*,
    },
    *,
};
use parking_lot::RwLock;
use primitives::MerkleHash;
use std::{cell::Cell, collections::HashMap, sync::Arc};
