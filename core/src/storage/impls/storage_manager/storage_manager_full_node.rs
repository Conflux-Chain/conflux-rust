pub struct StorageManagerFullNode<SnapshotDbManager: SnapshotDbManagerTrait> {
    // FIXME: implement a new method and remove pub on fields.
    pub snapshot_db_manager: SnapshotDbManager,
}

impl<SnapshotDbManager: SnapshotDbManagerTrait> GetSnapshotDbManager
    for StorageManagerFullNode<SnapshotDbManager>
{
    type DeltaMpt = SnapshotDbManager::DeltaMpt;
    type SnapshotDb = SnapshotDbManager::SnapshotDb;
    type SnapshotDbManager = SnapshotDbManager;

    fn get_snapshot_db_manager(&self) -> &Self::SnapshotDbManager {
        &self.snapshot_db_manager
    }
}

impl<SnapshotDbManager: SnapshotDbManagerTrait> SnapshotManagerTrait
    for StorageManagerFullNode<SnapshotDbManager>
{
    fn remove_old_pivot_snapshot(
        &self, _snapshot_root: &MerkleHash,
    ) -> Result<()> {
        // FIXME: implement, delete snapshot
        unimplemented!()
    }

    fn remove_non_pivot_snapshot(
        &self, _snapshot_root: &MerkleHash,
    ) -> Result<()> {
        // FIXME: implement, delete snapshot
        unimplemented!()
    }
}

use super::super::{
    super::{
        snapshot_manager::*,
        storage_db::snapshot_db_manager::SnapshotDbManagerTrait,
    },
    errors::*,
};
use primitives::MerkleHash;
