// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[allow(dead_code)]
pub struct StorageManagerArchiveNode<SnapshotDbManager: SnapshotDbManagerTrait>
{
    snapshot_db_manager: SnapshotDbManager,
}

impl<SnapshotDbManager: SnapshotDbManagerTrait> GetSnapshotDbManager
    for StorageManagerArchiveNode<SnapshotDbManager>
{
    type SnapshotDb = SnapshotDbManager::SnapshotDb;
    type SnapshotDbManager = SnapshotDbManager;

    fn get_snapshot_db_manager(&self) -> &Self::SnapshotDbManager {
        &self.snapshot_db_manager
    }
}

impl<SnapshotDbManager: SnapshotDbManagerTrait> SnapshotManagerTrait
    for StorageManagerArchiveNode<SnapshotDbManager>
{
    fn remove_old_pivot_snapshot(
        &self, _snapshot_epoch_id: &EpochId,
    ) -> Result<()> {
        // FIXME: implement, archive snapshot
        unimplemented!()
    }

    fn remove_non_pivot_snapshot(
        &self, _snapshot_epoch_id: &EpochId,
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
use primitives::EpochId;
