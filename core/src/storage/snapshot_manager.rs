// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Archive nodes and full nodes react differently for snapshot management.
pub trait SnapshotManagerTrait: GetSnapshotDbManager {
    fn new_snapshot_by_merging(
        &self, old_snapshot_root: &MerkleHash, snapshot_epoch_id: EpochId,
        height: i64, delta_db: DeltaMptInserter,
    ) -> Result<Self::SnapshotDb>
    where
        Self: Sized,
    {
        self.get_snapshot_db_manager().new_snapshot_by_merging(
            old_snapshot_root,
            snapshot_epoch_id,
            height,
            delta_db,
        )
    }

    fn get_snapshot(
        &self, snapshot_root: &MerkleHash,
    ) -> Result<Option<Self::SnapshotDb>>
    where Self: Sized {
        self.get_snapshot_db_manager().get_snapshot(snapshot_root)
    }

    fn get_snapshot_by_epoch_id(
        &self, epoch_id: &EpochId,
    ) -> Result<Option<Self::SnapshotDb>>
    where Self: Sized {
        self.get_snapshot_db_manager()
            .get_snapshot_by_epoch_id(epoch_id)
    }

    fn remove_old_pivot_snapshot(
        &self, snapshot_root: &MerkleHash,
    ) -> Result<()>;

    fn remove_non_pivot_snapshot(
        &self, snapshot_root: &MerkleHash,
    ) -> Result<()>;
}

pub trait GetSnapshotDbManager {
    type SnapshotDb: SnapshotDbTrait;
    type SnapshotDbManager: SnapshotDbManagerTrait<
        SnapshotDb = Self::SnapshotDb,
    >;

    fn get_snapshot_db_manager(&self) -> &Self::SnapshotDbManager;
}

use super::{
    impls::{errors::*, storage_manager::storage_manager::DeltaMptInserter},
    storage_db::{snapshot_db::*, snapshot_db_manager::*},
};
use primitives::{EpochId, MerkleHash};
