// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Archive nodes and full nodes react differently for snapshot management.
pub trait SnapshotManagerTrait: GetSnapshotDbManager {
    // FIXME: add check_make_register_snapshot_background into trait

    fn get_snapshot_by_epoch_id(
        &self, epoch_id: &EpochId,
    ) -> Result<Option<Self::SnapshotDb>> {
        self.get_snapshot_db_manager()
            .get_snapshot_by_epoch_id(epoch_id)
    }

    fn remove_old_pivot_snapshot(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Result<()>;

    fn remove_non_pivot_snapshot(
        &self, snapshot_epoch_id: &EpochId,
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
    impls::errors::*,
    storage_db::{snapshot_db::*, snapshot_db_manager::*},
};
use primitives::EpochId;
