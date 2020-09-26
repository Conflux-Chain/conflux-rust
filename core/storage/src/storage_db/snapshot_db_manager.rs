// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// The trait for database manager of Snapshot.
pub trait SnapshotDbManagerTrait {
    type SnapshotDb: SnapshotDbTrait<ValueType = Box<[u8]>>;

    fn get_snapshot_dir(&self) -> &Path;
    fn get_snapshot_db_name(&self, snapshot_epoch_id: &EpochId) -> String;
    fn get_snapshot_db_path(&self, snapshot_epoch_id: &EpochId) -> PathBuf;

    // Scan snapshot dir, remove extra files and return the list of missing
    // snapshots.
    fn scan_persist_state(
        &self, snapshot_info_map: &HashMap<EpochId, SnapshotInfo>,
    ) -> Result<Vec<EpochId>> {
        let mut missing_snapshots = HashMap::new();
        for (snapshot_epoch_id, _snapshot_info) in snapshot_info_map {
            missing_snapshots.insert(
                self.get_snapshot_db_name(snapshot_epoch_id).into_bytes(),
                snapshot_epoch_id.clone(),
            );
        }

        // Scan the snapshot dir. Remove extra files, and return the list of
        // missing snapshots.
        for entry in fs::read_dir(self.get_snapshot_dir())? {
            let entry = entry?;
            let path = entry.path();
            let dir_name = path.as_path().file_name().unwrap().to_str();
            if dir_name.is_none() {
                error!(
                    "Unexpected snapshot path {}, deleted.",
                    entry.path().display()
                );
                fs::remove_dir_all(entry.path())?;
                continue;
            }
            let dir_name = dir_name.unwrap();
            if !missing_snapshots.contains_key(dir_name.as_bytes()) {
                error!(
                    "Unexpected snapshot path {}, deleted.",
                    entry.path().display()
                );
                fs::remove_dir_all(entry.path())?;
            } else {
                missing_snapshots.remove(dir_name.as_bytes());
            }
        }

        Ok(missing_snapshots
            .into_iter()
            .map(|(_path_bytes, snapshot_epoch_id)| snapshot_epoch_id)
            .collect())
    }

    fn new_snapshot_by_merging<'m>(
        &self, old_snapshot_epoch_id: &EpochId, snapshot_epoch_id: EpochId,
        delta_mpt: DeltaMptIterator, in_progress_snapshot_info: SnapshotInfo,
        snapshot_info_map: &'m RwLock<PersistedSnapshotInfoMap>,
    ) -> Result<(RwLockWriteGuard<'m, PersistedSnapshotInfoMap>, SnapshotInfo)>;
    fn get_snapshot_by_epoch_id(
        &self, epoch_id: &EpochId, try_open: bool,
    ) -> Result<Option<Arc<Self::SnapshotDb>>>;
    fn destroy_snapshot(&self, snapshot_epoch_id: &EpochId) -> Result<()>;

    fn new_temp_snapshot_for_full_sync(
        &self, snapshot_epoch_id: &EpochId, merkle_root: &MerkleHash,
    ) -> Result<Self::SnapshotDb>;
    fn finalize_full_sync_snapshot<'m>(
        &self, snapshot_epoch_id: &EpochId, merkle_root: &MerkleHash,
        snapshot_info_map_rwlock: &'m RwLock<PersistedSnapshotInfoMap>,
    ) -> Result<RwLockWriteGuard<'m, PersistedSnapshotInfoMap>>;
}

use super::{
    super::impls::{delta_mpt::DeltaMptIterator, errors::*},
    snapshot_db::*,
};
use crate::impls::storage_manager::PersistedSnapshotInfoMap;
use parking_lot::{RwLock, RwLockWriteGuard};
use primitives::{EpochId, MerkleHash};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
