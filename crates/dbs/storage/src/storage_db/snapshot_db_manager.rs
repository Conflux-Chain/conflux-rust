// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Debug)]
pub struct SnapshotPersistState {
    pub missing_snapshots: Vec<EpochId>,
    pub max_epoch_id: EpochId,
    pub max_epoch_height: u64,
    pub temp_snapshot_db_existing: Option<EpochId>,
    pub removed_snapshots: HashSet<EpochId>,
    pub max_snapshot_epoch_height_has_mpt: Option<u64>,
}

pub trait SnapshotDbWriteableTrait: KeyValueDbTypes {
    type SnapshotDbBorrowMutType: SnapshotMptTraitRw;

    fn start_transaction(&mut self) -> Result<()>;

    fn commit_transaction(&mut self) -> Result<()>;

    fn put_kv(
        &mut self, key: &[u8], value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>>;

    fn open_snapshot_mpt_owned(
        &mut self,
    ) -> Result<Self::SnapshotDbBorrowMutType>;
}

/// The trait for database manager of Snapshot.
pub trait SnapshotDbManagerTrait {
    type SnapshotDb: SnapshotDbTrait<ValueType = Box<[u8]>>;
    type SnapshotDbWrite: SnapshotDbWriteableTrait<ValueType = Box<[u8]>>;

    fn get_snapshot_dir(&self) -> &Path;
    fn get_snapshot_db_name(&self, snapshot_epoch_id: &EpochId) -> String;
    fn get_snapshot_db_path(&self, snapshot_epoch_id: &EpochId) -> PathBuf;
    fn get_mpt_snapshot_dir(&self) -> &Path;
    fn get_latest_mpt_snapshot_db_name(&self) -> String;
    fn recovery_latest_mpt_snapshot_from_checkpoint(
        &self, snapshot_epoch_id: &EpochId,
        before_era_pivot_hash: Option<EpochId>,
    ) -> Result<()>;
    fn create_mpt_snapshot_from_latest(
        &self, new_snapshot_epoch_id: &EpochId,
    ) -> Result<()>;
    fn get_epoch_id_from_snapshot_db_name(
        &self, snapshot_db_name: &str,
    ) -> Result<EpochId>;
    fn try_get_new_snapshot_epoch_from_temp_path(
        &self, dir_name: &str,
    ) -> Option<EpochId>;
    fn try_get_new_snapshot_epoch_from_mpt_temp_path(
        &self, dir_name: &str,
    ) -> Option<EpochId>;

    // Scan snapshot dir, remove extra files and return the list of missing
    // snapshots.
    fn scan_persist_state(
        &self, snapshot_info_map: &HashMap<EpochId, SnapshotInfo>,
    ) -> Result<SnapshotPersistState> {
        let mut missing_snapshots = HashMap::new();
        let mut all_snapshots = HashMap::new();
        for (snapshot_epoch_id, snapshot_info) in snapshot_info_map {
            all_snapshots.insert(
                self.get_snapshot_db_name(snapshot_epoch_id).into_bytes(),
                snapshot_epoch_id.clone(),
            );
            // If the snapshot info is kept to provide sync, we allow the
            // snapshot itself to be missing, because a snapshot of
            // snapshot_epoch_id's ancestor is kept to provide sync. We need to
            // keep this snapshot info to know the parental relationship.
            if snapshot_info.snapshot_info_kept_to_provide_sync
                != SnapshotKeptToProvideSyncStatus::InfoOnly
            {
                missing_snapshots.insert(
                    self.get_snapshot_db_name(snapshot_epoch_id).into_bytes(),
                    (snapshot_epoch_id.clone(), snapshot_info.height),
                );
            }
        }

        // Scan the snapshot dir. Remove extra files, and return the list of
        // missing snapshots.
        let mut max_epoch_height = 0;
        let mut max_epoch_id = NULL_EPOCH;
        let mut temp_snapshot_db_existing = None;
        let mut removed_snapshots = HashSet::new();
        let mut max_snapshot_epoch_height_has_mpt = None;

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
            if !all_snapshots.contains_key(dir_name.as_bytes()) {
                error!(
                    "Unexpected snapshot path {}, deleted.",
                    entry.path().display()
                );

                match self.try_get_new_snapshot_epoch_from_temp_path(dir_name) {
                    Some(e) => {
                        info!("remove temp kv snapshot {}", e);
                        if temp_snapshot_db_existing.is_none() {
                            temp_snapshot_db_existing = Some(e);
                        } else {
                            panic!("there are more than one temp kv snapshot");
                        }
                    }
                    None => {
                        if let Ok(epoch_id) =
                            self.get_epoch_id_from_snapshot_db_name(dir_name)
                        {
                            removed_snapshots.insert(epoch_id);
                        }
                    }
                }

                fs::remove_dir_all(entry.path())?;
            } else {
                if let Some((epoch, height)) =
                    missing_snapshots.remove(dir_name.as_bytes())
                {
                    if height > max_epoch_height {
                        max_epoch_height = height;
                        max_epoch_id = epoch;
                    }

                    if self
                        .get_snapshot_by_epoch_id(&epoch, false, false)?
                        .expect("should be open snapshot")
                        .is_mpt_table_in_current_db()
                    {
                        if max_snapshot_epoch_height_has_mpt.is_none()
                            || *max_snapshot_epoch_height_has_mpt
                                .as_ref()
                                .unwrap()
                                < height
                        {
                            max_snapshot_epoch_height_has_mpt = Some(height);
                        }
                    }
                }
            }
        }

        // scan mpt directory, and delete unnecessary snapshots
        for entry in fs::read_dir(self.get_mpt_snapshot_dir())? {
            let entry = entry?;
            let path = entry.path();
            let dir_name = path.as_path().file_name().unwrap().to_str();

            if dir_name.is_none() {
                error!(
                    "Unexpected MPT snapshot path {}, deleted.",
                    entry.path().display()
                );
                fs::remove_dir_all(entry.path())?;
                continue;
            }

            let dir_name = dir_name.unwrap();
            if !all_snapshots.contains_key(dir_name.as_bytes())
                && !self.get_latest_mpt_snapshot_db_name().eq(dir_name)
            {
                error!(
                    "Unexpected MPT snapshot path {}, deleted.",
                    entry.path().display()
                );
                fs::remove_dir_all(entry.path())?;

                if let Some(snapshot_id) =
                    self.try_get_new_snapshot_epoch_from_mpt_temp_path(dir_name)
                {
                    if snapshot_id == max_epoch_id {
                        self.create_mpt_snapshot_from_latest(&snapshot_id)?;
                    }
                }
            }
        }

        info!("max epoch height: {}, temp snapshot db existing: {:?}, removed snapshots: {:?}, max snapshot epoch height has mpt: {:?}", max_epoch_height, temp_snapshot_db_existing, removed_snapshots, max_snapshot_epoch_height_has_mpt);
        Ok(SnapshotPersistState {
            missing_snapshots: missing_snapshots
                .into_iter()
                .map(|(_path_bytes, (snapshot_epoch_id, _))| snapshot_epoch_id)
                .collect(),
            max_epoch_id,
            max_epoch_height,
            temp_snapshot_db_existing,
            removed_snapshots,
            max_snapshot_epoch_height_has_mpt,
        })
    }

    fn new_snapshot_by_merging<'m>(
        &self, old_snapshot_epoch_id: &EpochId, snapshot_epoch_id: EpochId,
        delta_mpt: DeltaMptIterator, in_progress_snapshot_info: SnapshotInfo,
        snapshot_info_map: &'m RwLock<PersistedSnapshotInfoMap>,
        new_epoch_height: u64, recover_mpt_with_kv_snapshot_exist: bool,
    ) -> Result<(RwLockWriteGuard<'m, PersistedSnapshotInfoMap>, SnapshotInfo)>;
    fn get_snapshot_by_epoch_id(
        &self, epoch_id: &EpochId, try_open: bool, open_mpt_snapshot: bool,
    ) -> Result<Option<Self::SnapshotDb>>;
    fn destroy_snapshot(&self, snapshot_epoch_id: &EpochId) -> Result<()>;

    fn new_temp_snapshot_for_full_sync(
        &self, snapshot_epoch_id: &EpochId, merkle_root: &MerkleHash,
        new_epoch_height: u64,
    ) -> Result<Self::SnapshotDbWrite>;
    fn finalize_full_sync_snapshot<'m>(
        &self, snapshot_epoch_id: &EpochId, merkle_root: &MerkleHash,
        snapshot_info_map_rwlock: &'m RwLock<PersistedSnapshotInfoMap>,
    ) -> Result<RwLockWriteGuard<'m, PersistedSnapshotInfoMap>>;
}

use super::{
    super::impls::{delta_mpt::DeltaMptIterator, errors::*},
    snapshot_db::*,
    DbValueType, KeyValueDbTypes, SnapshotMptTraitRw,
};
use crate::impls::storage_manager::PersistedSnapshotInfoMap;
use parking_lot::{RwLock, RwLockWriteGuard};
use primitives::{EpochId, MerkleHash, NULL_EPOCH};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};
