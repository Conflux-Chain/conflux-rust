// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotDbManagerSqlite {
    snapshot_path: String,
    // FIXME: add an command line option to assert that this method made
    // successfully cow_copy and print error messages if it fails.
    force_cow: bool,
}

impl SnapshotDbManagerSqlite {
    const SNAPSHOT_DB_SQLITE_DIR_PREFIX: &'static str = "sqlite_";

    pub fn new(snapshot_path: String) -> Self {
        Self {
            snapshot_path: snapshot_path + Self::SNAPSHOT_DB_SQLITE_DIR_PREFIX,
            force_cow: false,
        }
    }

    fn get_snapshot_db_path(&self, snapshot_epoch_id: &EpochId) -> String {
        self.snapshot_path.clone() + &snapshot_epoch_id.to_hex()
    }

    fn get_merge_temp_snapshot_db_path(
        &self, old_snapshot_epoch_id: &EpochId, delta_merkle_root: &MerkleHash,
    ) -> String {
        self.snapshot_path.clone()
            + "merge_temp_"
            + &old_snapshot_epoch_id.to_hex()
            + &delta_merkle_root.to_hex()
    }

    fn get_full_sync_temp_snapshot_db_path(
        &self, snapshot_epoch_id: &EpochId, merkle_root: &MerkleHash,
    ) -> String {
        self.snapshot_path.clone()
            + "full_sync_temp_"
            + &snapshot_epoch_id.to_hex()
            + &merkle_root.to_hex()
    }

    /// Returns error when cow copy fails; Ok(true) when cow copy succeeded;
    /// Ok(false) when we are running on a system where cow copy isn't
    /// available.
    fn try_make_snapshot_cow_copy_impl(
        &self, old_snapshot_path: &str, new_snapshot_path: &str,
    ) -> Result<bool> {
        let mut command;
        if cfg!(target_os = "linux") {
            // XFS
            command = Command::new("cp");
            command
                .arg("-R --reflink=always")
                .arg(old_snapshot_path)
                .arg(new_snapshot_path);
        } else if cfg!(target_os = "macos") {
            // APFS
            command = Command::new("cp");
            command
                .arg("-R")
                .arg("-c")
                .arg(old_snapshot_path)
                .arg(new_snapshot_path);
        } else {
            return Ok(false);
        };

        let command_result = command.output();
        if command_result.is_err() {
            fs::remove_dir_all(new_snapshot_path)?;
        }
        if !command_result?.status.success() {
            if self.force_cow {
                error!(
                    "COW copy failed, check file system support. Command {:?}",
                    command,
                );
                Err(ErrorKind::SnapshotCowCreation.into())
            } else {
                info!(
                    "COW copy failed, check file system support. Command {:?}",
                    command,
                );
                Ok(false)
            }
        } else {
            Ok(true)
        }
    }

    fn try_copy_snapshot(
        &self, old_snapshot_path: &str, new_snapshot_path: &str,
    ) -> Result<()> {
        if self
            .try_make_snapshot_cow_copy(old_snapshot_path, new_snapshot_path)?
        {
            Ok(())
        } else {
            let mut options = CopyOptions::new();
            options.copy_inside = true; // copy recursively like `cp -r`
            fs_extra::dir::copy(old_snapshot_path, new_snapshot_path, &options)
                .map(|_| ())
                .map_err(|e| {
                    warn!(
                        "Fail to copy snapshot {:?}, err={:?}",
                        old_snapshot_path, e,
                    );
                    ErrorKind::SnapshotCopyFailure.into()
                })
        }
    }

    /// Returns error when cow copy fails, or when cow copy isn't supported with
    /// force_cow setting enabled; Ok(true) when cow copy succeeded;
    /// Ok(false) when cow copy isn't supported with force_cow setting disabled.
    fn try_make_snapshot_cow_copy(
        &self, old_snapshot_path: &str, new_snapshot_path: &str,
    ) -> Result<bool> {
        let result = self.try_make_snapshot_cow_copy_impl(
            old_snapshot_path,
            new_snapshot_path,
        );

        if result.is_err() {
            Ok(false)
        } else if result.unwrap() == false {
            if self.force_cow {
                // FIXME: Check error string.
                error!(
                    "Failed to create a new snapshot by COW. \
                     Use XFS on linux or APFS on Mac"
                );
                Err(ErrorKind::SnapshotCowCreation.into())
            } else {
                Ok(false)
            }
        } else {
            Ok(true)
        }
    }

    fn copy_and_merge(
        &self, temp_snapshot_db: &mut SnapshotDbSqlite,
        old_snapshot_epoch_id: &EpochId,
    ) -> Result<MerkleHash>
    {
        let maybe_old_snapshot_db = SnapshotDbSqlite::open(
            &self.get_snapshot_db_path(old_snapshot_epoch_id),
            true,
        )?;
        let mut old_snapshot_db = maybe_old_snapshot_db
            .ok_or(Error::from(ErrorKind::SnapshotNotFound))?;
        temp_snapshot_db.copy_and_merge(&mut old_snapshot_db)
    }

    fn rename_snapshot_db(old_path: &str, new_path: &str) -> Result<()> {
        Ok(fs::rename(old_path, new_path)?)
    }
}

impl SnapshotDbManagerTrait for SnapshotDbManagerSqlite {
    type SnapshotDb = SnapshotDbSqlite;

    fn scan_persist_state(
        &self, snapshot_info_map: &mut HashMap<EpochId, SnapshotInfo>,
    ) -> Result<Vec<H256>> {
        let mut missing_snapshots = HashMap::new();
        for (snapshot_epoch_id, _snapshot_info) in snapshot_info_map.iter() {
            missing_snapshots.insert(
                [
                    StorageConfiguration::SNAPSHOT_DIR.as_bytes(),
                    Self::SNAPSHOT_DB_SQLITE_DIR_PREFIX.as_bytes(),
                    snapshot_epoch_id.as_ref(),
                ]
                .concat(),
                snapshot_epoch_id.clone(),
            );
        }

        // Scan the snapshot dir. Remove extra files, and return the list of
        // missing snapshots.
        for entry in fs::read_dir(StorageConfiguration::SNAPSHOT_DIR)? {
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

    fn new_snapshot_by_merging(
        &self, old_snapshot_epoch_id: &EpochId, snapshot_epoch_id: EpochId,
        delta_mpt: DeltaMptIterator,
        mut in_progress_snapshot_info: SnapshotInfo,
    ) -> Result<SnapshotInfo>
    {
        debug!(
            "new_snapshot_by_merging: old={:?} new={:?}",
            old_snapshot_epoch_id, snapshot_epoch_id
        );
        // FIXME: clean-up when error happens.
        match &delta_mpt.maybe_root_node {
            None => {
                // This is only for the special case for the second delta mpt.
                // For the first a few blocks, the state is [Empty snapshot,
                // empty intermediate mpt, delta mpt],
                // then [Empty snapshot, intermediate mpt, delta mpt].
                // The merge of Empty snapshot and empty intermediate mpt
                // resulting into an empty snapshot, falls into this code path,
                // where we do nothing.
                in_progress_snapshot_info.merkle_root = MERKLE_NULL_NODE;
                Ok(in_progress_snapshot_info)
            }
            Some(_) => {
                // Unwrap here is safe because the delta MPT is guaranteed not
                // empty.
                let temp_db_path = self.get_merge_temp_snapshot_db_path(
                    old_snapshot_epoch_id,
                    &delta_mpt
                        .mpt
                        .get_merkle(delta_mpt.maybe_root_node.clone())?
                        .unwrap(),
                );

                let mut snapshot_db;
                let new_snapshot_root = if *old_snapshot_epoch_id == NULL_EPOCH
                {
                    // direct merge the first snapshot
                    snapshot_db = Self::SnapshotDb::create(&temp_db_path)?;
                    snapshot_db.dump_delta_mpt(&delta_mpt)?;
                    snapshot_db.direct_merge()?
                } else {
                    if self
                        .try_copy_snapshot(
                            &self.get_snapshot_db_path(old_snapshot_epoch_id),
                            &temp_db_path,
                        )
                        .is_ok()
                    {
                        // open the copied database.
                        snapshot_db =
                            Self::SnapshotDb::open(&temp_db_path, false)?
                                .unwrap();

                        // Drop copied old snapshot delta mpt dump
                        snapshot_db.drop_delta_mpt_dump()?;

                        // iterate and insert into temp table.
                        snapshot_db.dump_delta_mpt(&delta_mpt)?;
                        snapshot_db.direct_merge()?
                    } else {
                        snapshot_db = Self::SnapshotDb::create(&temp_db_path)?;
                        snapshot_db.dump_delta_mpt(&delta_mpt)?;
                        self.copy_and_merge(
                            &mut snapshot_db,
                            old_snapshot_epoch_id,
                        )?
                    }
                };
                in_progress_snapshot_info.merkle_root =
                    new_snapshot_root.clone();
                drop(snapshot_db);
                Self::rename_snapshot_db(
                    &temp_db_path,
                    &self.get_snapshot_db_path(&snapshot_epoch_id),
                )?;

                Ok(in_progress_snapshot_info)
            }
        }
    }

    fn get_snapshot_by_epoch_id(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Result<Option<Self::SnapshotDb>> {
        if snapshot_epoch_id.eq(&NULL_EPOCH) {
            return Ok(Some(Self::SnapshotDb::get_null_snapshot()));
        } else {
            Self::SnapshotDb::open(
                &self.get_snapshot_db_path(snapshot_epoch_id),
                true,
            )
        }
    }

    fn destroy_snapshot(&self, snapshot_epoch_id: &EpochId) -> Result<()> {
        Ok(fs::remove_dir_all(
            self.get_snapshot_db_path(snapshot_epoch_id),
        )?)
    }

    fn new_temp_snapshot_for_full_sync(
        &self, snapshot_epoch_id: &EpochId, merkle_root: &MerkleHash,
    ) -> Result<Self::SnapshotDb> {
        let temp_db_path = self.get_full_sync_temp_snapshot_db_path(
            snapshot_epoch_id,
            merkle_root,
        );
        Self::SnapshotDb::create(&temp_db_path)
    }

    fn finalize_full_sync_snapshot(
        &self, snapshot_epoch_id: &EpochId, merkle_root: &MerkleHash,
    ) -> Result<()> {
        let temp_db_path = self.get_full_sync_temp_snapshot_db_path(
            snapshot_epoch_id,
            merkle_root,
        );
        let final_db_path = self.get_snapshot_db_path(snapshot_epoch_id);
        Self::rename_snapshot_db(&temp_db_path, &final_db_path)
    }
}

use crate::storage::{
    impls::{
        delta_mpt::DeltaMptIterator, errors::*,
        storage_db::snapshot_db_sqlite::*,
    },
    storage_db::{SnapshotDbManagerTrait, SnapshotDbTrait, SnapshotInfo},
    StorageConfiguration,
};
use cfx_types::H256;
use fs_extra::dir::CopyOptions;
use parity_bytes::ToPretty;
use primitives::{EpochId, MerkleHash, MERKLE_NULL_NODE, NULL_EPOCH};
use std::{collections::HashMap, fs, process::Command};
