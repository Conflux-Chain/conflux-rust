// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotDbManagerSqlite {
    snapshot_path: String,
    // FIXME: add an command line option to assert that this method made
    // successfully cow_copy and print error messages if it fails.
    force_cow: bool,
    already_open_snapshots: AlreadyOpenSnapshots<SnapshotDbSqlite>,
    /// Set a limit on the number of open snapshots. When the limit is reached,
    /// consensus initiated open should wait, other non-critical opens such as
    /// rpc initiated opens should simply abort when the limit is reached.
    open_snapshot_semaphore: Arc<Semaphore>,
    open_create_delete_lock: Mutex<()>,
}

// The map from path to the already open snapshots.
// when the mapped snapshot is None, the snapshot is open exclusively for write,
// when the mapped snapshot is Some(), the snapshot can be shared by other
// readers.
pub type AlreadyOpenSnapshots<T> =
    Arc<RwLock<HashMap<String, Option<Weak<T>>>>>;

impl SnapshotDbManagerSqlite {
    const SNAPSHOT_DB_SQLITE_DIR_PREFIX: &'static str = "sqlite_";

    pub fn new(snapshot_path: String, max_open_snapshots: u16) -> Result<Self> {
        let snapshot_dir = Path::new(snapshot_path.as_str());
        if !snapshot_dir.exists() {
            fs::create_dir_all(snapshot_dir)?;
        }

        Ok(Self {
            snapshot_path,
            force_cow: false,
            already_open_snapshots: Default::default(),
            open_snapshot_semaphore: Arc::new(Semaphore::new(
                max_open_snapshots as usize,
            )),
            open_create_delete_lock: Default::default(),
        })
    }

    fn open_snapshot_readonly(
        &self, snapshot_path: &str, try_open: bool,
    ) -> Result<Option<Arc<SnapshotDbSqlite>>> {
        if let Some(already_open) =
            self.already_open_snapshots.read().get(snapshot_path)
        {
            match already_open {
                None => {
                    // Already open for exclusive write
                    return Ok(None);
                }
                Some(open_shared_weak) => {
                    match Weak::upgrade(open_shared_weak) {
                        None => {}
                        Some(already_open) => {
                            return Ok(Some(already_open));
                        }
                    }
                }
            }
        }
        let file_exists = Path::new(&snapshot_path).exists();
        if file_exists {
            let semaphore_permit = if try_open {
                self.open_snapshot_semaphore
                    .try_acquire()
                    // Unfortunately we have to use map_error because the
                    // TryAcquireError isn't public.
                    .map_err(|_err| ErrorKind::SemaphoreTryAcquireError)?
            } else {
                executor::block_on(self.open_snapshot_semaphore.acquire())
            };

            // To serialize simultaneous opens.
            let _open_lock = self.open_create_delete_lock.lock();
            if let Some(already_open) =
                self.already_open_snapshots.read().get(snapshot_path)
            {
                match already_open {
                    None => {
                        // Already open for exclusive write
                        return Ok(None);
                    }
                    Some(open_shared_weak) => {
                        match Weak::upgrade(open_shared_weak) {
                            None => {}
                            Some(already_open) => {
                                return Ok(Some(already_open));
                            }
                        }
                    }
                }
            }

            let snapshot_db = Arc::new(SnapshotDbSqlite::open(
                snapshot_path,
                /* readonly = */ true,
                &self.already_open_snapshots,
                &self.open_snapshot_semaphore,
            )?);

            semaphore_permit.forget();
            self.already_open_snapshots.write().insert(
                snapshot_path.into(),
                Some(Arc::downgrade(&snapshot_db)),
            );

            return Ok(Some(snapshot_db));
        } else {
            return Ok(None);
        }
    }

    fn open_snapshot_write(
        &self, snapshot_path: &str, create: bool,
    ) -> Result<SnapshotDbSqlite> {
        if self
            .already_open_snapshots
            .read()
            .get(snapshot_path)
            .is_some()
        {
            bail!(ErrorKind::SnapshotAlreadyExists)
        }

        let semaphore_permit =
            executor::block_on(self.open_snapshot_semaphore.acquire());
        // When an open happens around the same time, we should make sure that
        // the open returns None.
        let mut _open_lock = self.open_create_delete_lock.lock();

        // Simultaneous creation fails here.
        if self
            .already_open_snapshots
            .read()
            .get(snapshot_path)
            .is_some()
        {
            bail!(ErrorKind::SnapshotAlreadyExists)
        }

        let snapshot_db = if create {
            SnapshotDbSqlite::create(
                snapshot_path,
                &self.already_open_snapshots,
                &self.open_snapshot_semaphore,
            )
        } else {
            let file_exists = Path::new(&snapshot_path).exists();
            if file_exists {
                SnapshotDbSqlite::open(
                    snapshot_path,
                    /* readonly = */ false,
                    &self.already_open_snapshots,
                    &self.open_snapshot_semaphore,
                )
            } else {
                bail!(ErrorKind::SnapshotNotFound);
            }
        }?;

        semaphore_permit.forget();
        self.already_open_snapshots
            .write()
            .insert(snapshot_path.to_string(), None);
        Ok(snapshot_db)
    }

    pub fn on_close(
        already_open_snapshots: &AlreadyOpenSnapshots<SnapshotDbSqlite>,
        open_semaphore: &Arc<Semaphore>, path: &str, remove_on_close: bool,
    )
    {
        // Destroy at close.
        if remove_on_close {
            // When removal fails, we can not raise the error because this
            // function is called within a destructor.
            //
            // It's fine to just ignore the error because Conflux doesn't remove
            // then immediate create a snapshot, or open the snapshot for
            // modification.
            //
            // Conflux will remove orphan storage upon restart.
            Self::fs_remove_snapshot(path).ok();
        }
        already_open_snapshots.write().remove(path);
        open_semaphore.add_permits(1);
    }

    fn fs_remove_snapshot(path: &str) -> Result<()> {
        debug!("Remove snapshot at {}", path);
        Ok(fs::remove_dir_all(path)?)
    }

    fn get_merge_temp_snapshot_db_path(
        &self, old_snapshot_epoch_id: &EpochId, delta_merkle_root: &MerkleHash,
    ) -> String {
        self.snapshot_path.clone()
            + Self::SNAPSHOT_DB_SQLITE_DIR_PREFIX
            + "merge_temp_"
            + &old_snapshot_epoch_id.to_hex()
            + &delta_merkle_root.to_hex()
    }

    fn get_full_sync_temp_snapshot_db_path(
        &self, snapshot_epoch_id: &EpochId, merkle_root: &MerkleHash,
    ) -> String {
        self.snapshot_path.clone()
            + Self::SNAPSHOT_DB_SQLITE_DIR_PREFIX
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
                .arg("-R")
                .arg("--reflink=always")
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
            fs::remove_dir_all(new_snapshot_path)?;
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
        let snapshot_path = self.get_snapshot_db_path(old_snapshot_epoch_id);
        let maybe_old_snapshot_db = Self::open_snapshot_readonly(
            self,
            &snapshot_path,
            /* try_open = */ false,
        )?;
        let old_snapshot_db = maybe_old_snapshot_db
            .ok_or(Error::from(ErrorKind::SnapshotNotFound))?;
        temp_snapshot_db.copy_and_merge(&old_snapshot_db)
    }

    fn rename_snapshot_db(old_path: &str, new_path: &str) -> Result<()> {
        Ok(fs::rename(old_path, new_path)?)
    }
}

impl SnapshotDbManagerTrait for SnapshotDbManagerSqlite {
    type SnapshotDb = SnapshotDbSqlite;

    fn get_snapshot_dir(&self) -> String { self.snapshot_path.clone() }

    fn get_snapshot_db_name(&self, snapshot_epoch_id: &EpochId) -> String {
        Self::SNAPSHOT_DB_SQLITE_DIR_PREFIX.to_string()
            + &snapshot_epoch_id.to_hex()
    }

    fn get_snapshot_db_path(&self, snapshot_epoch_id: &EpochId) -> String {
        self.snapshot_path.clone()
            + &self.get_snapshot_db_name(snapshot_epoch_id)
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
                    snapshot_db = Self::SnapshotDb::create(
                        &temp_db_path,
                        &self.already_open_snapshots,
                        &self.open_snapshot_semaphore,
                    )?;
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
                        // Open the copied database.
                        snapshot_db = self.open_snapshot_write(
                            &temp_db_path,
                            /* create = */ false,
                        )?;

                        // Drop copied old snapshot delta mpt dump
                        snapshot_db.drop_delta_mpt_dump()?;

                        // iterate and insert into temp table.
                        snapshot_db.dump_delta_mpt(&delta_mpt)?;
                        snapshot_db.direct_merge()?
                    } else {
                        snapshot_db = self.open_snapshot_write(
                            &temp_db_path,
                            /* create = */ true,
                        )?;
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
        &self, snapshot_epoch_id: &EpochId, try_open: bool,
    ) -> Result<Option<Arc<Self::SnapshotDb>>> {
        if snapshot_epoch_id.eq(&NULL_EPOCH) {
            return Ok(Some(Arc::new(Self::SnapshotDb::get_null_snapshot())));
        } else {
            let path = self.get_snapshot_db_path(snapshot_epoch_id);
            self.open_snapshot_readonly(&path, try_open)
        }
    }

    fn destroy_snapshot(&self, snapshot_epoch_id: &EpochId) -> Result<()> {
        let path = self.get_snapshot_db_path(snapshot_epoch_id);
        let maybe_snapshot = match self.already_open_snapshots.read().get(&path)
        {
            Some(Some(snapshot)) => Weak::upgrade(snapshot),
            Some(None) => {
                // This should not happen because Conflux always write on a
                // snapshot db under a temporary name. All completed snapshots
                // are readonly.
                if cfg!(debug_assertions) {
                    unreachable!("Try to destroy a snapshot being open exclusively for write.")
                } else {
                    unsafe { unreachable_unchecked() }
                }
            }
            None => None,
        };

        match maybe_snapshot {
            None => {
                if snapshot_epoch_id.ne(&NULL_EPOCH) {
                    Self::fs_remove_snapshot(&path)?;
                }
            }
            Some(snapshot) => {
                snapshot.set_remove_on_last_close();
            }
        };

        Ok(())
    }

    fn new_temp_snapshot_for_full_sync(
        &self, snapshot_epoch_id: &EpochId, merkle_root: &MerkleHash,
    ) -> Result<Self::SnapshotDb> {
        let temp_db_path = self.get_full_sync_temp_snapshot_db_path(
            snapshot_epoch_id,
            merkle_root,
        );
        self.open_snapshot_write(&temp_db_path, /* create = */ true)
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
};
use fs_extra::dir::CopyOptions;
use futures::executor;
use parity_bytes::ToPretty;
use parking_lot::{Mutex, RwLock};
use primitives::{EpochId, MerkleHash, MERKLE_NULL_NODE, NULL_EPOCH};
use std::{
    collections::HashMap,
    fs,
    hint::unreachable_unchecked,
    path::Path,
    process::Command,
    sync::{Arc, Weak},
};
use tokio::sync::Semaphore;
