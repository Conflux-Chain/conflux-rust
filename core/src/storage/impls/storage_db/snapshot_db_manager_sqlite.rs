// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotDbManagerSqlite {
    snapshot_path: String,
    // TODO GC merkle_root
    merkle_root_by_snapshot_epoch_id: RwLock<HashMap<EpochId, MerkleHash>>,
    snapshot_metadata_db: Box<dyn KeyValueDbTrait<ValueType = Box<[u8]>>>,
    // FIXME: add an command line option to assert that this method made
    // successfully cow_copy and print error messages if it fails.
    force_cow: bool,
}

// TODO: used to sync checkpoint state
// Note, the sync state context only has instance of type StateManager.
impl Default for SnapshotDbManagerSqlite {
    fn default() -> Self { unimplemented!() }
}

impl SnapshotDbManagerSqlite {
    pub fn new(
        snapshot_path: String,
        snapshot_metadata_db: Box<dyn KeyValueDbTrait<ValueType = Box<[u8]>>>,
    ) -> Self
    {
        Self {
            snapshot_path: snapshot_path + "/sqlite_",
            force_cow: false,
            merkle_root_by_snapshot_epoch_id: Default::default(),
            snapshot_metadata_db,
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
        } else if cfg!(target_os = "mac") {
            // APFS
            command = Command::new("cp");
            command
                .arg("-R -c")
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
        delta_mpt: &DumpedDeltaMptIterator,
    ) -> Result<MerkleHash>
    {
        let maybe_old_snapshot_db = SnapshotDbSqlite::open(
            &self.get_snapshot_db_path(old_snapshot_epoch_id),
            *old_snapshot_merkle_root,
        )?;
        let mut old_snapshot_db = maybe_old_snapshot_db
            .ok_or(Error::from(ErrorKind::SnapshotNotFound))?;
        temp_snapshot_db.copy_and_merge(&mut old_snapshot_db)
    }

    fn rename_snapshot_db(old_path: &str, new_path: &str) -> Result<()> {
        Ok(fs::rename(old_path, new_path)?)
    }

    fn insert_snapshot_merkle_root(
        &self, snapshot_epoch_id: EpochId, merkle_root: MerkleHash,
    ) -> Result<()> {
        self.merkle_root_by_snapshot_epoch_id
            .write()
            .insert(snapshot_epoch_id, merkle_root);
        self.snapshot_metadata_db
            .put(snapshot_epoch_id.as_bytes(), &rlp::encode(&merkle_root))?;
        Ok(())
    }

    fn load_snapshot_merkle_root_from_db(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Result<Option<MerkleHash>> {
        let bytes = self
            .snapshot_metadata_db
            .get(snapshot_epoch_id.as_bytes())?;
        match bytes {
            Some(b) => Ok(rlp::decode(&b)?),
            None => Ok(None),
        }
    }

    fn get_snapshot_merkle_root(
        &self, snapshot_epoch_id: &EpochId,
    ) -> Result<Option<MerkleHash>> {
        match self
            .merkle_root_by_snapshot_epoch_id
            .read()
            .get(snapshot_epoch_id)
        {
            Some(merkle_root) => Ok(Some(*merkle_root)),
            None => self.load_snapshot_merkle_root_from_db(snapshot_epoch_id),
        }
    }
}

impl SnapshotDbManagerTrait for SnapshotDbManagerSqlite {
    type SnapshotDb = SnapshotDbSqlite;

    fn new_snapshot_by_merging(
        &self, old_snapshot_epoch_id: &EpochId, snapshot_epoch_id: EpochId,
        delta_mpt: DeltaMptIterator,
        mut in_progress_snapshot_info: SnapshotInfo,
    ) -> Result<SnapshotInfo>
    {
        let old_snapshot_merkle_root = self
            .get_snapshot_merkle_root(old_snapshot_epoch_id)?
            .unwrap_or(MERKLE_NULL_NODE);
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
                Ok(SnapshotInfo::genesis_snapshot_info())
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
                        old_snapshot_merkle_root,
                    )?;
                    let dumped = snapshot_db.dump_delta_mpt(&delta_mpt)?;
                    snapshot_db.direct_merge()?
                } else {
                    if self.try_make_snapshot_cow_copy(
                        &self.get_snapshot_db_path(old_snapshot_epoch_id),
                        &temp_db_path,
                    )? {
                        // open the copied database.
                        snapshot_db = Self::SnapshotDb::open(
                            &temp_db_path,
                            old_snapshot_merkle_root,
                        )?
                        .unwrap();

                        // Drop copied old snapshot delta mpt dump
                        snapshot_db.drop_delta_mpt_dump()?;

                        // iterate and insert into temp table.
                        let dumped = snapshot_db.dump_delta_mpt(&delta_mpt)?;
                        snapshot_db.direct_merge()?
                    } else {
                        snapshot_db = Self::SnapshotDb::create(
                            &temp_db_path,
                            old_snapshot_merkle_root,
                        )?;
                        let dumped = snapshot_db.dump_delta_mpt(&delta_mpt)?;
                        self.copy_and_merge(
                            &mut snapshot_db,
                            old_snapshot_epoch_id,
                            &old_snapshot_merkle_root,
                        )?
                    }
                };
                // TODO Check the order of all the operations to ensure
                // consistency
                self.insert_snapshot_merkle_root(
                    snapshot_epoch_id,
                    new_snapshot_root,
                )?;
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
            let merkle_root = self
                .get_snapshot_merkle_root(snapshot_epoch_id)?
                .unwrap_or(MERKLE_NULL_NODE);
            Self::SnapshotDb::open(
                &self.get_snapshot_db_path(snapshot_epoch_id),
                merkle_root,
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
        Self::SnapshotDb::create(&temp_db_path, *merkle_root)
    }
}

#[derive(Default)]
pub struct DumpedDeltaMptIterator {
    kv: Vec<(Vec<u8>, Box<[u8]>)>,
}

impl DumpedDeltaMptIterator {
    pub fn iterate<'a, DeltaMptDumper: KVInserter<(Vec<u8>, Box<[u8]>)>>(
        &self, dumper: &mut DeltaMptDumper,
    ) -> Result<()> {
        let mut sorted_kv = self.kv.clone();
        sorted_kv.sort();
        for kv_item in sorted_kv {
            dumper.push(kv_item)?;
        }
        Ok(())
    }
}

impl KVInserter<(Vec<u8>, Box<[u8]>)> for DumpedDeltaMptIterator {
    fn push(&mut self, v: (Vec<u8>, Box<[u8]>)) -> Result<()> {
        let (mpt_key, value) = v;
        let mut addr = Address::default();
        let snapshot_key =
            StorageKey::from_delta_mpt_key(&mpt_key, addr.as_bytes_mut())
                .to_key_bytes();

        self.kv.push((snapshot_key, value));
        Ok(())
    }
}

use super::{
    super::{
        super::storage_db::{
            SnapshotDbManagerTrait, SnapshotDbTrait, SnapshotInfo,
        },
        errors::*,
        storage_manager::DeltaMptIterator,
    },
    snapshot_db_sqlite::*,
};
use crate::storage::{KVInserter, KeyValueDbTrait};
use cfx_types::Address;
use parity_bytes::ToPretty;
use parking_lot::RwLock;
use primitives::{
    EpochId, MerkleHash, StorageKey, MERKLE_NULL_NODE, NULL_EPOCH,
};
use std::{collections::HashMap, fs, process::Command};
