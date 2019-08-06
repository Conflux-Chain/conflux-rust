// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotDbManagerSqlite {
    // TODO: persistent in db.
    epoch_to_snapshot_root: RwLock<HashMap<EpochId, MerkleHash>>,
    empty_snapshot: Arc<<Self as SnapshotDbManagerTrait>::SnapshotDb>,
    snapshot_path: String,
    force_cow: bool,
}

impl SnapshotDbManagerSqlite {
    pub fn new(snapshot_path: String) -> Self {
        Self {
            epoch_to_snapshot_root: Default::default(),
            empty_snapshot: Arc::new(
                <Self as SnapshotDbManagerTrait>::SnapshotDb::default(),
            ),
            snapshot_path: snapshot_path + "/sqlite",
            force_cow: true,
        }
    }

    fn get_snapshot_db_path(&self, snapshot_root: &MerkleHash) -> String {
        self.snapshot_path.clone() + &snapshot_root.hex()
    }

    fn get_temp_snapshot_db_path(
        &self, old_snapshot_root: &MerkleHash, delta_merkle_root: &MerkleHash,
    ) -> String {
        self.snapshot_path.clone()
            + "merge_temp_"
            + &old_snapshot_root.hex()
            + &delta_merkle_root.hex()
    }

    // FIXME: add an command line option to assert that this method made
    // successfully cow_copy and print error messages if it fails.
    fn try_make_cow_copy_impl(
        old_snapshot_path: &String, new_snapshot_path: &String,
    ) -> Result<bool> {
        if cfg!(target_os = "windows") {
            return Ok(false);
        } else if cfg!(target_os = "linux") {
            // FIXME: what if the command returns non-zero?
            // XFS
            Command::new("cp")
                .arg("--reflink")
                .arg(old_snapshot_path)
                .arg(new_snapshot_path)
                .output()?;
            return Ok(true);
        } else if cfg!(target_os = "mac") {
            // APFS
            Command::new("cp")
                .arg("-c")
                .arg(old_snapshot_path)
                .arg(new_snapshot_path)
                .output()?;
            return Ok(true);
        } else {
            return Ok(false);
        }
    }

    fn try_make_cow_copy(
        &self, old_snapshot_path: &String, new_snapshot_path: &String,
    ) -> Result<bool> {
        let result =
            Self::try_make_cow_copy_impl(old_snapshot_path, new_snapshot_path);

        if result.is_err() || (result.unwrap() == false) {
            if self.force_cow {
                // FIXME: do not duplicate error string.
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
        &self, temp_snapshot_db: &SnapshotDbSqlite,
        old_snapshot_root: &MerkleHash, delta_mpt: &DeltaMptInserter,
    ) -> Result<MerkleHash>
    {
        let maybe_old_snapshot_db = SnapshotDbSqlite::open(
            &self.get_snapshot_db_path(old_snapshot_root),
        )?;
        let old_snapshot_db = maybe_old_snapshot_db
            .ok_or(Error::from(ErrorKind::SnapshotNotFound))?;

        temp_snapshot_db.copy_and_merge(&old_snapshot_db, delta_mpt)
    }

    fn rename_snapshot_db(old_path: &String, new_path: &String) -> Result<()> {
        Ok(fs::rename(old_path, new_path)?)
    }
}

impl SnapshotDbManagerTrait for SnapshotDbManagerSqlite {
    type SnapshotDb = SnapshotDbSqlite;

    fn new_snapshot_by_merging(
        &self, old_snapshot_root: &MerkleHash, snapshot_epoch_id: EpochId,
        height: u64, delta_mpt: DeltaMptInserter,
    ) -> Result<Arc<Self::SnapshotDb>>
    {
        match &delta_mpt.maybe_root_node {
            None => Ok(self.get_snapshot(&old_snapshot_root)?.unwrap()),
            Some(_) => {
                // Unwrap here is safe because the delta MPT is guaranteed not
                // empty.
                let temp_db_name = self.get_temp_snapshot_db_path(
                    old_snapshot_root,
                    &delta_mpt
                        .mpt
                        .get_merkle(delta_mpt.maybe_root_node.clone())?
                        .unwrap(),
                );

                let snapshot_db;
                let new_snapshot_root = if self.try_make_cow_copy(
                    &self.get_snapshot_db_path(old_snapshot_root),
                    &temp_db_name,
                )? {
                    // open the database.
                    snapshot_db =
                        Self::SnapshotDb::open(&temp_db_name)?.unwrap();

                    // iterate and insert into temp table.
                    snapshot_db.dump_delta_mpt(&delta_mpt)?;
                    snapshot_db.direct_merge(&delta_mpt)?
                } else {
                    snapshot_db =
                        Self::SnapshotDb::create(&temp_db_name, height)?;
                    snapshot_db.dump_delta_mpt(&delta_mpt)?;
                    self.copy_and_merge(
                        &snapshot_db,
                        old_snapshot_root,
                        &delta_mpt,
                    )?
                };

                snapshot_db.drop_delta_mpt_dump()?;

                drop(snapshot_db);
                Self::rename_snapshot_db(
                    &temp_db_name,
                    &self.get_snapshot_db_path(&new_snapshot_root),
                )?;
                self.epoch_to_snapshot_root
                    .write()
                    .insert(snapshot_epoch_id, new_snapshot_root);

                Ok(self.get_snapshot(&new_snapshot_root)?.unwrap())
            }
        }
    }

    fn get_snapshot(
        &self, snapshot_root: &MerkleHash,
    ) -> Result<Option<Arc<Self::SnapshotDb>>> {
        if snapshot_root.eq(&MERKLE_NULL_NODE) {
            return Ok(Some(self.empty_snapshot.clone()));
        } else {
            Self::SnapshotDb::open(&self.get_snapshot_db_path(snapshot_root))
        }
    }

    // FIXME: when remove, remember TRIM
    fn destroy_snapshot(&self, snapshot_root: &MerkleHash) -> Result<()> {
        Ok(fs::remove_file(self.get_snapshot_db_path(snapshot_root))?)
    }

    fn get_snapshot_by_epoch_id(
        &self, epoch_id: &EpochId,
    ) -> Result<Option<Arc<Self::SnapshotDb>>> {
        match self.epoch_to_snapshot_root.read().get(epoch_id) {
            None => Ok(None),
            Some(snapshot_root) => self.get_snapshot(snapshot_root),
        }
    }
}

use super::{
    super::{
        super::storage_db::SnapshotDbManagerTrait, errors::*,
        storage_manager::DeltaMptInserter,
    },
    snapshot_db_sqlite::*,
};
use parking_lot::RwLock;
use primitives::{EpochId, MerkleHash, MERKLE_NULL_NODE};
use std::{collections::HashMap, fs, process::Command, sync::Arc};
