// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// The trait for database manager of Delta MPT.

pub type DeltaDbOwnedReadTraitObj<'db> =
    dyn 'db + KeyValueDbTraitOwnedRead<ValueType = Box<[u8]>>;

pub type DeltaDbTransactionTraitObj =
    dyn KeyValueDbTransactionTrait<ValueType = Box<[u8]>>;

pub trait DeltaDbTrait:
    KeyValueDbTypes<ValueType = Box<[u8]>>
    + KeyValueDbToOwnedReadTrait
    + KeyValueDbTraitRead
    + KeyValueDbTraitTransactionalDyn
{
}

pub trait DeltaDbManagerTrait {
    type DeltaDb: DeltaDbTrait;

    fn get_delta_db_dir(&self) -> String;
    fn get_delta_db_name(&self, snapshot_epoch_id: &EpochId) -> String;
    fn get_delta_db_path(&self, delta_db_name: &str) -> String;

    // Scan delta db dir, remove extra files and return the list of missing
    // snapshots for which the delta db is missing.
    fn scan_persist_state(
        &self, snapshot_info_map: &HashMap<EpochId, SnapshotInfo>,
    ) -> Result<(Vec<EpochId>, HashMap<EpochId, Self::DeltaDb>)> {
        let mut possible_delta_db_paths = HashMap::new();
        for (snapshot_epoch_id, snapshot_info) in snapshot_info_map {
            // Delta MPT
            possible_delta_db_paths.insert(
                self.get_delta_db_name(snapshot_epoch_id).into_bytes(),
                snapshot_epoch_id.clone(),
            );
            // Intermediate Delta MPT
            possible_delta_db_paths.insert(
                self.get_delta_db_name(&snapshot_info.parent_snapshot_epoch_id)
                    .into_bytes(),
                snapshot_info.parent_snapshot_epoch_id.clone(),
            );
        }
        let mut delta_mpts = HashMap::new();

        // Scan the delta db dir. Remove extra files, and return the list of
        // snapshots for which the delta db is missing.
        for entry in fs::read_dir(self.get_delta_db_dir())? {
            let entry = entry?;
            let path = entry.path();
            let dir_name = path.as_path().file_name().unwrap().to_str();
            if dir_name.is_none() {
                error!(
                    "Unexpected delta db path {}, deleted.",
                    entry.path().display()
                );
                fs::remove_dir_all(entry.path())?;
                continue;
            }
            let dir_name = dir_name.unwrap();
            if !possible_delta_db_paths.contains_key(dir_name.as_bytes()) {
                error!(
                    "Unexpected delta db path {}, deleted.",
                    entry.path().display()
                );
                fs::remove_dir_all(entry.path())?;
            } else {
                let snapshot_epoch_id = possible_delta_db_paths
                    .remove(dir_name.as_bytes())
                    .unwrap();
                delta_mpts.insert(
                    snapshot_epoch_id,
                    self.get_delta_db(
                        &self.get_delta_db_name(&snapshot_epoch_id),
                    )?
                    .unwrap(),
                );
            }
        }

        let mut missing_delta_dbs = vec![];
        for (snapshot_epoch_id, _) in snapshot_info_map {
            if !delta_mpts.contains_key(snapshot_epoch_id) {
                missing_delta_dbs.push(snapshot_epoch_id.clone())
            }
        }

        Ok((missing_delta_dbs, delta_mpts))
    }

    fn new_empty_delta_db(&self, delta_db_name: &str) -> Result<Self::DeltaDb>;

    fn get_delta_db(
        &self, delta_db_name: &str,
    ) -> Result<Option<Self::DeltaDb>>;

    /// Destroy a Delta DB. Keep in mind that this method is irrecoverable.
    /// Ref-counting is necessary for Delta1 MPT in Snapshot.
    fn destroy_delta_db(&self, delta_db_name: &str) -> Result<()>;
}

use crate::storage::{
    impls::errors::*,
    storage_db::{key_value_db::*, SnapshotInfo},
};
use primitives::EpochId;
use std::{collections::HashMap, fs};
