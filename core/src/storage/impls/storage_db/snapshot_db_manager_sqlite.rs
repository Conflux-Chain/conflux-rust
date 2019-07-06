pub struct SnapshotDbManagerSqlite {
    // TODO: persistent in db.
    epoch_to_snapshot_root: HashMap<EpochId, MerkleHash>,
    empty_snapshot: Arc<<Self as SnapshotDbManagerTrait>::SnapshotDb>,
}

impl SnapshotDbManagerSqlite {
    pub fn new() -> Self {
        Self {
            epoch_to_snapshot_root: Default::default(),
            empty_snapshot: Arc::new(
                <Self as SnapshotDbManagerTrait>::SnapshotDb::default(),
            ),
        }
    }
}

impl SnapshotDbManagerTrait for SnapshotDbManagerSqlite {
    type DeltaMpt = DeltaMpt;
    type SnapshotDb = KvdbSqlite;

    fn new_snapshot_by_merging(
        &self, _old_snapshot_root: &MerkleHash, _delta_mpt: &Self::DeltaMpt,
    ) -> Result<Arc<Self::SnapshotDb>> {
        unimplemented!()
    }

    fn get_snapshot(
        &self, snapshot_root: &MerkleHash,
    ) -> Result<Option<Arc<Self::SnapshotDb>>> {
        if snapshot_root.eq(&MERKLE_NULL_NODE) {
            return Ok(Some(self.empty_snapshot.clone()));
        }
        unimplemented!()
    }

    fn destroy_snapshot(&self, _snapshot_root: &MerkleHash) -> Result<()> {
        unimplemented!()
    }

    fn get_snapshot_by_epoch_id(
        &self, epoch_id: &EpochId,
    ) -> Result<Option<Arc<Self::SnapshotDb>>> {
        match self.epoch_to_snapshot_root.get(epoch_id) {
            None => Ok(None),
            Some(snapshot_root) => self.get_snapshot(snapshot_root),
        }
    }
}

use super::{
    super::{
        super::storage_db::snapshot_db_manager::SnapshotDbManagerTrait,
        errors::*, multi_version_merkle_patricia_trie::DeltaMpt,
    },
    kvdb_sqlite::KvdbSqlite,
};
use primitives::{EpochId, MerkleHash, MERKLE_NULL_NODE};
use std::{collections::HashMap, sync::Arc};
