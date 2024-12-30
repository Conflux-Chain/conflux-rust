// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotDbSqlite {
    pub snapshot_db: Arc<SnapshotKvDbSqlite>,
    pub mpt_snapshot_db: Option<Arc<SnapshotMptDbSqlite>>,
}

impl KeyValueDbTypes for SnapshotDbSqlite {
    type ValueType = Box<[u8]>;
}

// For Snapshot KV DB.
impl KvdbSqliteShardedRefDestructureTrait for SnapshotDbSqlite {
    fn destructure(
        &self,
    ) -> (Option<&[SqliteConnection]>, &KvdbSqliteStatements) {
        (
            self.snapshot_db.maybe_db_connections.as_ref().map(|b| &**b),
            &*SNAPSHOT_DB_STATEMENTS.kvdb_statements,
        )
    }
}

impl KvdbSqliteShardedDestructureTrait for SnapshotDbSqlite {
    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut [SqliteConnection]>, &KvdbSqliteStatements) {
        unreachable!()
    }
}

/// Automatically implement KeyValueDbTraitRead with the same code of
/// KvdbSqlite.
impl ReadImplFamily for SnapshotDbSqlite {
    type FamilyRepresentative = KvdbSqliteSharded<Box<[u8]>>;
}

impl OwnedReadImplFamily for SnapshotDbSqlite {
    type FamilyRepresentative = KvdbSqliteSharded<Box<[u8]>>;
}

impl SingleWriterImplFamily for SnapshotDbSqlite {
    type FamilyRepresentative = KvdbSqliteSharded<Box<[u8]>>;
}

impl<'db> OpenSnapshotMptTrait<'db> for SnapshotDbSqlite {
    type SnapshotDbAsOwnedType = SnapshotMpt<
        KvdbSqliteSharded<SnapshotMptDbValue>,
        KvdbSqliteSharded<SnapshotMptDbValue>,
    >;
    /// The 'static lifetime is for for<'db> KeyValueDbIterableTrait<'db, ...>.
    type SnapshotDbBorrowMutType = SnapshotMpt<
        KvdbSqliteShardedBorrowMut<'static, SnapshotMptDbValue>,
        KvdbSqliteShardedBorrowMut<'static, SnapshotMptDbValue>,
    >;
    type SnapshotDbBorrowSharedType = SnapshotMpt<
        KvdbSqliteShardedBorrowShared<'static, SnapshotMptDbValue>,
        KvdbSqliteShardedBorrowShared<'static, SnapshotMptDbValue>,
    >;

    fn open_snapshot_mpt_owned(
        &'db mut self,
    ) -> Result<Self::SnapshotDbBorrowMutType> {
        debug!(
            "open_snapshot_mpt_owned mpt_table_in_current_db {}",
            self.is_mpt_table_in_current_db()
        );
        unreachable!()
    }

    fn open_snapshot_mpt_as_owned(
        &'db self,
    ) -> Result<Self::SnapshotDbAsOwnedType> {
        debug!(
            "open_snapshot_mpt_as_owned mpt_table_in_current_db {}",
            self.is_mpt_table_in_current_db()
        );
        if self.is_mpt_table_in_current_db() {
            Ok(SnapshotMpt::new(
                KvdbSqliteSharded::<SnapshotMptDbValue>::new(
                    self.try_clone_connections()?,
                    SNAPSHOT_MPT_DB_STATEMENTS.mpt_statements.clone(),
                ),
            )?)
        } else {
            if self.mpt_snapshot_db.is_some() {
                self.mpt_snapshot_db
                    .as_ref()
                    .unwrap()
                    .open_snapshot_mpt_as_owned()
            } else {
                bail!("mpt_snapshot is none");
            }
        }
    }

    fn open_snapshot_mpt_shared(
        &'db self,
    ) -> Result<Self::SnapshotDbBorrowSharedType> {
        debug!(
            "open_snapshot_mpt_shared mpt_table_in_current_db {}",
            self.is_mpt_table_in_current_db()
        );
        if self.is_mpt_table_in_current_db() {
            Ok(SnapshotMpt::new(unsafe {
                std::mem::transmute(KvdbSqliteShardedBorrowShared::<
                    SnapshotMptDbValue,
                >::new(
                    self.snapshot_db
                        .maybe_db_connections
                        .as_ref()
                        .map(|b| &**b),
                    &SNAPSHOT_MPT_DB_STATEMENTS.mpt_statements,
                ))
            })?)
        } else {
            if self.mpt_snapshot_db.is_some() {
                self.mpt_snapshot_db
                    .as_ref()
                    .unwrap()
                    .open_snapshot_mpt_shared()
            } else {
                bail!("mpt_snapshot is none");
            }
        }
    }
}

impl SnapshotDbSqlite {
    fn try_clone_connections(&self) -> Result<Option<Box<[SqliteConnection]>>> {
        self.snapshot_db.try_clone_connections()
    }

    pub fn dumped_delta_kv_set_keys_iterator(
        &self,
    ) -> Result<KvdbSqliteSharded<<Self as KeyValueDbTypes>::ValueType>> {
        self.snapshot_db.dumped_delta_kv_set_keys_iterator()
    }

    pub fn dumped_delta_kv_delete_keys_iterator(
        &self,
    ) -> Result<KvdbSqliteSharded<()>> {
        self.snapshot_db.dumped_delta_kv_delete_keys_iterator()
    }
}

impl SnapshotDbTrait for SnapshotDbSqlite {
    type SnapshotKvdbIterTraitTag = KvdbSqliteShardedIteratorTag;
    type SnapshotKvdbIterType =
        KvdbSqliteSharded<<Self as KeyValueDbTypes>::ValueType>;

    fn get_null_snapshot() -> Self {
        Self {
            snapshot_db: Arc::new(SnapshotKvDbSqlite::get_null_snapshot()),
            mpt_snapshot_db: None,
        }
    }

    /// Store already_open_snapshots and open_semaphore to update
    /// SnapshotDbManager on destructor. SnapshotDb itself does not take
    /// care of the update on these data.
    fn open(
        _snapshot_path: &Path, _readonly: bool,
        _already_open_snapshots: &AlreadyOpenSnapshots<Self>,
        _open_semaphore: &Arc<Semaphore>,
    ) -> Result<SnapshotDbSqlite> {
        unreachable!()
    }

    /// Store already_open_snapshots and open_semaphore to update
    /// SnapshotDbManager on destructor. SnapshotDb itself does not take
    /// care of the update on these data.
    fn create(
        _snapshot_path: &Path,
        _already_open_snapshots: &AlreadyOpenSnapshots<Self>,
        _open_semaphore: &Arc<Semaphore>, _mpt_table_in_current_db: bool,
    ) -> Result<SnapshotDbSqlite> {
        unreachable!()
    }

    // FIXME: use a mechanism with rate limit.
    fn direct_merge(
        &mut self, _old_snapshot_db: Option<&Arc<SnapshotDbSqlite>>,
        _mpt_snapshot: &mut Option<SnapshotMptDbSqlite>,
        _recover_mpt_with_kv_snapshot_exist: bool,
        _in_reconstruct_snapshot_state: bool,
    ) -> Result<MerkleHash> {
        unreachable!()
    }

    fn copy_and_merge(
        &mut self, _old_snapshot_db: &Arc<SnapshotDbSqlite>,
        _mpt_snapshot_db: &mut Option<SnapshotMptDbSqlite>,
        _in_reconstruct_snapshot_state: bool,
    ) -> Result<MerkleHash> {
        unreachable!()
    }

    fn start_transaction(&mut self) -> Result<()> { unreachable!() }

    fn commit_transaction(&mut self) -> Result<()> { unreachable!() }

    fn is_mpt_table_in_current_db(&self) -> bool {
        self.snapshot_db.is_mpt_table_in_current_db()
    }

    fn snapshot_kv_iterator(
        &self,
    ) -> Result<
        Wrap<
            Self::SnapshotKvdbIterType,
            dyn KeyValueDbIterableTrait<
                MptKeyValue,
                [u8],
                KvdbSqliteShardedIteratorTag,
            >,
        >,
    > {
        Ok(Wrap(KvdbSqliteSharded::new(
            self.try_clone_connections()?,
            SNAPSHOT_DB_STATEMENTS.kvdb_statements.clone(),
        )))
    }
}

use crate::{
    impls::{
        errors::*,
        storage_db::{
            snapshot_kv_db_sqlite::*,
            snapshot_mpt_db_sqlite::SNAPSHOT_MPT_DB_STATEMENTS,
        },
    },
    storage_db::{
        KeyValueDbIterableTrait, KeyValueDbTypes, OpenSnapshotMptTrait,
        OwnedReadImplFamily, ReadImplFamily, SingleWriterImplFamily,
        SnapshotDbTrait, SnapshotMptDbValue,
    },
    utils::wrap::Wrap,
    KvdbSqliteStatements, MptKeyValue, SqliteConnection,
};
use primitives::MerkleHash;

use std::{path::Path, sync::Arc};
use tokio02::sync::Semaphore;

use super::{
    kvdb_sqlite_sharded::{
        KvdbSqliteSharded, KvdbSqliteShardedBorrowMut,
        KvdbSqliteShardedBorrowShared, KvdbSqliteShardedDestructureTrait,
        KvdbSqliteShardedIteratorTag, KvdbSqliteShardedRefDestructureTrait,
    },
    snapshot_db_manager_sqlite::AlreadyOpenSnapshots,
    snapshot_mpt::SnapshotMpt,
    snapshot_mpt_db_sqlite::SnapshotMptDbSqlite,
};
