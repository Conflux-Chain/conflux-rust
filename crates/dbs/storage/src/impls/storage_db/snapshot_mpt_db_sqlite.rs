// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotMptDbSqlite {
    maybe_db_connections: Option<Box<[SqliteConnection]>>,
    already_open_snapshots: AlreadyOpenSnapshots<Self>,
    open_semaphore: Arc<Semaphore>,
    path: PathBuf,
    remove_on_close: AtomicBool,
    latest_mpt_snapshot_semaphore: Option<Arc<Semaphore>>,
}

pub struct SnapshotMptDbStatements {
    pub mpt_statements: Arc<KvdbSqliteStatements>,
}

lazy_static! {
    pub static ref SNAPSHOT_MPT_DB_STATEMENTS: SnapshotMptDbStatements = {
        let mpt_statements = Arc::new(
            KvdbSqliteStatements::make_statements(
                &["node_rlp"],
                &["BLOB"],
                SnapshotMptDbSqlite::SNAPSHOT_MPT_TABLE_NAME,
                false,
            )
            .unwrap(),
        );

        SnapshotMptDbStatements { mpt_statements }
    };
}

impl Drop for SnapshotMptDbSqlite {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            debug!("drop SnapshotMptDbSqlite {:?}", self.path);

            self.maybe_db_connections.take();
            SnapshotDbManagerSqlite::on_close_mpt_snapshot(
                &self.already_open_snapshots,
                &self.open_semaphore,
                &self.path,
                self.remove_on_close.load(Ordering::Relaxed),
                &self.latest_mpt_snapshot_semaphore,
            )
        }
    }
}

impl SnapshotMptDbSqlite {
    pub const DB_SHARDS: u16 = 32;
    /// MPT Table.
    pub const SNAPSHOT_MPT_TABLE_NAME: &'static str = "snapshot_mpt";
}

impl KeyValueDbTypes for SnapshotMptDbSqlite {
    type ValueType = Box<[u8]>;
}

// For Snapshot MPT DB.
impl KvdbSqliteShardedRefDestructureTrait for SnapshotMptDbSqlite {
    fn destructure(
        &self,
    ) -> (Option<&[SqliteConnection]>, &KvdbSqliteStatements) {
        (
            self.maybe_db_connections.as_ref().map(|b| &**b),
            &*SNAPSHOT_MPT_DB_STATEMENTS.mpt_statements,
        )
    }
}

impl KvdbSqliteShardedDestructureTrait for SnapshotMptDbSqlite {
    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut [SqliteConnection]>, &KvdbSqliteStatements) {
        (
            self.maybe_db_connections.as_mut().map(|b| &mut **b),
            &*SNAPSHOT_MPT_DB_STATEMENTS.mpt_statements,
        )
    }
}

/// Automatically implement KeyValueDbTraitRead with the same code of
/// KvdbSqlite.
impl ReadImplFamily for SnapshotMptDbSqlite {
    type FamilyRepresentative = KvdbSqliteSharded<Box<[u8]>>;
}

impl OwnedReadImplFamily for SnapshotMptDbSqlite {
    type FamilyRepresentative = KvdbSqliteSharded<Box<[u8]>>;
}

impl SingleWriterImplFamily for SnapshotMptDbSqlite {
    type FamilyRepresentative = KvdbSqliteSharded<Box<[u8]>>;
}

impl<'db> OpenSnapshotMptTrait<'db> for SnapshotMptDbSqlite {
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
        Ok(SnapshotMpt::new(unsafe {
            std::mem::transmute(
                KvdbSqliteShardedBorrowMut::<SnapshotMptDbValue>::new(
                    self.maybe_db_connections.as_mut().map(|b| &mut **b),
                    &SNAPSHOT_MPT_DB_STATEMENTS.mpt_statements,
                ),
            )
        })?)
    }

    fn open_snapshot_mpt_as_owned(
        &'db self,
    ) -> Result<Self::SnapshotDbAsOwnedType> {
        Ok(SnapshotMpt::new(
            KvdbSqliteSharded::<SnapshotMptDbValue>::new(
                self.try_clone_connections()?,
                SNAPSHOT_MPT_DB_STATEMENTS.mpt_statements.clone(),
            ),
        )?)
    }

    fn open_snapshot_mpt_shared(
        &'db self,
    ) -> Result<Self::SnapshotDbBorrowSharedType> {
        Ok(SnapshotMpt::new(unsafe {
            std::mem::transmute(KvdbSqliteShardedBorrowShared::<
                SnapshotMptDbValue,
            >::new(
                self.maybe_db_connections.as_ref().map(|b| &**b),
                &SNAPSHOT_MPT_DB_STATEMENTS.mpt_statements,
            ))
        })?)
    }
}

impl SnapshotDbTrait for SnapshotMptDbSqlite {
    type SnapshotKvdbIterTraitTag = KvdbSqliteShardedIteratorTag;
    type SnapshotKvdbIterType =
        KvdbSqliteSharded<<Self as KeyValueDbTypes>::ValueType>;

    fn get_null_snapshot() -> Self { unreachable!() }

    fn open(
        _snapshot_path: &Path, _readonly: bool,
        _already_open_snapshots: &AlreadyOpenSnapshots<Self>,
        _open_semaphore: &Arc<Semaphore>,
    ) -> Result<SnapshotMptDbSqlite> {
        unreachable!()
    }

    fn create(
        _snapshot_path: &Path,
        _already_open_snapshots: &AlreadyOpenSnapshots<Self>,
        _open_snapshots_semaphore: &Arc<Semaphore>,
        _mpt_table_in_current_db: bool,
    ) -> Result<SnapshotMptDbSqlite> {
        unreachable!()
    }

    fn direct_merge(
        &mut self, _old_snapshot_db: Option<&Arc<SnapshotMptDbSqlite>>,
        _mpt_snapshot: &mut Option<SnapshotMptDbSqlite>,
        _recover_mpt_with_kv_snapshot_exist: bool,
        _in_reconstruct_snapshot_state: bool,
    ) -> Result<MerkleHash> {
        unreachable!()
    }

    fn copy_and_merge(
        &mut self, _old_snapshot_db: &Arc<SnapshotMptDbSqlite>,
        _mpt_snapshot_db: &mut Option<SnapshotMptDbSqlite>,
        _in_reconstruct_snapshot_state: bool,
    ) -> Result<MerkleHash> {
        unreachable!()
    }

    fn start_transaction(&mut self) -> Result<()> {
        if let Some(connections) = self.maybe_db_connections.as_mut() {
            for connection in connections.iter_mut() {
                connection.execute("BEGIN IMMEDIATE", SQLITE_NO_PARAM)?;
            }
        }
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<()> {
        if let Some(connections) = self.maybe_db_connections.as_mut() {
            for connection in connections.iter_mut() {
                connection.execute("COMMIT", SQLITE_NO_PARAM)?;
            }
        }
        Ok(())
    }

    fn is_mpt_table_in_current_db(&self) -> bool { unreachable!() }

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
        unreachable!()
    }
}

impl SnapshotMptDbSqlite {
    fn try_clone_connections(&self) -> Result<Option<Box<[SqliteConnection]>>> {
        match &self.maybe_db_connections {
            None => Ok(None),
            Some(old_connections) => {
                let mut connections = Vec::with_capacity(old_connections.len());
                for old_connection in old_connections.iter() {
                    let new_connection = old_connection.try_clone()?;
                    connections.push(new_connection);
                }
                Ok(Some(connections.into_boxed_slice()))
            }
        }
    }

    pub fn open(
        snapshot_path: &Path, readonly: bool,
        already_open_snapshots: &AlreadyOpenSnapshots<Self>,
        open_semaphore: &Arc<Semaphore>,
        latest_mpt_snapshot_semaphore: Option<Arc<Semaphore>>,
    ) -> Result<SnapshotMptDbSqlite> {
        let kvdb_sqlite_sharded = KvdbSqliteSharded::<Box<[u8]>>::open(
            Self::DB_SHARDS,
            snapshot_path,
            readonly,
            SNAPSHOT_MPT_DB_STATEMENTS.mpt_statements.clone(),
        )?;

        Ok(Self {
            maybe_db_connections: kvdb_sqlite_sharded.into_connections(),
            already_open_snapshots: already_open_snapshots.clone(),
            open_semaphore: open_semaphore.clone(),
            path: snapshot_path.to_path_buf(),
            remove_on_close: Default::default(),
            latest_mpt_snapshot_semaphore,
        })
    }

    pub fn create(
        snapshot_path: &Path,
        already_open_snapshots: &AlreadyOpenSnapshots<Self>,
        open_snapshots_semaphore: &Arc<Semaphore>,
        latest_mpt_snapshot_semaphore: Option<Arc<Semaphore>>,
    ) -> Result<SnapshotMptDbSqlite> {
        fs::create_dir_all(snapshot_path)?;
        let create_result = (|| -> Result<Box<[SqliteConnection]>> {
            let kvdb_sqlite_sharded =
                KvdbSqliteSharded::<Box<[u8]>>::create_and_open(
                    Self::DB_SHARDS,
                    snapshot_path,
                    SNAPSHOT_MPT_DB_STATEMENTS.mpt_statements.clone(),
                    /* create_table = */ true,
                    /* unsafe_mode = */ true,
                )?;
            let connections = kvdb_sqlite_sharded.into_connections().unwrap();

            Ok(connections)
        })();
        match create_result {
            Err(e) => {
                fs::remove_dir_all(&snapshot_path)?;
                bail!(e);
            }
            Ok(connections) => Ok(SnapshotMptDbSqlite {
                maybe_db_connections: Some(connections),
                already_open_snapshots: already_open_snapshots.clone(),
                open_semaphore: open_snapshots_semaphore.clone(),
                path: snapshot_path.to_path_buf(),
                remove_on_close: Default::default(),
                latest_mpt_snapshot_semaphore,
            }),
        }
    }

    pub fn set_remove_on_last_close(&self) {
        self.remove_on_close.store(true, Ordering::Relaxed);
    }

    pub fn snapshot_mpt_itertor(
        &self,
    ) -> Result<
        Wrap<
            KvdbSqliteSharded<<Self as KeyValueDbTypes>::ValueType>,
            dyn KeyValueDbIterableTrait<
                MptKeyValue,
                [u8],
                KvdbSqliteShardedIteratorTag,
            >,
        >,
    > {
        Ok(Wrap(KvdbSqliteSharded::new(
            self.try_clone_connections()?,
            SNAPSHOT_MPT_DB_STATEMENTS.mpt_statements.clone(),
        )))
    }
}

use primitives::MerkleHash;
use tokio02::sync::Semaphore;

use crate::{
    impls::{
        errors::*,
        storage_db::{
            kvdb_sqlite::KvdbSqliteStatements,
            kvdb_sqlite_sharded::{
                KvdbSqliteSharded, KvdbSqliteShardedBorrowMut,
                KvdbSqliteShardedBorrowShared,
            },
            snapshot_mpt::SnapshotMpt,
        },
    },
    storage_db::{
        KeyValueDbIterableTrait, KeyValueDbTypes, OpenSnapshotMptTrait,
        OwnedReadImplFamily, ReadImplFamily, SingleWriterImplFamily,
        SnapshotDbTrait, SnapshotMptDbValue,
    },
    utils::wrap::Wrap,
    MptKeyValue, SnapshotDbManagerSqlite, SqliteConnection,
};

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use super::{
    kvdb_sqlite_sharded::{
        KvdbSqliteShardedDestructureTrait, KvdbSqliteShardedIteratorTag,
        KvdbSqliteShardedRefDestructureTrait,
    },
    snapshot_db_manager_sqlite::AlreadyOpenSnapshots,
    sqlite::SQLITE_NO_PARAM,
};
