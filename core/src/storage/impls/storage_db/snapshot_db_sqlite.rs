// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotDbSqlite {
    // Option because we need an empty snapshot db for empty snapshot.
    maybe_db_connections: Option<Box<[SqliteConnection]>>,
    already_open_snapshots: AlreadyOpenSnapshots<Self>,
    open_semaphore: Arc<Semaphore>,
    path: PathBuf,
    remove_on_close: AtomicBool,
}

pub struct SnapshotDbStatements {
    kvdb_statements: Arc<KvdbSqliteStatements>,
    mpt_statements: Arc<KvdbSqliteStatements>,
    delta_mpt_set_keys_statements: Arc<KvdbSqliteStatements>,
    delta_mpt_delete_keys_statements: Arc<KvdbSqliteStatements>,
}

lazy_static! {
    pub static ref SNAPSHOT_DB_STATEMENTS: SnapshotDbStatements = {
        let kvdb_statements = Arc::new(
            KvdbSqliteStatements::make_statements(
                &["value"],
                &["BLOB"],
                SnapshotDbSqlite::SNAPSHOT_KV_TABLE_NAME,
                false,
            )
            .unwrap(),
        );
        let mpt_statements = Arc::new(
            KvdbSqliteStatements::make_statements(
                &["node_rlp"],
                &["BLOB"],
                SnapshotDbSqlite::SNAPSHOT_MPT_TABLE_NAME,
                false,
            )
            .unwrap(),
        );

        let delta_mpt_set_keys_statements = Arc::new(
            KvdbSqliteStatements::make_statements(
                &["value"],
                &["BLOB"],
                SnapshotDbSqlite::DELTA_KV_SET_TABLE_NAME,
                false,
            )
            .unwrap(),
        );
        let delta_mpt_delete_keys_statements = Arc::new(
            KvdbSqliteStatements::make_statements(
                &[],
                &[],
                SnapshotDbSqlite::DELTA_KV_DELETE_TABLE_NAME,
                false,
            )
            .unwrap(),
        );

        SnapshotDbStatements {
            kvdb_statements,
            mpt_statements,
            delta_mpt_set_keys_statements,
            delta_mpt_delete_keys_statements,
        }
    };
}

impl Drop for SnapshotDbSqlite {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            self.maybe_db_connections.take();
            SnapshotDbManagerSqlite::on_close(
                &self.already_open_snapshots,
                &self.open_semaphore,
                &self.path,
                self.remove_on_close.load(Ordering::Relaxed),
            )
        }
    }
}

impl SnapshotDbSqlite {
    pub const DB_SHARDS: u16 = 32;
    /// These two tables are temporary table for the merging process, but they
    /// remain to help other nodes to do 1-step syncing.
    pub const DELTA_KV_DELETE_TABLE_NAME: &'static str =
        "delta_mpt_key_value_delete";
    pub const DELTA_KV_SET_TABLE_NAME: &'static str = "delta_mpt_key_value_set";
    // FIXME: Archive node will have different db schema to support versioned
    // FIXME: read and to provide incremental syncing.
    // FIXME:
    // FIXME: for archive mode, the delete table may live in its own db file
    // FIXME: which contains delete table for a version range.
    // FIXME: model this fact and refactor.
    /*
    pub const KVV_PUT_STATEMENT: &'static str =
        "INSERT OR REPLACE INTO :table_name VALUES (:key, :value, :version)";
    /// Key is not unique, because the same key can appear with different
    /// version number.
    pub const SNAPSHOT_KV_DELETE_TABLE_NAME: &'static str =
        "snapshot_key_value_delete";
    */
    /// Key-Value table. Key is unique key in this table.
    pub const SNAPSHOT_KV_TABLE_NAME: &'static str = "snapshot_key_value";
    /// MPT Table.
    pub const SNAPSHOT_MPT_TABLE_NAME: &'static str = "snapshot_mpt";
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
            self.maybe_db_connections.as_ref().map(|b| &**b),
            &*SNAPSHOT_DB_STATEMENTS.kvdb_statements,
        )
    }
}

impl KvdbSqliteShardedDestructureTrait for SnapshotDbSqlite {
    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut [SqliteConnection]>, &KvdbSqliteStatements) {
        (
            self.maybe_db_connections.as_mut().map(|b| &mut **b),
            &*SNAPSHOT_DB_STATEMENTS.kvdb_statements,
        )
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

impl SnapshotMptLoadNode
    for KvdbSqliteShardedBorrowMut<'static, SnapshotMptDbValue>
{
    fn load_node_rlp(
        &mut self, key: &[u8],
    ) -> Result<Option<SnapshotMptDbValue>> {
        self.get_mut_impl(key)
    }
}

impl SnapshotMptLoadNode for KvdbSqliteSharded<SnapshotMptDbValue> {
    fn load_node_rlp(
        &mut self, key: &[u8],
    ) -> Result<Option<SnapshotMptDbValue>> {
        self.get_mut_impl(key)
    }
}

impl SnapshotMptLoadNode
    for KvdbSqliteShardedBorrowShared<'static, SnapshotMptDbValue>
{
    fn load_node_rlp(
        &mut self, key: &[u8],
    ) -> Result<Option<SnapshotMptDbValue>> {
        self.get_impl(key)
    }
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
        Ok(SnapshotMpt::new(unsafe {
            std::mem::transmute(
                KvdbSqliteShardedBorrowMut::<SnapshotMptDbValue>::new(
                    self.maybe_db_connections.as_mut().map(|b| &mut **b),
                    &SNAPSHOT_DB_STATEMENTS.mpt_statements,
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
                SNAPSHOT_DB_STATEMENTS.mpt_statements.clone(),
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
                &SNAPSHOT_DB_STATEMENTS.mpt_statements,
            ))
        })?)
    }
}

impl SnapshotDbTrait for SnapshotDbSqlite {
    fn get_null_snapshot() -> Self {
        Self {
            maybe_db_connections: None,
            already_open_snapshots: Default::default(),
            open_semaphore: Arc::new(Semaphore::new(0)),
            path: Default::default(),
            remove_on_close: Default::default(),
        }
    }

    fn open(
        snapshot_path: &Path, readonly: bool,
        already_open_snapshots: &AlreadyOpenSnapshots<Self>,
        open_semaphore: &Arc<Semaphore>,
    ) -> Result<SnapshotDbSqlite>
    {
        let kvdb_sqlite_sharded = KvdbSqliteSharded::<Box<[u8]>>::open(
            Self::DB_SHARDS,
            snapshot_path,
            readonly,
            SNAPSHOT_DB_STATEMENTS.kvdb_statements.clone(),
        )?;

        Ok(Self {
            maybe_db_connections: kvdb_sqlite_sharded.into_connections(),
            already_open_snapshots: already_open_snapshots.clone(),
            open_semaphore: open_semaphore.clone(),
            path: snapshot_path.to_path_buf(),
            remove_on_close: Default::default(),
        })
    }

    fn create(
        snapshot_path: &Path,
        already_open_snapshots: &AlreadyOpenSnapshots<Self>,
        open_snapshots_semaphore: &Arc<Semaphore>,
    ) -> Result<SnapshotDbSqlite>
    {
        fs::create_dir_all(snapshot_path)?;
        let create_result = (|| -> Result<Box<[SqliteConnection]>> {
            let kvdb_sqlite_sharded =
                KvdbSqliteSharded::<Box<[u8]>>::create_and_open(
                    Self::DB_SHARDS,
                    snapshot_path,
                    SNAPSHOT_DB_STATEMENTS.kvdb_statements.clone(),
                    /* create_table = */ true,
                    /* unsafe_mode = */ true,
                )?;
            let mut connections =
                // Safe to unwrap since the connections are newly created.
                kvdb_sqlite_sharded.into_connections().unwrap();
            // Create Snapshot MPT table.
            KvdbSqliteSharded::<Self::ValueType>::create_table(
                &mut connections,
                &SNAPSHOT_DB_STATEMENTS.mpt_statements,
            )?;
            Ok(connections)
        })();
        match create_result {
            Err(e) => {
                fs::remove_dir_all(&snapshot_path)?;
                bail!(e);
            }
            Ok(connections) => Ok(SnapshotDbSqlite {
                maybe_db_connections: Some(connections),
                already_open_snapshots: already_open_snapshots.clone(),
                open_semaphore: open_snapshots_semaphore.clone(),
                path: snapshot_path.to_path_buf(),
                remove_on_close: Default::default(),
            }),
        }
    }

    // FIXME: use a mechanism with rate limit.
    fn direct_merge(&mut self) -> Result<MerkleHash> {
        debug!("direct_merge begins.");
        self.apply_update_to_kvdb()?;

        let mut set_keys_iter = self.dumped_delta_kv_set_keys_iterator()?;
        let mut delete_keys_iter =
            self.dumped_delta_kv_delete_keys_iterator()?;

        self.start_transaction()?;
        // TODO: what about multi-threading node load?
        let mut mpt_to_modify = self.open_snapshot_mpt_owned()?;

        let mut mpt_merger = MptMerger::new(
            None,
            &mut mpt_to_modify as &mut dyn SnapshotMptTraitRw,
        );
        let snapshot_root = mpt_merger.merge_insertion_deletion_separated(
            delete_keys_iter.iter_range(&[], None)?,
            set_keys_iter.iter_range(&[], None)?,
        )?;
        self.commit_transaction()?;

        Ok(snapshot_root)
    }

    fn copy_and_merge(
        &mut self, old_snapshot_db: &SnapshotDbSqlite,
    ) -> Result<MerkleHash> {
        debug!("copy_and_merge begins.");
        let mut kv_iter = old_snapshot_db.snapshot_kv_iterator()?;
        let mut iter = kv_iter.iter_range(&[], None)?;
        while let Ok(kv_item) = iter.next() {
            match kv_item {
                Some((k, v)) => {
                    self.put(&k, &v)?;
                }
                None => break,
            }
        }
        self.apply_update_to_kvdb()?;

        let mut set_keys_iter = self.dumped_delta_kv_set_keys_iterator()?;
        let mut delete_keys_iter =
            self.dumped_delta_kv_delete_keys_iterator()?;
        self.start_transaction()?;
        // TODO: what about multi-threading node load?
        let mut base_mpt = old_snapshot_db.open_snapshot_mpt_as_owned()?;
        let mut save_as_mpt = self.open_snapshot_mpt_owned()?;
        let mut mpt_merger = MptMerger::new(
            Some(&mut base_mpt as &mut dyn SnapshotMptTraitReadAndIterate),
            &mut save_as_mpt as &mut dyn SnapshotMptTraitRw,
        );
        let snapshot_root = mpt_merger.merge_insertion_deletion_separated(
            delete_keys_iter.iter_range(&[], None)?,
            set_keys_iter.iter_range(&[], None)?,
        )?;
        self.commit_transaction()?;

        Ok(snapshot_root)
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
}

impl SnapshotDbSqlite {
    // FIXME: Do not clone connections.
    // FIXME: 1. we shouldn't not clone connections without acquire the
    // FIXME: semaphore; 2. we should implement the range iter for
    // FIXME: shared reading connections.
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

    pub fn set_remove_on_last_close(&self) {
        self.remove_on_close.store(true, Ordering::Relaxed);
    }

    pub fn snapshot_kv_iterator(
        &self,
    ) -> Result<KvdbSqliteSharded<<Self as KeyValueDbTypes>::ValueType>> {
        Ok(KvdbSqliteSharded::new(
            self.try_clone_connections()?,
            SNAPSHOT_DB_STATEMENTS.kvdb_statements.clone(),
        ))
    }

    pub fn dumped_delta_kv_set_keys_iterator(
        &self,
    ) -> Result<KvdbSqliteSharded<<Self as KeyValueDbTypes>::ValueType>> {
        Ok(KvdbSqliteSharded::new(
            self.try_clone_connections()?,
            SNAPSHOT_DB_STATEMENTS.delta_mpt_set_keys_statements.clone(),
        ))
    }

    pub fn dumped_delta_kv_delete_keys_iterator(
        &self,
    ) -> Result<KvdbSqliteSharded<()>> {
        Ok(KvdbSqliteSharded::new(
            self.try_clone_connections()?,
            SNAPSHOT_DB_STATEMENTS
                .delta_mpt_delete_keys_statements
                .clone(),
        ))
    }

    // FIXME: add rate limit.
    // FIXME: how to handle row_id, this should go to the merkle tree?
    pub fn dump_delta_mpt(
        &mut self, delta_mpt: &DeltaMptIterator,
    ) -> Result<()> {
        debug!("dump_delta_mpt starts");
        // Create tables.
        {
            // Safe to unwrap since we are not on a NULL snapshot.
            let connections = self.maybe_db_connections.as_mut().unwrap();
            <DeltaMptDumperSetDb as SingleWriterImplFamily>::FamilyRepresentative::create_table(
                connections,
                &SNAPSHOT_DB_STATEMENTS.delta_mpt_set_keys_statements,
            )?;
            <DeltaMptDumperDeleteDb as SingleWriterImplFamily>::FamilyRepresentative::create_table(
                connections,
                &SNAPSHOT_DB_STATEMENTS.delta_mpt_delete_keys_statements,
            )?;
        }

        // Dump code.
        self.start_transaction()?;
        delta_mpt.iterate(&mut DeltaMptMergeDumperSqlite {
            connections: self.maybe_db_connections.as_mut().unwrap(),
        })?;
        self.commit_transaction()?;

        Ok(())
    }

    /// Dropping is optional, because these tables are necessary to provide
    /// 1-step syncing.
    pub fn drop_delta_mpt_dump(&mut self) -> Result<()> {
        // Safe to unwrap since we are not on a NULL snapshot.
        let connections = self.maybe_db_connections.as_mut().unwrap();
        <DeltaMptDumperSetDb as SingleWriterImplFamily>::FamilyRepresentative::drop_table(
            connections,
            &SNAPSHOT_DB_STATEMENTS.delta_mpt_set_keys_statements,
        )?;
        <DeltaMptDumperDeleteDb as SingleWriterImplFamily>::FamilyRepresentative::drop_table(
            connections,
            &SNAPSHOT_DB_STATEMENTS.delta_mpt_delete_keys_statements,
        )
    }

    fn apply_update_to_kvdb(&mut self) -> Result<()> {
        // Safe to unwrap since we are not on a NULL snapshot.
        for sqlite in self.maybe_db_connections.as_mut().unwrap().iter_mut() {
            sqlite
                .execute(
                    format!(
                        "DELETE FROM {} WHERE KEY IN (SELECT key FROM {})",
                        Self::SNAPSHOT_KV_TABLE_NAME,
                        Self::DELTA_KV_DELETE_TABLE_NAME
                    )
                    .as_str(),
                    SQLITE_NO_PARAM,
                )?
                .finish_ignore_rows()?;
            sqlite
                .execute(
                    format!(
                        "INSERT OR REPLACE INTO {} (key, value) \
                         SELECT key, value FROM {}",
                        Self::SNAPSHOT_KV_TABLE_NAME,
                        Self::DELTA_KV_SET_TABLE_NAME
                    )
                    .as_str(),
                    SQLITE_NO_PARAM,
                )?
                .finish_ignore_rows()?;
        }
        Ok(())
    }
}

pub struct DeltaMptMergeDumperSqlite<'a> {
    connections: &'a mut [SqliteConnection],
}

pub struct DeltaMptDumperSetDb<'a> {
    connections: &'a mut [SqliteConnection],
}

pub struct DeltaMptDumperDeleteDb<'a> {
    connections: &'a mut [SqliteConnection],
}

impl KeyValueDbTypes for DeltaMptDumperSetDb<'_> {
    type ValueType = Box<[u8]>;
}

impl KeyValueDbTypes for DeltaMptDumperDeleteDb<'_> {
    type ValueType = ();
}

impl SingleWriterImplFamily for DeltaMptDumperSetDb<'_> {
    type FamilyRepresentative = KvdbSqliteSharded<Box<[u8]>>;
}

impl SingleWriterImplFamily for DeltaMptDumperDeleteDb<'_> {
    type FamilyRepresentative = KvdbSqliteSharded<()>;
}

impl KvdbSqliteShardedDestructureTrait for DeltaMptDumperSetDb<'_> {
    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut [SqliteConnection]>, &KvdbSqliteStatements) {
        (
            Some(*&mut self.connections),
            &SNAPSHOT_DB_STATEMENTS.delta_mpt_set_keys_statements,
        )
    }
}

impl KvdbSqliteShardedDestructureTrait for DeltaMptDumperDeleteDb<'_> {
    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut [SqliteConnection]>, &KvdbSqliteStatements) {
        (
            Some(*&mut self.connections),
            &SNAPSHOT_DB_STATEMENTS.delta_mpt_delete_keys_statements,
        )
    }
}

impl<'a> KVInserter<(Vec<u8>, Box<[u8]>)> for DeltaMptMergeDumperSqlite<'a> {
    fn push(&mut self, x: (Vec<u8>, Box<[u8]>)) -> Result<()> {
        // TODO: what about multi-threading put?
        let (mpt_key, value) = x;
        let snapshot_key =
            StorageKey::from_delta_mpt_key(&mpt_key).to_key_bytes();
        if value.len() > 0 {
            DeltaMptDumperSetDb {
                connections: *&mut self.connections,
            }
            .put_impl(&snapshot_key, &value)?;
        } else {
            DeltaMptDumperDeleteDb {
                connections: *&mut self.connections,
            }
            .put_impl(&snapshot_key, &())?;
        }

        Ok(())
    }
}

use crate::storage::{
    impls::{
        delta_mpt::DeltaMptIterator,
        errors::*,
        merkle_patricia_trie::MptMerger,
        storage_db::{
            kvdb_sqlite::KvdbSqliteStatements,
            kvdb_sqlite_sharded::{
                KvdbSqliteSharded, KvdbSqliteShardedBorrowMut,
                KvdbSqliteShardedBorrowShared,
                KvdbSqliteShardedDestructureTrait,
                KvdbSqliteShardedRefDestructureTrait,
            },
            snapshot_db_manager_sqlite::AlreadyOpenSnapshots,
            snapshot_mpt::{SnapshotMpt, SnapshotMptLoadNode},
            sqlite::SQLITE_NO_PARAM,
        },
    },
    storage_db::{
        KeyValueDbIterableTrait, KeyValueDbTraitSingleWriter, KeyValueDbTypes,
        OpenSnapshotMptTrait, OwnedReadImplByFamily, OwnedReadImplFamily,
        ReadImplByFamily, ReadImplFamily, SingleWriterImplByFamily,
        SingleWriterImplFamily, SnapshotDbTrait, SnapshotMptDbValue,
        SnapshotMptTraitReadAndIterate, SnapshotMptTraitRw,
    },
    KVInserter, SnapshotDbManagerSqlite, SqliteConnection,
};
use fallible_iterator::FallibleIterator;
use primitives::{MerkleHash, StorageKey};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::Semaphore;
