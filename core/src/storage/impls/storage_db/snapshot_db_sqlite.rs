// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Default)]
pub struct SnapshotDbSqlite {
    // Option because we need an empty snapshot db for empty snapshot.
    sqlite: Option<Mutex<SqliteConnection>>,
    height: u64,
}

impl SnapshotDbSqlite {
    fn lock_sqlite(&self) -> MutexGuard<SqliteConnection> {
        self.sqlite.as_ref().unwrap().lock()
    }
}

impl KeyValueDbTraitRead for SnapshotDbSqlite {
    fn get(&self, key: &[u8]) -> Result<Option<Box<[u8]>>> {
        match &self.sqlite {
            None => Ok(None),
            Some(_) => Ok(self
                .lock_sqlite()
                .query_row_named(
                    "SELECT value FROM snapshot_key_value WHERE key = :key",
                    &[("key", &key)],
                    |row| row.get(0),
                )
                .optional()?
                .map(|v: Vec<u8>| v.into_boxed_slice())),
        }
    }
}

impl KeyValueDbTraitSingleWriter for SnapshotDbSqlite {
    fn delete(&mut self, key: &[u8]) -> Result<Option<Option<Box<[u8]>>>> {
        match &self.sqlite {
            None => Err(Error::from(ErrorKind::SnapshotNotFound)),
            Some(_) => {
                let locked_sql = self.lock_sqlite();
                locked_sql.execute_named(
                    "DELETE FROM snapshot_key_value WHERE key = :key",
                    &[(":key", &key)],
                )?;
                locked_sql.execute_named(
                    "INSERT INTO snapshot_key_value_delete (:key, :version)",
                    &[(":key", &key), (":version", &self.height.to_string())],
                )?;
                Ok(None)
            }
        }
    }

    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        match &self.sqlite {
            None => Err(Error::from(ErrorKind::SnapshotNotFound)),
            Some(_) => {
                self.lock_sqlite().execute_named(
                    "INSERT INTO snapshot_key_value (:key, :value, :version)",
                    &[
                        (":key", &key),
                        (":value", &value),
                        (":version", &self.height.to_string()),
                    ],
                )?;
                Ok(())
            }
        }
    }
}

// FIXME: move approporiate methods into SnapshotDbTrait.
impl SnapshotDbTrait for SnapshotDbSqlite {}

impl SnapshotDbSqlite {
    pub fn open(
        snapshot_path: &String,
    ) -> Result<Option<Arc<SnapshotDbSqlite>>> {
        let file_exists = Path::new(&snapshot_path).exists();
        let sqlite_open_result = SqliteConnection::open_with_flags(
            &snapshot_path,
            SqliteOpenFlags::SQLITE_OPEN_CREATE
                | SqliteOpenFlags::SQLITE_OPEN_NO_MUTEX
                | SqliteOpenFlags::SQLITE_OPEN_URI,
        );
        if file_exists {
            return Ok(Some(Arc::new(SnapshotDbSqlite {
                sqlite: Some(Mutex::new(sqlite_open_result?)),
                height: 0,
            })));
        } else {
            return Ok(None);
        }
        // FIXME: load height.
    }

    pub fn create(
        snapshot_path: &String, height: u64,
    ) -> Result<Arc<SnapshotDbSqlite>> {
        let ok_result = Ok(Arc::new(SnapshotDbSqlite {
            sqlite: Some(Mutex::new(SqliteConnection::open(&snapshot_path)?)),
            height,
        }));

        {
            let snapshot_db = ok_result.as_ref().unwrap().lock_sqlite();
            snapshot_db.execute(
                "CREATE TABLE snapshot_key_value_delete \
                ( key BLOB UNIQUE PRIMARY KEY, version: INTEGER ) WITHOUT ROWID",
                rusqlite::NO_PARAMS)?;
            snapshot_db.execute(
                "CREATE TABLE snapshot_key_value \
                ( key BLOB UNIQUE PRIMARY KEY, value: BLOB, version: INTEGER ) WITHOUT ROWID",
                rusqlite::NO_PARAMS)?;
        }

        ok_result
    }

    fn open_snapshot_mpt_for_write(&self) -> SnapshotMpt<Self, &mut Self> {
        SnapshotMpt {
            db: unsafe { &mut *(self as *const Self as *mut Self) },
            _marker_db_type: Default::default(),
        }
    }

    fn open_snapshot_mpt_read_only(&self) -> SnapshotMpt<Self, &Self> {
        SnapshotMpt {
            db: &self,
            _marker_db_type: Default::default(),
        }
    }

    // FIXME: add rate limit.
    // FIXME: how to handle row_id, this should go to the merkle tree?
    pub fn dump_delta_mpt(&self, delta_mpt: &DeltaMptInserter) -> Result<()> {
        let locked_sqlite = self.lock_sqlite();
        locked_sqlite.execute(
            "CREATE TABLE delta_mpt_key_value_delete ( key BLOB UNIQUE PRIMARY KEY )",
            rusqlite::NO_PARAMS)?;
        locked_sqlite.execute(
            "CREATE TABLE delta_mpt_key_value_insert ( key BLOB UNIQUE PRIMARY KEY, value: BLOB )",
            rusqlite::NO_PARAMS)?;

        // Dump code.
        delta_mpt.iterate(DeltaMptDumperSqlite::new(self))
    }

    pub fn drop_delta_mpt_dump(&self) -> Result<()> {
        let locked_sqlite = self.lock_sqlite();
        locked_sqlite.execute(
            "DROP TABLE delta_mpt_key_value_delete",
            rusqlite::NO_PARAMS,
        )?;
        locked_sqlite.execute(
            "DROP TABLE delta_mpt_key_value_insert",
            rusqlite::NO_PARAMS,
        )?;

        Ok(())
    }

    // FIXME: use a mechanism with rate limit.
    pub fn direct_merge(
        &self, delta_mpt: &DeltaMptInserter,
    ) -> Result<MerkleHash> {
        let locked_sqlite = self.lock_sqlite();
        // FIXME: maintain snapshot_key_value_delete?
        locked_sqlite.execute(
            "DELETE FROM snapshot_key_value WHERE KEY IN (SELECT delta_mpt_key_value_delete.key)",
            rusqlite::NO_PARAMS
        )?;
        locked_sqlite.execute_named(
            "INSERT INTO snapshot_key_value (key, value, version) SELECT \
            delta_mpt_key_value_insert.key, delta_mpt_key_value_insert.value, :version",
            &[(":version", &self.height.to_string())]
        )?;

        {
            let mut mpt_to_modify = self.open_snapshot_mpt_for_write();
            let mut mpt_merger = MptMerger::new(
                None,
                &mut mpt_to_modify as &mut dyn SnapshotMptTraitSingleWriter,
            );
            mpt_merger.merge(delta_mpt)
        }
    }

    pub fn copy_and_merge(
        &self, old_snapshot_db: &SnapshotDbSqlite, delta_mpt: &DeltaMptInserter,
    ) -> Result<MerkleHash> {
        // FIXME: implement db copy..
        {
            let base_mpt = old_snapshot_db.open_snapshot_mpt_read_only();
            let mut save_as_mpt = self.open_snapshot_mpt_for_write();
            let mut mpt_merger = MptMerger::new(
                Some(&base_mpt as &dyn SnapshotMptTraitReadOnly),
                &mut save_as_mpt as &mut dyn SnapshotMptTraitSingleWriter,
            );
            mpt_merger.merge(delta_mpt)
        }
    }
}

pub struct DeltaMptDumperSqlite<'a> {
    snapshot_db: &'a SnapshotDbSqlite,
}

impl<'a> DeltaMptDumperSqlite<'a> {
    pub fn new(snapshot_db: &'a SnapshotDbSqlite) -> Self {
        Self { snapshot_db }
    }
}

impl<'a> KVInserter<(Vec<u8>, Box<[u8]>)> for DeltaMptDumperSqlite<'a> {
    fn push(&mut self, x: (Vec<u8>, Box<[u8]>)) -> Result<()> {
        let (key, value) = x;

        if value.len() > 0 {
            self.snapshot_db.lock_sqlite().execute_named(
                "INSERT INTO delta_mpt_key_value_insert (key, value) VALUES :key, :value",
                &[("key", &&*key), ("value", &&*value)])?;
        } else {
            self.snapshot_db.lock_sqlite().execute_named(
                "INSERT INTO delta_mpt_key_value_delete (key) VALUES :key",
                &[("key", &key)],
            )?;
        }

        Ok(())
    }
}

use super::{
    super::{
        super::storage_db::{
            KeyValueDbTraitRead, KeyValueDbTraitSingleWriter, SnapshotDbTrait,
            SnapshotMptTraitReadOnly, SnapshotMptTraitSingleWriter,
        },
        errors::*,
        multi_version_merkle_patricia_trie::merkle_patricia_trie::{
            cow_node_ref::KVInserter, mpt_merger::MptMerger,
        },
        storage_manager::DeltaMptInserter,
    },
    snapshot_mpt::SnapshotMpt,
};
use parking_lot::{Mutex, MutexGuard};
use primitives::MerkleHash;
use rusqlite::{
    Connection as SqliteConnection, OpenFlags as SqliteOpenFlags,
    OptionalExtension,
};
use std::{path::Path, sync::Arc};
