// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotDbSqlite {
    // Option because we need an empty snapshot db for empty snapshot.
    maybe_db: Option<SqliteConnection>,
}

pub struct SnapshotDbStatements {
    kvdb_statements: KvdbSqliteStatements,
    mpt_statements: KvdbSqliteStatements,
    delta_mpt_set_keys_statements: KvdbSqliteStatements,
    delta_mpt_delete_keys_statements: KvdbSqliteStatements,
}

lazy_static! {
    pub static ref SNAPSHOT_DB_STATEMENTS: SnapshotDbStatements = {
        let kvdb_statements = KvdbSqliteStatements::make_statements(
            &["value"],
            &["BLOB"],
            SnapshotDbSqlite::SNAPSHOT_KV_TABLE_NAME,
            false,
        )
        .unwrap();
        let mpt_statements = KvdbSqliteStatements::make_statements(
            &["node_rlp"],
            &["BLOB"],
            SnapshotDbSqlite::SNAPSHOT_MPT_TABLE_NAME,
            false,
        )
        .unwrap();

        let delta_mpt_set_keys_statements =
            KvdbSqliteStatements::make_statements(
                &["value"],
                &["BLOB"],
                SnapshotDbSqlite::DELTA_KV_INSERT_TABLE_NAME,
                false,
            )
            .unwrap();
        let delta_mpt_delete_keys_statements =
            KvdbSqliteStatements::make_statements(
                &[],
                &[],
                SnapshotDbSqlite::DELTA_KV_DELETE_TABLE_NAME,
                false,
            )
            .unwrap();

        SnapshotDbStatements {
            kvdb_statements,
            mpt_statements,
            delta_mpt_set_keys_statements,
            delta_mpt_delete_keys_statements,
        }
    };
}

impl SnapshotDbSqlite {
    /// These two tables are temporary table for the merging process, but they
    /// remain to help other nodes to do 1-step syncing.
    pub const DELTA_KV_DELETE_TABLE_NAME: &'static str =
        "delta_mpt_key_value_delete";
    pub const DELTA_KV_INSERT_TABLE_NAME: &'static str =
        "delta_mpt_key_value_insert";
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

impl KvdbSqliteDestructureTrait for SnapshotDbSqlite {
    fn destructure(
        &self,
    ) -> (Option<&SqliteConnection>, &KvdbSqliteStatements) {
        (
            self.maybe_db.as_ref(),
            &SNAPSHOT_DB_STATEMENTS.kvdb_statements,
        )
    }

    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut SqliteConnection>, &KvdbSqliteStatements) {
        (
            self.maybe_db.as_mut(),
            &SNAPSHOT_DB_STATEMENTS.kvdb_statements,
        )
    }
}

impl KeyValueDbTypes for SnapshotDbSqlite {
    type ValueType = Box<[u8]>;
}

/// Automatically implement KeyValueDbTraitRead with the same code of
/// KvdbSqlite.
impl ReadImplFamily for SnapshotDbSqlite {
    type FamilyRepresentative = KvdbSqlite<Box<[u8]>>;
}

impl OwnedReadImplFamily for SnapshotDbSqlite {
    type FamilyRepresentative = KvdbSqlite<Box<[u8]>>;
}

impl SingleWriterImplFamily for SnapshotDbSqlite {
    type FamilyRepresentative = KvdbSqlite<Box<[u8]>>;
}

impl KeyValueDbToOwnedReadTrait for SnapshotDbSqlite {
    fn to_owned_read<'a>(
        &'a self,
    ) -> Result<
        Box<dyn 'a + KeyValueDbTraitOwnedRead<ValueType = Self::ValueType>>,
    > {
        Ok(Box::new(self.try_clone()?))
    }
}

impl<'db> OpenSnapshotMptTrait<'db> for SnapshotDbSqlite {
    type SnapshotMptReadType = SnapshotMpt<
        ConnectionWithRowParser<
            KvdbSqliteBorrowMutReadOnly<'db, SnapshotMptDbValue>,
            SnapshotMptValueParserSqlite,
        >,
        ConnectionWithRowParser<
            KvdbSqliteBorrowMutReadOnly<'db, SnapshotMptDbValue>,
            SnapshotMptValueParserSqlite,
        >,
    >;
    type SnapshotMptWriteType = SnapshotMpt<
        ConnectionWithRowParser<
            KvdbSqliteBorrowMut<'db, SnapshotMptDbValue>,
            SnapshotMptValueParserSqlite,
        >,
        ConnectionWithRowParser<
            KvdbSqliteBorrowMut<'db, SnapshotMptDbValue>,
            SnapshotMptValueParserSqlite,
        >,
    >;

    fn open_snapshot_mpt_for_write(
        &'db mut self,
    ) -> Result<Self::SnapshotMptWriteType> {
        // Can't omit template types because it fails to compile if omitted.
        Ok(SnapshotMpt::new(ConnectionWithRowParser::<
            KvdbSqliteBorrowMut<'db, SnapshotMptDbValue>,
            SnapshotMptValueParserSqlite,
        >(
            KvdbSqliteBorrowMut::new((
                self.maybe_db.as_mut(),
                &SNAPSHOT_DB_STATEMENTS.mpt_statements,
            )),
            Box::new(|x| Self::snapshot_mpt_row_parser(x)),
        ))?)
    }

    fn open_snapshot_mpt_read_only(
        &'db mut self,
    ) -> Result<Self::SnapshotMptReadType> {
        // Can't omit template types because it fails to compile if omitted.
        Ok(SnapshotMpt::new(ConnectionWithRowParser::<
            KvdbSqliteBorrowMutReadOnly<'db, SnapshotMptDbValue>,
            SnapshotMptValueParserSqlite,
        >(
            KvdbSqliteBorrowMutReadOnly::new((
                self.maybe_db.as_mut(),
                &SNAPSHOT_DB_STATEMENTS.mpt_statements,
            )),
            Box::new(|x| Self::snapshot_mpt_row_parser(x)),
        ))?)
    }
}

impl SnapshotDbTrait for SnapshotDbSqlite {
    fn get_null_snapshot() -> Self { Self { maybe_db: None } }

    fn open(
        snapshot_path: &str, read_only: bool,
    ) -> Result<Option<SnapshotDbSqlite>> {
        let file_exists = Path::new(&snapshot_path).exists();
        let sqlite_open_result = SqliteConnection::open(
            &Self::db_file_paths(snapshot_path)[0],
            read_only,
            SqliteConnection::default_open_flags(),
        );
        if file_exists {
            return Ok(Some(SnapshotDbSqlite {
                maybe_db: Some(sqlite_open_result?),
            }));
        } else {
            return Ok(None);
        }
    }

    fn create(snapshot_path: &str) -> Result<SnapshotDbSqlite> {
        fs::create_dir_all(snapshot_path).ok();

        let create_result = SqliteConnection::create_and_open(
            &Self::db_file_paths(snapshot_path)[0],
            SqliteConnection::default_open_flags(),
        );

        let mut ok_result;
        match create_result {
            Err(e) => {
                fs::remove_dir_all(snapshot_path)?;
                bail!(e);
            }
            Ok(db_conn) => {
                ok_result = Ok(SnapshotDbSqlite {
                    maybe_db: Some(db_conn),
                });
            }
        }

        {
            let snapshot_db =
                ok_result.as_mut().unwrap().maybe_db.as_mut().unwrap();

            snapshot_db
                .execute(
                    &SNAPSHOT_DB_STATEMENTS
                        .kvdb_statements
                        .stmts_main_table
                        .create_table,
                    SQLITE_NO_PARAM,
                )?
                .finish_ignore_rows()?;
            snapshot_db
                .execute(
                    &SNAPSHOT_DB_STATEMENTS
                        .mpt_statements
                        .stmts_main_table
                        .create_table,
                    SQLITE_NO_PARAM,
                )?
                .finish_ignore_rows()?;
            // FIXME: create index.
        }

        ok_result
    }

    // FIXME: use a mechanism with rate limit.
    fn direct_merge(&mut self) -> Result<MerkleHash> {
        self.apply_update_to_kvdb()?;

        let mut insert_keys_iter =
            self.dumped_delta_kv_insert_keys_iterator()?;
        let mut delete_keys_iter =
            self.dumped_delta_kv_delete_keys_iterator()?;
        let mut mpt_to_modify = self.open_snapshot_mpt_for_write()?;
        let mut mpt_merger = MptMerger::new(
            None,
            &mut mpt_to_modify as &mut dyn SnapshotMptTraitSingleWriter,
        );
        mpt_merger.merge_insertion_deletion_separated(
            delete_keys_iter.iter_range(&[], None)?,
            insert_keys_iter.iter_range(&[], None)?,
        )
    }

    fn copy_and_merge(
        &mut self, old_snapshot_db: &mut SnapshotDbSqlite,
    ) -> Result<MerkleHash> {
        let mut kv_iter = old_snapshot_db.snapshot_kv_iterator();
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

        let mut insert_keys_iter =
            self.dumped_delta_kv_insert_keys_iterator()?;
        let mut delete_keys_iter =
            self.dumped_delta_kv_delete_keys_iterator()?;
        let mut base_mpt = old_snapshot_db.open_snapshot_mpt_read_only()?;
        let mut save_as_mpt = self.open_snapshot_mpt_for_write()?;
        let mut mpt_merger = MptMerger::new(
            Some(&mut base_mpt as &mut dyn SnapshotMptTraitReadOnly),
            &mut save_as_mpt as &mut dyn SnapshotMptTraitSingleWriter,
        );
        mpt_merger.merge_insertion_deletion_separated(
            delete_keys_iter.iter_range(&[], None)?,
            insert_keys_iter.iter_range(&[], None)?,
        )
    }
}

impl SnapshotDbSqlite {
    pub fn db_file_paths(db_path: &str) -> Vec<String> {
        vec![db_path.to_string() + "/shard_00"]
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            maybe_db: match &self.maybe_db {
                None => None,
                Some(conn) => Some(conn.try_clone()?),
            },
        })
    }

    // FIXME: pub is problematic.
    pub fn snapshot_kv_row_parser<'db>(
        row: &Statement<'db>,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let key = row.read::<Vec<u8>>(0)?;
        let value = row.read::<Vec<u8>>(1)?;

        Ok((key, value))
    }

    pub fn snapshot_kv_iterator(
        &mut self,
    ) -> ConnectionWithRowParser<
        KvdbSqliteBorrowMut<SnapshotMptDbValue>,
        SnapshotKVParserSqlite,
    > {
        ConnectionWithRowParser(
            KvdbSqliteBorrowMut::new((
                self.maybe_db.as_mut(),
                &SNAPSHOT_DB_STATEMENTS.kvdb_statements,
            )),
            Box::new(|x| Self::snapshot_kv_row_parser(x)),
        )
    }

    fn snapshot_mpt_row_parser<'db>(
        row: &Statement<'db>,
    ) -> Result<SnapshotMptValue> {
        let key = row.read::<Vec<u8>>(0)?;
        let value = row.read::<Vec<u8>>(1)?;
        Ok((key.into_boxed_slice(), value.into_boxed_slice()))
    }

    fn delta_kv_insertion_row_parser<'db>(
        row: &Statement<'db>,
    ) -> Result<(Vec<u8>, Box<[u8]>)> {
        let key = row.read::<Vec<u8>>(0)?;
        let value = row.read::<Vec<u8>>(1)?;
        Ok((key, value.into_boxed_slice()))
    }

    pub fn dumped_delta_kv_insert_keys_iterator(
        &self,
    ) -> Result<
        ConnectionWithRowParser<
            KvdbSqlite<Box<[u8]>>,
            DeltaKVInsertionParserSqlite,
        >,
    > {
        let maybe_db = match &self.maybe_db {
            None => None,
            Some(db) => Some(db.try_clone()?),
        };
        Ok(ConnectionWithRowParser(
            KvdbSqlite::new(
                maybe_db,
                Arc::new(
                    SNAPSHOT_DB_STATEMENTS
                        .delta_mpt_set_keys_statements
                        .clone(),
                ),
            )?,
            Box::new(|x| Self::delta_kv_insertion_row_parser(x)),
        ))
    }

    fn delta_kv_deletion_row_parser<'db>(
        row: &Statement<'db>,
    ) -> Result<Vec<u8>> {
        let key = row.read::<Vec<u8>>(0)?;

        Ok(key)
    }

    pub fn dumped_delta_kv_delete_keys_iterator(
        &self,
    ) -> Result<
        ConnectionWithRowParser<
            KvdbSqlite<Box<[u8]>>,
            DeltaKVDeletionParserSqlite,
        >,
    > {
        let maybe_db = match &self.maybe_db {
            None => None,
            Some(db) => Some(db.try_clone()?),
        };
        Ok(ConnectionWithRowParser(
            KvdbSqlite::new(
                maybe_db,
                Arc::new(
                    SNAPSHOT_DB_STATEMENTS
                        .delta_mpt_delete_keys_statements
                        .clone(),
                ),
            )?,
            Box::new(|x| Self::delta_kv_deletion_row_parser(x)),
        ))
    }

    // FIXME: add rate limit.
    // FIXME: how to handle row_id, this should go to the merkle tree?
    pub fn dump_delta_mpt(
        &mut self, delta_mpt: &DeltaMptIterator,
    ) -> Result<()> {
        let sqlite = self.maybe_db.as_mut().unwrap();
        sqlite
            .execute(
                &SNAPSHOT_DB_STATEMENTS
                    .delta_mpt_delete_keys_statements
                    .stmts_main_table
                    .create_table,
                SQLITE_NO_PARAM,
            )?
            .finish_ignore_rows()?;
        sqlite
            .execute(
                &SNAPSHOT_DB_STATEMENTS
                    .delta_mpt_set_keys_statements
                    .stmts_main_table
                    .create_table,
                SQLITE_NO_PARAM,
            )?
            .finish_ignore_rows()?;

        // Dump code.
        delta_mpt.iterate(&mut DeltaMptDumperSqlite::new(self))
    }

    /// Dropping is optional, because these tables are necessary to provide
    /// 1-step syncing.
    pub fn drop_delta_mpt_dump(&mut self) -> Result<()> {
        let sqlite = self.maybe_db.as_mut().unwrap();
        sqlite
            .execute(
                &SNAPSHOT_DB_STATEMENTS
                    .delta_mpt_set_keys_statements
                    .stmts_main_table
                    .drop_table,
                SQLITE_NO_PARAM,
            )?
            .finish_ignore_rows()?;
        sqlite
            .execute(
                &SNAPSHOT_DB_STATEMENTS
                    .delta_mpt_delete_keys_statements
                    .stmts_main_table
                    .drop_table,
                SQLITE_NO_PARAM,
            )?
            .finish_ignore_rows()?;

        Ok(())
    }

    fn apply_update_to_kvdb(&mut self) -> Result<()> {
        let sqlite = self.maybe_db.as_mut().unwrap();
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
                    Self::DELTA_KV_INSERT_TABLE_NAME
                )
                .as_str(),
                SQLITE_NO_PARAM,
            )?
            .finish_ignore_rows()?;
        Ok(())
    }
}

pub struct DeltaMptDumperSqlite<'a> {
    snapshot_db: &'a mut SnapshotDbSqlite,
}

impl<'a> DeltaMptDumperSqlite<'a> {
    pub fn new(snapshot_db: &'a mut SnapshotDbSqlite) -> Self {
        Self { snapshot_db }
    }
}

impl<'a> KVInserter<(Vec<u8>, Box<[u8]>)> for DeltaMptDumperSqlite<'a> {
    fn push(&mut self, x: (Vec<u8>, Box<[u8]>)) -> Result<()> {
        let (mpt_key, value) = x;
        let snapshot_key =
            StorageKey::from_delta_mpt_key(&mpt_key).to_key_bytes();

        if value.len() > 0 {
            self.snapshot_db
                .maybe_db
                .as_mut()
                .unwrap()
                .execute(
                    &SNAPSHOT_DB_STATEMENTS
                        .delta_mpt_set_keys_statements
                        .stmts_main_table
                        .put,
                    &[&&snapshot_key as SqlBindableRef, &&value],
                )?
                .finish_ignore_rows()?;
        } else {
            self.snapshot_db
                .maybe_db
                .as_mut()
                .unwrap()
                .execute(
                    &SNAPSHOT_DB_STATEMENTS
                        .delta_mpt_delete_keys_statements
                        .stmts_main_table
                        .put,
                    &[&&snapshot_key as SqlBindableRef],
                )?
                .finish_ignore_rows()?;
        }

        Ok(())
    }
}

// FIXME: These Parser are all trivial, why not name them by key, value, and put
// into a central place?
pub type SnapshotKVParserSqlite =
    Box<dyn for<'db> FnMut(&Statement<'db>) -> Result<(Vec<u8>, Vec<u8>)>>;
pub type SnapshotMptValueParserSqlite =
    Box<dyn for<'db> FnMut(&Statement<'db>) -> Result<SnapshotMptValue>>;
pub type DeltaKVInsertionParserSqlite =
    Box<dyn for<'db> FnMut(&Statement<'db>) -> Result<(Vec<u8>, Box<[u8]>)>>;
pub type DeltaKVDeletionParserSqlite =
    Box<dyn for<'db> FnMut(&Statement<'db>) -> Result<Vec<u8>>>;

use crate::storage::{
    impls::{
        delta_mpt::DeltaMptIterator,
        errors::*,
        merkle_patricia_trie::{KVInserter, MptMerger},
        storage_db::{
            kvdb_sqlite::{
                KvdbSqlite, KvdbSqliteBorrowMut, KvdbSqliteBorrowMutReadOnly,
                KvdbSqliteDestructureTrait, KvdbSqliteStatements,
            },
            snapshot_mpt::SnapshotMpt,
            sqlite::{
                ConnectionWithRowParser, SqlBindableRef, SqliteConnection,
                SQLITE_NO_PARAM,
            },
        },
    },
    storage_db::{
        KeyValueDbIterableTrait, KeyValueDbToOwnedReadTrait,
        KeyValueDbTraitOwnedRead, KeyValueDbTraitSingleWriter, KeyValueDbTypes,
        OpenSnapshotMptTrait, OwnedReadImplFamily, ReadImplFamily,
        SingleWriterImplFamily, SnapshotDbTrait, SnapshotMptDbValue,
        SnapshotMptTraitReadOnly, SnapshotMptTraitSingleWriter,
        SnapshotMptValue,
    },
};
use fallible_iterator::FallibleIterator;
use primitives::{MerkleHash, StorageKey};
use sqlite::Statement;
use std::{fs, path::Path, sync::Arc};
