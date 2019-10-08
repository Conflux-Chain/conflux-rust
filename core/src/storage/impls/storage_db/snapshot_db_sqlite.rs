// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotDbSqlite {
    // Option because we need an empty snapshot db for empty snapshot.
    maybe_db: Option<SqliteConnection>,
    height: i64,
}

pub struct SnapshotDbStatements {
    kvdb_statements: KvdbSqliteStatements,
    mpt_statements: KvdbSqliteStatements,
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
            &["node_rlp", "subtree_kv_rlp_size"],
            &["BLOB", "INTEGER"],
            SnapshotDbSqlite::SNAPSHOT_MPT_TABLE_NAME,
            false,
        )
        .unwrap();

        SnapshotDbStatements {
            kvdb_statements,
            mpt_statements,
        }
    };
}

impl SnapshotDbSqlite {
    // TODO(yz): check if WITHOUT ROWID is faster: see https://www.sqlite.org/withoutrowid.html.
    pub const CREATE_TABLE_BLOB_KEY_STATEMENT: &'static str =
        "CREATE TABLE {} ( key BLOB PRIMARY KEY ) WITHOUT ROWID";
    pub const DELETE_TABLE_KEY_INSERT_STATEMENT: &'static str =
        "INSERT INTO {} VALUES :key";
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

impl SnapshotDbTrait for SnapshotDbSqlite {
    fn get_null_snapshot() -> Self {
        Self {
            maybe_db: None,
            height: 0,
        }
    }

    fn open(snapshot_path: &str) -> Result<Option<SnapshotDbSqlite>> {
        let file_exists = Path::new(&snapshot_path).exists();
        let sqlite_open_result = SqliteConnection::open(
            &snapshot_path,
            true,
            SqliteConnection::default_open_flags(),
        );
        if file_exists {
            return Ok(Some(SnapshotDbSqlite {
                maybe_db: Some(sqlite_open_result?),
                height: 0,
            }));
        } else {
            return Ok(None);
        }
        // FIXME: load height.
    }

    fn create(snapshot_path: &str, height: i64) -> Result<SnapshotDbSqlite> {
        let mut ok_result = Ok(SnapshotDbSqlite {
            maybe_db: Some(SqliteConnection::create_and_open(
                &snapshot_path,
                SqliteConnection::default_open_flags(),
            )?),
            height,
        });

        {
            let snapshot_db =
                ok_result.as_mut().unwrap().maybe_db.as_mut().unwrap();

            snapshot_db
                .execute(
                    &SNAPSHOT_DB_STATEMENTS
                        .kvdb_statements
                        .stmts_main_table
                        .create_table,
                    &[&&Self::SNAPSHOT_KV_TABLE_NAME as SqlBindableRef],
                )?
                .finish_ignore_rows()?;
            snapshot_db
                .execute(
                    &SNAPSHOT_DB_STATEMENTS
                        .mpt_statements
                        .stmts_main_table
                        .create_table,
                    &[&&Self::SNAPSHOT_MPT_TABLE_NAME as SqlBindableRef],
                )?
                .finish_ignore_rows()?;
            // FIXME: create index.
        }

        ok_result
    }

    // FIXME: use a mechanism with rate limit.
    fn direct_merge(
        &mut self, delta_mpt: &DeltaMptInserter,
    ) -> Result<MerkleHash> {
        {
            let sqlite = self.maybe_db.as_mut().unwrap();
            // FIXME: maintain snapshot_key_value_delete?
            sqlite.execute(
                "DELETE FROM :snapshot_table_name WHERE KEY IN (SELECT :delta_kv_delete_table_name.key)",
                &[&&Self::SNAPSHOT_KV_TABLE_NAME as SqlBindableRef, &&Self::DELTA_KV_DELETE_TABLE_NAME],
            )?.finish_ignore_rows()?;
            sqlite.execute(
                "INSERT OR REPLACE INTO :snapshot_table_name (key, value, version) SELECT \
            :delta_kv_insert_table_name.key, :delta_kv_insert_table_name.value, :version",
                &[
                    &&Self::SNAPSHOT_KV_TABLE_NAME as SqlBindableRef,
                    &&Self::DELTA_KV_INSERT_TABLE_NAME,
                    &self.height]
            )?.finish_ignore_rows()?;
        }

        {
            let mut mpt_to_modify = self.open_snapshot_mpt_for_write()?;
            let mut mpt_merger = MptMerger::new(
                None,
                &mut mpt_to_modify as &mut dyn SnapshotMptTraitSingleWriter,
            );
            mpt_merger.merge(delta_mpt)
        }
    }

    fn copy_and_merge(
        &mut self, old_snapshot_db: &mut SnapshotDbSqlite,
        delta_mpt: &DeltaMptInserter,
    ) -> Result<MerkleHash>
    {
        let mut base_mpt = old_snapshot_db.open_snapshot_mpt_read_only()?;
        let mut save_as_mpt = self.open_snapshot_mpt_for_write()?;
        let mut mpt_merger = MptMerger::new(
            Some(&mut base_mpt as &mut dyn SnapshotMptTraitReadOnly),
            &mut save_as_mpt as &mut dyn SnapshotMptTraitSingleWriter,
        );
        mpt_merger.merge(delta_mpt)
    }
}

impl SnapshotDbSqlite {
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            maybe_db: match &self.maybe_db {
                None => None,
                Some(conn) => Some(conn.try_clone()?),
            },
            height: self.height,
        })
    }

    fn snapshot_kv_row_parser<'db>(
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
        let subtree_size = row.read::<i64>(2)?;
        Ok((
            key.into_boxed_slice(),
            value.into_boxed_slice(),
            subtree_size,
        ))
    }

    fn open_snapshot_mpt_for_write(
        &mut self,
    ) -> Result<
        SnapshotMpt<
            ConnectionWithRowParser<
                KvdbSqliteBorrowMut<SnapshotMptDbValue>,
                SnapshotMptValueParserSqlite,
            >,
            ConnectionWithRowParser<
                KvdbSqliteBorrowMut<SnapshotMptDbValue>,
                SnapshotMptValueParserSqlite,
            >,
        >,
    > {
        Ok(SnapshotMpt {
            db: ConnectionWithRowParser(
                KvdbSqliteBorrowMut::new((
                    self.maybe_db.as_mut(),
                    &SNAPSHOT_DB_STATEMENTS.mpt_statements,
                )),
                Box::new(|x| Self::snapshot_mpt_row_parser(x)),
            ),
            _marker_db_type: Default::default(),
        })
    }

    pub fn open_snapshot_mpt_read_only(
        &mut self,
    ) -> Result<
        SnapshotMpt<
            ConnectionWithRowParser<
                KvdbSqliteBorrowMutReadOnly<SnapshotMptDbValue>,
                SnapshotMptValueParserSqlite,
            >,
            ConnectionWithRowParser<
                KvdbSqliteBorrowMutReadOnly<SnapshotMptDbValue>,
                SnapshotMptValueParserSqlite,
            >,
        >,
    > {
        Ok(SnapshotMpt {
            db: ConnectionWithRowParser(
                KvdbSqliteBorrowMutReadOnly::new((
                    self.maybe_db.as_mut(),
                    Self::SNAPSHOT_MPT_TABLE_NAME,
                    Self::SNAPSHOT_MPT_TABLE_NAME,
                    &SNAPSHOT_DB_STATEMENTS.mpt_statements,
                )),
                Box::new(|x| Self::snapshot_mpt_row_parser(x)),
            ),
            _marker_db_type: Default::default(),
        })
    }

    // FIXME: add rate limit.
    // FIXME: how to handle row_id, this should go to the merkle tree?
    pub fn dump_delta_mpt(
        &mut self, delta_mpt: &DeltaMptInserter,
    ) -> Result<()> {
        let sqlite = self.maybe_db.as_mut().unwrap();
        sqlite
            .execute(
                format!(
                    "CREATE TABLE {} ( key BLOB PRIMARY KEY ) WITHOUT ROWID",
                    Self::DELTA_KV_DELETE_TABLE_NAME
                )
                .as_str(),
                SQLITE_NO_PARAM,
            )?
            .finish_ignore_rows()?;
        sqlite
            .execute(
                &SNAPSHOT_DB_STATEMENTS
                    .kvdb_statements
                    .stmts_main_table
                    .create_table,
                &[&&Self::DELTA_KV_INSERT_TABLE_NAME as SqlBindableRef],
            )?
            .finish_ignore_rows()?;

        // Dump code.
        delta_mpt.iterate(DeltaMptDumperSqlite::new(self))
    }

    /// Dropping is optional, because these tables are necessary to provide
    /// 1-step syncing.
    pub fn drop_delta_mpt_dump(&mut self) -> Result<()> {
        let sqlite = self.maybe_db.as_mut().unwrap();
        sqlite
            .execute(
                SNAPSHOT_DB_STATEMENTS
                    .kvdb_statements
                    .stmts_main_table
                    .drop_table,
                &[&&Self::DELTA_KV_INSERT_TABLE_NAME as SqlBindableRef],
            )?
            .finish_ignore_rows()?;

        sqlite
            .execute(
                KvdbSqliteStatements::DROP_TABLE_STATEMENT,
                &[&&Self::DELTA_KV_DELETE_TABLE_NAME as SqlBindableRef],
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
        let (key, value) = x;

        if value.len() > 0 {
            self.snapshot_db
                .maybe_db
                .as_mut()
                .unwrap()
                .execute(
                    &SNAPSHOT_DB_STATEMENTS
                        .kvdb_statements
                        .stmts_main_table
                        .put,
                    &[
                        &&SnapshotDbSqlite::DELTA_KV_INSERT_TABLE_NAME
                            as SqlBindableRef,
                        &&key,
                        &&value,
                    ],
                )?
                .finish_ignore_rows()?;
        } else {
            self.snapshot_db
                .maybe_db
                .as_mut()
                .unwrap()
                .execute(
                    format!(
                        "INSERT INTO {} VALUES :key",
                        SnapshotDbSqlite::DELTA_KV_DELETE_TABLE_NAME
                    )
                    .as_str(),
                    &[&&key as SqlBindableRef],
                )?
                .finish_ignore_rows()?;
        }

        Ok(())
    }
}

pub type SnapshotKVParserSqlite =
    Box<dyn for<'db> FnMut(&Statement<'db>) -> Result<(Vec<u8>, Vec<u8>)>>;
pub type SnapshotMptValueParserSqlite =
    Box<dyn for<'db> FnMut(&Statement<'db>) -> Result<SnapshotMptValue>>;

use super::{
    super::{
        super::storage_db::{
            KeyValueDbToOwnedReadTrait, KeyValueDbTraitOwnedRead,
            KeyValueDbTypes, OwnedReadImplFamily, ReadImplFamily,
            SingleWriterImplFamily, SnapshotDbTrait, SnapshotMptDbValue,
            SnapshotMptTraitReadOnly, SnapshotMptTraitSingleWriter,
            SnapshotMptValue,
        },
        errors::*,
        multi_version_merkle_patricia_trie::merkle_patricia_trie::{
            cow_node_ref::KVInserter, mpt_merger::MptMerger,
        },
        storage_manager::DeltaMptInserter,
    },
    kvdb_sqlite::{
        KvdbSqlite, KvdbSqliteBorrowMut, KvdbSqliteBorrowMutReadOnly,
        KvdbSqliteDestructureTrait, KvdbSqliteStatements,
    },
    snapshot_mpt::SnapshotMpt,
    sqlite::{ConnectionWithRowParser, SqlBindableRef, SqliteConnection},
};
use crate::storage::impls::storage_db::sqlite::SQLITE_NO_PARAM;
use primitives::MerkleHash;
use sqlite::Statement;
use std::path::Path;
