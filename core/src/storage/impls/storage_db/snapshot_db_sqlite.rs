// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotDbSqlite {
    // Option because we need an empty snapshot db for empty snapshot.
    maybe_db: Option<SqliteConnection>,
    height: i64,
}

impl SnapshotDbSqlite {
    // TODO(yz): check if WITHOUT ROWID is faster: see https://www.sqlite.org/withoutrowid.html.
    pub const CREATE_TABLE_BLOB_KEY_STATEMENT: &'static str =
        "CREATE TABLE :table_name ( key BLOB PRIMARY KEY ) WITHOUT ROWID";
    pub const CREATE_TABLE_BLOB_KEY_VALUE_VERSION_STATEMENT: &'static str =
        "CREATE TABLE :table_name ( key BLOB PRIMARY KEY, value: BLOB, version: INTEGER ) WITHOUT ROWID";
    pub const CREATE_TABLE_BLOB_KEY_VERSION_STATEMENT: &'static str =
        "CREATE TABLE :table_name ( key BLOB PRIMARY KEY, version: INTEGER ) WITHOUT ROWID";
    pub const DELETE_TABLE_KEY_INSERT_STATEMENT: &'static str =
        "INSERT INTO :table_name VALUES :key";
    pub const DELETE_TABLE_KEY_VERSION_INSERT_STATEMENT: &'static str =
        "INSERT INTO :table_name VALUES (:key, :version)";
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
    pub const KVV_PUT_STATEMENT: &'static str =
        "INSERT OR REPLACE INTO :table_name VALUES (:key, :value, :version)";
    /// Key is not unique, because the same key can appear with different
    /// version number.
    pub const SNAPSHOT_KV_DELETE_TABLE_NAME: &'static str =
        "snapshot_key_value_delete";
    /// Key-Value table. Key is unique key in this table.
    pub const SNAPSHOT_KV_TABLE_NAME: &'static str = "snapshot_key_value";
    /// MPT Table.
    pub const SNAPSHOT_MPT_TABLE_NAME: &'static str = "snapshot_mpt";
}

impl KvdbSqliteDestructureTrait for SnapshotDbSqlite {
    fn destructure(&self) -> (Option<&SqliteConnection>, &str) {
        (self.maybe_db.as_ref(), Self::SNAPSHOT_KV_TABLE_NAME)
    }

    fn destructure_mut(&mut self) -> (Option<&mut SqliteConnection>, &str) {
        (self.maybe_db.as_mut(), Self::SNAPSHOT_KV_TABLE_NAME)
    }
}

/// Automatically implement KeyValueDbTraitRead with the same code of
/// KvdbSqlite.
impl ReadImplFamily for SnapshotDbSqlite {
    type FamilyRepresentitive = KvdbSqlite;
}

impl OwnedReadImplFamily for SnapshotDbSqlite {
    type FamilyRepresentitive = KvdbSqlite;
}

impl SingleWriterImplFamily for SnapshotDbSqlite {
    type FamilyRepresentitive = KvdbSqlite;
}

impl KeyValueDbToOwnedReadTrait for SnapshotDbSqlite {
    fn to_owned_read<'a>(
        &'a self,
    ) -> Result<Box<dyn 'a + KeyValueDbTraitOwnedRead>> {
        Ok(Box::new(self.try_clone()?))
    }
}

// FIXME: move appropriate methods into SnapshotDbTrait.
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
                    Self::CREATE_TABLE_BLOB_KEY_VERSION_STATEMENT,
                    &[&&Self::SNAPSHOT_KV_DELETE_TABLE_NAME],
                )?
                .finish_ignore_rows()?;
            snapshot_db
                .execute(
                    Self::CREATE_TABLE_BLOB_KEY_VALUE_VERSION_STATEMENT,
                    &[&&Self::SNAPSHOT_KV_TABLE_NAME],
                )?
                .finish_ignore_rows()?;
            snapshot_db
                .execute(
                    KvdbSqlite::CREATE_TABLE_BLOB_KV_STATEMENT,
                    &[&&Self::SNAPSHOT_MPT_TABLE_NAME],
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
                &[&&Self::SNAPSHOT_KV_TABLE_NAME, &&Self::DELTA_KV_DELETE_TABLE_NAME],
            )?.finish_ignore_rows()?;
            sqlite.execute(
                "INSERT OR REPLACE INTO :snapshot_table_name (key, value, version) SELECT \
            :delta_kv_insert_table_name.key, :delta_kv_insert_table_name.value, :version",
                &[
                    &&Self::SNAPSHOT_KV_TABLE_NAME,
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
                KvdbSqliteBorrowMut,
                SnapshotMptValueParserSqlite,
            >,
            ConnectionWithRowParser<
                KvdbSqliteBorrowMut,
                SnapshotMptValueParserSqlite,
            >,
        >,
    > {
        Ok(SnapshotMpt {
            db: ConnectionWithRowParser(
                KvdbSqliteBorrowMut::new((
                    self.maybe_db.as_mut(),
                    Self::SNAPSHOT_MPT_TABLE_NAME,
                )),
                Box::new(|x| Self::snapshot_mpt_row_parser(x)),
            ),
            _marker_db_type: Default::default(),
        })
    }

    fn open_snapshot_mpt_read_only(
        &mut self,
    ) -> Result<
        SnapshotMpt<
            ConnectionWithRowParser<
                KvdbSqliteBorrowMutReadOnly,
                SnapshotMptValueParserSqlite,
            >,
            ConnectionWithRowParser<
                KvdbSqliteBorrowMutReadOnly,
                SnapshotMptValueParserSqlite,
            >,
        >,
    > {
        Ok(SnapshotMpt {
            db: ConnectionWithRowParser(
                KvdbSqliteBorrowMutReadOnly::new((
                    self.maybe_db.as_mut(),
                    Self::SNAPSHOT_MPT_TABLE_NAME,
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
                Self::CREATE_TABLE_BLOB_KEY_STATEMENT,
                &[&&Self::DELTA_KV_DELETE_TABLE_NAME],
            )?
            .finish_ignore_rows()?;
        sqlite
            .execute(
                KvdbSqlite::CREATE_TABLE_BLOB_KV_STATEMENT,
                &[&&Self::DELTA_KV_INSERT_TABLE_NAME],
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
                KvdbSqlite::DROP_TABLE_STATEMENT,
                &[&&Self::DELTA_KV_INSERT_TABLE_NAME],
            )?
            .finish_ignore_rows()?;

        sqlite
            .execute(
                KvdbSqlite::DROP_TABLE_STATEMENT,
                &[&&Self::DELTA_KV_DELETE_TABLE_NAME],
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
                    KvdbSqlite::PUT_STATEMENT,
                    &[
                        &&SnapshotDbSqlite::DELTA_KV_INSERT_TABLE_NAME,
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
                    SnapshotDbSqlite::DELETE_TABLE_KEY_INSERT_STATEMENT,
                    &[&&SnapshotDbSqlite::DELTA_KV_DELETE_TABLE_NAME, &&key],
                )?
                .finish_ignore_rows()?;
        }

        Ok(())
    }
}

pub type SnapshotMptValueParserSqlite =
    Box<dyn for<'db> FnMut(&Statement<'db>) -> Result<SnapshotMptValue>>;

use super::{
    super::{
        super::storage_db::{
            KeyValueDbToOwnedReadTrait, KeyValueDbTraitOwnedRead,
            OwnedReadImplFamily, ReadImplFamily, SingleWriterImplFamily,
            SnapshotDbTrait, SnapshotMptTraitReadOnly,
            SnapshotMptTraitSingleWriter,
        },
        errors::*,
        multi_version_merkle_patricia_trie::merkle_patricia_trie::{
            cow_node_ref::KVInserter, mpt_merger::MptMerger,
        },
        storage_manager::DeltaMptInserter,
    },
    kvdb_sqlite::{
        KvdbSqlite, KvdbSqliteBorrowMut, KvdbSqliteBorrowMutReadOnly,
        KvdbSqliteDestructureTrait,
    },
    snapshot_mpt::{SnapshotMpt, SnapshotMptValue},
    sqlite::{ConnectionWithRowParser, SqliteConnection},
};
use primitives::MerkleHash;
use sqlite::Statement;
use std::path::Path;
