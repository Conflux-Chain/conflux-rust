// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct KvdbSqlite {
    pub(super) table_name: String,
    pub(super) connection: Option<SqliteConnection>,
}

pub struct KvdbSqliteBorrowMut<'db> {
    connection: Option<*mut SqliteConnection>,
    table_name: *const str,
    __marker_lifetime: PhantomData<&'db mut SqliteConnection>,
}

pub struct KvdbSqliteBorrowMutReadOnly<'db> {
    connection: Option<*mut SqliteConnection>,
    table_name: *const str,
    __marker_lifetime: PhantomData<&'db mut SqliteConnection>,
}

impl KvdbSqlite {
    // TODO(yz): check if WITHOUT ROWID is faster: see https://www.sqlite.org/withoutrowid.html.
    pub const CREATE_TABLE_BLOB_KV_STATEMENT: &'static str =
        "CREATE TABLE :table_name ( key BLOB PRIMARY KEY, value: BLOB ) WITHOUT ROWID";
    // INTEGER PRIMARY KEY is special, see https://www.sqlite.org/lang_createtable.html#rowid.
    pub const CREATE_TABLE_NUMBER_KV_STATEMENT: &'static str =
        "CREATE TABLE :table_name ( key INTEGER PRIMARY KEY, value: BLOB )";
    pub const DELETE_STATEMENT: &'static str =
        "DELETE FROM :table_name where key = :key";
    pub const DROP_TABLE_STATEMENT: &'static str = "DROP TABLE :table_name";
    pub const GET_STATEMENT: &'static str =
        "SELECT value FROM :table_name WHERE key = :key";
    pub const PUT_STATEMENT: &'static str =
        "INSERT OR REPLACE INTO :table_name VALUES (:key, :value)";
    pub const RANGE_EXCL_SELECT_STATEMENT: &'static str =
        "SELECT key, value FROM :table_name \
        WHERE key > :lower_bound_excl AND key < :upper_bound_excl ORDERED BY key ASC";

    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            table_name: self.table_name.clone(),
            connection: match &self.connection {
                None => None,
                Some(conn) => Some(conn.try_clone()?),
            },
        })
    }
}

impl Default for KvdbSqlite {
    fn default() -> Self {
        Self {
            table_name: Default::default(),
            connection: None,
        }
    }
}

impl KvdbSqlite {
    pub fn new(connection: Option<SqliteConnection>, table_name: &str) -> Self {
        Self {
            connection,
            table_name: table_name.to_string(),
        }
    }

    pub fn create_and_open<P: AsRef<Path>>(
        path: P, table_name: &str,
    ) -> Result<KvdbSqlite> {
        let mut connection = SqliteConnection::create_and_open(
            path,
            SqliteConnection::default_open_flags(),
        )?;
        connection
            .execute(Self::CREATE_TABLE_NUMBER_KV_STATEMENT, &[&&table_name])?
            .finish_ignore_rows()?;;

        Ok(Self {
            table_name: table_name.to_string(),
            connection: Some(connection),
        })
    }
}

impl KeyValueDbTraitTransactional for KvdbSqlite {
    type TransactionType = KvdbSqliteTransaction;

    fn start_transaction(
        &self, immediate_write: bool,
    ) -> Result<KvdbSqliteTransaction> {
        if self.connection.is_none() {
            bail!(ErrorKind::DbNotExist);
        }

        KvdbSqliteTransaction::new(self.try_clone()?, immediate_write)
    }
}

impl KeyValueDbToOwnedReadTrait for KvdbSqlite {
    fn to_owned_read<'a>(
        &'a self,
    ) -> Result<Box<dyn 'a + KeyValueDbTraitOwnedRead>> {
        Ok(Box::new(self.try_clone()?))
    }
}

impl DeltaDbTrait for KvdbSqlite {}

pub struct KvdbSqliteTransaction {
    db: KvdbSqlite,
    committed: bool,
}

impl KvdbSqliteTransaction {
    fn new(mut db: KvdbSqlite, immediate_write: bool) -> Result<Self> {
        match &mut db.connection {
            None => {}
            Some(conn) => {
                Self::start_transaction(conn.get_db_mut(), immediate_write)?;
            }
        }
        Ok(Self {
            db,
            committed: false,
        })
    }

    fn start_transaction(
        db: &mut Connection, immediate_write: bool,
    ) -> Result<()> {
        if immediate_write {
            db.execute("BEGIN IMMEDIATE")?;
        } else {
            db.execute("BEGIN DEFERRED")?;
        }
        Ok(())
    }
}

impl Drop for KvdbSqliteTransaction {
    fn drop(&mut self) {
        if !self.committed {
            self.revert();
        }
    }
}

impl KeyValueDbTransactionTrait for KvdbSqliteTransaction {
    fn commit(&mut self, _db: &dyn Any) -> Result<()> {
        self.committed = true;
        Ok(self
            .connection
            .as_mut()
            .unwrap()
            .get_db_mut()
            .execute("COMMIT")?)
    }

    fn revert(&mut self) {
        self.committed = true;
        self.connection
            .as_mut()
            .unwrap()
            .get_db_mut()
            .execute("ROLLBACK")
            .ok();
    }

    fn restart(
        &mut self, immediate_write: bool, no_revert: bool,
    ) -> Result<()> {
        if !no_revert {
            self.revert();
        }
        Self::start_transaction(
            self.connection.as_mut().unwrap().get_db_mut(),
            immediate_write,
        )
    }
}

impl Deref for KvdbSqliteTransaction {
    type Target = KvdbSqlite;

    fn deref(&self) -> &Self::Target { &self.db }
}

impl DerefMut for KvdbSqliteTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.db }
}

// FIXME: check if the error is SQLITE_BUSY, and if so, assert.
// FIXME: our code should not hit this error.

impl<
        'db,
        'any: 'db,
        Item: 'db,
        T: DerefMutPlusImplOrBorrowMutSelf<dyn 'any + KvdbSqliteDestructureTrait>,
        F: 'db + FnMut(&Statement<'db>) -> Result<Item>,
    > KeyValueDbIterableTrait<'db, Item, Error, [u8]>
    for ConnectionWithRowParser<T, F>
{
    type Iterator = MappedRows<'db, &'db mut F>;

    fn iter_range_excl(
        &'db mut self, lower_bound_excl: &[u8], upper_bound_excl: &[u8],
    ) -> Result<Self::Iterator> {
        let (connection, table_name) = self.0.borrow_mut().destructure_mut();
        match connection {
            None => Ok(MaybeRows::default().map(&mut self.1)),
            Some(conn) => Ok(conn
                .execute(
                    KvdbSqlite::RANGE_EXCL_SELECT_STATEMENT,
                    &[&&table_name, &&lower_bound_excl, &&upper_bound_excl],
                )?
                .map(&mut self.1)),
        }
    }
}

impl<T: ReadImplFamily<FamilyRepresentitive = KvdbSqlite>>
    ReadImplByFamily<KvdbSqlite> for T
where T: KvdbSqliteDestructureTrait
{
    fn get_impl(&self, key: &[u8]) -> Result<Option<Box<[u8]>>> {
        let (connection, table_name) = self.destructure();
        match connection {
            None => Ok(None),
            Some(conn) => {
                let mut db = conn.lock_db();
                let mut statement_cache = conn.lock_statement_cache();

                let statement = SqliteConnection::prepare(
                    &mut db,
                    &mut statement_cache,
                    KvdbSqlite::GET_STATEMENT,
                )?;
                let mut maybe_rows = SqliteConnection::execute_locked(
                    statement,
                    &[&&table_name, &&key],
                )?
                .map(|row| row.read::<Vec<u8>>(0));
                Ok(maybe_rows
                    .expect_one_row()?
                    .transpose()?
                    .map(|v| v.into_boxed_slice()))
            }
        }
    }

    fn get_with_number_key_impl(&self, key: i64) -> Result<Option<Box<[u8]>>> {
        let (connection, table_name) = self.destructure();
        match connection {
            None => Ok(None),
            Some(conn) => {
                let mut db = conn.lock_db();
                let mut statement_cache = conn.lock_statement_cache();

                let statement = SqliteConnection::prepare(
                    &mut db,
                    &mut statement_cache,
                    KvdbSqlite::GET_STATEMENT,
                )?;
                let mut maybe_rows = SqliteConnection::execute_locked(
                    statement,
                    &[&&table_name, &key],
                )?
                .map(|row| row.read::<Vec<u8>>(0));
                Ok(maybe_rows
                    .expect_one_row()?
                    .transpose()?
                    .map(|v| v.into_boxed_slice()))
            }
        }
    }
}

impl<T: OwnedReadImplFamily<FamilyRepresentitive = KvdbSqlite>>
    OwnedReadImplByFamily<KvdbSqlite> for T
where T: KvdbSqliteDestructureTrait
{
    fn get_mut_impl(&mut self, key: &[u8]) -> Result<Option<Box<[u8]>>> {
        let (connection, table_name) = self.destructure_mut();
        match connection {
            None => Ok(None),
            Some(conn) => Ok(conn
                .execute(KvdbSqlite::GET_STATEMENT, &[&&table_name, &&key])?
                .map(|row| row.read::<Vec<u8>>(0))
                .expect_one_row()?
                .transpose()?
                .map(|v| v.into_boxed_slice())),
        }
    }

    fn get_mut_with_number_key_impl(
        &mut self, key: i64,
    ) -> Result<Option<Box<[u8]>>> {
        let (connection, table_name) = self.destructure_mut();
        match connection {
            None => Ok(None),
            Some(conn) => Ok(conn
                .execute(KvdbSqlite::GET_STATEMENT, &[&&table_name, &key])?
                .map(|row| row.read::<Vec<u8>>(0))
                .expect_one_row()?
                .transpose()?
                .map(|v| v.into_boxed_slice())),
        }
    }
}

impl<T: SingleWriterImplFamily<FamilyRepresentitive = KvdbSqlite>>
    SingleWriterImplByFamily<KvdbSqlite> for T
where T: KvdbSqliteDestructureTrait
{
    fn delete_impl(&mut self, key: &[u8]) -> Result<Option<Option<Box<[u8]>>>> {
        let (connection, table_name) = self.destructure_mut();
        match connection {
            None => Err(Error::from(ErrorKind::DbNotExist)),
            Some(conn) => {
                conn.execute(
                    KvdbSqlite::DELETE_STATEMENT,
                    &[&&table_name, &&key],
                )?
                .finish_ignore_rows()?;;
                Ok(None)
            }
        }
    }

    fn put_impl(
        &mut self, key: &[u8], value: &[u8],
    ) -> Result<Option<Option<Box<[u8]>>>> {
        let (connection, table_name) = self.destructure_mut();
        match connection {
            None => Err(Error::from(ErrorKind::DbNotExist)),
            Some(conn) => {
                conn.execute(
                    KvdbSqlite::PUT_STATEMENT,
                    &[&&table_name, &&key, &&value],
                )?
                .finish_ignore_rows()?;;
                Ok(None)
            }
        }
    }

    fn put_with_number_key_impl(
        &mut self, key: i64, value: &[u8],
    ) -> Result<Option<Option<Box<[u8]>>>> {
        let (connection, table_name) = self.destructure_mut();
        match connection {
            None => Err(Error::from(ErrorKind::DbNotExist)),
            Some(conn) => {
                conn.execute(
                    KvdbSqlite::PUT_STATEMENT,
                    &[&&table_name, &key, &&value],
                )?
                .finish_ignore_rows()?;;
                Ok(None)
            }
        }
    }
}

// Section for marking automatic implmentation of KeyValueDbTraitOwnedRead, etc.
impl OwnedReadImplFamily for KvdbSqlite {
    type FamilyRepresentitive = KvdbSqlite;
}

impl OwnedReadImplFamily for KvdbSqliteTransaction {
    type FamilyRepresentitive = KvdbSqlite;
}

impl OwnedReadImplFamily for KvdbSqliteBorrowMut<'_> {
    type FamilyRepresentitive = KvdbSqlite;
}

impl OwnedReadImplFamily for KvdbSqliteBorrowMutReadOnly<'_> {
    type FamilyRepresentitive = KvdbSqlite;
}

impl<
        'any,
        T: ImplOrBorrowMutSelf<dyn 'any + KvdbSqliteDestructureTrait>,
        F,
    > OwnedReadImplFamily for ConnectionWithRowParser<T, F>
{
    type FamilyRepresentitive = KvdbSqlite;
}

impl SingleWriterImplFamily for KvdbSqlite {
    type FamilyRepresentitive = KvdbSqlite;
}

impl SingleWriterImplFamily for KvdbSqliteTransaction {
    type FamilyRepresentitive = KvdbSqlite;
}

impl SingleWriterImplFamily for KvdbSqliteBorrowMut<'_> {
    type FamilyRepresentitive = KvdbSqlite;
}

impl<
        'any,
        T: ImplOrBorrowMutSelf<dyn 'any + KvdbSqliteDestructureTrait>,
        F,
    > SingleWriterImplFamily for ConnectionWithRowParser<T, F>
{
    type FamilyRepresentitive = KvdbSqlite;
}

impl ReadImplFamily for KvdbSqlite {
    type FamilyRepresentitive = KvdbSqlite;
}

impl ReadImplFamily for KvdbSqliteTransaction {
    type FamilyRepresentitive = KvdbSqlite;
}

impl ReadImplFamily for KvdbSqliteBorrowMut<'_> {
    type FamilyRepresentitive = KvdbSqlite;
}

impl ReadImplFamily for KvdbSqliteBorrowMutReadOnly<'_> {
    type FamilyRepresentitive = KvdbSqlite;
}

impl<
        'any,
        T: ImplOrBorrowMutSelf<dyn 'any + KvdbSqliteDestructureTrait>,
        F,
    > ReadImplFamily for ConnectionWithRowParser<T, F>
{
    type FamilyRepresentitive = KvdbSqlite;
}

pub trait KvdbSqliteDestructureTrait {
    fn destructure(&self) -> (Option<&SqliteConnection>, &str);
    fn destructure_mut(&mut self) -> (Option<&mut SqliteConnection>, &str);
}

enable_deref_plus_impl_or_borrow_self!(KvdbSqliteDestructureTrait);
enable_deref_mut_plus_impl_or_borrow_mut_self!(KvdbSqliteDestructureTrait);

impl KvdbSqliteDestructureTrait for KvdbSqlite {
    fn destructure(&self) -> (Option<&SqliteConnection>, &str) {
        (self.connection.as_ref(), self.table_name.as_str())
    }

    fn destructure_mut(&mut self) -> (Option<&mut SqliteConnection>, &str) {
        (self.connection.as_mut(), self.table_name.as_str())
    }
}

impl KvdbSqliteDestructureTrait for KvdbSqliteTransaction {
    fn destructure(&self) -> (Option<&SqliteConnection>, &str) {
        (self.db.connection.as_ref(), self.db.table_name.as_str())
    }

    fn destructure_mut(&mut self) -> (Option<&mut SqliteConnection>, &str) {
        (self.db.connection.as_mut(), self.db.table_name.as_str())
    }
}

impl KvdbSqliteDestructureTrait for KvdbSqliteBorrowMut<'_> {
    fn destructure(&self) -> (Option<&SqliteConnection>, &str) {
        unsafe { ((self.connection.map(|conn| &*conn)), &*self.table_name) }
    }

    fn destructure_mut(&mut self) -> (Option<&mut SqliteConnection>, &str) {
        unsafe { ((self.connection.map(|conn| &mut *conn)), &*self.table_name) }
    }
}

impl KvdbSqliteDestructureTrait for KvdbSqliteBorrowMutReadOnly<'_> {
    fn destructure(&self) -> (Option<&SqliteConnection>, &str) {
        unsafe { ((self.connection.map(|conn| &*conn)), &*self.table_name) }
    }

    fn destructure_mut(&mut self) -> (Option<&mut SqliteConnection>, &str) {
        unsafe { ((self.connection.map(|conn| &mut *conn)), &*self.table_name) }
    }
}

impl<T: DerefMutPlusImplOrBorrowMutSelf<dyn KvdbSqliteDestructureTrait>, F>
    KvdbSqliteDestructureTrait for ConnectionWithRowParser<T, F>
where T: DerefPlusImplOrBorrowSelf<dyn KvdbSqliteDestructureTrait>
{
    fn destructure(&self) -> (Option<&SqliteConnection>, &str) {
        self.0.borrow().destructure()
    }

    fn destructure_mut(&mut self) -> (Option<&mut SqliteConnection>, &str) {
        self.0.borrow_mut().destructure_mut()
    }
}

impl KvdbSqliteBorrowMut<'_> {
    pub fn new(
        destructure: (Option<&'_ mut SqliteConnection>, &'_ str),
    ) -> Self {
        Self {
            connection: destructure.0.map(|x| x as *mut SqliteConnection),
            table_name: destructure.1,
            __marker_lifetime: Default::default(),
        }
    }

    #[allow(unused)]
    pub fn to_read_only(&mut self) -> KvdbSqliteBorrowMutReadOnly {
        KvdbSqliteBorrowMutReadOnly {
            connection: self.connection,
            table_name: self.table_name,
            __marker_lifetime: Default::default(),
        }
    }
}

impl KvdbSqliteBorrowMutReadOnly<'_> {
    pub fn new(
        destructure: (Option<&'_ mut SqliteConnection>, &'_ str),
    ) -> Self {
        Self {
            connection: destructure.0.map(|x| x as *mut SqliteConnection),
            table_name: destructure.1,
            __marker_lifetime: Default::default(),
        }
    }
}

/// It's safe to "deref" the borrow to a 'static lifetime since the object has
/// already borrowed the SqliteConnection, so there can not be other user of
/// SqliteConnection while the object is alive. The lifetime doesn't matter at
/// all because all methods of KvdbSqliteBorrowMut returns a borrow of itself.
///
/// We need the Deref/DerefMut conversion from KvdbSqliteBorrowMut<'a> to
/// KvdbSqliteBorrowMut<'static> because then we have
/// KvdbSqliteBorrowMut<'a> : DerefMutPlusImplOrBorrowMutSelf<dyn 'static +
/// KvdbSqliteDestructureTrait>,  therefore for any <'db> we have
/// KvdbSqliteBorrowMut<'a>: KeyValueDbIterableTrait<'db, Item, Error, [u8]>
impl Deref for KvdbSqliteBorrowMut<'_> {
    type Target = KvdbSqliteBorrowMut<'static>;

    fn deref(&self) -> &Self::Target {
        unsafe { std::mem::transmute::<&Self, &Self::Target>(self) }
    }
}

impl DerefMut for KvdbSqliteBorrowMut<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::mem::transmute::<&mut Self, &mut Self::Target>(self) }
    }
}

impl Deref for KvdbSqliteBorrowMutReadOnly<'_> {
    type Target = KvdbSqliteBorrowMutReadOnly<'static>;

    fn deref(&self) -> &Self::Target {
        unsafe { std::mem::transmute::<&Self, &Self::Target>(self) }
    }
}

impl DerefMut for KvdbSqliteBorrowMutReadOnly<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::mem::transmute::<&mut Self, &mut Self::Target>(self) }
    }
}

use super::{
    super::{
        super::{
            storage_db::{delta_db_manager::DeltaDbTrait, key_value_db::*},
            utils::deref_plus_impl_or_borrow_self::*,
        },
        errors::*,
    },
    sqlite::*,
};
use sqlite::{Connection, Statement};
use std::{
    any::Any,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    path::Path,
};
