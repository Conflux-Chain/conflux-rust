// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub const SQLITE_NO_PARAM: &[SqlBindableRef] = &[];
pub type SqlBindableRef<'a> = &'a (dyn SqlBindable + 'a);
pub type SqlBindableBox<'a> = Box<dyn SqlBindable + 'a>;

pub struct SqliteConnection {
    info: SqliteConnectionInfo,
    connection: Mutex<Connection>,
    cached_statements: Mutex<StatementCache>,
}

pub struct SqliteConnectionInfo {
    pub readonly: bool,
    pub path: PathBuf,
    pub open_flags: OpenFlags,
}

type StatementCache = HashMap<String, ScopedStatement>;

impl Drop for SqliteConnection {
    fn drop(&mut self) {
        // Clear all associated statement otherwise the sqlite connection will
        // be left open because sqlite3_close returns BUSY.
        // https://www.sqlite.org/c3ref/close.html
        self.cached_statements.get_mut().clear();
        // We would like to check return value of sqlite close, and run close_v2
        // when necessary. After that we'd like to prevent Connection's drop
        // from running. To do so we open a new Connection and overwrite
        // self.connection.
        //
        // When we can't open a new connection successfully, give up and simply
        // let Connection close the db. However we lose the ability to
        // run close_v2() if close fails.
        unsafe {
            if let Ok(new_connection) = Connection::open_with_flags(
                self.info.path.clone(),
                Self::default_open_flags().set_read_write(),
            ) {
                self.connection.get_mut().remove_busy_handler().ok();
                if self.close().is_err() {
                    error!(
                        "Closing sqlite connection while still being used.
                         The sqlite connection will be closed when all pending
                         resources are released. However it suggests that the
                         code may not managing object ownership and lifetime
                         of sqlite execution well."
                    );
                    self.close_v2().ok();
                }

                std::ptr::write(self.connection.get_mut(), new_connection);
            }
        }
    }
}

unsafe impl Send for SqliteConnection {}
unsafe impl Sync for SqliteConnection {}

impl SqliteConnection {
    pub fn close(&mut self) -> Result<()> {
        match unsafe { sqlite_ffi::sqlite3_close(self.get_db_mut().as_raw()) } {
            sqlite_ffi::SQLITE_OK => Ok(()),
            code => bail!(sqlite::Error {
                code: Some(code as isize),
                message: None
            }),
        }
    }

    pub fn close_v2(&mut self) -> Result<()> {
        match unsafe {
            sqlite_ffi::sqlite3_close_v2(self.get_db_mut().as_raw())
        } {
            sqlite_ffi::SQLITE_OK => Ok(()),
            code => bail!(sqlite::Error {
                code: Some(code as isize),
                message: None
            }),
        }
    }

    pub fn default_open_flags() -> OpenFlags {
        // The sqlite library didn't provide a function to construct customary
        // open_flags.
        unsafe {
            std::mem::transmute::<i32, OpenFlags>(
                sqlite_ffi::SQLITE_OPEN_NOMUTEX
                    // TODO: check if SHARED_CACHE improves the performance or not.
                    | sqlite_ffi::SQLITE_OPEN_SHAREDCACHE
                    | sqlite_ffi::SQLITE_OPEN_URI,
            )
        }
    }

    pub fn create_and_init<P: AsRef<Path>>(path: P) -> Result<()> {
        let conn = Connection::open_with_flags(
            &path,
            Self::default_open_flags().set_read_write().set_create(),
        )?;
        conn.execute("PRAGMA journal_mode=WAL")?;
        // Prevent other processes from accessing the db.
        // The "-shm" file will not be created,
        // see https://www.sqlite.org/tempfiles.html#shared_memory_files.
        conn.execute("PRAGMA locking_mode=EXCLUSIVE")?;
        Ok(())
    }

    pub fn create_and_open<P: AsRef<Path>>(
        path: P, open_flags: OpenFlags,
    ) -> Result<Self> {
        Self::create_and_init(path.as_ref())?;
        Self::open(path, false, open_flags)
    }

    pub fn open<P: AsRef<Path>>(
        path: P, readonly: bool, open_flags: OpenFlags,
    ) -> Result<Self> {
        let conn_open_flags = if readonly {
            open_flags.set_read_only()
        } else {
            open_flags.set_read_write()
        };

        Ok(Self {
            info: SqliteConnectionInfo {
                readonly,
                path: path.as_ref().to_path_buf(),
                open_flags,
            },
            connection: Mutex::new(Connection::open_with_flags(
                path,
                conn_open_flags,
            )?),
            cached_statements: Mutex::new(HashMap::new()),
        })
    }

    pub fn try_clone(&self) -> Result<Self> {
        Self::open(&self.info.path, self.info.readonly, self.info.open_flags)
    }

    pub fn prepare<'db>(
        db: &'db mut Connection, statement_cache: &'db mut StatementCache,
        sql: &str,
    ) -> Result<&'db mut ScopedStatement>
    {
        // Actually safe. I don't want an unnecessary to_string() for the sql.
        // But the borrow-checker doesn't seem to understand branch very well.
        Ok(unsafe {
            let maybe_statement = statement_cache
                .get_mut(sql)
                .map(|x| x as *mut ScopedStatement);
            if maybe_statement.is_some() {
                &mut *maybe_statement.unwrap()
            } else {
                statement_cache.entry(sql.to_string()).or_insert(
                    // This is safe because we store the
                    // ScopedStatement in the same struct where the
                    // connection is.
                    ScopedStatement::new(db.prepare(sql)?),
                )
            }
        })
    }

    /// The statement must be created with the db. Then the statement is a mut
    /// borrow of db, so it's guaranteed that the db is only used by one
    /// thread.
    pub fn execute_locked<'db, 'p, Param: Borrow<dyn SqlBindable + 'p>>(
        statement: &'db mut ScopedStatement, params: &[Param],
    ) -> Result<MaybeRows<'db>> {
        Ok(MaybeRows(statement.execute(params)?))
    }

    pub fn execute<'p, Param: Borrow<dyn SqlBindable + 'p>>(
        &mut self, sql: &str, params: &[Param],
    ) -> Result<MaybeRows<'_>> {
        let db = self.connection.get_mut();
        let statement =
            Self::prepare(db, self.cached_statements.get_mut(), sql)?;

        Self::execute_locked(statement, params)
    }

    pub fn get_db_mut(&mut self) -> &mut Connection {
        self.connection.get_mut()
    }

    pub fn lock_db(&self) -> MutexGuard<Connection> { self.connection.lock() }

    pub fn lock_statement_cache(&self) -> MutexGuard<StatementCache> {
        self.cached_statements.lock()
    }

    pub fn possible_temporary_files(db_path: &str) -> Vec<String> {
        let mut paths = vec![];
        paths.push(Self::wal_path(db_path));
        paths.push(Self::shm_path(db_path));

        paths
    }

    fn wal_path(db_path: &str) -> String { db_path.to_string() + "-wal" }

    fn shm_path(db_path: &str) -> String { db_path.to_string() + "-shm" }
}

/// Upstream didn't implement Bindable for trait object, which makes passing
/// an array of params impossible. Therefore we define a new trait and implement
/// Bindable for its trait object.
pub trait SqlBindable {
    fn bind(&self, statement: &mut Statement, i: usize) -> sqlite::Result<()>;
}

/// To implement SqlBindable for String, Vec<[u8]>, etc, whichever is Deref to a
/// Bindable.
pub trait SqlDerefBindable<'a> {
    type Type: Bindable;

    fn as_bindable(&'a self) -> Self::Type;
}

impl<'a, T: ?Sized + 'a + Deref> SqlDerefBindable<'a> for T
where &'a T::Target: Bindable
{
    type Type = &'a T::Target;

    fn as_bindable(&'a self) -> Self::Type { self.deref() }
}

impl SqlBindable for i64 {
    fn bind(&self, statement: &mut Statement, i: usize) -> sqlite::Result<()> {
        Bindable::bind(*self as i64, statement, i)
    }
}

impl<'a, T: 'a + Deref> SqlBindable for Pin<T>
where for<'x> &'x T::Target: Bindable
{
    fn bind(&self, statement: &mut Statement, i: usize) -> sqlite::Result<()> {
        Bindable::bind(&**self, statement, i)
    }
}

impl<'a, T: 'a + ?Sized> SqlBindable for &'a T
where T: SqlDerefBindable<'a>
{
    fn bind(&self, statement: &mut Statement, i: usize) -> sqlite::Result<()> {
        Bindable::bind(self.as_bindable(), statement, i)
    }
}

pub trait SqlReadable: SqlReadableIntoSelf + Sized {
    fn from_column(row: &Statement<'_>, column: usize) -> Result<Self>;
}

impl SqlReadable for Vec<u8> {
    fn from_column(row: &Statement<'_>, column: usize) -> Result<Self> {
        Ok(Self::read(row, column)?)
    }
}

impl SqlReadable for Box<[u8]> {
    fn from_column(row: &Statement<'_>, column: usize) -> Result<Self> {
        Ok(Vec::<u8>::read(row, column)?.into_boxed_slice())
    }
}

impl SqlReadable for i64 {
    fn from_column(row: &Statement<'_>, column: usize) -> Result<Self> {
        Ok(i64::read(row, column)?)
    }
}

/// This trait can be made into trait object.
pub trait SqlReadableIntoSelf {
    fn read_into_self(
        &mut self, row: &Statement<'_>, column: usize,
    ) -> Result<()>;
}

impl<T: SqlReadable> SqlReadableIntoSelf for T {
    fn read_into_self(
        &mut self, row: &Statement<'_>, column: usize,
    ) -> Result<()> {
        Ok(*self = Self::from_column(row, column)?)
    }
}

impl<'a> Bindable for &'a dyn SqlBindable {
    fn bind(self, statement: &mut Statement, i: usize) -> sqlite::Result<()> {
        self.bind(statement, i)
    }
}

type MaybeUnfinishedStatement<'db> = Option<&'db mut Statement<'db>>;

#[derive(Default)]
pub struct MaybeRows<'db>(MaybeUnfinishedStatement<'db>);

impl<'db> MaybeRows<'db> {
    pub fn finish_ignore_rows(&mut self) -> Result<()> {
        while Self::next(&mut self.0)?.is_some() {}
        Ok(())
    }

    pub fn map<Item, F: FnMut(&Statement<'db>) -> Item>(
        mut self, f: F,
    ) -> MappedRows<'db, F> {
        MappedRows {
            maybe_rows: self.0.take(),
            f,
        }
    }

    pub fn statement_ref<'a>(
        maybe_statement: &'a mut MaybeUnfinishedStatement<'db>,
    ) -> &'a Statement<'db> {
        maybe_statement.as_ref().unwrap()
    }

    pub fn next<'a>(
        maybe_statement: &'a mut MaybeUnfinishedStatement<'db>,
    ) -> Result<Option<&'a Statement<'db>>> {
        let state = match maybe_statement {
            None => return Ok(None),
            Some(statement) => statement.next()?,
        };

        match state {
            State::Row => Ok(Some(Self::statement_ref(maybe_statement))),
            State::Done => {
                *maybe_statement = None;
                Ok(None)
            }
        }
    }
}

pub struct ConnectionWithRowParser<Connection, RowParser>(
    pub Connection,
    pub RowParser,
);

pub struct MappedRows<'db, F> {
    /// If Rows is default constructible, we could remove the option and
    /// default construct it for the empty database.
    maybe_rows: MaybeUnfinishedStatement<'db>,
    f: F,
}

impl<'db, Item, F: FnMut(&Statement<'db>) -> Item> MappedRows<'db, F> {
    pub fn expect_one_row(&mut self) -> Result<Option<Item>> {
        if self.maybe_rows.is_none() {
            Ok(None)
        } else {
            let row_mapped =
                (self.f)(MaybeRows::statement_ref(&mut self.maybe_rows));
            if MaybeRows::next(&mut self.maybe_rows)?.is_none() {
                Ok(Some(row_mapped))
            } else {
                bail!(ErrorKind::DbValueError)
            }
        }
    }
}

impl<'db, Item, F: FnMut(&Statement<'db>) -> Result<Item>> FallibleIterator
    for MappedRows<'db, F>
{
    type Error = Error;
    type Item = Item;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        if self.maybe_rows.is_none() {
            Ok(None)
        } else {
            let value =
                (self.f)(MaybeRows::statement_ref(&mut self.maybe_rows))?;
            MaybeRows::next(&mut self.maybe_rows)?;
            Ok(Some(value))
        }
    }
}

/// The ScopedStatement struct is a wrapper solely meant to store
/// cached statement object together with the connection because it's
/// otherwise too painful for the user to maintain especially in multi-threaded
/// environment.
///
/// The ScopedStatement should only be stored in the struct where the
/// corresponding sqlite Connection is.
///
/// The ScopedStatement should in general not be extended. Any more code added
/// should examined carefully so that the database connection can not be used in
/// more than one thread at the same time.
pub struct ScopedStatement {
    stmt: Statement<'static>,
}

impl ScopedStatement {
    /// This method is unsafe because it extended the lifetime of Statement to
    /// infinity.
    unsafe fn new<'a>(scoped_statement: Statement<'a>) -> Self {
        Self {
            stmt: std::mem::transmute::<Statement<'a>, Statement<'static>>(
                scoped_statement,
            ),
        }
    }

    fn as_mut(&mut self) -> &mut Statement<'_> {
        unsafe {
            std::mem::transmute::<&mut Statement<'static>, &mut Statement<'_>>(
                &mut self.stmt,
            )
        }
    }

    /// It is essential to have `&mut self` in order to execute. As required by
    /// sqlite "Multi-thread mode" https://sqlite.org/threadsafe.html, there can
    /// be only one active use of a database connection.
    ///
    /// Even binding an variable modifies the error field in database
    /// connection.
    ///
    /// We should never allow a mutable Statement returned from a
    /// SqliteConnection reference because then we can not prevent using
    /// database connection from multiple threads.
    fn bind<'p, Param: Borrow<dyn SqlBindable + 'p>>(
        &mut self, params: &[Param],
    ) -> Result<()> {
        self.stmt.reset().ok();
        for i in 0..params.len() {
            // Sqlite index starts at 1.
            self.stmt.bind(i + 1, params[i].borrow())?
        }
        Ok(())
    }

    fn execute<'p, Param: Borrow<dyn SqlBindable + 'p>>(
        &mut self, params: &[Param],
    ) -> Result<MaybeUnfinishedStatement<'_>> {
        self.bind(params)?;

        // FIXME: Should we wait for the first row to become available?
        let result = self.stmt.next();
        match result {
            Ok(State::Done) => Ok(None),
            Ok(State::Row) => Ok(Some(self.as_mut())),
            Err(e) => {
                bail!(e);
            }
        }
    }
}

pub trait ValueReadImpl<Kind: ?Sized>: Sized {
    fn from_row_impl(row: &Statement<'_>, value_column: usize) -> Result<Self>;
    fn from_kv_row_impl(
        row: &Statement<'_>, key: &mut dyn SqlReadableIntoSelf,
    ) -> Result<Self>;
}

pub trait ValueRead {
    type Kind: ?Sized;
}

impl ValueRead for () {
    type Kind = ();
}

impl ValueRead for Box<[u8]> {
    type Kind = dyn SqlReadableIntoSelf;
}

impl ValueReadImpl<()> for () {
    fn from_row_impl(
        _row: &Statement<'_>, _value_column: usize,
    ) -> Result<Self> {
        Ok(())
    }

    fn from_kv_row_impl(
        _row: &Statement<'_>, _key: &mut dyn SqlReadableIntoSelf,
    ) -> Result<Self> {
        Ok(())
    }
}

impl<ValueType: SqlReadable> ValueReadImpl<dyn SqlReadableIntoSelf>
    for ValueType
{
    fn from_row_impl(row: &Statement<'_>, value_column: usize) -> Result<Self> {
        ValueType::from_column(row, value_column)
    }

    fn from_kv_row_impl(
        row: &Statement<'_>, key: &mut dyn SqlReadableIntoSelf,
    ) -> Result<Self> {
        key.read_into_self(row, 0)?;
        ValueType::from_column(row, 1)
    }
}

impl<
        ValueType: Default + TupleIndexExt + TupleIterate<dyn SqlReadableIntoSelf>,
    > ValueRead for ValueType
{
    type Kind = dyn ElementSatisfy<dyn SqlReadableIntoSelf>;
}

impl<
        ValueType: Default + TupleIndexExt + TupleIterate<dyn SqlReadableIntoSelf>,
    > ValueReadImpl<dyn ElementSatisfy<dyn SqlReadableIntoSelf>> for ValueType
{
    fn from_row_impl(
        row: &Statement<'_>, value_column: usize,
    ) -> Result<ValueType> {
        let mut result = Ok(ValueType::default());

        struct Load<'r, 'db, ValueType> {
            t: &'r mut ValueType,
            row: &'r Statement<'db>,
            error: Option<Error>,
            value_column: usize,
        }

        impl<ValueType: TupleIndexExt>
            IterCallFamilyTrait<ValueType, dyn SqlReadableIntoSelf>
            for &mut Load<'_, '_, ValueType>
        {
            fn iter_step<
                Index: OfElementSatisfiesOnTuple<ValueType, dyn SqlReadableIntoSelf>,
            >(
                &mut self, _: &'static Index, index: usize,
            ) {
                match self.error {
                    None => {
                        let column_read_result = ElementSatisfy::<
                            dyn SqlReadableIntoSelf,
                        >::to_constrain_object_mut(
                            Index::getter_for_tuple_mut(self.t).get_mut_impl(),
                        )
                        .read_into_self(self.row, index + self.value_column);

                        if column_read_result.is_err() {
                            self.error = column_read_result.err()
                        }
                    }
                    _ => { /* Skip */ }
                }
            }
        }

        let mut loader = Load {
            t: result.as_mut().unwrap(),
            row,
            error: None,
            value_column,
        };
        ValueType::iterate(&mut loader);

        match loader.error {
            Some(e) => bail!(e),
            None => result,
        }
    }

    fn from_kv_row_impl(
        row: &Statement<'_>, key: &mut dyn SqlReadableIntoSelf,
    ) -> Result<Self> {
        key.read_into_self(row, 0)?;
        Self::from_row_impl(row, 1)
    }
}

pub trait SqlBindableValue {
    type Kind: ?Sized;
}

impl SqlBindableValue for () {
    type Kind = ();
}

impl SqlBindableValue for [u8] {
    /// Use SqlBindable for all single element.
    type Kind = dyn SqlBindable;
}

impl SqlBindableValue for i64 {
    type Kind = dyn SqlBindable;
}

impl<
        ValueType: Default + TupleIndexExt + TupleIterate<dyn SqlReadableIntoSelf>,
    > SqlBindableValue for ValueType
{
    type Kind = dyn ElementSatisfy<dyn BindValueAppendImpl<dyn SqlBindable>>;
}

impl<
        ValueType: Default + TupleIndexExt + TupleIterate<dyn SqlReadableIntoSelf>,
    > DbValueType for ValueType
{
    type Type = ValueType;
}

/// This trait should be implemented for all types implement SqlBindableValue.
pub trait BindValueAppendImpl<Kind: ?Sized> {
    fn make_bind_list(&self) -> Vec<SqlBindableBox<'_>>;
}

// FIXME: Clone? Is it possible to impl it for &T?
impl<T: 'static + SqlBindableValue + SqlBindable + Clone>
    BindValueAppendImpl<dyn SqlBindable> for T
{
    fn make_bind_list(&self) -> Vec<SqlBindableBox<'_>> {
        vec![Box::new(self.clone())]
    }
}

impl BindValueAppendImpl<()> for () {
    fn make_bind_list(&self) -> Vec<Box<dyn SqlBindable>> { vec![] }
}

impl BindValueAppendImpl<dyn SqlBindable> for [u8] {
    fn make_bind_list(&self) -> Vec<SqlBindableBox<'_>> {
        vec![Box::new(Pin::new(self))]
    }
}

impl BindValueAppendImpl<dyn SqlBindable> for Box<[u8]> {
    fn make_bind_list(&self) -> Vec<SqlBindableBox<'_>> {
        vec![Box::new(Pin::new(self.deref()))]
    }
}

impl<
        ValueType: TupleIndexExt + TupleIterate<dyn BindValueAppendImpl<dyn SqlBindable>>,
    >
    BindValueAppendImpl<
        dyn ElementSatisfy<dyn BindValueAppendImpl<dyn SqlBindable>>,
    > for ValueType
{
    fn make_bind_list(&self) -> Vec<SqlBindableBox<'_>> {
        struct Append<'x, ValueType> {
            v: &'x ValueType,
            l: *mut Vec<SqlBindableBox<'x>>,
        }

        impl<'x, ValueType>
            IterCallFamilyTrait<
                ValueType,
                dyn BindValueAppendImpl<dyn SqlBindable>,
            > for Append<'x, ValueType>
        {
            // FIXME: we shoull note that, if Self contains a mut pointer of
            // FIXME: a Tuple, then iter_step can only return a
            // FIXME: contrain object of the current lifetime.
            // FIXME: we must find a way to make it possible to get an
            // FIXME: constrain_object from the same lifetime.
            fn iter_step<
                Index: OfElementSatisfiesOnTuple<
                    ValueType,
                    dyn BindValueAppendImpl<dyn SqlBindable>,
                >,
            >(
                &mut self, _: &'static Index, _: usize,
            ) {
                let mut to_append = ElementSatisfy::<
                    dyn BindValueAppendImpl<dyn SqlBindable>,
                >::to_constrain_object(
                    Index::getter_for_tuple(self.v).get_impl(),
                )
                .make_bind_list();
                unsafe { &mut *self.l }.append(&mut to_append);
            }
        }

        let mut bind_list =
            Vec::<SqlBindableBox<'_>>::with_capacity(ValueType::size_tuple());
        {
            let append = Append {
                v: self,
                l: &mut bind_list,
            };
            ValueType::iterate(append);
        }

        bind_list
    }
}

use super::super::{
    super::{storage_db::key_value_db::DbValueType, utils::tuple::*},
    errors::*,
};
use fallible_iterator::FallibleIterator;
use parking_lot::{Mutex, MutexGuard};
use sqlite::{Bindable, Connection, OpenFlags, Readable, State, Statement};
use sqlite3_sys as sqlite_ffi;
use std::{
    borrow::Borrow,
    collections::HashMap,
    ops::Deref,
    path::{Path, PathBuf},
    pin::Pin,
};
