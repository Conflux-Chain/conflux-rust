// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct KvdbSqlite<ValueType> {
    // The main table is the number_key_table_name, if with_number_key_table in
    // methods #new() and #create_and_open() is true.
    connection: Option<SqliteConnection>,
    statements: Arc<KvdbSqliteStatements>,
    __marker_value: PhantomData<ValueType>,
}

pub struct KvdbSqliteBorrowMut<'db, ValueType> {
    connection: Option<*mut SqliteConnection>,
    statements: *const KvdbSqliteStatements,
    __marker_lifetime: PhantomData<&'db mut SqliteConnection>,
    __marker_value: PhantomData<ValueType>,
}

pub struct KvdbSqliteBorrowMutReadOnly<'db, ValueType> {
    connection: Option<*mut SqliteConnection>,
    statements: *const KvdbSqliteStatements,
    __marker_lifetime: PhantomData<&'db mut SqliteConnection>,
    __marker_value: PhantomData<ValueType>,
}

pub struct KvdbSqliteStatements {
    pub stmts_main_table: KvdbSqliteStatementsPerTable,
    /// When numbered key is turned off, the bytes_key_table is the same as the
    /// main table.
    pub stmts_bytes_key_table: KvdbSqliteStatementsPerTable,
}

pub struct KvdbSqliteStatementsPerTable {
    pub create_table: String,
    pub drop_table: &'static str,
    pub get: String,
    pub put: String,
    pub delete: &'static str,
    pub range_excl_select_statement: String,
}

impl KvdbSqliteStatements {
    pub const BYTES_KEY_TABLE_SUFFIX: &'static str = "_bytes_key";
    // TODO(yz): check if WITHOUT ROWID is faster: see https://www.sqlite.org/withoutrowid.html.
    pub const CREATE_TABLE_BLOB_KV_STATEMENT_TMPL: &'static str =
        "CREATE TABLE IF NOT EXISTS {table_name} ( key BLOB PRIMARY KEY, {value_columns_def} ) WITHOUT ROWID";
    // INTEGER PRIMARY KEY is special, see https://www.sqlite.org/lang_createtable.html#rowid.
    pub const CREATE_TABLE_NUMBER_KV_STATEMENT_TMPL: &'static str =
        "CREATE TABLE IF NOT EXISTS {table_name} ( key INTEGER PRIMARY KEY, {value_columns_def} )";
    pub const DELETE_STATEMENT: &'static str =
        "DELETE FROM {table_name} where key = :key";
    pub const DROP_TABLE_STATEMENT: &'static str = "DROP TABLE {table_name}";
    pub const GET_STATEMENT_TMPL: &'static str =
        "SELECT {value_columns} FROM {table_name} WHERE key = :key";
    pub const PUT_STATEMENT_TMPL: &'static str =
        "INSERT OR REPLACE INTO {table_name} VALUES (:key, {value_columns_to_bind})";
    pub const RANGE_EXCL_SELECT_STATEMENT: &'static str =
        "SELECT key, {value_columns} FROM {table_name} \
        WHERE key > :lower_bound_excl AND key < :upper_bound_excl ORDERED BY key ASC";

    pub fn make_statements(
        value_column_names: &[&str], value_column_types: &[&str],
        main_table_name: &str, with_number_key_table: bool,
    ) -> Result<Self>
    {
        let bytes_key_table_name;
        let bytes_key_table;
        if with_number_key_table {
            bytes_key_table = main_table_name.to_string()
                + KvdbSqliteStatements::BYTES_KEY_TABLE_SUFFIX;
            bytes_key_table_name = bytes_key_table.as_str();
        } else {
            bytes_key_table_name = main_table_name;
        }
        Ok(Self {
            stmts_main_table:
                KvdbSqliteStatementsPerTable::make_table_statements(
                    value_column_names,
                    value_column_types,
                    main_table_name,
                    if with_number_key_table {
                        Self::CREATE_TABLE_NUMBER_KV_STATEMENT_TMPL
                    } else {
                        Self::CREATE_TABLE_BLOB_KV_STATEMENT_TMPL
                    },
                )?,
            stmts_bytes_key_table: {
                KvdbSqliteStatementsPerTable::make_table_statements(
                    value_column_names,
                    value_column_types,
                    bytes_key_table_name,
                    Self::CREATE_TABLE_BLOB_KV_STATEMENT_TMPL,
                )?
            },
        })
    }
}

impl KvdbSqliteStatementsPerTable {
    pub fn make_table_statements(
        value_column_names: &[&str], value_column_types: &[&str],
        table_name: &str, create_table_sql: &str,
    ) -> Result<Self>
    {
        let value_columns_def = value_column_names
            .iter()
            .zip(value_column_types.iter())
            .map(|(n, t)| format!("{} {}", n, t))
            .collect::<Vec<String>>()
            .join(", ");
        let value_columns = value_column_names.join(", ");
        let value_columns_to_bind = value_column_names
            .iter()
            .map(|n| ":".to_string() + n)
            .collect::<Vec<String>>()
            .join(", ");

        let mut strfmt_vars = HashMap::new();
        strfmt_vars.insert("value_columns_def".to_string(), value_columns_def);
        strfmt_vars.insert("value_columns".to_string(), value_columns);
        strfmt_vars
            .insert("value_columns_to_bind".to_string(), value_columns_to_bind);
        strfmt_vars.insert("table_name".to_string(), table_name.to_string());

        Ok(Self {
            create_table: strfmt(create_table_sql, &strfmt_vars)?,
            drop_table: KvdbSqliteStatements::DROP_TABLE_STATEMENT,
            get: strfmt(
                KvdbSqliteStatements::GET_STATEMENT_TMPL,
                &strfmt_vars,
            )?,
            put: strfmt(
                KvdbSqliteStatements::PUT_STATEMENT_TMPL,
                &strfmt_vars,
            )?,
            delete: KvdbSqliteStatements::DELETE_STATEMENT,
            range_excl_select_statement: strfmt(
                KvdbSqliteStatements::RANGE_EXCL_SELECT_STATEMENT,
                &strfmt_vars,
            )?,
        })
    }
}

impl<ValueType> KvdbSqlite<ValueType> {
    pub fn new(
        connection: Option<SqliteConnection>, table_name: &str,
        with_number_key_table: bool, value_column_names: &[&str],
        value_column_types: &[&str],
    ) -> Result<Self>
    {
        Ok(Self {
            connection,
            statements: Arc::new(KvdbSqliteStatements::make_statements(
                value_column_names,
                value_column_types,
                table_name,
                with_number_key_table,
            )?),
            __marker_value: Default::default(),
        })
    }
}

impl<ValueType> KvdbSqlite<ValueType> {
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            connection: match &self.connection {
                None => None,
                Some(conn) => Some(conn.try_clone()?),
            },
            statements: self.statements.clone(),
            __marker_value: Default::default(),
        })
    }

    pub fn create_and_open<P: AsRef<Path>>(
        path: P, table_name: &str, value_column_names: &[&str],
        value_column_types: &[&str], with_number_key_table: bool,
    ) -> Result<Self>
    {
        let mut connection = SqliteConnection::create_and_open(
            path,
            SqliteConnection::default_open_flags(),
        )?;
        let statements = Arc::new(KvdbSqliteStatements::make_statements(
            value_column_names,
            value_column_types,
            table_name,
            with_number_key_table,
        )?);

        // Create the extra table for bytes key when the main table has number
        // key.
        if with_number_key_table {
            connection
                .execute(
                    &statements.stmts_bytes_key_table.create_table,
                    SQLITE_NO_PARAM,
                )?
                .finish_ignore_rows()?;
        }

        // Main table. When with_number_key_table is true it's the number key
        // table. Otherwise it's the bytes key table.
        connection
            .execute(
                &statements.stmts_main_table.create_table,
                SQLITE_NO_PARAM,
            )?
            .finish_ignore_rows()?;;

        Ok(Self {
            connection: Some(connection),
            statements,
            __marker_value: Default::default(),
        })
    }
}

impl ElementConstrainMark for dyn SqlReadableIntoSelf {}
impl<Element: 'static + SqlReadableIntoSelf>
    ElementSatisfy<dyn SqlReadableIntoSelf> for Element
{
    fn to_constrain_object(&self) -> &(dyn 'static + SqlReadableIntoSelf) {
        self
    }

    fn to_constrain_object_mut(
        &mut self,
    ) -> &mut (dyn 'static + SqlReadableIntoSelf) {
        self
    }
}

impl ElementConstrainMark for dyn BindValueAppendImpl<dyn SqlBindable> {}
impl<Element: 'static + BindValueAppendImpl<dyn SqlBindable>>
    ElementSatisfy<dyn BindValueAppendImpl<dyn SqlBindable>> for Element
{
    fn to_constrain_object(
        &self,
    ) -> &(dyn 'static + BindValueAppendImpl<dyn SqlBindable>) {
        self
    }

    fn to_constrain_object_mut(
        &mut self,
    ) -> &mut (dyn 'static + BindValueAppendImpl<dyn SqlBindable>) {
        self
    }
}

impl<ValueType: ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>>
    KvdbSqlite<ValueType>
{
    pub fn from_row(row: &Statement<'_>) -> Result<ValueType> {
        ValueType::from_row_impl(row)
    }
}

impl<ValueType: PutType> KeyValueDbTypes for KvdbSqlite<ValueType> {
    type ValueType = ValueType;
}

// 'static because Any is static.
impl<
        ValueType: 'static
            + PutType
            + ValueRead
            + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > KeyValueDbTraitTransactional for KvdbSqlite<ValueType>
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    type TransactionType = KvdbSqliteTransaction<ValueType>;

    fn start_transaction(
        &self, immediate_write: bool,
    ) -> Result<KvdbSqliteTransaction<ValueType>> {
        if self.connection.is_none() {
            bail!(ErrorKind::DbNotExist);
        }

        KvdbSqliteTransaction::new(self.try_clone()?, immediate_write)
    }
}

impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > KeyValueDbToOwnedReadTrait for KvdbSqlite<ValueType>
{
    fn to_owned_read<'a>(
        &'a self,
    ) -> Result<Box<dyn 'a + KeyValueDbTraitOwnedRead<ValueType = ValueType>>>
    {
        Ok(Box::new(self.try_clone()?))
    }
}

impl DeltaDbTrait for KvdbSqlite<Box<[u8]>> {}

pub struct KvdbSqliteTransaction<
    ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
> where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    db: KvdbSqlite<ValueType>,
    committed: bool,
}

impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > KvdbSqliteTransaction<ValueType>
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    fn new(
        mut db: KvdbSqlite<ValueType>, immediate_write: bool,
    ) -> Result<Self> {
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

impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > Drop for KvdbSqliteTransaction<ValueType>
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    fn drop(&mut self) {
        if !self.committed {
            self.revert();
        }
    }
}

impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > KeyValueDbTypes for KvdbSqliteTransaction<ValueType>
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    type ValueType = ValueType;
}

impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > KeyValueDbTransactionTrait for KvdbSqliteTransaction<ValueType>
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
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

impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > Deref for KvdbSqliteTransaction<ValueType>
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    type Target = KvdbSqlite<ValueType>;

    fn deref(&self) -> &Self::Target { &self.db }
}

impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > DerefMut for KvdbSqliteTransaction<ValueType>
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.db }
}

impl<ValueType: PutType> KeyValueDbTypes
    for KvdbSqliteBorrowMut<'_, ValueType>
{
    type ValueType = ValueType;
}

impl<ValueType: PutType> KeyValueDbTypes
    for KvdbSqliteBorrowMutReadOnly<'_, ValueType>
{
    type ValueType = ValueType;
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
        let (connection, statements) = self.0.borrow_mut().destructure_mut();
        match connection {
            None => Ok(MaybeRows::default().map(&mut self.1)),
            Some(conn) => Ok(conn
                .execute(
                    &statements.stmts_main_table.range_excl_select_statement,
                    &[&&lower_bound_excl as SqlBindableRef, &&upper_bound_excl],
                )?
                .map(&mut self.1)),
        }
    }
}

/// TODO: Check if these are correct
impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > KeyValueDbTraitMultiReader for KvdbSqlite<ValueType>
{
}

impl<
        T: ReadImplFamily<FamilyRepresentative = KvdbSqlite<ValueType>>
            + KvdbSqliteDestructureTrait
            + KeyValueDbTypes<ValueType = ValueType>,
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > ReadImplByFamily<KvdbSqlite<ValueType>> for T
{
    fn get_impl(&self, key: &[u8]) -> Result<Option<Self::ValueType>> {
        let (connection, statements) = self.destructure();
        match connection {
            None => Ok(None),
            Some(conn) => {
                // TODO try clone connection
                let mut db = conn.lock_db();
                let mut statement_cache = conn.lock_statement_cache();

                let statement = SqliteConnection::prepare(
                    &mut db,
                    &mut statement_cache,
                    &statements.stmts_bytes_key_table.get,
                )?;
                let mut maybe_rows = SqliteConnection::execute_locked(
                    statement,
                    &[&&key as SqlBindableRef],
                )?
                .map(|row| KvdbSqlite::<ValueType>::from_row(row));
                Ok(maybe_rows.expect_one_row()?.transpose()?)
            }
        }
    }

    fn get_with_number_key_impl(
        &self, key: i64,
    ) -> Result<Option<Self::ValueType>> {
        let (connection, statements) = self.destructure();
        match connection {
            None => Ok(None),
            Some(conn) => {
                let mut db = conn.lock_db();
                let mut statement_cache = conn.lock_statement_cache();

                let statement = SqliteConnection::prepare(
                    &mut db,
                    &mut statement_cache,
                    &statements.stmts_main_table.get,
                )?;
                let mut maybe_rows = SqliteConnection::execute_locked(
                    statement,
                    &[&key as SqlBindableRef],
                )?
                .map(|row| KvdbSqlite::<ValueType>::from_row(row));
                Ok(maybe_rows.expect_one_row()?.transpose()?)
            }
        }
    }
}

impl<
        T: OwnedReadImplFamily<FamilyRepresentative = KvdbSqlite<ValueType>>
            + KvdbSqliteDestructureTrait
            + KeyValueDbTypes<ValueType = ValueType>,
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > OwnedReadImplByFamily<KvdbSqlite<ValueType>> for T
{
    fn get_mut_impl(&mut self, key: &[u8]) -> Result<Option<Self::ValueType>> {
        let (connection, statements) = self.destructure_mut();
        match connection {
            None => Ok(None),
            Some(conn) => Ok(conn
                .execute(
                    &statements.stmts_bytes_key_table.get,
                    &[&&key as SqlBindableRef],
                )?
                .map(|row| KvdbSqlite::<ValueType>::from_row(row))
                .expect_one_row()?
                .transpose()?),
        }
    }

    fn get_mut_with_number_key_impl(
        &mut self, key: i64,
    ) -> Result<Option<Self::ValueType>> {
        let (connection, statements) = self.destructure_mut();
        match connection {
            None => Ok(None),
            Some(conn) => Ok(conn
                .execute(
                    &statements.stmts_main_table.get,
                    &[&key as SqlBindableRef],
                )?
                .map(|row| KvdbSqlite::<ValueType>::from_row(row))
                .expect_one_row()?
                .transpose()?),
        }
    }
}

impl<
        T: SingleWriterImplFamily<FamilyRepresentative = KvdbSqlite<ValueType>>
            + KvdbSqliteDestructureTrait
            + KeyValueDbTypes<ValueType = ValueType>,
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > SingleWriterImplByFamily<KvdbSqlite<ValueType>> for T
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    fn delete_impl(
        &mut self, key: &[u8],
    ) -> Result<Option<Option<Self::ValueType>>> {
        let (connection, statements) = self.destructure_mut();
        match connection {
            None => Err(Error::from(ErrorKind::DbNotExist)),
            Some(conn) => {
                conn.execute(
                    statements.stmts_bytes_key_table.delete,
                    &[&&key as SqlBindableRef],
                )?
                .finish_ignore_rows()?;;
                Ok(None)
            }
        }
    }

    fn delete_with_number_key_impl(
        &mut self, key: i64,
    ) -> Result<Option<Option<<Self as KeyValueDbTypes>::ValueType>>> {
        let (connection, statements) = self.destructure_mut();
        match connection {
            None => Err(Error::from(ErrorKind::DbNotExist)),
            Some(conn) => {
                conn.execute(
                    statements.stmts_main_table.delete,
                    &[&key as SqlBindableRef],
                )?
                .finish_ignore_rows()?;;
                Ok(None)
            }
        }
    }

    fn put_impl(
        &mut self, key: &[u8], value: &<Self::ValueType as PutType>::PutType,
    ) -> Result<Option<Option<Self::ValueType>>> {
        let (connection, statements) = self.destructure_mut();
        match connection {
            None => Err(Error::from(ErrorKind::DbNotExist)),
            Some(conn) => {
                let mut bind_list = Vec::<SqlBindableBox>::new();
                bind_list.push(Box::new(&key));
                let mut value_bind_list = value.make_bind_list();
                bind_list.append(&mut value_bind_list);

                conn.execute(
                    &statements.stmts_bytes_key_table.put,
                    &bind_list,
                )?
                .finish_ignore_rows()?;;
                Ok(None)
            }
        }
    }

    fn put_with_number_key_impl(
        &mut self, key: i64, value: &<Self::ValueType as PutType>::PutType,
    ) -> Result<Option<Option<Self::ValueType>>> {
        let (connection, statements) = self.destructure_mut();
        match connection {
            None => Err(Error::from(ErrorKind::DbNotExist)),
            Some(conn) => {
                let mut bind_list = Vec::<SqlBindableBox>::new();
                bind_list.push(Box::new(key));
                let mut value_bind_list = value.make_bind_list();
                bind_list.append(&mut value_bind_list);

                conn.execute(&statements.stmts_main_table.put, &bind_list)?
                    .finish_ignore_rows()?;;
                Ok(None)
            }
        }
    }
}

impl<
        T: DbImplFamily<FamilyRepresentative = KvdbSqlite<ValueType>>
            + KvdbSqliteDestructureTrait
            + KeyValueDbTypes<ValueType = ValueType>,
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > DbImplByFamily<KvdbSqlite<ValueType>> for T
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    fn delete_impl(
        &self, key: &[u8],
    ) -> Result<Option<Option<Self::ValueType>>> {
        let (connection, statements) = self.destructure();
        match connection {
            None => Ok(None),
            Some(conn) => {
                let mut db = conn.lock_db();
                let mut statement_cache = conn.lock_statement_cache();

                let statement = SqliteConnection::prepare(
                    &mut db,
                    &mut statement_cache,
                    &statements.stmts_bytes_key_table.delete,
                )?;
                SqliteConnection::execute_locked(
                    statement,
                    &[&&key as SqlBindableRef],
                )?
                .finish_ignore_rows()?;
                Ok(None)
            }
        }
    }

    fn delete_with_number_key_impl(
        &self, key: i64,
    ) -> Result<Option<Option<Self::ValueType>>> {
        let (connection, statements) = self.destructure();
        match connection {
            None => Ok(None),
            Some(conn) => {
                let mut db = conn.lock_db();
                let mut statement_cache = conn.lock_statement_cache();

                let statement = SqliteConnection::prepare(
                    &mut db,
                    &mut statement_cache,
                    &statements.stmts_main_table.delete,
                )?;
                SqliteConnection::execute_locked(
                    statement,
                    &[&key as SqlBindableRef],
                )?
                .finish_ignore_rows()?;
                Ok(None)
            }
        }
    }

    fn put_impl(
        &self, key: &[u8], value: &<Self::ValueType as PutType>::PutType,
    ) -> Result<Option<Option<Self::ValueType>>> {
        let (connection, statements) = self.destructure();
        match connection {
            None => Ok(None),
            Some(conn) => {
                let mut bind_list = Vec::<SqlBindableBox>::new();
                bind_list.push(Box::new(&key));
                let mut value_bind_list = value.make_bind_list();
                bind_list.append(&mut value_bind_list);

                let mut db = conn.lock_db();
                let mut statement_cache = conn.lock_statement_cache();

                let statement = SqliteConnection::prepare(
                    &mut db,
                    &mut statement_cache,
                    &statements.stmts_bytes_key_table.put,
                )?;

                SqliteConnection::execute_locked(statement, &bind_list)?
                    .finish_ignore_rows()?;
                Ok(None)
            }
        }
    }

    fn put_with_number_key_impl(
        &self, key: i64,
        value: &<<Self as KeyValueDbTypes>::ValueType as PutType>::PutType,
    ) -> Result<Option<Option<Self::ValueType>>>
    {
        let (connection, statements) = self.destructure();
        match connection {
            None => Ok(None),
            Some(conn) => {
                let mut bind_list = Vec::<SqlBindableBox>::new();
                bind_list.push(Box::new(key));
                let mut value_bind_list = value.make_bind_list();
                bind_list.append(&mut value_bind_list);

                let mut db = conn.lock_db();
                let mut statement_cache = conn.lock_statement_cache();

                let statement = SqliteConnection::prepare(
                    &mut db,
                    &mut statement_cache,
                    &statements.stmts_main_table.put,
                )?;
                SqliteConnection::execute_locked(statement, &bind_list)?
                    .finish_ignore_rows()?;
                Ok(None)
            }
        }
    }
}

// Section for marking automatic implmentation of KeyValueDbTraitOwnedRead, etc.

impl<ValueType> OwnedReadImplFamily for KvdbSqlite<ValueType> {
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > OwnedReadImplFamily for KvdbSqliteTransaction<ValueType>
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<ValueType> OwnedReadImplFamily for KvdbSqliteBorrowMut<'_, ValueType> {
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<ValueType> OwnedReadImplFamily
    for KvdbSqliteBorrowMutReadOnly<'_, ValueType>
{
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<
        'any,
        ValueType: PutType,
        T: KeyValueDbTypes<ValueType = ValueType>
            + ImplOrBorrowMutSelf<dyn 'any + KvdbSqliteDestructureTrait>,
        F,
    > KeyValueDbTypes for ConnectionWithRowParser<T, F>
{
    type ValueType = ValueType;
}

impl<
        'any,
        ValueType: PutType,
        T: KeyValueDbTypes<ValueType = ValueType>
            + ImplOrBorrowMutSelf<dyn 'any + KvdbSqliteDestructureTrait>,
        F,
    > OwnedReadImplFamily for ConnectionWithRowParser<T, F>
{
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<ValueType> SingleWriterImplFamily for KvdbSqlite<ValueType> {
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > SingleWriterImplFamily for KvdbSqliteTransaction<ValueType>
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<ValueType> SingleWriterImplFamily for KvdbSqliteBorrowMut<'_, ValueType> {
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<
        'any,
        ValueType: PutType,
        T: KeyValueDbTypes<ValueType = ValueType>
            + ImplOrBorrowMutSelf<dyn 'any + KvdbSqliteDestructureTrait>,
        F,
    > SingleWriterImplFamily for ConnectionWithRowParser<T, F>
{
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<ValueType> ReadImplFamily for KvdbSqlite<ValueType> {
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > ReadImplFamily for KvdbSqliteTransaction<ValueType>
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<ValueType> ReadImplFamily for KvdbSqliteBorrowMut<'_, ValueType> {
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<ValueType> ReadImplFamily for KvdbSqliteBorrowMutReadOnly<'_, ValueType> {
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<
        'any,
        ValueType: PutType,
        T: KeyValueDbTypes<ValueType = ValueType>
            + ImplOrBorrowMutSelf<dyn 'any + KvdbSqliteDestructureTrait>,
        F,
    > ReadImplFamily for ConnectionWithRowParser<T, F>
{
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<ValueType> DbImplFamily for KvdbSqlite<ValueType> {
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > DbImplFamily for KvdbSqliteTransaction<ValueType>
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

impl<ValueType> DbImplFamily for KvdbSqliteBorrowMut<'_, ValueType> {
    type FamilyRepresentative = KvdbSqlite<ValueType>;
}

pub trait KvdbSqliteDestructureTrait {
    fn destructure(&self)
        -> (Option<&SqliteConnection>, &KvdbSqliteStatements);
    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut SqliteConnection>, &KvdbSqliteStatements);
}

enable_deref_plus_impl_or_borrow_self!(KvdbSqliteDestructureTrait);
enable_deref_mut_plus_impl_or_borrow_mut_self!(KvdbSqliteDestructureTrait);

impl<ValueType> KvdbSqliteDestructureTrait for KvdbSqlite<ValueType> {
    fn destructure(
        &self,
    ) -> (Option<&SqliteConnection>, &KvdbSqliteStatements) {
        (self.connection.as_ref(), &self.statements)
    }

    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut SqliteConnection>, &KvdbSqliteStatements) {
        (self.connection.as_mut(), &self.statements)
    }
}

impl<
        ValueType: PutType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > KvdbSqliteDestructureTrait for KvdbSqliteTransaction<ValueType>
where ValueType::PutType: SqlBindableValue
        + BindValueAppendImpl<
            <ValueType::PutType as SqlBindableValue>::Kind,
        >
{
    fn destructure(
        &self,
    ) -> (Option<&SqliteConnection>, &KvdbSqliteStatements) {
        (self.db.connection.as_ref(), &self.db.statements)
    }

    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut SqliteConnection>, &KvdbSqliteStatements) {
        (self.db.connection.as_mut(), &self.db.statements)
    }
}

impl<ValueType> KvdbSqliteDestructureTrait
    for KvdbSqliteBorrowMut<'_, ValueType>
{
    fn destructure(
        &self,
    ) -> (Option<&SqliteConnection>, &KvdbSqliteStatements) {
        unsafe { ((self.connection.map(|conn| &*conn)), &*self.statements) }
    }

    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut SqliteConnection>, &KvdbSqliteStatements) {
        unsafe { ((self.connection.map(|conn| &mut *conn)), &*self.statements) }
    }
}

impl<ValueType> KvdbSqliteDestructureTrait
    for KvdbSqliteBorrowMutReadOnly<'_, ValueType>
{
    fn destructure(
        &self,
    ) -> (Option<&SqliteConnection>, &KvdbSqliteStatements) {
        unsafe { ((self.connection.map(|conn| &*conn)), &*self.statements) }
    }

    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut SqliteConnection>, &KvdbSqliteStatements) {
        unsafe { ((self.connection.map(|conn| &mut *conn)), &*self.statements) }
    }
}

impl<
        T: DerefPlusImplOrBorrowSelf<dyn KvdbSqliteDestructureTrait>
            + DerefMutPlusImplOrBorrowMutSelf<dyn KvdbSqliteDestructureTrait>,
        F,
    > KvdbSqliteDestructureTrait for ConnectionWithRowParser<T, F>
{
    fn destructure(
        &self,
    ) -> (Option<&SqliteConnection>, &KvdbSqliteStatements) {
        self.0.borrow().destructure()
    }

    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut SqliteConnection>, &KvdbSqliteStatements) {
        self.0.borrow_mut().destructure_mut()
    }
}

impl<ValueType> KvdbSqliteBorrowMut<'_, ValueType> {
    pub fn new(
        destructure: (
            Option<&'_ mut SqliteConnection>,
            &'_ KvdbSqliteStatements,
        ),
    ) -> Self
    {
        Self {
            connection: destructure.0.map(|x| x as *mut SqliteConnection),
            statements: destructure.1,
            __marker_lifetime: Default::default(),
            __marker_value: Default::default(),
        }
    }

    #[allow(unused)]
    pub fn to_read_only(&mut self) -> KvdbSqliteBorrowMutReadOnly<ValueType> {
        KvdbSqliteBorrowMutReadOnly {
            connection: self.connection,
            statements: self.statements,
            __marker_lifetime: Default::default(),
            __marker_value: Default::default(),
        }
    }
}

impl<ValueType> KvdbSqliteBorrowMutReadOnly<'_, ValueType> {
    pub fn new(
        destructure: (
            Option<&'_ mut SqliteConnection>,
            &'_ str,
            &'_ str,
            &'_ KvdbSqliteStatements,
        ),
    ) -> Self
    {
        Self {
            connection: destructure.0.map(|x| x as *mut SqliteConnection),
            statements: destructure.3,
            __marker_lifetime: Default::default(),
            __marker_value: Default::default(),
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
impl<ValueType> Deref for KvdbSqliteBorrowMut<'_, ValueType> {
    type Target = KvdbSqliteBorrowMut<'static, ValueType>;

    fn deref(&self) -> &Self::Target {
        unsafe { std::mem::transmute::<&Self, &Self::Target>(self) }
    }
}

impl<ValueType> DerefMut for KvdbSqliteBorrowMut<'_, ValueType> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::mem::transmute::<&mut Self, &mut Self::Target>(self) }
    }
}

impl<ValueType> Deref for KvdbSqliteBorrowMutReadOnly<'_, ValueType> {
    type Target = KvdbSqliteBorrowMutReadOnly<'static, ValueType>;

    fn deref(&self) -> &Self::Target {
        unsafe { std::mem::transmute::<&Self, &Self::Target>(self) }
    }
}

impl<ValueType> DerefMut for KvdbSqliteBorrowMutReadOnly<'_, ValueType> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::mem::transmute::<&mut Self, &mut Self::Target>(self) }
    }
}

use super::{
    super::{
        super::{
            storage_db::{delta_db_manager::DeltaDbTrait, key_value_db::*},
            utils::{deref_plus_impl_or_borrow_self::*, tuple::*},
        },
        errors::*,
    },
    sqlite::*,
};
use sqlite::{Connection, Statement};
use std::{
    any::Any,
    collections::HashMap,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    path::Path,
    sync::Arc,
};
use strfmt::strfmt;
