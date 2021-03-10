// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct KvdbSqliteSharded<ValueType> {
    // The main table is the number_key_table_name, if with_number_key_table
    // was true when statements are created.
    shards_connections: Option<Box<[SqliteConnection]>>,
    statements: Arc<KvdbSqliteStatements>,
    __marker_value: PhantomData<ValueType>,
}

impl<ValueType> MallocSizeOf for KvdbSqliteSharded<ValueType> {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let mut size = 0;
        if let Some(connections) = &self.shards_connections {
            for connection in &**connections {
                size += connection.size_of(ops);
            }
        }
        // statements is small so can be ignored
        size
    }
}

impl<ValueType> KvdbSqliteSharded<ValueType> {
    pub fn new(
        shard_connections: Option<Box<[SqliteConnection]>>,
        statements: Arc<KvdbSqliteStatements>,
    ) -> Self {
        if let Some(connections) = shard_connections.as_ref() {
            assert_valid_num_shards(connections.len() as u16);
        }
        Self {
            shards_connections: shard_connections,
            statements,
            __marker_value: Default::default(),
        }
    }

    pub fn into_connections(self) -> Option<Box<[SqliteConnection]>> {
        self.shards_connections
    }
}

pub struct KvdbSqliteShardedBorrowMut<'db, ValueType> {
    shards_connections: Option<*mut [SqliteConnection]>,
    statements: &'db KvdbSqliteStatements,
    __marker_lifetime: PhantomData<&'db mut SqliteConnection>,
    __marker_value: PhantomData<ValueType>,
}

impl<'db, ValueType> KvdbSqliteShardedBorrowMut<'db, ValueType> {
    pub fn new(
        shard_connections: Option<&'db mut [SqliteConnection]>,
        statements: &'db KvdbSqliteStatements,
    ) -> Self {
        if let Some(connections) = shard_connections.as_ref() {
            assert_valid_num_shards(connections.len() as u16);
        }
        Self {
            shards_connections: shard_connections
                .map(|x| x as *mut [SqliteConnection]),
            statements,
            __marker_lifetime: Default::default(),
            __marker_value: Default::default(),
        }
    }
}

pub struct KvdbSqliteShardedBorrowShared<'db, ValueType> {
    shards_connections: Option<*const [SqliteConnection]>,
    statements: &'db KvdbSqliteStatements,
    __marker_lifetime: PhantomData<&'db SqliteConnection>,
    __marker_value: PhantomData<ValueType>,
}

impl<'db, ValueType> KvdbSqliteShardedBorrowShared<'db, ValueType> {
    pub fn new(
        shard_connections: Option<&'db [SqliteConnection]>,
        statements: &'db KvdbSqliteStatements,
    ) -> Self {
        if let Some(connections) = shard_connections.as_ref() {
            assert_valid_num_shards(connections.len() as u16);
        }
        Self {
            shards_connections: shard_connections
                .map(|x| x as *const [SqliteConnection]),
            statements,
            __marker_lifetime: Default::default(),
            __marker_value: Default::default(),
        }
    }
}

pub trait KvdbSqliteShardedRefDestructureTrait {
    fn destructure(
        &self,
    ) -> (Option<&[SqliteConnection]>, &KvdbSqliteStatements);
}

pub trait KvdbSqliteShardedDestructureTrait {
    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut [SqliteConnection]>, &KvdbSqliteStatements);
}

impl<ValueType> KvdbSqliteSharded<ValueType> {
    pub fn db_path<P: AsRef<Path>>(path: P, shard_id: u16) -> PathBuf {
        path.as_ref().join(format!("shard_{:02x}", shard_id))
    }

    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            shards_connections: match &self.shards_connections {
                None => None,
                Some(connections) => {
                    let mut cloned_connections =
                        Vec::with_capacity(connections.len());
                    for conn in connections.iter() {
                        cloned_connections.push(conn.try_clone()?)
                    }
                    Some(cloned_connections.into_boxed_slice())
                }
            },
            statements: self.statements.clone(),
            __marker_value: Default::default(),
        })
    }

    pub fn open<P: AsRef<Path>>(
        num_shards: u16, dir: P, readonly: bool,
        statements: Arc<KvdbSqliteStatements>,
    ) -> Result<Self> {
        assert_valid_num_shards(num_shards);
        let mut shards_connections = Vec::with_capacity(num_shards as usize);
        for i in 0..num_shards {
            shards_connections.push(SqliteConnection::open(
                Self::db_path(&dir, i),
                readonly,
                SqliteConnection::default_open_flags(),
            )?)
        }
        Ok(Self {
            shards_connections: Some(shards_connections.into_boxed_slice()),
            statements,
            __marker_value: Default::default(),
        })
    }

    pub fn open_or_create<P: AsRef<Path>>(
        num_shards: u16, dir: P, statements: Arc<KvdbSqliteStatements>,
        unsafe_mode: bool,
    ) -> Result<(bool, Self)> {
        if dir.as_ref().exists() {
            Ok((
                true,
                Self::open(
                    num_shards, dir, /* readonly = */ false, statements,
                )?,
            ))
        } else {
            Ok((
                false,
                Self::create_and_open(
                    num_shards,
                    dir,
                    statements,
                    /* create_table = */ true,
                    unsafe_mode,
                )?,
            ))
        }
    }

    pub fn create_and_open<P: AsRef<Path>>(
        num_shards: u16, dir: P, statements: Arc<KvdbSqliteStatements>,
        create_table: bool, unsafe_mode: bool,
    ) -> Result<Self> {
        assert_valid_num_shards(num_shards);
        let mut shards_connections = Vec::with_capacity(num_shards as usize);
        for i in 0..num_shards {
            let connection = KvdbSqlite::<ValueType>::create_and_open(
                Self::db_path(&dir, i),
                statements.clone(),
                /* create_table = */ create_table,
                unsafe_mode,
            )?
            .into_connection()
            // Safe to unwrap since the connection is newly created.
            .unwrap();
            shards_connections.push(connection);
        }
        Ok(Self {
            shards_connections: Some(shards_connections.into_boxed_slice()),
            statements,
            __marker_value: Default::default(),
        })
    }

    /// Call initialize databases separately. Typical usage is to create a new
    /// table from the existing db.
    pub fn create_table(
        connections: &mut Box<[SqliteConnection]>,
        statements: &KvdbSqliteStatements,
    ) -> Result<()> {
        for connection in connections.iter_mut() {
            KvdbSqlite::<ValueType>::create_table(connection, statements)?
        }
        Ok(())
    }

    pub fn drop_table(
        connections: &mut Box<[SqliteConnection]>,
        statements: &KvdbSqliteStatements,
    ) -> Result<()> {
        for connection in connections.iter_mut() {
            KvdbSqlite::<ValueType>::drop_table(connection, statements)?
        }
        Ok(())
    }
}

fn assert_valid_num_shards(num_shards: u16) {
    assert_eq!(0, 256 % num_shards)
}

pub fn key_to_shard_id(key: &[u8], num_shards: usize) -> usize {
    let k_len = key.len();
    let b0 = if k_len > 0 {
        unsafe { *key.get_unchecked(0) as usize }
    } else {
        0
    };
    let b1 = if k_len > 1 {
        unsafe { *key.get_unchecked(1) as usize }
    } else {
        0
    };
    let b2 = if k_len > 2 {
        unsafe { *key.get_unchecked(2) as usize }
    } else {
        0
    };
    let b3 = if k_len > 3 {
        unsafe { *key.get_unchecked(3) as usize }
    } else {
        0
    };
    let mapped_key = ((b0 + b1) << 4) + b2 + b3;
    mapped_key % num_shards
}

pub fn number_key_to_shard_id(key: i64, num_shards: usize) -> usize {
    let x = (((key >> 52) & 0x0000000000000ff0)
        + ((key & 0x00ff000000000000) >> 44)) as usize;
    let y = (((key & 0x0000ff0000000000) >> 40)
        + ((key & 0x000000ff00000000) >> 32)) as usize;
    (x + y) % num_shards
}

/// Map as in Map-Reduce.
pub trait KeyPrefixToMap {
    fn key_prefix_to_map(&self) -> u32;
}

impl KeyPrefixToMap for Vec<u8> {
    fn key_prefix_to_map(&self) -> u32 {
        let k_len = self.len();
        let b0 = if k_len > 0 {
            unsafe { *self.get_unchecked(0) as u32 }
        } else {
            0
        };
        let b1 = if k_len > 1 {
            unsafe { *self.get_unchecked(1) as u32 }
        } else {
            0
        };
        let b2 = if k_len > 2 {
            unsafe { *self.get_unchecked(2) as u32 }
        } else {
            0
        };
        let b3 = if k_len > 3 {
            unsafe { *self.get_unchecked(3) as u32 }
        } else {
            0
        };
        (b0 << 24) + (b1 << 16) + (b2 << 8) + b3
    }
}

impl KeyPrefixToMap for i64 {
    fn key_prefix_to_map(&self) -> u32 {
        // We have to xor the first bit to order negative keys before positive
        // keys.
        (*self >> 32) as u32 ^ 0x80000000
    }
}

impl<
        T: ReadImplFamily
            + KvdbSqliteShardedRefDestructureTrait
            + KeyValueDbTypes<ValueType = ValueType>,
        ValueType: DbValueType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > ReadImplByFamily<KvdbSqliteSharded<ValueType>> for T
{
    fn get_impl(&self, key: &[u8]) -> Result<Option<Self::ValueType>> {
        let (maybe_connections, statements) = self.destructure();
        match maybe_connections {
            None => Ok(None),
            Some(connections) => KvdbSqliteBorrowShared::new((
                connections.get(key_to_shard_id(key, connections.len())),
                statements,
            ))
            .get_impl(key),
        }
    }

    fn get_with_number_key_impl(
        &self, key: i64,
    ) -> Result<Option<Self::ValueType>> {
        let (maybe_connections, statements) = self.destructure();
        match maybe_connections {
            None => Ok(None),
            Some(connections) => KvdbSqliteBorrowShared::new((
                connections.get(number_key_to_shard_id(key, connections.len())),
                statements,
            ))
            .get_with_number_key_impl(key),
        }
    }
}

impl<
        T: OwnedReadImplFamily
            + KvdbSqliteShardedDestructureTrait
            + KeyValueDbTypes<ValueType = ValueType>,
        ValueType: DbValueType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > OwnedReadImplByFamily<KvdbSqliteSharded<ValueType>> for T
{
    fn get_mut_impl(&mut self, key: &[u8]) -> Result<Option<Self::ValueType>> {
        let (maybe_connections, statements) = self.destructure_mut();
        match maybe_connections {
            None => Ok(None),
            Some(connections) => KvdbSqliteBorrowMut::new((
                connections.get_mut(key_to_shard_id(key, connections.len())),
                statements,
            ))
            .get_mut_impl(key),
        }
    }

    fn get_mut_with_number_key_impl(
        &mut self, key: i64,
    ) -> Result<Option<Self::ValueType>> {
        let (maybe_connections, statements) = self.destructure_mut();
        match maybe_connections {
            None => Ok(None),
            Some(connections) => KvdbSqliteBorrowMut::new((
                connections
                    .get_mut(number_key_to_shard_id(key, connections.len())),
                statements,
            ))
            .get_mut_with_number_key_impl(key),
        }
    }
}

impl<
        T: SingleWriterImplFamily
            + KvdbSqliteShardedDestructureTrait
            + KeyValueDbTypes<ValueType = ValueType>,
        ValueType: DbValueType,
    > SingleWriterImplByFamily<KvdbSqliteSharded<ValueType>> for T
where
    ValueType::Type: SqlBindableValue
        + BindValueAppendImpl<<ValueType::Type as SqlBindableValue>::Kind>,
{
    fn delete_impl(
        &mut self, key: &[u8],
    ) -> Result<Option<Option<Self::ValueType>>> {
        let (maybe_connections, statements) = self.destructure_mut();
        match maybe_connections {
            None => Err(Error::from(ErrorKind::DbNotExist)),
            Some(connections) => KvdbSqliteBorrowMut::<ValueType>::new((
                connections.get_mut(key_to_shard_id(key, connections.len())),
                statements,
            ))
            .delete_impl(key),
        }
    }

    fn delete_with_number_key_impl(
        &mut self, key: i64,
    ) -> Result<Option<Option<Self::ValueType>>> {
        let (maybe_connections, statements) = self.destructure_mut();
        match maybe_connections {
            None => Err(Error::from(ErrorKind::DbNotExist)),
            Some(connections) => KvdbSqliteBorrowMut::new((
                connections
                    .get_mut(number_key_to_shard_id(key, connections.len())),
                statements,
            ))
            .delete_with_number_key_impl(key),
        }
    }

    fn put_impl(
        &mut self, key: &[u8], value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>> {
        let (maybe_connections, statements) = self.destructure_mut();
        match maybe_connections {
            None => Err(Error::from(ErrorKind::DbNotExist)),
            Some(connections) => KvdbSqliteBorrowMut::<ValueType>::new((
                connections.get_mut(key_to_shard_id(key, connections.len())),
                statements,
            ))
            .put_impl(key, value),
        }
    }

    fn put_with_number_key_impl(
        &mut self, key: i64, value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>> {
        let (maybe_connections, statements) = self.destructure_mut();
        match maybe_connections {
            None => Err(Error::from(ErrorKind::DbNotExist)),
            Some(connections) => KvdbSqliteBorrowMut::new((
                connections
                    .get_mut(number_key_to_shard_id(key, connections.len())),
                statements,
            ))
            .put_with_number_key_impl(key, value),
        }
    }
}

pub struct ShardedIterMerger<
    Key: KeyPrefixToMap,
    Value,
    ShardIter: FallibleIterator<Item = (Key, Value)>,
> {
    shard_iters: Vec<ShardIter>,
    ordered_iter_ids: Vec<u8>,
    ordered_key_prefixes_to_map: Vec<u32>,
    maybe_next_key_values: Vec<Option<(Key, Value)>>,
}

impl<
        Key: KeyPrefixToMap,
        Value,
        ShardIter: FallibleIterator<Item = (Key, Value)>,
    > ShardedIterMerger<Key, Value, ShardIter>
{
    pub fn new() -> Self {
        Self {
            shard_iters: vec![],
            ordered_iter_ids: vec![],
            ordered_key_prefixes_to_map: vec![],
            // Keep the rear element to None to help the while loops.
            maybe_next_key_values: vec![None],
        }
    }

    pub fn push_shard_iter(
        &mut self, mut iter: ShardIter,
    ) -> std::result::Result<(), ShardIter::Error> {
        let maybe_first_key_value = iter.next()?;
        let iter_id = self.shard_iters.len() as u8;
        self.shard_iters.push(iter);
        self.kv_push(iter_id, maybe_first_key_value);
        Ok(())
    }

    fn kv_push(&mut self, iter_id: u8, kv: Option<(Key, Value)>) {
        if kv.is_some() {
            let mut i = 0;
            let this_key_prefix_to_map =
                kv.as_ref().unwrap().0.key_prefix_to_map();
            while self.maybe_next_key_values[i].is_some() {
                if this_key_prefix_to_map < self.ordered_key_prefixes_to_map[i]
                {
                    break;
                }
                i += 1;
            }
            self.ordered_iter_ids.insert(i, iter_id);
            self.ordered_key_prefixes_to_map
                .insert(i, this_key_prefix_to_map);
            self.maybe_next_key_values.insert(i, kv);
        }
    }

    fn peek(&self) -> Option<u8> {
        self.ordered_iter_ids.get(0).cloned()
    }

    fn kv_pop_and_push(
        &mut self, iter_id: u8, kv: Option<(Key, Value)>,
    ) -> std::result::Result<Option<(Key, Value)>, ShardIter::Error> {
        let mut i;
        if kv.is_some() {
            i = 0;
            let this_key_prefix_to_map =
                kv.as_ref().unwrap().0.key_prefix_to_map();
            while self.maybe_next_key_values[i].is_some() {
                if this_key_prefix_to_map < self.ordered_key_prefixes_to_map[i]
                {
                    break;
                }
                i += 1;
            }
            // i is at least 1, because key_prefix_to_map[0] is the smallest,
            // and kv is the next element, which has to be >=
            // key_prefix_to_map[0]. Have to use memmove, etc.
            debug_assert!(i > 0);
            unsafe {
                let pos = i - 1;
                std::ptr::copy(
                    self.ordered_iter_ids.get_unchecked(1),
                    self.ordered_iter_ids.get_unchecked_mut(0),
                    pos,
                );
                std::ptr::write(
                    self.ordered_iter_ids.get_unchecked_mut(pos),
                    iter_id,
                );
                std::ptr::copy(
                    self.ordered_key_prefixes_to_map.get_unchecked(1),
                    self.ordered_key_prefixes_to_map.get_unchecked_mut(0),
                    pos,
                );
                std::ptr::write(
                    self.ordered_key_prefixes_to_map.get_unchecked_mut(pos),
                    this_key_prefix_to_map,
                );
                let popped = Ok(std::ptr::read(
                    self.maybe_next_key_values.get_unchecked(0),
                ));
                std::ptr::copy(
                    self.maybe_next_key_values.get_unchecked(1),
                    self.maybe_next_key_values.get_unchecked_mut(0),
                    pos,
                );
                std::ptr::write(
                    self.maybe_next_key_values.get_unchecked_mut(pos),
                    kv,
                );

                popped
            }
        } else {
            self.ordered_iter_ids.remove(0);
            self.ordered_key_prefixes_to_map.remove(0);
            Ok(self.maybe_next_key_values.remove(0))
        }
    }
}

impl<
        Key: KeyPrefixToMap,
        Value,
        ShardIter: FallibleIterator<Item = (Key, Value)>,
    > FallibleIterator for ShardedIterMerger<Key, Value, ShardIter>
{
    type Error = ShardIter::Error;
    type Item = (Key, Value);

    fn next(&mut self) -> std::result::Result<Option<Self::Item>, Self::Error> {
        match self.peek() {
            None => Ok(None),
            Some(iter_id) => {
                // TODO: iter executions are not in parallel. Current
                // performance seems OK.
                let next_kv = self.shard_iters[iter_id as usize].next()?;
                self.kv_pop_and_push(iter_id, next_kv)
            }
        }
    }
}

pub trait KvdbSqliteShardedDestructureTraitWithValueType:
    KvdbSqliteShardedDestructureTrait + KeyValueDbTypes
{
}
impl<T: KvdbSqliteShardedDestructureTrait + KeyValueDbTypes>
    KvdbSqliteShardedDestructureTraitWithValueType for T
{
}

// TODO: iter executions are not in parallel. Current performance seems OK.
pub fn kvdb_sqlite_sharded_iter_range_impl<
    'db,
    Key: 'db + KeyPrefixToMap,
    Value: 'db,
    F: Clone + FnMut(&Statement<'db>) -> Result<(Key, Value)>,
>(
    maybe_shards_connections: Option<&'db mut [SqliteConnection]>,
    statements: &KvdbSqliteStatements, lower_bound_incl: &[u8],
    upper_bound_excl: Option<&[u8]>, f: F,
) -> Result<ShardedIterMerger<Key, Value, MappedRows<'db, F>>> {
    let mut shards_iter_merger_result = Ok(ShardedIterMerger::new());
    if let Some(shards_connections) = maybe_shards_connections {
        let shards_iter_merger = shards_iter_merger_result.as_mut().unwrap();
        for connection in shards_connections.iter_mut() {
            let shard_iter = kvdb_sqlite_iter_range_impl(
                Some(connection),
                statements,
                lower_bound_incl,
                upper_bound_excl,
                f.clone(),
            )?;
            shards_iter_merger.push_shard_iter(shard_iter)?;
        }
    }

    shards_iter_merger_result
}

pub fn kvdb_sqlite_sharded_iter_range_excl_impl<
    'db,
    Key: 'db + KeyPrefixToMap,
    Value: 'db,
    F: Clone + FnMut(&Statement<'db>) -> Result<(Key, Value)>,
>(
    maybe_shards_connections: Option<&'db mut [SqliteConnection]>,
    statements: &KvdbSqliteStatements, lower_bound_excl: &[u8],
    upper_bound_excl: &[u8], f: F,
) -> Result<ShardedIterMerger<Key, Value, MappedRows<'db, F>>> {
    let mut shards_iter_merger_result = Ok(ShardedIterMerger::new());
    if let Some(shards_connections) = maybe_shards_connections {
        let shards_iter_merger = shards_iter_merger_result.as_mut().unwrap();
        for connection in shards_connections.iter_mut() {
            let shard_iter = kvdb_sqlite_iter_range_excl_impl(
                Some(connection),
                statements,
                lower_bound_excl,
                upper_bound_excl,
                f.clone(),
            )?;
            shards_iter_merger.push_shard_iter(shard_iter)?;
        }
    }

    shards_iter_merger_result
}

macro_rules! enable_KvdbIterIterator_for_KvdbSqliteSharded_families {
    ($ItemKeyType:ty, $ItemValueType:ty, $KeyType:ty) => {
        impl<'a>
            WrappedLifetimeFamily<
                'a,
                dyn FallibleIterator<
                    Item = ($ItemKeyType, $ItemValueType),
                    Error = Error,
                >,
            >
            for KvdbIterIterator<
                ($ItemKeyType, $ItemValueType),
                $KeyType,
                KvdbSqliteShardedIteratorTag,
            >
        {
            type Out = ShardedIterMerger<
                $ItemKeyType,
                $ItemValueType,
                MappedRows<
                    'a,
                    for<'r, 's> fn(
                        &'r Statement<'s>,
                    )
                        -> Result<($ItemKeyType, $ItemValueType)>,
                >,
            >;
        }
        impl
            WrappedTrait<
                dyn FallibleIterator<
                    Item = ($ItemKeyType, $ItemValueType),
                    Error = Error,
                >,
            >
            for KvdbIterIterator<
                ($ItemKeyType, $ItemValueType),
                $KeyType,
                KvdbSqliteShardedIteratorTag,
            >
        {
        }
    };
}

pub struct KvdbSqliteShardedIteratorTag();

enable_KvdbIterIterator_for_KvdbSqliteSharded_families!(
    Vec<u8>,
    Box<[u8]>,
    [u8]
);
enable_KvdbIterIterator_for_KvdbSqliteSharded_families!(Vec<u8>, (), [u8]);

macro_rules! make_wrap_of_KeyValueDbIterableTrait_of_KvdbSqliteSharded_families {
    ($ItemType:ty, $Ttype:ty) => {
        impl
            ElementSatisfy<
                dyn KeyValueDbIterableTrait<
                    $ItemType,
                    [u8],
                    KvdbSqliteShardedIteratorTag,
                >,
            > for $Ttype
        {
            fn to_constrain_object(
                &self,
            ) -> &(dyn KeyValueDbIterableTrait<
                $ItemType,
                [u8],
                KvdbSqliteShardedIteratorTag,
            > + 'static) {
                self
            }

            fn to_constrain_object_mut(
                &mut self,
            ) -> &mut (dyn KeyValueDbIterableTrait<
                $ItemType,
                [u8],
                KvdbSqliteShardedIteratorTag,
            > + 'static) {
                self
            }
        }

        impl
            WrappedLifetimeFamily<
                '_,
                dyn KeyValueDbIterableTrait<
                    $ItemType,
                    [u8],
                    KvdbSqliteShardedIteratorTag,
                >,
            > for $Ttype
        {
            type Out = Self;
        }
        impl
            WrappedTrait<
                dyn KeyValueDbIterableTrait<
                    $ItemType,
                    [u8],
                    KvdbSqliteShardedIteratorTag,
                >,
            > for $Ttype
        {
        }
    };
}

make_wrap_of_KeyValueDbIterableTrait_of_KvdbSqliteSharded_families!(
    MptKeyValue,
    KvdbSqliteSharded<Box<[u8]>>
);
make_wrap_of_KeyValueDbIterableTrait_of_KvdbSqliteSharded_families!(
    (Vec<u8>, ()),
    KvdbSqliteSharded<()>
);
make_wrap_of_KeyValueDbIterableTrait_of_KvdbSqliteSharded_families!(
    MptKeyValue,
    KvdbSqliteShardedBorrowMut<'static, Box<[u8]>>
);

// FIXME: implement for more general types
// (DerefOr...<KvdbSqliteShardedBorrow...>)
impl<
        ValueType: 'static + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
        T: DerefMutPlusImplOrBorrowMutSelf<
            dyn KvdbSqliteShardedDestructureTraitWithValueType<
                ValueType = ValueType,
            >,
        >,
    >
    KeyValueDbIterableTrait<
        (Vec<u8>, ValueType),
        [u8],
        KvdbSqliteShardedIteratorTag,
    > for T
where
    KvdbIterIterator<(Vec<u8>, ValueType), [u8], KvdbSqliteShardedIteratorTag>:
        WrappedTrait<
                dyn FallibleIterator<
                    Item = (Vec<u8>, ValueType),
                    Error = Error,
                >,
            > + for<'a> WrappedLifetimeFamily<
                'a,
                dyn FallibleIterator<
                    Item = (Vec<u8>, ValueType),
                    Error = Error,
                >,
                Out = ShardedIterMerger<
                    Vec<u8>,
                    ValueType,
                    MappedRows<
                        'a,
                        for<'r, 's> fn(
                            &'r Statement<'s>,
                        )
                            -> Result<(Vec<u8>, ValueType)>,
                    >,
                >,
            >,
{
    fn iter_range(
        &mut self, lower_bound_incl: &[u8], upper_bound_excl: Option<&[u8]>,
    ) -> Result<
        Wrap<
            KvdbIterIterator<
                (Vec<u8>, ValueType),
                [u8],
                KvdbSqliteShardedIteratorTag,
            >,
            dyn FallibleIterator<Item = (Vec<u8>, ValueType), Error = Error>,
        >,
    > {
        let (maybe_shards_connections, statements) =
            self.borrow_mut().destructure_mut();
        Ok(Wrap(kvdb_sqlite_sharded_iter_range_impl(
            maybe_shards_connections,
            statements,
            lower_bound_incl,
            upper_bound_excl,
            KvdbSqlite::<ValueType>::kv_from_iter_row::<Vec<u8>>
                as for<'r, 's> fn(
                    &'r Statement<'s>,
                )
                    -> Result<(Vec<u8>, ValueType)>,
        )?))
    }

    fn iter_range_excl(
        &mut self, lower_bound_excl: &[u8], upper_bound_excl: &[u8],
    ) -> Result<
        Wrap<
            KvdbIterIterator<
                (Vec<u8>, ValueType),
                [u8],
                KvdbSqliteShardedIteratorTag,
            >,
            dyn FallibleIterator<Item = (Vec<u8>, ValueType), Error = Error>,
        >,
    > {
        let (maybe_shards_connections, statements) =
            self.borrow_mut().destructure_mut();
        Ok(Wrap(kvdb_sqlite_sharded_iter_range_excl_impl(
            maybe_shards_connections,
            statements,
            lower_bound_excl,
            upper_bound_excl,
            KvdbSqlite::<ValueType>::kv_from_iter_row::<Vec<u8>>
                as for<'r, 's> fn(
                    &'r Statement<'s>,
                )
                    -> Result<(Vec<u8>, ValueType)>,
        )?))
    }
}

// 'static because Any is static.
impl<
        ValueType: 'static
            + DbValueType
            + ValueRead
            + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > KeyValueDbTraitTransactional for KvdbSqliteSharded<ValueType>
where
    ValueType::Type: SqlBindableValue
        + BindValueAppendImpl<<ValueType::Type as SqlBindableValue>::Kind>,
{
    type TransactionType = KvdbSqliteShardedTransaction<ValueType>;

    fn start_transaction(
        &self, immediate_write: bool,
    ) -> Result<KvdbSqliteShardedTransaction<ValueType>> {
        if self.shards_connections.is_none() {
            bail!(ErrorKind::DbNotExist);
        }

        KvdbSqliteShardedTransaction::new(self.try_clone()?, immediate_write)
    }
}

pub struct KvdbSqliteShardedTransaction<
    ValueType: DbValueType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
> where
    ValueType::Type: SqlBindableValue
        + BindValueAppendImpl<<ValueType::Type as SqlBindableValue>::Kind>,
{
    db: KvdbSqliteSharded<ValueType>,
    committed: bool,
}

impl<
        ValueType: DbValueType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > Drop for KvdbSqliteShardedTransaction<ValueType>
where
    ValueType::Type: SqlBindableValue
        + BindValueAppendImpl<<ValueType::Type as SqlBindableValue>::Kind>,
{
    fn drop(&mut self) {
        if !self.committed {
            self.revert().ok();
        }
    }
}

impl<
        ValueType: DbValueType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > KvdbSqliteShardedTransaction<ValueType>
where
    ValueType::Type: SqlBindableValue
        + BindValueAppendImpl<<ValueType::Type as SqlBindableValue>::Kind>,
{
    fn new(
        mut db: KvdbSqliteSharded<ValueType>, immediate_write: bool,
    ) -> Result<Self> {
        Self::start_transaction(
            db.shards_connections.as_mut(),
            immediate_write,
        )?;
        Ok(Self {
            db,
            committed: false,
        })
    }

    fn start_transaction(
        maybe_shard_connections: Option<&mut Box<[SqliteConnection]>>,
        immediate_write: bool,
    ) -> Result<()> {
        if let Some(connections) = maybe_shard_connections {
            for conn in connections.iter_mut() {
                KvdbSqliteTransaction::<ValueType>::start_transaction(
                    conn.get_db_mut(),
                    immediate_write,
                )?
            }
        }
        Ok(())
    }
}

impl<
        ValueType: DbValueType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > KeyValueDbTransactionTrait for KvdbSqliteShardedTransaction<ValueType>
where
    ValueType::Type: SqlBindableValue
        + BindValueAppendImpl<<ValueType::Type as SqlBindableValue>::Kind>,
{
    fn commit(&mut self, _db: &dyn Any) -> Result<()> {
        self.committed = true;
        if let Some(connections) = self.db.shards_connections.as_mut() {
            for conn in connections.iter_mut() {
                conn.get_db_mut().execute("COMMIT")?;
            }
        }
        Ok(())
    }

    fn revert(&mut self) -> Result<()> {
        self.committed = true;
        if let Some(connections) = self.db.shards_connections.as_mut() {
            for conn in connections.iter_mut() {
                conn.get_db_mut().execute("ROLLBACK")?;
            }
        }
        Ok(())
    }

    fn restart(
        &mut self, immediate_write: bool, no_revert: bool,
    ) -> Result<()> {
        if !no_revert {
            self.revert()?;
        }
        Self::start_transaction(
            self.db.shards_connections.as_mut(),
            immediate_write,
        )
    }
}

impl<
        ValueType: DbValueType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > KeyValueDbTypes for KvdbSqliteShardedTransaction<ValueType>
where
    ValueType::Type: SqlBindableValue
        + BindValueAppendImpl<<ValueType::Type as SqlBindableValue>::Kind>,
{
    type ValueType = ValueType;
}

impl KeyValueDbTraitMultiReader for KvdbSqliteSharded<Box<[u8]>> {}
impl OwnedReadImplFamily for &KvdbSqliteSharded<Box<[u8]>> {
    type FamilyRepresentative =
        dyn KeyValueDbTraitMultiReader<ValueType = Box<[u8]>>;
}
impl DeltaDbTrait for KvdbSqliteSharded<Box<[u8]>> {}

impl<ValueType: DbValueType> KeyValueDbTypes for KvdbSqliteSharded<ValueType> {
    type ValueType = ValueType;
}

impl<ValueType: DbValueType> KeyValueDbTypes
    for KvdbSqliteShardedBorrowMut<'_, ValueType>
{
    type ValueType = ValueType;
}

impl<ValueType: DbValueType> KeyValueDbTypes
    for KvdbSqliteShardedBorrowShared<'_, ValueType>
{
    type ValueType = ValueType;
}

impl<ValueType: DbValueType> KvdbSqliteShardedRefDestructureTrait
    for KvdbSqliteSharded<ValueType>
{
    fn destructure(
        &self,
    ) -> (Option<&[SqliteConnection]>, &KvdbSqliteStatements) {
        (
            self.shards_connections.as_ref().map(|r| &**r),
            &self.statements,
        )
    }
}

impl<ValueType: DbValueType> KvdbSqliteShardedDestructureTrait
    for KvdbSqliteSharded<ValueType>
{
    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut [SqliteConnection]>, &KvdbSqliteStatements) {
        (
            self.shards_connections.as_mut().map(|r| &mut **r),
            &self.statements,
        )
    }
}

impl<
        ValueType: DbValueType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > KvdbSqliteShardedDestructureTrait
    for KvdbSqliteShardedTransaction<ValueType>
where
    ValueType::Type: SqlBindableValue
        + BindValueAppendImpl<<ValueType::Type as SqlBindableValue>::Kind>,
{
    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut [SqliteConnection]>, &KvdbSqliteStatements) {
        self.db.destructure_mut()
    }
}

impl<ValueType: DbValueType> KvdbSqliteShardedRefDestructureTrait
    for KvdbSqliteShardedBorrowMut<'_, ValueType>
{
    fn destructure(
        &self,
    ) -> (Option<&[SqliteConnection]>, &KvdbSqliteStatements) {
        (
            self.shards_connections.clone().map(|r| unsafe { &*r }),
            &self.statements,
        )
    }
}

impl<ValueType: DbValueType> KvdbSqliteShardedDestructureTrait
    for KvdbSqliteShardedBorrowMut<'_, ValueType>
{
    fn destructure_mut(
        &mut self,
    ) -> (Option<&mut [SqliteConnection]>, &KvdbSqliteStatements) {
        (
            self.shards_connections.clone().map(|r| unsafe { &mut *r }),
            &self.statements,
        )
    }
}

impl<ValueType: DbValueType> KvdbSqliteShardedRefDestructureTrait
    for KvdbSqliteShardedBorrowShared<'_, ValueType>
{
    fn destructure(
        &self,
    ) -> (Option<&[SqliteConnection]>, &KvdbSqliteStatements) {
        (
            self.shards_connections.clone().map(|r| unsafe { &*r }),
            &self.statements,
        )
    }
}

impl<ValueType> ReadImplFamily for KvdbSqliteSharded<ValueType> {
    type FamilyRepresentative = KvdbSqliteSharded<ValueType>;
}

impl<ValueType> OwnedReadImplFamily for KvdbSqliteSharded<ValueType> {
    type FamilyRepresentative = KvdbSqliteSharded<ValueType>;
}

impl<ValueType> SingleWriterImplFamily for KvdbSqliteSharded<ValueType> {
    type FamilyRepresentative = KvdbSqliteSharded<ValueType>;
}

impl<ValueType> ReadImplFamily for KvdbSqliteShardedBorrowMut<'_, ValueType> {
    type FamilyRepresentative = KvdbSqliteSharded<ValueType>;
}

impl<
        ValueType: DbValueType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > OwnedReadImplFamily for KvdbSqliteShardedTransaction<ValueType>
where
    ValueType::Type: SqlBindableValue
        + BindValueAppendImpl<<ValueType::Type as SqlBindableValue>::Kind>,
{
    type FamilyRepresentative = KvdbSqliteSharded<ValueType>;
}

impl<
        ValueType: DbValueType + ValueRead + ValueReadImpl<<ValueType as ValueRead>::Kind>,
    > SingleWriterImplFamily for KvdbSqliteShardedTransaction<ValueType>
where
    ValueType::Type: SqlBindableValue
        + BindValueAppendImpl<<ValueType::Type as SqlBindableValue>::Kind>,
{
    type FamilyRepresentative = KvdbSqliteSharded<ValueType>;
}

impl<ValueType> OwnedReadImplFamily
    for KvdbSqliteShardedBorrowMut<'_, ValueType>
{
    type FamilyRepresentative = KvdbSqliteSharded<ValueType>;
}

impl<ValueType> SingleWriterImplFamily
    for KvdbSqliteShardedBorrowMut<'_, ValueType>
{
    type FamilyRepresentative = KvdbSqliteSharded<ValueType>;
}

impl<ValueType> ReadImplFamily
    for KvdbSqliteShardedBorrowShared<'_, ValueType>
{
    type FamilyRepresentative = KvdbSqliteSharded<ValueType>;
}

enable_deref_for_self! {KvdbSqliteSharded<Box<[u8]>>}
enable_deref_for_self! {KvdbSqliteSharded<()>}
enable_deref_for_self! {KvdbSqliteShardedBorrowShared<'_, Box<[u8]>>}
enable_deref_for_self! {KvdbSqliteShardedBorrowMut<'_, Box<[u8]>>}
enable_deref_mut_plus_impl_or_borrow_mut_self!(
    KvdbSqliteShardedDestructureTraitWithValueType<ValueType = Box<[u8]>>
);
enable_deref_mut_plus_impl_or_borrow_mut_self!(
    KvdbSqliteShardedDestructureTraitWithValueType<ValueType = ()>
);

use crate::{
    impls::{
        errors::*,
        storage_db::{
            kvdb_sqlite::{
                kvdb_sqlite_iter_range_excl_impl, kvdb_sqlite_iter_range_impl,
                KvdbSqliteBorrowMut, KvdbSqliteBorrowShared,
                KvdbSqliteTransaction,
            },
            sqlite::{
                BindValueAppendImpl, MappedRows, SqlBindableValue, ValueRead,
                ValueReadImpl,
            },
        },
    },
    storage_db::{
        DbValueType, DeltaDbTrait, KeyValueDbIterableTrait,
        KeyValueDbTraitMultiReader, KeyValueDbTraitTransactional,
        KeyValueDbTransactionTrait, KeyValueDbTypes, KvdbIterIterator,
        OwnedReadImplByFamily, OwnedReadImplFamily, ReadImplByFamily,
        ReadImplFamily, SingleWriterImplByFamily, SingleWriterImplFamily,
    },
    utils::{
        deref_plus_impl_or_borrow_self::*,
        tuple::ElementSatisfy,
        wrap::{Wrap, WrappedLifetimeFamily, WrappedTrait},
    },
    KvdbSqlite, KvdbSqliteStatements, MptKeyValue, SqliteConnection,
};
use fallible_iterator::FallibleIterator;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use serde::export::PhantomData;
use sqlite::Statement;
use std::{
    any::Any,
    path::{Path, PathBuf},
    sync::Arc,
};
