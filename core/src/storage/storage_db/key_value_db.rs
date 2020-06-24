// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// One of the elementary value type supported by db.
pub trait DbValueType {
    type Type: ?Sized;
}

pub trait KeyValueDbTypes {
    type ValueType: DbValueType;
}

pub trait KeyValueDbTraitRead: KeyValueDbTypes {
    fn get(&self, key: &[u8]) -> Result<Option<Self::ValueType>>;

    fn get_with_number_key(&self, key: i64) -> Result<Option<Self::ValueType>> {
        self.get(key.to_string().as_bytes())
    }
}

/// The difference between this trait and KeyValueDbTraitRead is that, the type
/// which implements KeyValueDbTraitRead may use lock to serialize the reads,
/// which is not necessarily a multi reader.
pub trait KeyValueDbTraitMultiReader: KeyValueDbTraitRead {}

/// These special get methods are provided for db like sqlite, where concurrency
/// can only be achieved by opening a separate connection, otherwise
/// lock is required for concurrent read.
pub trait KeyValueDbTraitOwnedRead: KeyValueDbTypes {
    fn get_mut(&mut self, key: &[u8]) -> Result<Option<Self::ValueType>>;

    fn get_mut_with_number_key(
        &mut self, key: i64,
    ) -> Result<Option<Self::ValueType>> {
        self.get_mut(key.to_string().as_bytes())
    }
}

pub trait KeyValueDbIterableTrait<'db, Item, Error, KeyType: ?Sized> {
    /// Initially we'd like to use FallibleStreamingIterator however it's only
    /// possible to return a borrow from the iteration, but we want to be
    /// able to extract value with static lifetime out from the iterator, so
    /// we are using FallibleIterator. But then with FallibleIterator it's
    /// not possible to just return borrow of the db row in iteration.
    // TODO(yz): is it possible to write an iterator like what I did with 'self
    // TODO(yz): lifetime? Then create a HRTB for it?
    // TODO(yz): Maybe Lukas who wrote http://lukaskalbertodt.github.io/2018/08/03/solving-the-generalized-streaming-iterator-problem-without-gats.html#workaround-b-hrtbs--the-family-trait-pattern
    // TODO(yz): has a library?
    type Iterator: FallibleIterator<Item = Item, Error = Error> + 'db;

    fn iter_range(
        &'db mut self, lower_bound_incl: &KeyType,
        upper_bound_excl: Option<&KeyType>,
    ) -> Result<Self::Iterator>;

    fn iter_range_excl(
        &'db mut self, lower_bound_excl: &KeyType, upper_bound_excl: &KeyType,
    ) -> Result<Self::Iterator>;
}

pub trait KeyValueDbTraitSingleWriter: KeyValueDbTraitOwnedRead {
    /// Return Some(maybe_old_value) or None if the db don't support reading the
    /// old value at deletion.
    fn delete(&mut self, key: &[u8])
        -> Result<Option<Option<Self::ValueType>>>;
    fn delete_with_number_key(
        &mut self, key: i64,
    ) -> Result<Option<Option<Self::ValueType>>> {
        self.delete(key.to_string().as_bytes())
    }
    fn put(
        &mut self, key: &[u8], value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>>;
    fn put_with_number_key(
        &mut self, key: i64, value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>> {
        self.put(key.to_string().as_bytes(), value)
    }
}

pub trait KeyValueDbTraitSingleWriterMultiReader:
    KeyValueDbTraitMultiReader + KeyValueDbTraitSingleWriter
{
}

pub trait KeyValueDbTrait:
    KeyValueDbTraitMultiReader + Send + Sync + MallocSizeOf
{
    /// Return Some(maybe_old_value) or None if the db don't support reading the
    /// old value at deletion.
    fn delete(&self, key: &[u8]) -> Result<Option<Option<Self::ValueType>>>;
    fn delete_with_number_key(
        &self, key: i64,
    ) -> Result<Option<Option<Self::ValueType>>> {
        self.delete(key.to_string().as_bytes())
    }
    fn put(
        &self, key: &[u8], value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>>;
    fn put_with_number_key(
        &self, key: i64, value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>> {
        self.put(key.to_string().as_bytes(), value)
    }
}

// FIXME: Is it possible to detach SingleWriter from it, so that the
// implementation doesn't look so ugly on KvdbSqliteTransaction?
pub trait KeyValueDbTransactionTrait:
    KeyValueDbTraitSingleWriter + Drop
{
    /// Commit may be retried upon failure.
    fn commit(&mut self, db: &dyn Any) -> Result<()>;
    fn revert(&mut self) -> Result<()>;
    /// When error occured within a transaction before commit, user may have to
    /// revert the transaction and restart a new transaction.
    ///
    /// When restart fails, user may retry with no_revert set to true.
    fn restart(&mut self, immediate_write: bool, no_revert: bool)
        -> Result<()>;
}

/// This trait is to help with the committing of the transaction for which
/// the db object should be provided for serialization.
pub trait KeyValueDbAsAnyTrait: KeyValueDbTypes {
    fn as_any(&self) -> &dyn Any;
}

impl<T: KeyValueDbTypes + Any> KeyValueDbAsAnyTrait for T {
    fn as_any(&self) -> &dyn Any { self }
}

pub trait KeyValueDbTraitTransactional: KeyValueDbAsAnyTrait {
    type TransactionType: KeyValueDbTransactionTrait<
        ValueType = Self::ValueType,
    >;

    /// Immediate_write indicates whether the transaction should acquire a
    /// write-lock immediately if any.
    fn start_transaction(
        &self, immediate_write: bool,
    ) -> Result<Self::TransactionType>;
}

pub trait KeyValueDbTraitTransactionalDyn: KeyValueDbAsAnyTrait {
    fn start_transaction_dyn(
        &self, immediate_write: bool,
    ) -> Result<Box<dyn KeyValueDbTransactionTrait<ValueType = Self::ValueType>>>;
}

impl<T: KeyValueDbTraitTransactional> KeyValueDbTraitTransactionalDyn for T
where T::TransactionType: 'static
{
    fn start_transaction_dyn(
        &self, immediate_write: bool,
    ) -> Result<Box<dyn KeyValueDbTransactionTrait<ValueType = Self::ValueType>>>
    {
        Ok(Box::new(self.start_transaction(immediate_write)?))
    }
}

pub trait KeyValueDbToOwnedReadTrait: KeyValueDbTypes {
    fn to_owned_read(
        &self,
    ) -> Result<
        Box<dyn '_ + KeyValueDbTraitOwnedRead<ValueType = Self::ValueType>>,
    >;
}

impl<T: 'static + KeyValueDbTraitMultiReader> KeyValueDbToOwnedReadTrait for T
where for<'a> &'a T: KeyValueDbTraitOwnedRead<ValueType = Self::ValueType>
{
    fn to_owned_read(
        &self,
    ) -> Result<
        Box<dyn '_ + KeyValueDbTraitOwnedRead<ValueType = Self::ValueType>>,
    > {
        Ok(Box::new(self))
    }
}

/// We implement the family dispatching for types which implements
/// KeyValueDbTraitOwnedRead by different reasons:
///
/// a) Any type which implements KvdbSqliteAsReadOnlyAndIterableTrait can issue
/// sql queries to load db; The feature is required by SnapshotDbSqlite where
/// the sqlite connection is shared for MPT table and for KV table.
///
/// b) similar requirement may hold for any different database engine;
///
/// c) For a db engine which is by default KeyValueDbTraitMultiReader,
/// KeyValueDbTraitOwnedRead is naturally read without explicit locking.
impl<
        T: OwnedReadImplFamily
            + OwnedReadImplByFamily<<T as OwnedReadImplFamily>::FamilyRepresentative>,
    > KeyValueDbTraitOwnedRead for T
{
    fn get_mut(&mut self, key: &[u8]) -> Result<Option<Self::ValueType>> {
        self.get_mut_impl(key)
    }

    fn get_mut_with_number_key(
        &mut self, key: i64,
    ) -> Result<Option<Self::ValueType>> {
        self.get_mut_with_number_key_impl(key)
    }
}

pub trait OwnedReadImplFamily {
    type FamilyRepresentative: ?Sized;
}

pub trait OwnedReadImplByFamily<FamilyRepresentative: ?Sized>:
    KeyValueDbTypes
{
    fn get_mut_impl(&mut self, key: &[u8]) -> Result<Option<Self::ValueType>>;
    fn get_mut_with_number_key_impl(
        &mut self, key: i64,
    ) -> Result<Option<Self::ValueType>>;
}

impl<
        T: SingleWriterImplFamily
            + SingleWriterImplByFamily<
                <T as SingleWriterImplFamily>::FamilyRepresentative,
            > + KeyValueDbTraitOwnedRead,
    > KeyValueDbTraitSingleWriter for T
{
    fn delete(
        &mut self, key: &[u8],
    ) -> Result<Option<Option<Self::ValueType>>> {
        self.delete_impl(key)
    }

    fn delete_with_number_key(
        &mut self, key: i64,
    ) -> Result<Option<Option<Self::ValueType>>> {
        self.delete_with_number_key_impl(key)
    }

    fn put(
        &mut self, key: &[u8], value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>> {
        self.put_impl(key, value)
    }

    fn put_with_number_key(
        &mut self, key: i64, value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>> {
        self.put_with_number_key_impl(key, value)
    }
}

pub trait SingleWriterImplFamily {
    type FamilyRepresentative: ?Sized;
}

pub trait SingleWriterImplByFamily<FamilyRepresentative: ?Sized>:
    KeyValueDbTypes
{
    fn delete_impl(
        &mut self, key: &[u8],
    ) -> Result<Option<Option<Self::ValueType>>>;

    fn delete_with_number_key_impl(
        &mut self, key: i64,
    ) -> Result<Option<Option<Self::ValueType>>>;

    fn put_impl(
        &mut self, key: &[u8], value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>>;

    fn put_with_number_key_impl(
        &mut self, key: i64, value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>>;
}

impl<
        T: ReadImplFamily
            + ReadImplByFamily<<T as ReadImplFamily>::FamilyRepresentative>,
    > KeyValueDbTraitRead for T
{
    fn get(&self, key: &[u8]) -> Result<Option<Self::ValueType>> {
        self.get_impl(key)
    }

    fn get_with_number_key(&self, key: i64) -> Result<Option<Self::ValueType>> {
        self.get_with_number_key_impl(key)
    }
}

pub trait ReadImplFamily {
    type FamilyRepresentative: ?Sized;
}

pub trait ReadImplByFamily<FamilyRepresentative: ?Sized>:
    KeyValueDbTypes
{
    fn get_impl(&self, key: &[u8]) -> Result<Option<Self::ValueType>>;

    fn get_with_number_key_impl(
        &self, key: i64,
    ) -> Result<Option<Self::ValueType>>;
}

impl<
        T: DbImplFamily
            + DbImplByFamily<<T as DbImplFamily>::FamilyRepresentative>
            + KeyValueDbTraitMultiReader
            + Send
            + Sync
            + MallocSizeOf,
    > KeyValueDbTrait for T
{
    fn delete(&self, key: &[u8]) -> Result<Option<Option<Self::ValueType>>> {
        self.delete_impl(key)
    }

    fn delete_with_number_key(
        &self, key: i64,
    ) -> Result<Option<Option<Self::ValueType>>> {
        self.delete_with_number_key_impl(key)
    }

    fn put(
        &self, key: &[u8], value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>> {
        self.put_impl(key, value)
    }

    fn put_with_number_key(
        &self, key: i64, value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>> {
        self.put_with_number_key_impl(key, value)
    }
}

pub trait DbImplFamily {
    type FamilyRepresentative: ?Sized;
}

pub trait DbImplByFamily<FamilyRepresentative: ?Sized>:
    KeyValueDbTypes
{
    fn delete_impl(
        &self, key: &[u8],
    ) -> Result<Option<Option<Self::ValueType>>>;

    fn delete_with_number_key_impl(
        &self, key: i64,
    ) -> Result<Option<Option<Self::ValueType>>>;

    fn put_impl(
        &self, key: &[u8], value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>>;

    fn put_with_number_key_impl(
        &self, key: i64, value: &<Self::ValueType as DbValueType>::Type,
    ) -> Result<Option<Option<Self::ValueType>>>;
}

impl<ValueType: DbValueType> OwnedReadImplFamily
    for dyn KeyValueDbTraitMultiReader<ValueType = ValueType>
{
    type FamilyRepresentative =
        dyn KeyValueDbTraitMultiReader<ValueType = ValueType>;
}

/// Implement KeyValueDbTraitOwnedRead automatically for database engine which
/// satisfies KeyValueDbTraitMultiReader.
impl<
        T: KeyValueDbTraitMultiReader<ValueType = ValueType>,
        ValueType: DbValueType,
    > KeyValueDbTypes for &T
{
    type ValueType = T::ValueType;
}

impl<
        T: KeyValueDbTraitMultiReader<ValueType = ValueType>,
        ValueType: DbValueType,
    >
    OwnedReadImplByFamily<dyn KeyValueDbTraitMultiReader<ValueType = ValueType>>
    for &T
{
    fn get_mut_impl(&mut self, key: &[u8]) -> Result<Option<Self::ValueType>> {
        self.get(key)
    }

    fn get_mut_with_number_key_impl(
        &mut self, key: i64,
    ) -> Result<Option<Self::ValueType>> {
        self.get_with_number_key(key)
    }
}

macro_rules! mark_kvdb_multi_reader {
    ($type:ty) => {
        impl KeyValueDbTraitMultiReader for $type {}
        // Family dispatching
        impl OwnedReadImplFamily for &$type {
            type FamilyRepresentative = dyn KeyValueDbTraitMultiReader<
                ValueType = <$type as KeyValueDbTypes>::ValueType,
            >;
        }
    };
}

impl DbValueType for () {
    type Type = ();
}

impl DbValueType for Box<[u8]> {
    type Type = [u8];
}

impl DbValueType for i64 {
    type Type = i64;
}

use super::super::impls::errors::*;
use fallible_iterator::FallibleIterator;
use malloc_size_of::MallocSizeOf;
use std::any::Any;
