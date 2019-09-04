// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait KeyValueDbTraitRead {
    fn get(&self, key: &[u8]) -> Result<Option<Box<[u8]>>>;

    fn get_with_number_key(&self, key: i64) -> Result<Option<Box<[u8]>>> {
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
pub trait KeyValueDbTraitOwnedRead {
    fn get_mut(&mut self, key: &[u8]) -> Result<Option<Box<[u8]>>>;

    fn get_mut_with_number_key(
        &mut self, key: i64,
    ) -> Result<Option<Box<[u8]>>> {
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

    fn iter_range_excl(
        &'db mut self, lower_bound_excl: &KeyType, upper_bound_excl: &KeyType,
    ) -> Result<Self::Iterator>;
}

pub trait KeyValueDbTraitSingleWriter: KeyValueDbTraitOwnedRead {
    /// Return Some(maybe_old_value) or None if the db don't support reading the
    /// old value at deletion.
    fn delete(&mut self, key: &[u8]) -> Result<Option<Option<Box<[u8]>>>>;
    fn put(
        &mut self, key: &[u8], value: &[u8],
    ) -> Result<Option<Option<Box<[u8]>>>>;
    fn put_with_number_key(
        &mut self, key: i64, value: &[u8],
    ) -> Result<Option<Option<Box<[u8]>>>> {
        self.put(key.to_string().as_bytes(), value)
    }
}

pub trait KeyValueDbTraitSingleWriterMultiReader:
    KeyValueDbTraitMultiReader + KeyValueDbTraitSingleWriter
{
}

pub trait KeyValueDbTrait: KeyValueDbTraitMultiReader {
    /// Return Some(maybe_old_value) or None if the db don't support reading the
    /// old value at deletion.
    fn delete(&self, key: &[u8]) -> Result<Option<Option<Box<[u8]>>>>;
    fn put(
        &self, key: &[u8], value: &[u8],
    ) -> Result<Option<Option<Box<[u8]>>>>;
    fn put_with_number_key(
        &self, key: i64, value: &[u8],
    ) -> Result<Option<Option<Box<[u8]>>>> {
        self.put(key.to_string().as_bytes(), value)
    }
}

pub trait KeyValueDbTransactionTrait:
    KeyValueDbTraitSingleWriter + Drop
{
    /// Commit may be retried upon failure.
    fn commit(&mut self, db: &dyn Any) -> Result<()>;
    fn revert(&mut self);
    /// When error occured within a transaction before commit, user may have to
    /// revert the transaction and restart a new transaction.
    ///
    /// When restart fails, user may retry with no_revert set to true.
    fn restart(&mut self, immediate_write: bool, no_revert: bool)
        -> Result<()>;
}

/// This trait is to help with the committing of the transaction for which
/// the db object should be provided for serialization.
pub trait KeyValueDbAsAnyTrait {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> KeyValueDbAsAnyTrait for T {
    fn as_any(&self) -> &dyn Any { self }
}

pub trait KeyValueDbTraitTransactional: KeyValueDbAsAnyTrait {
    type TransactionType: KeyValueDbTransactionTrait;

    /// Immediate_write indicates whether the transaction should acquire a
    /// write-lock immediately if any.
    fn start_transaction(
        &self, immediate_write: bool,
    ) -> Result<Self::TransactionType>;
}

pub trait KeyValueDbTraitTransactionalDyn: KeyValueDbAsAnyTrait {
    fn start_transaction_dyn(
        &self, immediate_write: bool,
    ) -> Result<Box<dyn KeyValueDbTransactionTrait>>;
}

impl<T: KeyValueDbTraitTransactional> KeyValueDbTraitTransactionalDyn for T
where T::TransactionType: 'static
{
    fn start_transaction_dyn(
        &self, immediate_write: bool,
    ) -> Result<Box<dyn KeyValueDbTransactionTrait>> {
        Ok(Box::new(self.start_transaction(immediate_write)?))
    }
}

pub trait KeyValueDbToOwnedReadTrait {
    fn to_owned_read(&self) -> Result<Box<dyn '_ + KeyValueDbTraitOwnedRead>>;
}

impl<T: 'static + KeyValueDbTraitMultiReader> KeyValueDbToOwnedReadTrait for T
where for<'a> &'a T: KeyValueDbTraitOwnedRead
{
    fn to_owned_read(&self) -> Result<Box<dyn '_ + KeyValueDbTraitOwnedRead>> {
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
        T: OwnedReadImplByFamily<<T as OwnedReadImplFamily>::FamilyRepresentitive>,
    > KeyValueDbTraitOwnedRead for T
where T: OwnedReadImplFamily
{
    fn get_mut(&mut self, key: &[u8]) -> Result<Option<Box<[u8]>>> {
        self.get_mut_impl(key)
    }

    fn get_mut_with_number_key(
        &mut self, key: i64,
    ) -> Result<Option<Box<[u8]>>> {
        self.get_mut_with_number_key_impl(key)
    }
}

pub trait OwnedReadImplFamily {
    type FamilyRepresentitive: ?Sized;
}

pub trait OwnedReadImplByFamily<FamilyRepresentative: ?Sized> {
    fn get_mut_impl(&mut self, key: &[u8]) -> Result<Option<Box<[u8]>>>;
    fn get_mut_with_number_key_impl(
        &mut self, key: i64,
    ) -> Result<Option<Box<[u8]>>>;
}

impl<
        T: SingleWriterImplByFamily<
            <T as SingleWriterImplFamily>::FamilyRepresentitive,
        >,
    > KeyValueDbTraitSingleWriter for T
where
    T: SingleWriterImplFamily,
    // KeyValueDbTraitSingleWriter must also be KeyValueDbTraitOwnedRead
    T: KeyValueDbTraitOwnedRead,
{
    fn delete(&mut self, key: &[u8]) -> Result<Option<Option<Box<[u8]>>>> {
        self.delete_impl(key)
    }

    fn put(
        &mut self, key: &[u8], value: &[u8],
    ) -> Result<Option<Option<Box<[u8]>>>> {
        self.put_impl(key, value)
    }

    fn put_with_number_key(
        &mut self, key: i64, value: &[u8],
    ) -> Result<Option<Option<Box<[u8]>>>> {
        self.put_with_number_key_impl(key, value)
    }
}

pub trait SingleWriterImplFamily {
    type FamilyRepresentitive: ?Sized;
}

pub trait SingleWriterImplByFamily<FamilyRepresentative: ?Sized> {
    fn delete_impl(&mut self, key: &[u8]) -> Result<Option<Option<Box<[u8]>>>>;

    fn put_impl(
        &mut self, key: &[u8], value: &[u8],
    ) -> Result<Option<Option<Box<[u8]>>>>;

    fn put_with_number_key_impl(
        &mut self, key: i64, value: &[u8],
    ) -> Result<Option<Option<Box<[u8]>>>>;
}

impl<T: ReadImplByFamily<<T as ReadImplFamily>::FamilyRepresentitive>>
    KeyValueDbTraitRead for T
where T: ReadImplFamily
{
    fn get(&self, key: &[u8]) -> Result<Option<Box<[u8]>>> {
        self.get_impl(key)
    }

    fn get_with_number_key(&self, key: i64) -> Result<Option<Box<[u8]>>> {
        self.get_with_number_key_impl(key)
    }
}

pub trait ReadImplFamily {
    type FamilyRepresentitive: ?Sized;
}

pub trait ReadImplByFamily<FamilyRepresentative: ?Sized> {
    fn get_impl(&self, key: &[u8]) -> Result<Option<Box<[u8]>>>;

    fn get_with_number_key_impl(&self, key: i64) -> Result<Option<Box<[u8]>>>;
}

impl OwnedReadImplFamily for dyn KeyValueDbTraitMultiReader {
    type FamilyRepresentitive = dyn KeyValueDbTraitMultiReader;
}

/// Implement KeyValueDbTraitOwnedRead automatically for database engine which
/// satisfies KeyValueDbTraitMultiReader.
impl<T: KeyValueDbTraitMultiReader>
    OwnedReadImplByFamily<dyn KeyValueDbTraitMultiReader> for &T
{
    fn get_mut_impl(&mut self, key: &[u8]) -> Result<Option<Box<[u8]>>> {
        self.get(key)
    }

    fn get_mut_with_number_key_impl(
        &mut self, key: i64,
    ) -> Result<Option<Box<[u8]>>> {
        self.get_with_number_key(key)
    }
}

macro_rules! mark_kvdb_multi_reader {
    ($type:ty) => {
        impl KeyValueDbTraitMultiReader for $type {}
        // Family dispatching
        impl OwnedReadImplFamily for &$type {
            type FamilyRepresentitive = dyn KeyValueDbTraitMultiReader;
        }
    };
}

use super::super::impls::errors::*;
use fallible_iterator::FallibleIterator;
use std::any::Any;
