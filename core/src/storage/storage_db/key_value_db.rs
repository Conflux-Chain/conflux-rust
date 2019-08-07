// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub trait KeyValueDbTraitRead: KeyValueDbAsReadTrait {
    fn get(&self, key: &[u8]) -> Result<Option<Box<[u8]>>>;

    fn get_with_number_key(&self, key: i64) -> Result<Option<Box<[u8]>>> {
        self.get(key.to_string().as_bytes())
    }
}

/// Multi-reader, single-writer.
pub trait KeyValueDbTraitSingleWriter: KeyValueDbTraitRead {
    /// Return Some(maybe_old_value) or None if the db don't support reading the
    /// old value at deletion.
    fn delete(&mut self, key: &[u8]) -> Result<Option<Option<Box<[u8]>>>>;
    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()>;
    fn put_with_number_key(&mut self, key: i64, value: &[u8]) -> Result<()> {
        self.put(key.to_string().as_bytes(), value)
    }
}

pub trait KeyValueDbTrait: KeyValueDbTraitRead + KeyValueDbAsAnyTrait {
    /// Return Some(maybe_old_value) or None if the db don't support reading the
    /// old value at deletion.
    fn delete(&self, key: &[u8]) -> Result<Option<Option<Box<[u8]>>>>;
    fn put(&self, key: &[u8], value: &[u8]) -> Result<()>;
    fn put_with_number_key(&self, key: i64, value: &[u8]) -> Result<()> {
        self.put(key.to_string().as_bytes(), value)
    }
}

pub trait KeyValueDbTransactionTrait:
    KeyValueDbTraitSingleWriter + Drop
{
    fn commit(&mut self, db: &dyn Any) -> Result<()>;
    fn revert(&mut self);
}

pub trait KeyValueDbTraitTransactional: KeyValueDbTrait {
    type TransactionType: KeyValueDbTransactionTrait;

    fn start_transaction(&self) -> Result<Self::TransactionType>;
}

pub trait KeyValueDbTraitTransactionalDyn: KeyValueDbTrait {
    fn start_transaction_dyn(
        &self,
    ) -> Result<Box<dyn KeyValueDbTransactionTrait>>;
}

impl<T: KeyValueDbTraitTransactional> KeyValueDbTraitTransactionalDyn for T
where T::TransactionType: 'static
{
    fn start_transaction_dyn(
        &self,
    ) -> Result<Box<dyn KeyValueDbTransactionTrait>> {
        Ok(Box::new(self.start_transaction()?))
    }
}

pub trait KeyValueDbAsReadTrait {
    fn as_read_only(&self) -> &KeyValueDbTraitRead;
}

impl<T: KeyValueDbTraitRead> KeyValueDbAsReadTrait for T {
    fn as_read_only(&self) -> &KeyValueDbTraitRead { self }
}

pub trait KeyValueDbAsAnyTrait {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> KeyValueDbAsAnyTrait for T {
    fn as_any(&self) -> &dyn Any { self }
}

use super::super::impls::errors::*;
use std::any::Any;
