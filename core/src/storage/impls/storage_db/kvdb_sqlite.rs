// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// FIXME: implement.
pub struct KvdbSqlite {
    readonly: bool,
    empty: bool,
}

impl Default for KvdbSqlite {
    fn default() -> Self {
        Self {
            readonly: true,
            empty: true,
        }
    }
}

pub struct KvdbSqliteTransaction {
    // FIXME: implement
}

impl KvdbSqlite {
    fn get(&self, _key: &[u8]) -> Result<Option<Box<[u8]>>> {
        if self.empty && self.readonly {
            return Ok(None);
        }
        unimplemented!()
    }
}

impl KeyValueDbTraitRead for KvdbSqlite {
    fn get(&self, key: &[u8]) -> Result<Option<Box<[u8]>>> { self.get(key) }

    fn get_with_number_key(&self, _key: i64) -> Result<Option<Box<[u8]>>> {
        unimplemented!()
    }
}

impl KeyValueDbTrait for KvdbSqlite {
    fn delete(&self, _key: &[u8]) -> Result<Option<Option<Box<[u8]>>>> {
        unimplemented!()
    }

    fn put(&self, _key: &[u8], _value: &[u8]) -> Result<()> { unimplemented!() }

    fn put_with_number_key(&self, _key: i64, _value: &[u8]) -> Result<()> {
        unimplemented!()
    }
}

impl KeyValueDbTraitTransactional for KvdbSqlite {
    type TransactionType = KvdbSqliteTransaction;

    fn start_transaction(&self) -> Result<KvdbSqliteTransaction> {
        unimplemented!()
    }
}

impl KeyValueDbTraitRead for KvdbSqliteTransaction {
    fn get(&self, _key: &[u8]) -> Result<Option<Box<[u8]>>> { unimplemented!() }

    fn get_with_number_key(&self, _key: i64) -> Result<Option<Box<[u8]>>> {
        unimplemented!()
    }
}

impl KeyValueDbTraitSingleWriter for KvdbSqliteTransaction {
    fn delete(&mut self, _key: &[u8]) -> Result<Option<Option<Box<[u8]>>>> {
        unimplemented!()
    }

    fn put(&mut self, _key: &[u8], _value: &[u8]) -> Result<()> {
        unimplemented!()
    }

    fn put_with_number_key(&mut self, _key: i64, _value: &[u8]) -> Result<()> {
        unimplemented!()
    }
}

impl Drop for KvdbSqliteTransaction {
    fn drop(&mut self) { unimplemented!() }
}

impl KeyValueDbTransactionTrait for KvdbSqliteTransaction {
    fn commit(&mut self, _db: &dyn Any) -> Result<()> { unimplemented!() }

    fn revert(&mut self) { unimplemented!() }
}

use super::super::{super::storage_db::key_value_db::*, errors::*};
use std::any::Any;
