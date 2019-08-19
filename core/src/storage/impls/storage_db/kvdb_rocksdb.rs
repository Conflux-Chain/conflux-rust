// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct KvdbRocksdb {
    /// Currently this is only a wrapper around the old system_db.
    /// This is going to be deprecated.
    pub kvdb: Arc<dyn KeyValueDB>,
}

pub struct KvdbRocksDbTransaction {
    pending: DBTransaction,
}

impl KeyValueDbTraitRead for KvdbRocksdb {
    fn get(&self, key: &[u8]) -> Result<Option<Box<[u8]>>> {
        Ok(self
            .kvdb
            .get(COL_DELTA_TRIE, key)?
            .map(|elastic_array| elastic_array.into_vec().into_boxed_slice()))
    }
}

impl KeyValueDbTrait for KvdbRocksdb {
    fn delete(&self, key: &[u8]) -> Result<Option<Option<Box<[u8]>>>> {
        let mut transaction = self.kvdb.transaction();
        transaction.delete(COL_DELTA_TRIE, key);
        Ok(None)
    }

    fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let mut transaction = self.kvdb.transaction();
        transaction.put(COL_DELTA_TRIE, key, value);
        Ok(self.kvdb.write(transaction)?)
    }
}

impl KeyValueDbTraitSingleWriter for KvdbRocksDbTransaction {
    fn delete(&mut self, key: &[u8]) -> Result<Option<Option<Box<[u8]>>>> {
        self.pending.delete(COL_DELTA_TRIE, key);
        Ok(None)
    }

    fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        Ok(self.pending.put(COL_DELTA_TRIE, key, value))
    }
}

impl KeyValueDbTraitRead for KvdbRocksDbTransaction {
    fn get(&self, _key: &[u8]) -> Result<Option<Box<[u8]>>> {
        // DBTransaction doesn't implement get method, so the user shouldn't
        // rely on this method.
        unreachable!()
    }
}

impl KeyValueDbTransactionTrait for KvdbRocksDbTransaction {
    fn commit(&mut self, db: &dyn Any) -> Result<()> {
        match db.downcast_ref::<KvdbRocksdb>() {
            Some(as_kvdb_rocksdb) => {
                Ok(as_kvdb_rocksdb.kvdb.write(DBTransaction {
                    ops: std::mem::replace(&mut self.pending.ops, vec![]),
                })?)
            }
            None => {
                unreachable!();
            }
        }
    }

    fn revert(&mut self) {}
}

impl Drop for KvdbRocksDbTransaction {
    fn drop(&mut self) {
        // No-op
    }
}

impl KeyValueDbTraitTransactional for KvdbRocksdb {
    type TransactionType = KvdbRocksDbTransaction;

    fn start_transaction(&self) -> Result<Self::TransactionType> {
        Ok(KvdbRocksDbTransaction {
            pending: self.kvdb.transaction(),
        })
    }
}

use super::super::{
    super::{super::db::COL_DELTA_TRIE, storage_db::key_value_db::*},
    errors::*,
};
use kvdb::{DBTransaction, KeyValueDB};
use std::{any::Any, sync::Arc};
