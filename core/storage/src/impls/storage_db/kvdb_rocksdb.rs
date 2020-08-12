// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(MallocSizeOfDerive)]
pub struct KvdbRocksdb {
    pub kvdb: Arc<Database>,
    pub col: u32,
}

pub struct KvdbRocksDbTransaction {
    pending: DBTransaction,
    col: u32,
}

impl KeyValueDbTraitRead for KvdbRocksdb {
    fn get(&self, key: &[u8]) -> Result<Option<Box<[u8]>>> {
        Ok(self
            .kvdb
            .get(self.col, key)?
            .map(|db_value| db_value.into_boxed_slice()))
    }
}

mark_kvdb_multi_reader!(KvdbRocksdb);

impl KeyValueDbTypes for KvdbRocksdb {
    type ValueType = Box<[u8]>;
}

impl KeyValueDbTrait for KvdbRocksdb {
    fn delete(&self, key: &[u8]) -> Result<Option<Option<Box<[u8]>>>> {
        random_crash_if_enabled("rocksdb delete");
        let mut transaction = self.kvdb.transaction();
        transaction.delete(self.col, key);
        self.kvdb.write(transaction)?;
        Ok(None)
    }

    fn put(
        &self, key: &[u8], value: &[u8],
    ) -> Result<Option<Option<Box<[u8]>>>> {
        random_crash_if_enabled("rocksdb put");
        let mut transaction = self.kvdb.transaction();
        transaction.put(self.col, key, value);
        self.kvdb.write(transaction)?;
        Ok(None)
    }
}

impl KeyValueDbTypes for KvdbRocksDbTransaction {
    type ValueType = Box<[u8]>;
}

impl KeyValueDbTraitSingleWriter for KvdbRocksDbTransaction {
    fn delete(&mut self, key: &[u8]) -> Result<Option<Option<Box<[u8]>>>> {
        self.pending.delete(self.col, key);
        Ok(None)
    }

    fn put(
        &mut self, key: &[u8], value: &[u8],
    ) -> Result<Option<Option<Box<[u8]>>>> {
        self.pending.put(self.col, key, value);
        Ok(None)
    }
}

impl KeyValueDbTraitOwnedRead for KvdbRocksDbTransaction {
    fn get_mut(&mut self, _key: &[u8]) -> Result<Option<Box<[u8]>>> {
        // DBTransaction doesn't implement get method, so the user shouldn't
        // rely on this method.
        unreachable!()
    }
}

impl KeyValueDbTransactionTrait for KvdbRocksDbTransaction {
    fn commit(&mut self, db: &dyn Any) -> Result<()> {
        random_crash_if_enabled("rocksdb commit");
        match db.downcast_ref::<KvdbRocksdb>() {
            Some(as_kvdb_rocksdb) => {
                let wrapped_ops = DBTransaction {
                    ops: self.pending.ops.clone(),
                };
                let result = as_kvdb_rocksdb.kvdb.write(wrapped_ops);
                match result {
                    Ok(_) => {
                        self.pending.ops.clear();
                        Ok(())
                    }
                    Err(e) => bail!(e),
                }
            }
            None => {
                unreachable!();
            }
        }
    }

    fn revert(&mut self) -> Result<()> {
        self.pending.ops = vec![];
        Ok(())
    }

    fn restart(
        &mut self, _immediate_write: bool, no_revert: bool,
    ) -> Result<()> {
        if !no_revert {
            self.revert()?;
        }
        Ok(())
    }
}

impl Drop for KvdbRocksDbTransaction {
    fn drop(&mut self) {
        // No-op
    }
}

impl KeyValueDbTraitTransactional for KvdbRocksdb {
    type TransactionType = KvdbRocksDbTransaction;

    fn start_transaction(
        &self, _immediate_write: bool,
    ) -> Result<Self::TransactionType> {
        Ok(KvdbRocksDbTransaction {
            pending: self.kvdb.transaction(),
            col: self.col,
        })
    }
}

impl DeltaDbTrait for KvdbRocksdb {}

use super::super::{
    super::storage_db::{delta_db_manager::DeltaDbTrait, key_value_db::*},
    errors::*,
};
use kvdb::DBTransaction;
use kvdb_rocksdb::Database;
use malloc_size_of_derive::MallocSizeOf as MallocSizeOfDerive;
use random_crash::random_crash_if_enabled;
use std::{any::Any, sync::Arc};
