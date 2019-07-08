pub struct KvdbRocksdb {
    /// Currently this is only a wrapper around the old system_db.
    /// This is going to be deprecated.
    pub kvdb: Arc<KeyValueDB>,
}

impl DeltaDbTrait for KvdbRocksdb {
    fn get(&self, key: &[u8]) -> Result<Option<Box<[u8]>>> {
        Ok(self
            .kvdb
            .get(COL_DELTA_TRIE, key)?
            .map(|elastic_array| elastic_array.into_vec().into_boxed_slice()))
    }
}

use super::super::{
    super::{super::db::COL_DELTA_TRIE, storage_db::delta_db::DeltaDbTrait},
    errors::*,
};
use kvdb::KeyValueDB;
use std::sync::Arc;
