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

impl KvdbSqlite {
    fn get(&self, _key: &[u8]) -> Result<Option<Box<[u8]>>> {
        if self.empty && self.readonly {
            return Ok(None);
        }
        unimplemented!()
    }
}

impl DeltaDbTrait for KvdbSqlite {
    fn get(&self, key: &[u8]) -> Result<Option<Box<[u8]>>> { self.get(key) }
}

impl SnapshotDbTrait for KvdbSqlite {
    fn get(&self, key: &[u8]) -> Result<Option<Box<[u8]>>> { self.get(key) }
}

use super::super::{
    super::storage_db::{delta_db::DeltaDbTrait, snapshot_db::SnapshotDbTrait},
    errors::*,
};
