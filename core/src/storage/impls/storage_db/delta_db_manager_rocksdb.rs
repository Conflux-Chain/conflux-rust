// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct DeltaDbManagerRocksdb {
    pub system_db: Arc<SystemDB>,
}

impl DeltaDbManagerRocksdb {
    pub fn new(system_db: Arc<SystemDB>) -> DeltaDbManagerRocksdb {
        Self { system_db }
    }
}

impl DeltaDbManagerTrait for DeltaDbManagerRocksdb {
    type DeltaDb = KvdbRocksdb;

    fn new_empty_delta_db(
        &self, _delta_db_name: &String,
    ) -> Result<Self::DeltaDb> {
        Ok(KvdbRocksdb {
            kvdb: self.system_db.key_value().clone(),
        })
    }

    fn get_delta_db(
        &self, _delta_db_name: &String,
    ) -> Result<Option<Self::DeltaDb>> {
        unimplemented!()
    }

    fn destroy_delta_db(&self, _delta_db_name: &String) -> Result<()> {
        // No-op
        Ok(())
    }
}

use super::{
    super::{
        super::storage_db::delta_db_manager::DeltaDbManagerTrait, errors::*,
    },
    kvdb_rocksdb::KvdbRocksdb,
};
use crate::ext_db::SystemDB;
use std::sync::Arc;
