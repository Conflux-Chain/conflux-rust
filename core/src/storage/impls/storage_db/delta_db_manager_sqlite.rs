// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct DeltaDbManagerSqlite {}

impl DeltaDbManagerSqlite {
    const DELTA_DB_TABLE_NAME: &'static str = "delta_mpt";

    #[allow(unused)]
    pub fn new(_num_shards: u16) -> Self { Self {} }
}

impl DeltaDbManagerTrait for DeltaDbManagerSqlite {
    type DeltaDb = KvdbSqlite;

    fn new_empty_delta_db(&self, delta_db_name: &str) -> Result<Self::DeltaDb> {
        KvdbSqlite::create_and_open(delta_db_name, Self::DELTA_DB_TABLE_NAME)
    }

    fn get_delta_db(
        &self, _delta_db_name: &str,
    ) -> Result<Option<Self::DeltaDb>> {
        unimplemented!()
    }

    fn destroy_delta_db(&self, delta_db_name: &str) -> Result<()> {
        Ok(remove_file(delta_db_name)?)
    }
}

use super::{
    super::{
        super::storage_db::delta_db_manager::DeltaDbManagerTrait, errors::*,
    },
    kvdb_sqlite::KvdbSqlite,
};
use std::fs::remove_file;
