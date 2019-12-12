// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct DeltaDbManagerSqlite {}

impl DeltaDbManagerSqlite {
    const DELTA_DB_TABLE_NAME: &'static str = "delta_mpt";

    #[allow(unused)]
    pub fn new(_num_shards: u16) -> Self { Self {} }

    pub fn kvdb_sqlite_statements() -> Arc<KvdbSqliteStatements> {
        Arc::new(
            KvdbSqliteStatements::make_statements(
                &[&"value"],
                &[&"BLOB"],
                Self::DELTA_DB_TABLE_NAME,
                true,
            )
            .unwrap(),
        )
    }
}

impl DeltaDbManagerTrait for DeltaDbManagerSqlite {
    type DeltaDb = KvdbSqlite<Box<[u8]>>;

    fn new_empty_delta_db(&self, delta_db_name: &str) -> Result<Self::DeltaDb> {
        KvdbSqlite::create_and_open(
            delta_db_name,
            Self::kvdb_sqlite_statements(),
        )
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
use crate::storage::impls::storage_db::kvdb_sqlite::KvdbSqliteStatements;
use std::{fs::remove_file, sync::Arc};
