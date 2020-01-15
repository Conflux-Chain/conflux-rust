// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct DeltaDbManagerSqlite {
    pub delta_db_path: String,
}

impl DeltaDbManagerSqlite {
    const DELTA_DB_SQLITE_DIR_PREFIX: &'static str = "sqlite_";
    const DELTA_DB_TABLE_NAME: &'static str = "delta_mpt";

    #[allow(unused)]
    pub fn new(_num_shards: u16, delta_db_path: String) -> Self {
        Self { delta_db_path }
    }

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

    fn get_delta_db_dir(&self) -> String { self.delta_db_path.clone() }

    fn get_delta_db_name(&self, snapshot_epoch_id: &EpochId) -> String {
        Self::DELTA_DB_SQLITE_DIR_PREFIX.to_string()
            + &snapshot_epoch_id.to_hex()
    }

    fn get_delta_db_path(&self, delta_db_name: &str) -> String {
        self.delta_db_path.clone() + delta_db_name
    }

    fn new_empty_delta_db(&self, delta_db_name: &str) -> Result<Self::DeltaDb> {
        KvdbSqlite::create_and_open(
            delta_db_name,
            Self::kvdb_sqlite_statements(),
            /* create_table = */ true,
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
use parity_bytes::ToPretty;
use primitives::EpochId;
use std::{fs::remove_file, sync::Arc};
