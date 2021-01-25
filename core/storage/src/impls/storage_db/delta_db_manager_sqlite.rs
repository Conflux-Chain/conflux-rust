// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct DeltaDbManagerSqlite {
    num_shards: u16,
    delta_db_path: PathBuf,
    creation_mutex: Mutex<()>,
}

impl DeltaDbManagerSqlite {
    #[allow(unused)]
    pub const DB_SHARDS: u16 = 32;
    const DELTA_DB_SQLITE_DIR_PREFIX: &'static str = "sqlite_";
    const DELTA_DB_TABLE_NAME: &'static str = "delta_mpt";

    #[allow(unused)]
    pub fn new(num_shards: u16, delta_db_path: PathBuf) -> Result<Self> {
        if !delta_db_path.exists() {
            fs::create_dir_all(delta_db_path.clone())?;
        }

        Ok(Self {
            num_shards,
            delta_db_path,
            creation_mutex: Default::default(),
        })
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
    type DeltaDb = KvdbSqliteSharded<Box<[u8]>>;

    fn get_delta_db_dir(&self) -> &Path { self.delta_db_path.as_path() }

    fn get_delta_db_name(&self, snapshot_epoch_id: &EpochId) -> String {
        Self::DELTA_DB_SQLITE_DIR_PREFIX.to_string()
            + &snapshot_epoch_id.as_ref().to_hex::<String>()
    }

    fn get_delta_db_path(&self, delta_db_name: &str) -> PathBuf {
        self.delta_db_path.join(delta_db_name)
    }

    fn new_empty_delta_db(&self, delta_db_name: &str) -> Result<Self::DeltaDb> {
        let _lock = self.creation_mutex.lock();

        let path_str = self.get_delta_db_path(delta_db_name);
        if Path::new(&path_str).exists() {
            Err(ErrorKind::DeltaMPTAlreadyExists.into())
        } else {
            fs::create_dir_all(&path_str).ok();
            KvdbSqliteSharded::create_and_open(
                self.num_shards,
                path_str,
                Self::kvdb_sqlite_statements(),
                /* create_table = */ true,
                /* unsafe_mode = */ false,
            )
        }
    }

    fn get_delta_db(
        &self, delta_db_name: &str,
    ) -> Result<Option<Self::DeltaDb>> {
        let path_str = self.get_delta_db_path(delta_db_name);
        if Path::new(&path_str).exists() {
            Ok(Some(KvdbSqliteSharded::open(
                self.num_shards,
                delta_db_name,
                /* readonly = */ false,
                Self::kvdb_sqlite_statements(),
            )?))
        } else {
            Ok(None)
        }
    }

    fn destroy_delta_db(&self, delta_db_name: &str) -> Result<()> {
        Ok(fs::remove_dir_all(self.get_delta_db_path(delta_db_name))?)
    }
}

use crate::{
    impls::{
        errors::*,
        storage_db::{
            kvdb_sqlite::KvdbSqliteStatements,
            kvdb_sqlite_sharded::KvdbSqliteSharded,
        },
    },
    storage_db::delta_db_manager::DeltaDbManagerTrait,
};
use parking_lot::Mutex;
use primitives::EpochId;
use rustc_hex::ToHex;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
