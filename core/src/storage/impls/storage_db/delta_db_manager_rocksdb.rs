// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct DeltaDbManagerRocksdb {
    delta_db_path: PathBuf,
    creation_mutex: Mutex<()>,
}

impl DeltaDbManagerRocksdb {
    const DELTA_DB_ROCKSDB_DIR_PREFIX: &'static str = "rocksdb_";
    const ROCKSDB_CONFIG: DatabaseConfig = DatabaseConfig {
        max_open_files: 512,
        memory_budget: None,
        compaction: CompactionProfile {
            initial_file_size: 512 * 1048576 as u64,
            block_size: 16 * 1024,
            write_rate_limit: Some(64 * 1048576 as u64),
        },
        columns: 1,
        disable_wal: false,
    };

    pub fn new(delta_db_path: PathBuf) -> Result<DeltaDbManagerRocksdb> {
        if !delta_db_path.exists() {
            fs::create_dir_all(delta_db_path.clone())?;
        }

        Ok(Self {
            delta_db_path,
            creation_mutex: Default::default(),
        })
    }
}

impl DeltaDbManagerTrait for DeltaDbManagerRocksdb {
    type DeltaDb = KvdbRocksdb;

    fn get_delta_db_dir(&self) -> &Path { self.delta_db_path.as_path() }

    fn get_delta_db_name(&self, snapshot_epoch_id: &EpochId) -> String {
        Self::DELTA_DB_ROCKSDB_DIR_PREFIX.to_string()
            + &snapshot_epoch_id.to_hex()
    }

    fn get_delta_db_path(&self, delta_db_name: &str) -> PathBuf {
        self.delta_db_path.join(delta_db_name)
    }

    fn new_empty_delta_db(&self, delta_db_name: &str) -> Result<Self::DeltaDb> {
        let _lock = self.creation_mutex.lock();

        let path = self.get_delta_db_path(delta_db_name);
        if path.exists() {
            Err(ErrorKind::DeltaMPTAlreadyExists.into())
        } else {
            Ok(KvdbRocksdb {
                kvdb: Arc::new(Database::open(
                    &Self::ROCKSDB_CONFIG,
                    path.to_str().unwrap(),
                )?),
                col: 0,
            })
        }
    }

    fn get_delta_db(
        &self, delta_db_name: &str,
    ) -> Result<Option<Self::DeltaDb>> {
        let path = self.get_delta_db_path(delta_db_name);
        if path.exists() {
            Ok(Some(KvdbRocksdb {
                kvdb: Arc::new(Database::open(
                    &Self::ROCKSDB_CONFIG,
                    path.to_str().unwrap(),
                )?),
                col: 0,
            }))
        } else {
            Ok(None)
        }
    }

    fn destroy_delta_db(&self, delta_db_name: &str) -> Result<()> {
        Ok(fs::remove_dir_all(self.get_delta_db_path(delta_db_name))?)
    }
}

use super::{
    super::{
        super::storage_db::delta_db_manager::DeltaDbManagerTrait, errors::*,
    },
    kvdb_rocksdb::KvdbRocksdb,
};
use kvdb_rocksdb::{CompactionProfile, Database, DatabaseConfig};
use parity_bytes::ToPretty;
use parking_lot::Mutex;
use primitives::EpochId;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
