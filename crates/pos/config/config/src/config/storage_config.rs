// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Port selected RocksDB options for tuning underlying rocksdb instance of
/// DiemDB. see <https://github.com/facebook/rocksdb/blob/master/include/rocksdb/options.h>
/// for detailed explanations.
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RocksdbConfig {
    pub max_open_files: i32,
    pub max_total_wal_size: u64,
}

impl Default for RocksdbConfig {
    fn default() -> Self {
        Self {
            // Set max_open_files to 10k instead of -1 to avoid keep-growing memory in accordance
            // with the number of files.
            max_open_files: 10_000,
            // For now we set the max total WAL size to be 1G. This config can be useful when column
            // families are updated at non-uniform frequencies.
            #[allow(clippy::integer_arithmetic)] // TODO: remove once clippy lint fixed
            max_total_wal_size: 1u64 << 30,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub dir: PathBuf,
    #[serde(skip)]
    data_dir: PathBuf,
    /// Rocksdb-specific configurations
    pub rocksdb_config: RocksdbConfig,
}

impl Default for StorageConfig {
    fn default() -> StorageConfig {
        StorageConfig {
            dir: PathBuf::from("db"),
            data_dir: PathBuf::from("./pos_db"),
            rocksdb_config: RocksdbConfig::default(),
        }
    }
}

impl StorageConfig {
    pub fn dir(&self) -> PathBuf {
        if self.dir.is_relative() {
            self.data_dir.join(&self.dir)
        } else {
            self.dir.clone()
        }
    }

    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.data_dir = data_dir;
    }
}
