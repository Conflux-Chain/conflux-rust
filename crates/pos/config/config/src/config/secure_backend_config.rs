// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_secure_storage::{OnDiskStorage, Storage};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OnDiskStorageConfig {
    // Required path for on disk storage
    pub path: PathBuf,
    #[serde(skip)]
    data_dir: PathBuf,
}

impl Default for OnDiskStorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("secure_storage.json"),
            data_dir: PathBuf::from("/opt/diem/data"),
        }
    }
}

impl OnDiskStorageConfig {
    pub fn path(&self) -> PathBuf {
        if self.path.is_relative() {
            self.data_dir.join(&self.path)
        } else {
            self.path.clone()
        }
    }

    pub fn set_data_dir(&mut self, data_dir: PathBuf) {
        self.data_dir = data_dir;
    }
}

impl From<&OnDiskStorageConfig> for Storage {
    fn from(config: &OnDiskStorageConfig) -> Self {
        Storage::from(OnDiskStorage::new(config.path()))
    }
}
