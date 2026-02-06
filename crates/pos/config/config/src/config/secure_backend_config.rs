// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use diem_secure_storage::{
    InMemoryStorage, NamespacedStorage, OnDiskStorage, Storage,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum SecureBackend {
    InMemoryStorage,
    OnDiskStorage(OnDiskStorageConfig),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OnDiskStorageConfig {
    // Required path for on disk storage
    pub path: PathBuf,
    /// A namespace is an optional portion of the path to a key stored within
    /// OnDiskStorage. For example, a key, S, without a namespace would be
    /// available in S, with a namespace, N, it would be in N/S.
    pub namespace: Option<String>,
    #[serde(skip)]
    data_dir: PathBuf,
}

impl Default for OnDiskStorageConfig {
    fn default() -> Self {
        Self {
            namespace: None,
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

impl From<&SecureBackend> for Storage {
    fn from(backend: &SecureBackend) -> Self {
        match backend {
            SecureBackend::InMemoryStorage => {
                Storage::from(InMemoryStorage::new())
            }
            SecureBackend::OnDiskStorage(config) => {
                let storage = Storage::from(OnDiskStorage::new(config.path()));
                if let Some(namespace) = &config.namespace {
                    Storage::from(NamespacedStorage::new(
                        storage,
                        namespace.clone(),
                    ))
                } else {
                    storage
                }
            }
        }
    }
}
