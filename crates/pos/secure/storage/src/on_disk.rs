// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{CryptoKVStorage, Error, GetResponse, KVStorage};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// A key-value store persisted to a single JSON file.
///
/// The file is the source of truth: `get` reads it on every call and `set`
/// rewrites it atomically (temp file + rename). Callers that need a fast
/// per-read path cache one layer up (see
/// `PersistentSafetyStorage::cached_safety_data`).
///
/// Tradeoffs inherited from Diem's non-Vault path:
/// - No OS-level permission gating — relies on the file's Unix permissions.
/// - Key material is held in plaintext in process memory — not an HSM.
///
/// Not thread-safe on its own; callers wrap it in `Arc<RwLock<_>>`.
pub struct OnDiskStorage {
    file_path: PathBuf,
}

impl OnDiskStorage {
    pub fn new(file_path: PathBuf) -> Self {
        if !file_path.exists() {
            File::create(&file_path).expect("Unable to create storage");
        }
        Self { file_path }
    }

    pub fn file_path(&self) -> &PathBuf { &self.file_path }

    fn read(&self) -> Result<HashMap<String, Value>, Error> {
        let mut file = File::open(&self.file_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        if contents.is_empty() {
            return Ok(HashMap::new());
        }
        Ok(serde_json::from_str(&contents)?)
    }

    fn write(&self, data: &HashMap<String, Value>) -> Result<(), Error> {
        let contents = serde_json::to_vec(data)?;
        let dir = self.file_path.parent().unwrap_or_else(|| Path::new("."));
        let mut temp = tempfile::Builder::new().tempfile_in(dir)?;
        temp.write_all(&contents)?;
        temp.persist(&self.file_path)
            .map_err(|e| Error::from(e.error))?;
        Ok(())
    }
}

impl KVStorage for OnDiskStorage {
    fn available(&self) -> Result<(), Error> { Ok(()) }

    fn get<V: DeserializeOwned>(
        &self, key: &str,
    ) -> Result<GetResponse<V>, Error> {
        let mut data = self.read()?;
        data.remove(key)
            .ok_or_else(|| Error::KeyNotSet(key.to_string()))
            .and_then(|value| {
                serde_json::from_value(value).map_err(|e| e.into())
            })
    }

    fn set<V: Serialize>(&mut self, key: &str, value: V) -> Result<(), Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time is before UNIX_EPOCH")
            .as_secs();
        let mut data = self.read()?;
        data.insert(
            key.to_string(),
            serde_json::to_value(&GetResponse::new(value, now))?,
        );
        self.write(&data)
    }

    #[cfg(any(test, feature = "testing"))]
    fn reset_and_clear(&mut self) -> Result<(), Error> {
        self.write(&HashMap::new())
    }
}

impl CryptoKVStorage for OnDiskStorage {}
