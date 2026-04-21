// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{CryptoKVStorage, Error, GetResponse, KVStorage};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

/// InMemoryStorage represents a key value store that is purely in memory and
/// intended for single threads (or must be wrapped by a Arc<RwLock<>>). This
/// provides no permission checks and simply is a proof of concept to unblock
/// building of applications without more complex data stores. Internally, it
/// retains all data, which means that it must make copies of all key material
/// which violates the Diem code base. It violates it because the anticipation
/// is that data stores would securely handle key material. This should not be
/// used in production.
#[derive(Default)]
pub struct InMemoryStorage {
    data: HashMap<String, Vec<u8>>,
}

impl InMemoryStorage {
    pub fn new() -> Self { Self::default() }
}

impl KVStorage for InMemoryStorage {
    fn available(&self) -> Result<(), Error> { Ok(()) }

    fn get<V: DeserializeOwned>(
        &self, key: &str,
    ) -> Result<GetResponse<V>, Error> {
        let response = self
            .data
            .get(key)
            .ok_or_else(|| Error::KeyNotSet(key.to_string()))?;

        serde_json::from_slice(&response).map_err(|e| e.into())
    }

    fn set<V: Serialize>(&mut self, key: &str, value: V) -> Result<(), Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time is before UNIX_EPOCH")
            .as_secs();
        self.data.insert(
            key.to_string(),
            serde_json::to_vec(&GetResponse::new(value, now))?,
        );
        Ok(())
    }

    #[cfg(any(test, feature = "testing"))]
    fn reset_and_clear(&mut self) -> Result<(), Error> {
        self.data.clear();
        Ok(())
    }
}

impl CryptoKVStorage for InMemoryStorage {}
