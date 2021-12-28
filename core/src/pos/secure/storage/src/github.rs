// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{CryptoKVStorage, Error, GetResponse, KVStorage};
use diem_github_client::Client;
use diem_time_service::{TimeService, TimeServiceTrait};
use serde::{de::DeserializeOwned, Serialize};

/// GitHubStorage leverages a GitHub repository to provide a file system
/// approach to key / value storage.  This is not intended for storing private
/// data but for organizing public data.
pub struct GitHubStorage {
    client: Client,
    time_service: TimeService,
}

impl GitHubStorage {
    pub fn new(
        owner: String, repository: String, branch: String, token: String,
    ) -> Self {
        Self {
            client: Client::new(owner, repository, branch, token),
            time_service: TimeService::real(),
        }
    }
}

impl KVStorage for GitHubStorage {
    fn available(&self) -> Result<(), Error> {
        if !self.client.get_branches()?.is_empty() {
            Ok(())
        } else {
            Err(Error::InternalError("No branches found.".into()))
        }
    }

    fn get<T: DeserializeOwned>(
        &self, key: &str,
    ) -> Result<GetResponse<T>, Error> {
        let data = self.client.get_file(key)?;
        let data = base64::decode(&data)?;
        let data = std::str::from_utf8(&data).map_err(|e| {
            Error::InternalError(format!(
                "Unparseable data: {:?}\n returned from Github KV Storage, met Error:{}",
                data, e
            ))
        })?;
        serde_json::from_str(&data).map_err(|e| e.into())
    }

    fn set<T: Serialize>(&mut self, key: &str, value: T) -> Result<(), Error> {
        let now = self.time_service.now_secs();
        let data = GetResponse::new(value, now);
        let data = serde_json::to_string(&data)?;
        let data = base64::encode(&data);
        self.client.put(key, &data)?;
        Ok(())
    }

    #[cfg(any(test, feature = "testing"))]
    fn reset_and_clear(&mut self) -> Result<(), Error> {
        self.client.delete_directory("/").map_err(|e| e.into())
    }
}

impl CryptoKVStorage for GitHubStorage {}
