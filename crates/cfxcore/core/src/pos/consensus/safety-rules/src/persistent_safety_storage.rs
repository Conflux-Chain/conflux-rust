// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    counters,
    logging::{self, LogEntry, LogEvent},
    Error,
};
use consensus_types::{common::Author, safety_data::SafetyData};
use diem_crypto::{
    hash::CryptoHash, PrivateKey, SigningKey, ValidCryptoMaterial,
};
use diem_global_constants::{
    CONSENSUS_KEY, EXECUTION_KEY, OWNER_ACCOUNT, SAFETY_DATA, WAYPOINT,
};
use diem_logger::prelude::*;
use diem_secure_storage::{CryptoStorage, KVStorage, OnDiskStorage, Storage};
use diem_types::{
    validator_config::{
        ConsensusPrivateKey, ConsensusPublicKey, ConsensusSignature,
    },
    waypoint::Waypoint,
};
use serde::Serialize;
use std::{convert::TryFrom, fs};

/// SafetyRules needs an abstract storage interface to act as a common utility
/// for storing persistent data to local disk, cloud, secrets managers, or even
/// memory (for tests) Any set function is expected to sync to the remote system
/// before returning.
///
/// Note: cached_safety_data is a local in-memory copy of SafetyData. As
/// SafetyData should only ever be used by safety rules, we maintain an
/// in-memory copy to avoid issuing reads to the internal storage if the
/// SafetyData hasn't changed. On writes, we update the cache and internal
/// storage.
pub struct PersistentSafetyStorage {
    enable_cached_safety_data: bool,
    cached_safety_data: Option<SafetyData>,
    internal_store: Storage,
    private_key: ConsensusPrivateKey,
}

impl PersistentSafetyStorage {
    /// Use this to instantiate a PersistentStorage for a new data store, one
    /// that has no SafetyRules values set.
    pub fn initialize(
        mut internal_store: Storage, author: Author,
        private_key: ConsensusPrivateKey, waypoint: Waypoint,
        enable_cached_safety_data: bool,
    ) -> Self {
        let geneisis_safety_data = SafetyData::new(1, 0, 0, None);
        let safety_data = Self::initialize_(
            &mut internal_store,
            geneisis_safety_data,
            author,
            waypoint,
        )
        .expect("Unable to initialize backend storage");

        Self {
            enable_cached_safety_data,
            cached_safety_data: Some(safety_data),
            internal_store,
            private_key,
        }
    }

    pub fn replace_with_suffix(
        &mut self, new_storage_suffix: &str,
    ) -> Result<(), Error> {
        match &mut self.internal_store {
            Storage::OnDiskStorage(disk_storage) => {
                let new_path =
                    disk_storage.file_path().with_extension(new_storage_suffix);
                if !new_path.exists() {
                    return Err(Error::SecureStorageUnexpectedError(format!(
                        "new secure storage path incorrect: {:?}",
                        new_path
                    )));
                }
                let new_disk_storage = OnDiskStorage::new(new_path.clone());
                let old_account: Author =
                    disk_storage.get(OWNER_ACCOUNT)?.value;
                let new_account: Author =
                    new_disk_storage.get(OWNER_ACCOUNT)?.value;
                if old_account != new_account {
                    return Err(Error::SecureStorageUnexpectedError(format!(
                        "current: {}, new: {}",
                        old_account, new_account
                    )));
                }
                // Replace the old secure storage file with the new one.
                fs::rename(&new_path, disk_storage.file_path())
                    .map_err(|e| Error::InternalError(e.to_string()))?;
                // Just replacing file should be sufficient. We create a new
                // instance here in case we have any cached data
                // within `OnDiskStorage` in future.
                *disk_storage =
                    OnDiskStorage::new(disk_storage.file_path().clone());
                self.cached_safety_data = disk_storage.get(SAFETY_DATA)?.value;
                Ok(())
            }
            _ => Err(Error::InternalError(
                "unsupported secure storage type".to_string(),
            )),
        }
    }

    pub fn save_to_suffix(
        &mut self, new_storage_suffix: &str,
    ) -> Result<(), Error> {
        match &self.internal_store {
            Storage::OnDiskStorage(disk_storage) => {
                let new_path =
                    disk_storage.file_path().with_extension(new_storage_suffix);
                fs::rename(disk_storage.file_path(), &new_path)
                    .map_err(|e| Error::InternalError(e.to_string()))?;
                Ok(())
            }
            _ => Err(Error::InternalError(
                "unsupported secure storage type".to_string(),
            )),
        }
    }

    fn initialize_(
        internal_store: &mut Storage, safety_data: SafetyData, author: Author,
        waypoint: Waypoint,
    ) -> Result<SafetyData, Error> {
        // Attempting to re-initialize existing storage. This can happen in
        // environments like cluster test. Rather than be rigid here,
        // leave it up to the developer to detect inconsistencies or why
        // they did not reset storage between rounds. Do not repeat the
        // checks again below, because it is just too strange to have a
        // partially configured storage.
        // NOTE: If the key exists, `OnDiskStorage` does not return error
        // when we `set` the value, so we need to `get` first here.
        if let Ok(safety_data) = internal_store.get::<SafetyData>(SAFETY_DATA) {
            diem_warn!("Attempted to re-initialize existing storage");
            return Ok(safety_data.value);
        }

        internal_store.set(SAFETY_DATA, safety_data.clone())?;
        internal_store.set(OWNER_ACCOUNT, author)?;
        internal_store.set(WAYPOINT, waypoint)?;
        Ok(safety_data)
    }

    pub fn author(&self) -> Result<Author, Error> {
        let _timer = counters::start_timer("get", OWNER_ACCOUNT);
        Ok(self.internal_store.get(OWNER_ACCOUNT).map(|v| v.value)?)
    }

    pub fn consensus_key_for_version(
        &self, version: ConsensusPublicKey,
    ) -> Result<ConsensusPrivateKey, Error> {
        let _timer = counters::start_timer("get", CONSENSUS_KEY);
        if self.private_key.public_key() == version {
            let serialized: &[u8] = &(self.private_key.to_bytes());
            let cloned = ConsensusPrivateKey::try_from(serialized).unwrap();
            Ok(cloned)
        } else {
            Ok(self
                .internal_store
                .export_private_key_for_version(CONSENSUS_KEY, version)?)
        }
    }

    pub fn sign<T: Serialize + CryptoHash>(
        &self, key_name: String, key_version: ConsensusPublicKey, message: &T,
    ) -> Result<ConsensusSignature, Error> {
        if key_name == CONSENSUS_KEY || key_name == EXECUTION_KEY {
            Ok(self.private_key.sign(message))
        } else {
            Ok(self.internal_store.sign_using_version(
                &key_name,
                key_version,
                message,
            )?)
        }
    }

    pub fn safety_data(&mut self) -> Result<SafetyData, Error> {
        if !self.enable_cached_safety_data {
            let _timer = counters::start_timer("get", SAFETY_DATA);
            return self.internal_store.get(SAFETY_DATA).map(|v| v.value)?;
        }

        if let Some(cached_safety_data) = self.cached_safety_data.clone() {
            Ok(cached_safety_data)
        } else {
            let _timer = counters::start_timer("get", SAFETY_DATA);
            let safety_data: SafetyData =
                self.internal_store.get(SAFETY_DATA).map(|v| v.value)?;
            self.cached_safety_data = Some(safety_data.clone());
            Ok(safety_data)
        }
    }

    pub fn set_safety_data(&mut self, data: SafetyData) -> Result<(), Error> {
        let _timer = counters::start_timer("set", SAFETY_DATA);
        counters::set_state("epoch", data.epoch as i64);
        counters::set_state("last_voted_round", data.last_voted_round as i64);
        counters::set_state("preferred_round", data.preferred_round as i64);

        match self.internal_store.set(SAFETY_DATA, data.clone()) {
            Ok(_) => {
                self.cached_safety_data = Some(data);
                Ok(())
            }
            Err(error) => {
                self.cached_safety_data = None;
                Err(Error::SecureStorageUnexpectedError(error.to_string()))
            }
        }
    }

    pub fn waypoint(&self) -> Result<Waypoint, Error> {
        let _timer = counters::start_timer("get", WAYPOINT);
        Ok(self.internal_store.get(WAYPOINT).map(|v| v.value)?)
    }

    pub fn set_waypoint(&mut self, waypoint: &Waypoint) -> Result<(), Error> {
        let _timer = counters::start_timer("set", WAYPOINT);
        self.internal_store.set(WAYPOINT, waypoint)?;
        diem_info!(logging::SafetyLogSchema::new(
            LogEntry::Waypoint,
            LogEvent::Update
        )
        .waypoint(*waypoint));
        Ok(())
    }

    #[cfg(any(test, feature = "testing"))]
    pub fn internal_store(&mut self) -> &mut Storage {
        &mut self.internal_store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diem_secure_storage::InMemoryStorage;
    use diem_types::validator_signer::ValidatorSigner;

    #[test]
    fn test() {
        let consensus_private_key =
            ValidatorSigner::from_int(0).private_key().clone();
        let storage = Storage::from(InMemoryStorage::new());
        let mut safety_storage = PersistentSafetyStorage::initialize(
            storage,
            Author::random(),
            consensus_private_key,
            Waypoint::default(),
            true,
        );

        let safety_data = safety_storage.safety_data().unwrap();
        assert_eq!(safety_data.epoch, 1);
        assert_eq!(safety_data.last_voted_round, 0);
        assert_eq!(safety_data.preferred_round, 0);

        safety_storage
            .set_safety_data(SafetyData::new(9, 8, 1, None))
            .unwrap();

        let safety_data = safety_storage.safety_data().unwrap();
        assert_eq!(safety_data.epoch, 9);
        assert_eq!(safety_data.last_voted_round, 8);
        assert_eq!(safety_data.preferred_round, 1);
    }
}
