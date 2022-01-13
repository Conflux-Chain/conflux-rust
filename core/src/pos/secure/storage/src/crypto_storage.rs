// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::Error;
use diem_types::validator_config::{
    ConsensusPrivateKey, ConsensusPublicKey, ConsensusSignature,
};
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};

/// CryptoStorage provides an abstraction for secure generation and handling of
/// cryptographic keys.
#[enum_dispatch]
pub trait CryptoStorage {
    /// Securely generates a new named Consensus private key. The behavior for
    /// calling this interface multiple times with the same name is
    /// implementation specific.
    fn create_key(&mut self, name: &str) -> Result<ConsensusPublicKey, Error>;

    /// Returns the Consensus private key stored at 'name'.
    fn export_private_key(
        &self, name: &str,
    ) -> Result<ConsensusPrivateKey, Error>;

    /// An optional API that allows importing private keys and storing them at
    /// the provided name. This is not intended to be used in production and
    /// the API may throw unimplemented if not used correctly. As this is
    /// purely a testing API, there is no defined behavior for importing a
    /// key for a given name if that name already exists.  It only exists to
    /// allow Diem to be run in test environments where a set of
    /// deterministic keys must be generated.
    fn import_private_key(
        &mut self, name: &str, key: ConsensusPrivateKey,
    ) -> Result<(), Error>;

    /// Returns the Consensus private key stored at 'name' and identified by
    /// 'version', which is the corresponding public key. This may fail even
    /// if the 'named' key exists but the version is not present.
    fn export_private_key_for_version(
        &self, name: &str, version: ConsensusPublicKey,
    ) -> Result<ConsensusPrivateKey, Error>;

    /// Returns the Consensus public key stored at 'name'.
    fn get_public_key(&self, name: &str) -> Result<PublicKeyResponse, Error>;

    /// Returns the previous version of the Consensus public key stored at
    /// 'name'. For the most recent version, see 'get_public_key(..)' above.
    fn get_public_key_previous_version(
        &self, name: &str,
    ) -> Result<ConsensusPublicKey, Error>;

    /// Rotates an Consensus private key. Future calls without version to this
    /// 'named' key will return the rotated key instance. The previous key
    /// is retained and can be accessed via the version. At most two
    /// versions are expected to be retained.
    fn rotate_key(&mut self, name: &str) -> Result<ConsensusPublicKey, Error>;

    /// Signs the provided securely-hashable struct, using the 'named' private
    /// key.
    // The FQDNs on the next line help macros don't remove them
    fn sign<T: diem_crypto::hash::CryptoHash + serde::Serialize>(
        &self, name: &str, message: &T,
    ) -> Result<ConsensusSignature, Error>;

    /// Signs the provided securely-hashable struct, using the 'named' and
    /// 'versioned' private key. This may fail even if the 'named' key
    /// exists but the version is not present.
    // The FQDNs on the next line help macros, don't remove them
    fn sign_using_version<T: diem_crypto::hash::CryptoHash + serde::Serialize>(
        &self, name: &str, version: ConsensusPublicKey, message: &T,
    ) -> Result<ConsensusSignature, Error>;
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "data")]
pub struct PublicKeyResponse {
    /// Time since Unix Epoch in seconds.
    pub last_update: u64,
    /// ConsensusPublicKey stored at the provided key
    pub public_key: ConsensusPublicKey,
}
