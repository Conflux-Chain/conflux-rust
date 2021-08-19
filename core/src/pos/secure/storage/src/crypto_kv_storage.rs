// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{CryptoStorage, Error, KVStorage, PublicKeyResponse};
use diem_crypto::{hash::CryptoHash, PrivateKey, SigningKey, Uniform};
use diem_types::validator_config::{
    ConsensusPrivateKey, ConsensusPublicKey, ConsensusSignature,
};
use rand::{rngs::OsRng, Rng, SeedableRng};
use serde::ser::Serialize;

/// CryptoKVStorage offers a CryptoStorage implementation by extending a key
/// value store (KVStorage) to create and manage cryptographic keys. This is
/// useful for providing a simple CryptoStorage implementation based upon an
/// existing KVStorage engine (e.g. for test purposes).
pub trait CryptoKVStorage: KVStorage {}

impl<T: CryptoKVStorage> CryptoStorage for T {
    fn create_key(&mut self, name: &str) -> Result<ConsensusPublicKey, Error> {
        // Generate and store the new named key pair
        let (private_key, public_key) = new_key_pair::<ConsensusPrivateKey>();
        self.import_private_key(name, private_key)?;
        Ok(public_key)
    }

    fn export_private_key(
        &self, name: &str,
    ) -> Result<ConsensusPrivateKey, Error> {
        self.get(name).map(|v| v.value)
    }

    fn export_private_key_for_version(
        &self, name: &str, version: ConsensusPublicKey,
    ) -> Result<ConsensusPrivateKey, Error> {
        let current_private_key = self.export_private_key(name)?;
        if current_private_key.public_key().eq(&version) {
            return Ok(current_private_key);
        }

        match self.export_private_key(&get_previous_version_name(name)) {
            Ok(previous_private_key) => {
                if previous_private_key.public_key().eq(&version) {
                    Ok(previous_private_key)
                } else {
                    Err(Error::KeyVersionNotFound(
                        name.into(),
                        version.to_string(),
                    ))
                }
            }
            Err(Error::KeyNotSet(_)) => {
                Err(Error::KeyVersionNotFound(name.into(), version.to_string()))
            }
            Err(e) => Err(e),
        }
    }

    fn import_private_key(
        &mut self, name: &str, key: ConsensusPrivateKey,
    ) -> Result<(), Error> {
        self.set(name, key)
    }

    fn get_public_key(&self, name: &str) -> Result<PublicKeyResponse, Error> {
        let response = self.get(name)?;
        let key: ConsensusPrivateKey = response.value;

        Ok(PublicKeyResponse {
            last_update: response.last_update,
            public_key: key.public_key(),
        })
    }

    fn get_public_key_previous_version(
        &self, name: &str,
    ) -> Result<ConsensusPublicKey, Error> {
        match self.export_private_key(&get_previous_version_name(name)) {
            Ok(previous_private_key) => Ok(previous_private_key.public_key()),
            Err(Error::KeyNotSet(_)) => Err(Error::KeyVersionNotFound(
                name.into(),
                "previous version".into(),
            )),
            Err(e) => Err(e),
        }
    }

    fn rotate_key(&mut self, name: &str) -> Result<ConsensusPublicKey, Error> {
        let private_key: ConsensusPrivateKey = self.get(name)?.value;
        let (new_private_key, new_public_key) =
            new_key_pair::<ConsensusPrivateKey>();
        self.set(&get_previous_version_name(name), private_key)?;
        self.set(name, new_private_key)?;
        Ok(new_public_key)
    }

    fn sign<U: CryptoHash + Serialize>(
        &self, name: &str, message: &U,
    ) -> Result<ConsensusSignature, Error> {
        let private_key = self.export_private_key(name)?;
        Ok(private_key.sign(message))
    }

    fn sign_using_version<U: CryptoHash + Serialize>(
        &self, name: &str, version: ConsensusPublicKey, message: &U,
    ) -> Result<ConsensusSignature, Error> {
        let private_key = self.export_private_key_for_version(name, version)?;
        Ok(private_key.sign(message))
    }
}

fn new_key_pair<SK: SigningKey + Uniform>() -> (SK, SK::PublicKeyMaterial) {
    let mut seed_rng = OsRng;
    let mut rng = rand::rngs::StdRng::from_seed(seed_rng.gen());
    let private_key = SK::generate(&mut rng);
    let public_key = private_key.public_key();
    (private_key, public_key)
}

/// Private helper method to get the name of the previous version of the given
/// key pair, as held in secure cryptographic storage.
fn get_previous_version_name(name: &str) -> String {
    format!("{}_previous", name)
}
