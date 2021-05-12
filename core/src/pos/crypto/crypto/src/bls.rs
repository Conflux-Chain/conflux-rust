// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    hash::CryptoHash, CryptoMaterialError, PrivateKey, PublicKey, Signature,
    SigningKey, ValidCryptoMaterial, ValidCryptoMaterialStringExt,
    VerifyingKey,
};
use anyhow::Result;
use bls_signatures::{
    PrivateKey as RawPrivateKey, PublicKey as RawPublicKey,
    Serialize as BLSSerialize, Signature as RawSignature,
};
use diem_crypto_derive::{
    DeserializeKey, SerializeKey, SilentDebug, SilentDisplay,
};
use serde::Serialize;
use std::convert::TryFrom;

/// BLS signature private key
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
pub struct BLSPrivateKey(RawPrivateKey);

/// BLS signature public key
#[derive(DeserializeKey, Clone, SerializeKey, Debug, PartialEq)]
pub struct BLSPublicKey(RawPublicKey);

/// BLS signature wrapper
#[derive(DeserializeKey, Clone, SerializeKey, Debug, PartialEq)]
pub struct BLSSignature(RawSignature);

impl SigningKey for BLSPrivateKey {
    type SignatureMaterial = BLSSignature;
    type VerifyingKeyMaterial = BLSPublicKey;

    fn sign<T: CryptoHash + Serialize>(
        &self, message: &T,
    ) -> Self::SignatureMaterial {
        todo!()
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn sign_arbitrary_message(
        &self, message: &[u8],
    ) -> Self::SignatureMaterial {
        todo!()
    }
}

impl VerifyingKey for BLSPublicKey {
    type SignatureMaterial = BLSSignature;
    type SigningKeyMaterial = BLSPrivateKey;
}

impl PrivateKey for BLSPrivateKey {
    type PublicKeyMaterial = BLSPublicKey;
}

impl Signature for BLSSignature {
    type SigningKeyMaterial = BLSPrivateKey;
    type VerifyingKeyMaterial = BLSPublicKey;

    fn verify<T: CryptoHash + Serialize>(
        &self, message: &T, public_key: &Self::VerifyingKeyMaterial,
    ) -> Result<()> {
        todo!()
    }

    fn verify_arbitrary_msg(
        &self, message: &[u8], public_key: &Self::VerifyingKeyMaterial,
    ) -> Result<()> {
        todo!()
    }

    fn to_bytes(&self) -> Vec<u8> { todo!() }
}

impl PublicKey for BLSPublicKey {
    type PrivateKeyMaterial = BLSPrivateKey;
}

impl From<&BLSPrivateKey> for BLSPublicKey {
    fn from(private_key: &BLSPrivateKey) -> Self {
        BLSPublicKey(private_key.0.public_key())
    }
}

impl TryFrom<&[u8]> for BLSPrivateKey {
    type Error = CryptoMaterialError;

    /// Deserialize an BLSPrivateKey. This method will also check for key
    /// validity.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<BLSPrivateKey, CryptoMaterialError> {
        match RawPrivateKey::from_bytes(bytes) {
            Ok(sig) => Ok(Self(sig)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }
}

impl TryFrom<&[u8]> for BLSPublicKey {
    type Error = CryptoMaterialError;

    /// Deserialize an BLSPrivateKey. This method will also check for key
    /// validity.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<BLSPublicKey, CryptoMaterialError> {
        match RawPublicKey::from_bytes(bytes) {
            Ok(sig) => Ok(Self(sig)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }
}

impl TryFrom<&[u8]> for BLSSignature {
    type Error = CryptoMaterialError;

    /// Deserialize an BLSPrivateKey. This method will also check for key
    /// validity.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<BLSSignature, CryptoMaterialError> {
        // TODO(lpl): Check malleability?
        match RawSignature::from_bytes(bytes) {
            Ok(sig) => Ok(Self(sig)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }
}

impl std::hash::Hash for BLSPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = self.to_bytes();
        state.write(&encoded_pubkey);
    }
}

impl std::hash::Hash for BLSSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = ValidCryptoMaterial::to_bytes(self);
        state.write(&encoded_pubkey);
    }
}

impl Eq for BLSPublicKey {}

impl Eq for BLSSignature {}

impl ValidCryptoMaterial for BLSPrivateKey {
    fn to_bytes(&self) -> Vec<u8> { self.0.as_bytes() }
}

impl ValidCryptoMaterial for BLSPublicKey {
    fn to_bytes(&self) -> Vec<u8> { self.0.as_bytes() }
}

impl ValidCryptoMaterial for BLSSignature {
    fn to_bytes(&self) -> Vec<u8> { self.0.as_bytes() }
}
