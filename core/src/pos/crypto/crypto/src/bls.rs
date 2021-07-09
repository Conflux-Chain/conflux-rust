// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    hash::{CryptoHash, CryptoHasher},
    CryptoMaterialError, PrivateKey, PublicKey, Signature, SigningKey, Uniform,
    ValidCryptoMaterial, ValidCryptoMaterialStringExt, VerifyingKey,
};
use anyhow::{anyhow, Result};
use bls_signatures::{
    hash as bls_hash, PrivateKey as RawPrivateKey, PublicKey as RawPublicKey,
    Serialize as BLSSerialize, Signature as RawSignature,
};
use diem_crypto_derive::{
    DeserializeKey, SerializeKey, SilentDebug, SilentDisplay,
};
use mirai_annotations::*;
use serde::Serialize;
use std::convert::TryFrom;

#[cfg(mirai)]
use crate::tags::ValidatedPublicKeyTag;
use std::fmt::{self, Formatter};

/// Private key length in bytes. The actual key length should be 255 bits.
pub const BLS_PRIVATE_KEY_LENGTH: usize = 32;

#[cfg(not(mirai))]
struct ValidatedPublicKeyTag {}

/// BLS signature private key
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
pub struct BLSPrivateKey(RawPrivateKey);

/// BLS signature public key
#[derive(DeserializeKey, Clone, SerializeKey, PartialEq)]
pub struct BLSPublicKey(RawPublicKey);

// TODO(lpl): Signature aggregation.
/// BLS signature wrapper
#[derive(DeserializeKey, Clone, SerializeKey, PartialEq)]
pub struct BLSSignature(RawSignature);

impl BLSPrivateKey {
    ///
    pub fn raw_key(self) -> RawPrivateKey { self.0 }
}

impl SigningKey for BLSPrivateKey {
    type SignatureMaterial = BLSSignature;
    type VerifyingKeyMaterial = BLSPublicKey;

    // FIXME(lpl): Append public key or rely on a proof in ElectionTransaction
    // to avoid attack?
    fn sign<T: CryptoHash + Serialize>(
        &self, message: &T,
    ) -> Self::SignatureMaterial {
        let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| CryptoMaterialError::SerializationError)
            .expect("Serialization of signable material should not fail.");
        BLSSignature(self.0.sign(bytes))
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn sign_arbitrary_message(
        &self, message: &[u8],
    ) -> Self::SignatureMaterial {
        BLSSignature(self.0.sign(message))
    }
}

impl From<RawPublicKey> for BLSPublicKey {
    fn from(raw: RawPublicKey) -> Self { BLSPublicKey(raw) }
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
        let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| CryptoMaterialError::SerializationError)?;
        self.verify_arbitrary_msg(&bytes, public_key)
    }

    fn verify_arbitrary_msg(
        &self, message: &[u8], public_key: &Self::VerifyingKeyMaterial,
    ) -> Result<()> {
        precondition!(has_tag!(public_key, ValidatedPublicKeyTag));
        match bls_signatures::verify(
            &self.0,
            std::slice::from_ref(&bls_hash(message)),
            std::slice::from_ref(&public_key.0),
        ) {
            true => Ok(()),
            false => Err(anyhow!("Invalid BLS signature!")),
        }
    }
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

impl fmt::Display for BLSPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_encoded_string().map_err(|_| fmt::Error)?)
    }
}

impl Uniform for BLSPrivateKey {
    fn generate<R>(rng: &mut R) -> Self
    where R: ::rand::RngCore + ::rand::CryptoRng {
        BLSPrivateKey(RawPrivateKey::generate(rng))
    }
}

impl fmt::Debug for BLSPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BLSPublicKey({})", self)
    }
}

impl fmt::Display for BLSSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_encoded_string().map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for BLSSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BLSSignature({})", self)
    }
}

mod test {
    use crate as diem_crypto;
    use crate::{
        bls::{BLSPrivateKey, BLSSignature},
        SigningKey, Uniform, ValidCryptoMaterial,
    };
    use diem_crypto_derive::{BCSCryptoHash, CryptoHasher};
    use serde::{Deserialize, Serialize};
    use std::{convert::TryFrom, time::Instant};

    #[derive(Debug, CryptoHasher, BCSCryptoHash, Serialize, Deserialize)]
    pub struct TestDiemCrypto(pub String);
    #[test]
    fn test_bls_sig_decode() {
        let sk = BLSPrivateKey::generate(&mut rand::thread_rng());
        let sig = sk.sign(&TestDiemCrypto("".to_string()));
        let sig_bytes = sig.to_bytes();
        let start = Instant::now();
        let _decoded = BLSSignature::try_from(sig_bytes.as_slice()).unwrap();
        println!("Time elapsed: {} us", start.elapsed().as_micros());
    }
}
