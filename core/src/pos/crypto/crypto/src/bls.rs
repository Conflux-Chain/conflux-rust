// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    hash::{CryptoHash, CryptoHasher},
    traits::*,
    CryptoMaterialError, PrivateKey, PublicKey, Signature, SigningKey, Uniform,
    ValidCryptoMaterial, ValidCryptoMaterialStringExt, VerifyingKey,
};
use anyhow::{anyhow, Result};
use bls_signatures::{
    DeserializeUnchecked, PrivateKey as RawPrivateKey,
    PublicKey as RawPublicKey, Serialize as BLSSerialize,
    Signature as RawSignature,
};
use diem_crypto_derive::{
    DeserializeKey, SerializeKey, SilentDebug, SilentDisplay,
};
use diem_logger::prelude::*;
use mirai_annotations::*;
use serde::{Deserialize, Deserializer, Serialize};
use std::convert::TryFrom;

#[cfg(mirai)]
use crate::tags::ValidatedPublicKeyTag;
use std::fmt::{self, Formatter};

/// Private key length in bytes. The actual key length should be 255 bits.
pub const BLS_PRIVATE_KEY_LENGTH: usize = 32;
/// Public key length in bytes.
pub const BLS_PUBLIC_KEY_LENGTH: usize = 48;
/// Signature length in bytes.
pub const BLS_SIGNATURE_LENGTH: usize = 96;

#[cfg(not(mirai))]
struct ValidatedPublicKeyTag {}

/// BLS signature private key
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
pub struct BLSPrivateKey(RawPrivateKey);

#[cfg(feature = "assert-private-keys-not-cloneable")]
static_assertions::assert_not_impl_any!(BLSPrivateKey: Clone);

#[cfg(any(test, feature = "cloneable-private-keys"))]
impl Clone for BLSPrivateKey {
    fn clone(&self) -> Self {
        let serialized: &[u8] = &(self.to_bytes());
        BLSPrivateKey::try_from(serialized).unwrap()
    }
}

/// BLS signature public key
#[derive(DeserializeKey, Clone, SerializeKey)]
pub struct BLSPublicKey(RawPublicKey);

// TODO(lpl): Signature aggregation.
/// BLS signature wrapper
#[derive(DeserializeKey, Clone, SerializeKey)]
pub struct BLSSignature(RawSignature);

impl BLSPrivateKey {
    ///
    pub fn raw_key(self) -> RawPrivateKey { self.0 }
}

impl PartialEq<Self> for BLSPrivateKey {
    fn eq(&self, other: &Self) -> bool { self.to_bytes() == other.to_bytes() }
}

impl Eq for BLSPrivateKey {}

impl SigningKey for BLSPrivateKey {
    type SignatureMaterial = BLSSignature;
    type VerifyingKeyMaterial = BLSPublicKey;

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

impl BLSPublicKey {
    /// return raw public key
    pub fn raw(self) -> RawPublicKey { self.0 }
}

impl BLSSignature {
    /// return an all-zero signature (for test only)
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn dummy_signature() -> Self {
        let bytes = [0u8; BLS_SIGNATURE_LENGTH];
        Self::try_from(&bytes[..]).unwrap()
    }

    /// return raw signature
    pub fn raw(self) -> RawSignature { self.0 }
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
        match bls_signatures::verify_messages(
            &self.0,
            std::slice::from_ref(&message),
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

impl From<&RawPrivateKey> for BLSPrivateKey {
    fn from(raw_private_key: &RawPrivateKey) -> Self {
        BLSPrivateKey(*raw_private_key)
    }
}

impl From<RawPrivateKey> for BLSPrivateKey {
    fn from(raw_private_key: RawPrivateKey) -> Self {
        BLSPrivateKey(raw_private_key)
    }
}

impl From<&RawSignature> for BLSSignature {
    fn from(raw_signature: &RawSignature) -> Self {
        BLSSignature(*raw_signature)
    }
}

impl From<RawSignature> for BLSSignature {
    fn from(raw_signature: RawSignature) -> Self { BLSSignature(raw_signature) }
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
        match RawPublicKey::from_bytes_unchecked(bytes) {
            Ok(sig) => Ok(Self(sig)),
            Err(e) => {
                diem_debug!(
                    "BLSPublicKey debug error: bytes={:?}, err={:?}",
                    bytes,
                    e
                );
                Err(CryptoMaterialError::DeserializationError)
            }
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
        match RawSignature::from_bytes_unchecked(bytes) {
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

impl PartialEq for BLSPublicKey {
    fn eq(&self, other: &BLSPublicKey) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl std::hash::Hash for BLSSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = ValidCryptoMaterial::to_bytes(self);
        state.write(&encoded_pubkey);
    }
}

impl PartialEq for BLSSignature {
    fn eq(&self, other: &BLSSignature) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for BLSPublicKey {}

impl Eq for BLSSignature {}

impl ValidCryptoMaterial for BLSPrivateKey {
    fn to_bytes(&self) -> Vec<u8> { self.0.as_bytes() }
}

impl Genesis for BLSPrivateKey {
    fn genesis() -> Self {
        let mut buf = [0u8; BLS_PRIVATE_KEY_LENGTH];
        buf[BLS_PRIVATE_KEY_LENGTH - 1] = 1;
        Self::try_from(buf.as_ref()).unwrap()
    }
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

/// Used to deserialize keys in local storage whose validity has been checked
/// before.
#[derive(SerializeKey, DeserializeKey)]
pub struct BLSPublicKeyUnchecked(RawPublicKey);
/// Used to deserialize keys in local storage whose validity has been checked
/// before.
#[derive(SerializeKey, DeserializeKey)]
pub struct BLSSignatureUnchecked(RawSignature);

impl TryFrom<&[u8]> for BLSPublicKeyUnchecked {
    type Error = CryptoMaterialError;

    /// Deserialize an BLSPrivateKey. This method will also check for key
    /// validity.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<BLSPublicKeyUnchecked, CryptoMaterialError> {
        match RawPublicKey::from_bytes_unchecked(bytes) {
            Ok(sig) => Ok(Self(sig)),
            Err(e) => {
                diem_debug!(
                    "BLSPublicKey debug error: bytes={:?}, err={:?}",
                    bytes,
                    e
                );
                Err(CryptoMaterialError::DeserializationError)
            }
        }
    }
}

impl TryFrom<&[u8]> for BLSSignatureUnchecked {
    type Error = CryptoMaterialError;

    /// Deserialize an BLSPrivateKey. This method will also check for key
    /// validity.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<BLSSignatureUnchecked, CryptoMaterialError> {
        // TODO(lpl): Check malleability?
        match RawSignature::from_bytes_unchecked(bytes) {
            Ok(sig) => Ok(Self(sig)),
            Err(_) => Err(CryptoMaterialError::DeserializationError),
        }
    }
}

impl ValidCryptoMaterial for BLSPublicKeyUnchecked {
    fn to_bytes(&self) -> Vec<u8> { self.0.as_bytes() }
}

impl ValidCryptoMaterial for BLSSignatureUnchecked {
    fn to_bytes(&self) -> Vec<u8> { self.0.as_bytes() }
}

impl From<BLSPublicKeyUnchecked> for BLSPublicKey {
    fn from(unchecked: BLSPublicKeyUnchecked) -> Self { Self(unchecked.0) }
}

impl From<BLSSignatureUnchecked> for BLSSignature {
    fn from(unchecked: BLSSignatureUnchecked) -> Self { Self(unchecked.0) }
}

/// Deserialize public key from local storage.
pub fn deserialize_bls_public_key_unchecked<'de, D>(
    deserializer: D,
) -> Result<BLSPublicKey, D::Error>
where D: Deserializer<'de> {
    BLSPublicKeyUnchecked::deserialize(deserializer).map(Into::into)
}

#[cfg(any(test, feature = "fuzzing"))]
use crate::test_utils::{self, KeyPair};

/// Produces a uniformly random bls keypair from a seed
#[cfg(any(test, feature = "fuzzing"))]
pub fn keypair_strategy(
) -> impl Strategy<Value = KeyPair<BLSPrivateKey, BLSPublicKey>> {
    test_utils::uniform_keypair_strategy::<BLSPrivateKey, BLSPublicKey>()
}

#[cfg(any(test, feature = "fuzzing"))]
use proptest::prelude::*;

#[cfg(any(test, feature = "fuzzing"))]
impl proptest::arbitrary::Arbitrary for BLSPublicKey {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        crate::test_utils::uniform_keypair_strategy::<
            BLSPrivateKey,
            BLSPublicKey,
        >()
        .prop_map(|v| v.public_key)
        .boxed()
    }
}

#[cfg(test)]
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
