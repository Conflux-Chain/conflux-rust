// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    bls::{
        BLSPrivateKey, BLSPublicKey, BLSSignature, BLS_PRIVATE_KEY_LENGTH,
        BLS_PUBLIC_KEY_LENGTH,
    },
    hash::{CryptoHash, CryptoHasher},
    traits::*,
    CryptoMaterialError, PrivateKey, PublicKey, Signature, SigningKey, Uniform,
    ValidCryptoMaterial, ValidCryptoMaterialStringExt, VerifyingKey,
};
use anyhow::{anyhow, Result};
pub use bls_signatures::{
    aggregate, hash as bls_hash, PrivateKey as RawPrivateKey,
    PublicKey as RawPublicKey, Serialize as BLSSerialize,
    Signature as RawSignature,
};
use core::convert::TryFrom;
use diem_crypto_derive::{
    DeserializeKey, SerializeKey, SilentDebug, SilentDisplay,
};
use mirai_annotations::*;
use rand::Rng;
use serde::Serialize;
use std::fmt;

const MAX_NUM_OF_KEYS: usize = 300;
const BITMAP_NUM_OF_BYTES: usize = 40;

/// Vector of private keys in the multi-key BLS structure.
#[derive(
    DeserializeKey, Eq, PartialEq, SilentDisplay, SilentDebug, SerializeKey,
)]
pub struct MultiBLSPrivateKey {
    private_keys: Vec<BLSPrivateKey>,
}

#[cfg(feature = "assert-private-keys-not-cloneable")]
static_assertions::assert_not_impl_any!(MultiBLSPrivateKey: Clone);

/// Vector of public keys in the multi-key BLS structure.
#[derive(Clone, DeserializeKey, Eq, PartialEq, SerializeKey)]
pub struct MultiBLSPublicKey {
    public_keys: Vec<BLSPublicKey>,
}

#[cfg(mirai)]
use crate::tags::ValidatedPublicKeyTag;
#[cfg(not(mirai))]
struct ValidatedPublicKeyTag {}

/// Multi BLS signature wrapper
#[derive(DeserializeKey, Clone, SerializeKey, PartialEq)]
pub struct MultiBLSSignature {
    bitmap: [u8; BITMAP_NUM_OF_BYTES],
    signature: RawSignature,
}

impl MultiBLSPrivateKey {
    /// Construct a new MultiBLSPrivateKey.
    pub fn new(
        private_keys: Vec<BLSPrivateKey>,
    ) -> std::result::Result<Self, CryptoMaterialError> {
        Ok(MultiBLSPrivateKey { private_keys })
    }

    /// Serialize a MultiBLSPrivateKey.
    pub fn to_bytes(&self) -> Vec<u8> { to_bytes(&self.private_keys) }
}

impl MultiBLSPublicKey {
    /// Construct a new MultiBLSPublicKey.
    pub fn new(public_keys: Vec<BLSPublicKey>) -> Self {
        MultiBLSPublicKey { public_keys }
    }

    /// Getter public_keys
    pub fn public_keys(&self) -> &Vec<BLSPublicKey> { &self.public_keys }

    /// Serialize a MultiBLSPublicKey.
    pub fn to_bytes(&self) -> Vec<u8> { to_bytes(&self.public_keys) }
}

///////////////////////
// PrivateKey Traits //
///////////////////////

/// Convenient method to create a MultiBLSPrivateKey from a single
/// BLSPrivateKey.
impl From<&BLSPrivateKey> for MultiBLSPrivateKey {
    fn from(bls_private_key: &BLSPrivateKey) -> Self {
        MultiBLSPrivateKey {
            private_keys: vec![BLSPrivateKey::try_from(
                &bls_private_key.to_bytes()[..],
            )
            .unwrap()],
        }
    }
}

impl PrivateKey for MultiBLSPrivateKey {
    type PublicKeyMaterial = MultiBLSPublicKey;
}

impl SigningKey for MultiBLSPrivateKey {
    type SignatureMaterial = MultiBLSSignature;
    type VerifyingKeyMaterial = MultiBLSPublicKey;

    fn sign<T: CryptoHash + Serialize>(
        &self, message: &T,
    ) -> MultiBLSSignature {
        let signatures: Vec<RawSignature> = self
            .private_keys
            .iter()
            .enumerate()
            .map(|(_, item)| item.sign(message).raw())
            .collect();

        MultiBLSSignature {
            bitmap: [255; BITMAP_NUM_OF_BYTES],
            signature: aggregate(&signatures).unwrap(),
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn sign_arbitrary_message(&self, message: &[u8]) -> MultiBLSSignature {
        let signatures: Vec<RawSignature> = self
            .private_keys
            .iter()
            .enumerate()
            .map(|(_, item)| item.sign_arbitrary_message(message).raw())
            .collect();

        MultiBLSSignature {
            bitmap: [255; BITMAP_NUM_OF_BYTES],
            signature: aggregate(&signatures).unwrap(),
        }
    }
}

// Generating a random K out-of N key for testing.
impl Uniform for MultiBLSPrivateKey {
    fn generate<R>(rng: &mut R) -> Self
    where R: ::rand::RngCore + ::rand::CryptoRng {
        let num_of_keys = rng.gen_range(1..=MAX_NUM_OF_KEYS);
        let mut private_keys: Vec<BLSPrivateKey> =
            Vec::with_capacity(num_of_keys);
        for _ in 0..num_of_keys {
            private_keys
                .push(BLSPrivateKey::from(RawPrivateKey::generate(rng)));
        }
        MultiBLSPrivateKey { private_keys }
    }
}

impl TryFrom<&[u8]> for MultiBLSPrivateKey {
    type Error = CryptoMaterialError;

    /// Deserialize an BLSPrivateKey. This method will also check for key
    /// and threshold validity.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<MultiBLSPrivateKey, CryptoMaterialError> {
        if bytes.is_empty() {
            return Err(CryptoMaterialError::WrongLengthError);
        }

        let private_keys: Result<Vec<BLSPrivateKey>, _> = bytes
            .chunks_exact(BLS_PRIVATE_KEY_LENGTH)
            .map(BLSPrivateKey::try_from)
            .collect();

        private_keys.map(|private_keys| MultiBLSPrivateKey { private_keys })
    }
}

impl Length for MultiBLSPrivateKey {
    fn length(&self) -> usize {
        self.private_keys.len() * BLS_PRIVATE_KEY_LENGTH
    }
}

impl ValidCryptoMaterial for MultiBLSPrivateKey {
    fn to_bytes(&self) -> Vec<u8> { self.to_bytes() }
}

impl Genesis for MultiBLSPrivateKey {
    fn genesis() -> Self {
        let mut buf = [0u8; BLS_PRIVATE_KEY_LENGTH];
        buf[BLS_PRIVATE_KEY_LENGTH - 1] = 1u8;
        MultiBLSPrivateKey {
            private_keys: vec![BLSPrivateKey::try_from(buf.as_ref()).unwrap()],
        }
    }
}

//////////////////////
// PublicKey Traits //
//////////////////////

/// Convenient method to create a MultiBLSPublicKey from a single
/// BLSPublicKey.
impl From<BLSPublicKey> for MultiBLSPublicKey {
    fn from(ed_public_key: BLSPublicKey) -> Self {
        MultiBLSPublicKey {
            public_keys: vec![ed_public_key],
        }
    }
}

/// Implementing From<&PrivateKey<...>> allows to derive a public key in a more
/// elegant fashion.
impl From<&MultiBLSPrivateKey> for MultiBLSPublicKey {
    fn from(private_key: &MultiBLSPrivateKey) -> Self {
        let public_keys = private_key
            .private_keys
            .iter()
            .map(PrivateKey::public_key)
            .collect();
        MultiBLSPublicKey { public_keys }
    }
}

/// We deduce PublicKey from this.
impl PublicKey for MultiBLSPublicKey {
    type PrivateKeyMaterial = MultiBLSPrivateKey;
}

#[allow(clippy::derive_hash_xor_eq)]
impl std::hash::Hash for MultiBLSPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = self.to_bytes();
        state.write(&encoded_pubkey);
    }
}

impl TryFrom<&[u8]> for MultiBLSPublicKey {
    type Error = CryptoMaterialError;

    /// Deserialize a MultiBLSPublicKey. This method will also check for key
    /// and threshold validity, and will only deserialize keys that are safe
    /// against small subgroup attacks.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<MultiBLSPublicKey, CryptoMaterialError> {
        if bytes.is_empty() {
            return Err(CryptoMaterialError::WrongLengthError);
        }
        let public_keys: Result<Vec<BLSPublicKey>, _> = bytes
            .chunks_exact(BLS_PUBLIC_KEY_LENGTH)
            .map(BLSPublicKey::try_from)
            .collect();
        public_keys.map(|public_keys| {
            let public_key = MultiBLSPublicKey { public_keys };
            add_tag!(&public_key, ValidatedPublicKeyTag);
            public_key
        })
    }
}

/// We deduce VerifyingKey from pointing to the signature material
/// we get the ability to do `pubkey.validate(msg, signature)`
impl VerifyingKey for MultiBLSPublicKey {
    type SignatureMaterial = MultiBLSSignature;
    type SigningKeyMaterial = MultiBLSPrivateKey;
}

impl fmt::Display for MultiBLSPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.to_bytes()))
    }
}

impl fmt::Debug for MultiBLSPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MultiBLSPublicKey({})", self)
    }
}

impl Length for MultiBLSPublicKey {
    fn length(&self) -> usize { self.public_keys.len() * BLS_PUBLIC_KEY_LENGTH }
}

impl ValidCryptoMaterial for MultiBLSPublicKey {
    fn to_bytes(&self) -> Vec<u8> { self.to_bytes() }
}

impl MultiBLSSignature {
    /// This method will also sort signatures based on index.
    pub fn new(
        signatures: Vec<(BLSSignature, usize)>,
    ) -> std::result::Result<Self, CryptoMaterialError> {
        let num_of_sigs = signatures.len();
        if num_of_sigs == 0 || num_of_sigs > MAX_NUM_OF_KEYS {
            return Err(CryptoMaterialError::ValidationError);
        }
        let mut bitmap = [0u8; BITMAP_NUM_OF_BYTES];
        let (sigs, indexes): (Vec<_>, Vec<_>) =
            signatures.iter().cloned().unzip();
        for i in indexes {
            if i >= MAX_NUM_OF_KEYS {
                return Err(CryptoMaterialError::ValidationError);
            }
            if bitmap_get_bit(bitmap, i) {
                return Err(CryptoMaterialError::BitVecError(
                    "Duplicate signature index".to_string(),
                ));
            } else {
                bitmap_set_bit(&mut bitmap, i as usize);
            }
        }

        let raw_signatures: Vec<RawSignature> =
            sigs.into_iter().map(|sig| sig.raw()).collect();
        let signature = match aggregate(&raw_signatures) {
            Ok(signature) => Ok(signature),
            Err(_) => Err(CryptoMaterialError::AggregateError),
        }?;
        Ok(Self { bitmap, signature })
    }

    /// Getter raw signature.
    pub fn raw(&self) -> &RawSignature { &self.signature }

    /// to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        bytes.extend(&self.bitmap[..]);
        bytes.extend(&self.signature.as_bytes()[..]);
        bytes
    }
}

//////////////////////
// Signature Traits //
//////////////////////

impl Eq for MultiBLSSignature {}

impl TryFrom<&[u8]> for MultiBLSSignature {
    type Error = CryptoMaterialError;

    /// Deserialize a MultiBLSSignature. This method will also check for
    /// malleable signatures and bitmap validity.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<MultiBLSSignature, CryptoMaterialError> {
        if bytes.len() < BITMAP_NUM_OF_BYTES {
            return Err(CryptoMaterialError::DeserializationError);
        }
        let mut bitmap = [0u8; BITMAP_NUM_OF_BYTES];
        for i in 0..BITMAP_NUM_OF_BYTES {
            bitmap[i] = bytes[i];
        }
        let signature =
            match RawSignature::from_bytes(&bytes[BITMAP_NUM_OF_BYTES..]) {
                Ok(signature) => signature,
                Err(_) => {
                    return Err(CryptoMaterialError::DeserializationError)
                }
            };
        Ok(Self { bitmap, signature })
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl std::hash::Hash for MultiBLSSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_signature = self.to_bytes();
        state.write(&encoded_signature);
    }
}

impl fmt::Display for MultiBLSSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.to_bytes()[..]))
    }
}

impl fmt::Debug for MultiBLSSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MultiBLSSignature({})", self)
    }
}

impl ValidCryptoMaterial for MultiBLSSignature {
    fn to_bytes(&self) -> Vec<u8> { self.to_bytes() }
}

impl Signature for MultiBLSSignature {
    type SigningKeyMaterial = MultiBLSPrivateKey;
    type VerifyingKeyMaterial = MultiBLSPublicKey;

    fn verify<T: CryptoHash + Serialize>(
        &self, message: &T, public_key: &MultiBLSPublicKey,
    ) -> Result<()> {
        // Public keys should be validated to be safe against small subgroup
        // attacks, etc.
        precondition!(has_tag!(public_key, ValidatedPublicKeyTag));
        let mut bytes = <T as CryptoHash>::Hasher::seed().to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| CryptoMaterialError::SerializationError)?;
        Self::verify_arbitrary_msg(self, &bytes, public_key)
    }

    /// Checks that `self` is valid for an arbitrary &[u8] `message` using
    /// `public_key`. Outside of this crate, this particular function should
    /// only be used for native signature verification in Move.
    fn verify_arbitrary_msg(
        &self, message: &[u8], public_key: &MultiBLSPublicKey,
    ) -> Result<()> {
        precondition!(has_tag!(public_key, ValidatedPublicKeyTag));
        match bitmap_last_set_bit(self.bitmap) {
            Some(last_bit)
                if last_bit as usize <= public_key.public_keys().len() =>
            {
                ()
            }
            _ => {
                return Err(anyhow!(
                    "{}",
                    CryptoMaterialError::BitVecError(
                        "Signature index is out of range".to_string()
                    )
                ))
            }
        };

        let mut raw_public_keys: Vec<RawPublicKey> = vec![];
        for i in 0..public_key.public_keys().len() {
            if bitmap_get_bit(self.bitmap, i) {
                raw_public_keys.push(public_key.public_keys()[i].clone().raw())
            }
        }
        match bls_signatures::verify_same_message(
            &self.signature,
            message,
            &raw_public_keys,
        ) {
            true => Ok(()),
            false => Err(anyhow!("Invalid BLS signature!")),
        }
    }
}

impl From<BLSSignature> for MultiBLSSignature {
    fn from(bls_signature: BLSSignature) -> Self {
        let mut bitmap = [0u8; BITMAP_NUM_OF_BYTES];
        bitmap[0] = 1;
        MultiBLSSignature {
            bitmap,
            signature: bls_signature.raw(),
        }
    }
}

//////////////////////
// Helper functions //
//////////////////////

// Helper function required to MultiBLS keys to_bytes to add the threshold.
fn to_bytes<T: ValidCryptoMaterial>(keys: &[T]) -> Vec<u8> {
    let bytes: Vec<u8> = keys
        .iter()
        .flat_map(ValidCryptoMaterial::to_bytes)
        .collect();
    bytes
}

fn bitmap_set_bit(input: &mut [u8; BITMAP_NUM_OF_BYTES], index: usize) {
    let bucket = index / 8;
    // It's always invoked with index < 32, thus there is no need to check
    // range.
    let bucket_pos = index - (bucket * 8);
    input[bucket] |= 128 >> bucket_pos as u8;
}

// Helper method to get the input's bit at index.
fn bitmap_get_bit(input: [u8; BITMAP_NUM_OF_BYTES], index: usize) -> bool {
    let bucket = index / 8;
    // It's always invoked with index < 32, thus there is no need to check
    // range.
    let bucket_pos = index - (bucket * 8);
    (input[bucket] & (128 >> bucket_pos as u8)) != 0
}

// Find the last set bit.
fn bitmap_last_set_bit(input: [u8; BITMAP_NUM_OF_BYTES]) -> Option<u8> {
    input
        .iter()
        .rev()
        .enumerate()
        .find(|(_, byte)| byte != &&0u8)
        .map(|(i, byte)| {
            (8 * (BITMAP_NUM_OF_BYTES - i) - byte.trailing_zeros() as usize - 1)
                as u8
        })
}

#[test]
fn bitmap_tests() {
    let mut bitmap = [0u8; BITMAP_NUM_OF_BYTES];
    bitmap[0] = 0b0100_0000u8;
    bitmap[1] = 0b1111_1111u8;
    bitmap[3] = 0b1000_0000u8;
    assert!(!bitmap_get_bit(bitmap, 0));
    assert!(bitmap_get_bit(bitmap, 1));
    for i in 8..16 {
        assert!(bitmap_get_bit(bitmap, i));
    }
    for i in 16..24 {
        assert!(!bitmap_get_bit(bitmap, i));
    }
    assert!(bitmap_get_bit(bitmap, 24));
    assert!(!bitmap_get_bit(bitmap, 31));
    assert_eq!(bitmap_last_set_bit(bitmap), Some(24));

    bitmap_set_bit(&mut bitmap, 30);
    assert!(bitmap_get_bit(bitmap, 30));
    assert_eq!(bitmap_last_set_bit(bitmap), Some(30));
}
