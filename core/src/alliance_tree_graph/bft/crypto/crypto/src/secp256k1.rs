// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

//! # Examples

use crate::{traits::*, HashValue};
use anyhow::Result;
use cfx_types::{H256, H520};
use core::convert::TryFrom;
use ethkey::{
    Generator, Public, Random as EthkeyRandom, Secret,
    Signature as EthkeySignature, SECP256K1,
};
use libra_crypto_derive::{SilentDebug, SilentDisplay};
use secp256k1::key;
use serde::{de, ser};
use std::fmt;

/// The length of the Secp256k1PrivateKey
pub const SECP256K1_PRIVATE_KEY_LENGTH: usize = 32;
/// The length of the Secp256k1PublicKey
pub const SECP256K1_PUBLIC_KEY_LENGTH: usize = 64;
/// The length of the Secp256k1Signature
pub const SECP256K1_SIGNATURE_LENGTH: usize = 65;

/// A private key
#[derive(SilentDisplay, SilentDebug)]
pub struct Secp256k1PrivateKey(Secret);

//#[cfg(feature = "assert-private-keys-not-cloneable")]
//static_assertions::assert_not_impl_any!(Secp256k1PrivateKey: Clone);

/// A public key
#[derive(Clone, Debug)]
pub struct Secp256k1PublicKey(Public);

/// A signature
#[derive(Clone, Debug)]
pub struct Secp256k1Signature(EthkeySignature);

impl Secp256k1PrivateKey {
    /// Serialize an Secp256k1PrivateKey.
    pub fn to_bytes(&self) -> [u8; SECP256K1_PRIVATE_KEY_LENGTH] {
        self.0.to_fixed_bytes()
    }

    /// Deserialize an Secp256k1PrivateKey without any validation checks apart
    /// from expected key size.
    fn from_bytes_unchecked(
        bytes: &[u8],
    ) -> std::result::Result<Secp256k1PrivateKey, CryptoMaterialError> {
        match Secret::from_slice(bytes) {
            Some(secret) => Ok(Secp256k1PrivateKey(secret)),
            None => Err(CryptoMaterialError::DeserializationError),
        }
    }

    /// Generate Secp256k1PrivateKey from Secret
    pub fn from_secret(secret: Secret) -> Self { Self(secret) }
}

impl Secp256k1PublicKey {
    /// Serialize an Secp256k1PublicKey.
    pub fn to_bytes(&self) -> [u8; SECP256K1_PUBLIC_KEY_LENGTH] {
        self.0.to_fixed_bytes()
    }

    /// Deserialize an Secp256k1PublicKey without any validation checks apart
    /// from expected key size.
    pub(crate) fn from_bytes_unchecked(
        bytes: &[u8],
    ) -> std::result::Result<Secp256k1PublicKey, CryptoMaterialError> {
        if bytes.len() != SECP256K1_PUBLIC_KEY_LENGTH {
            return Err(CryptoMaterialError::DeserializationError);
        }

        let mut public = Public::zero();
        public
            .as_bytes_mut()
            .copy_from_slice(&bytes[0..SECP256K1_PUBLIC_KEY_LENGTH]);
        Ok(Secp256k1PublicKey(public))
    }

    /// Return the reference on the internal public key.
    pub fn public(&self) -> &Public { &self.0 }
}

impl Secp256k1Signature {
    /// Serialize an Secp256k1Signature.
    pub fn to_bytes(&self) -> [u8; SECP256K1_SIGNATURE_LENGTH] {
        self.0.clone().into()
    }

    /// Deserialize an Secp256k1Signature without any validation checks
    /// (malleability) apart from expected key size.
    pub(crate) fn from_bytes_unchecked(
        bytes: &[u8],
    ) -> std::result::Result<Secp256k1Signature, CryptoMaterialError> {
        if bytes.len() != SECP256K1_SIGNATURE_LENGTH {
            return Err(CryptoMaterialError::DeserializationError);
        }

        let sig_h520 = H520::from_slice(bytes);
        let signature = EthkeySignature::from(sig_h520);
        Ok(Secp256k1Signature(signature))
    }

    /// Check for correct size and third-party based signature malleability
    /// issues. This method is required to ensure that given a valid
    /// signature for some message under some key, an attacker cannot
    /// produce another valid signature for the same message and key.
    ///
    /// According to [RFC8032](https://tools.ietf.org/html/rfc8032), signatures comprise elements
    /// {R, S} and we should enforce that S is of canonical form (smaller than
    /// L, where L is the order of edwards25519 curve group) to prevent
    /// signature malleability. Without this check, one could add a multiple
    /// of L into S and still pass signature verification, resulting in
    /// a distinct yet valid signature.
    ///
    /// This method does not check the R component of the signature, because R
    /// is hashed during signing and verification to compute h = H(ENC(R) ||
    /// ENC(A) || M), which means that a third-party cannot modify R without
    /// being detected.
    ///
    /// Note: It's true that malicious signers can already produce varying
    /// signatures by choosing a different nonce, so this method protects
    /// against malleability attacks performed by a non-signer.
    pub fn check_malleability(
        bytes: &[u8],
    ) -> std::result::Result<(), CryptoMaterialError> {
        let sig = Self::from_bytes_unchecked(bytes)?;
        if !sig.0.is_low_s() || !sig.0.is_valid() {
            return Err(CryptoMaterialError::CanonicalRepresentationError);
        }
        Ok(())
    }
}

///////////////////////
// PrivateKey Traits //
///////////////////////

impl PrivateKey for Secp256k1PrivateKey {
    type PublicKeyMaterial = Secp256k1PublicKey;
}

impl SigningKey for Secp256k1PrivateKey {
    type SignatureMaterial = Secp256k1Signature;
    type VerifyingKeyMaterial = Secp256k1PublicKey;

    fn sign_message(&self, message: &HashValue) -> Secp256k1Signature {
        let secret = &self.0;
        let msg = H256::from_slice(message.to_vec().as_slice());
        let sig = ethkey::sign(secret, &msg).expect("Error signing message");
        Secp256k1Signature(sig)
    }
}

impl Uniform for Secp256k1PrivateKey {
    fn generate_for_testing<R>(_rng: &mut R) -> Self
    where R: ::rand::SeedableRng + ::rand::RngCore + ::rand::CryptoRng {
        let key_pair = EthkeyRandom
            .generate()
            .expect("Error generating random key pair");
        Secp256k1PrivateKey(key_pair.secret().clone())
    }
}

impl PartialEq<Self> for Secp256k1PrivateKey {
    fn eq(&self, other: &Self) -> bool { self.to_bytes() == other.to_bytes() }
}

impl Eq for Secp256k1PrivateKey {}

// We could have a distinct kind of validation for the PrivateKey, for
// ex. checking the derived PublicKey is valid?
impl TryFrom<&[u8]> for Secp256k1PrivateKey {
    type Error = CryptoMaterialError;

    /// Deserialize an Secp256k1PrivateKey. This method will also check for key
    /// validity.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<Secp256k1PrivateKey, CryptoMaterialError> {
        // Note that the only requirement is that the size of the key is 32
        // bytes, something that is already checked during
        // deserialization of ed25519_dalek::SecretKey
        // Also, the underlying ed25519_dalek implementation ensures that the
        // derived public key is safe and it will not lie in a
        // small-order group, thus no extra check for PublicKey
        // validation is required.
        Secp256k1PrivateKey::from_bytes_unchecked(bytes)
    }
}
impl ValidKey for Secp256k1PrivateKey {
    fn to_bytes(&self) -> Vec<u8> { self.to_bytes().to_vec() }
}

impl Genesis for Secp256k1PrivateKey {
    fn genesis() -> Self {
        let mut buf = [0u8; SECP256K1_PRIVATE_KEY_LENGTH];
        buf[SECP256K1_PRIVATE_KEY_LENGTH - 1] = 1;
        Self::try_from(buf.as_ref()).unwrap()
    }
}

//////////////////////
// PublicKey Traits //
//////////////////////

// Implementing From<&PrivateKey<...>> allows to derive a public key in a more
// elegant fashion
impl From<&Secp256k1PrivateKey> for Secp256k1PublicKey {
    fn from(secret_key: &Secp256k1PrivateKey) -> Self {
        let secret = &secret_key.0;
        let context = &SECP256K1;
        let s: key::SecretKey =
            key::SecretKey::from_slice(context, &secret[..])
                .expect("Error secret!");
        let pub_key = key::PublicKey::from_secret_key(context, &s)
            .expect("Error public!");
        let serialized = pub_key.serialize_vec(context, false);

        let mut public = Public::default();
        public.as_bytes_mut().copy_from_slice(&serialized[1..65]);
        Secp256k1PublicKey(public)
    }
}

// We deduce PublicKey from this
impl PublicKey for Secp256k1PublicKey {
    type PrivateKeyMaterial = Secp256k1PrivateKey;
}

impl std::hash::Hash for Secp256k1PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = self.to_bytes();
        state.write(&encoded_pubkey);
    }
}

// Those are required by the implementation of hash above
impl PartialEq for Secp256k1PublicKey {
    fn eq(&self, other: &Secp256k1PublicKey) -> bool {
        self.to_bytes().as_ref() == other.to_bytes().as_ref()
    }
}

impl Eq for Secp256k1PublicKey {}

// We deduce VerifyingKey from pointing to the signature material
// we get the ability to do `pubkey.validate(msg, signature)`
impl VerifyingKey for Secp256k1PublicKey {
    type SignatureMaterial = Secp256k1Signature;
    type SigningKeyMaterial = Secp256k1PrivateKey;
}

impl std::fmt::Display for Secp256k1PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.to_bytes()[..]))
    }
}

impl TryFrom<&[u8]> for Secp256k1PublicKey {
    type Error = CryptoMaterialError;

    /// Deserialize an Secp256k1PublicKey. This method will also check for key
    /// validity, for instance  it will only deserialize keys that are safe
    /// against small subgroup attacks.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<Secp256k1PublicKey, CryptoMaterialError> {
        // Unfortunately, tuple struct `PublicKey` is private so we cannot
        // Ok(Secp256k1PublicKey(ed25519_dalek::PublicKey(compressed, point)))
        // and we have to again invoke deserialization.
        Secp256k1PublicKey::from_bytes_unchecked(bytes)
    }
}

impl ValidKey for Secp256k1PublicKey {
    fn to_bytes(&self) -> Vec<u8> { self.to_bytes().to_vec() }
}

//////////////////////
// Signature Traits //
//////////////////////

impl Signature for Secp256k1Signature {
    type SigningKeyMaterial = Secp256k1PrivateKey;
    type VerifyingKeyMaterial = Secp256k1PublicKey;

    /// Checks that `self` is valid for `message` using `public_key`.
    fn verify(
        &self, message: &HashValue, public_key: &Secp256k1PublicKey,
    ) -> Result<()> {
        Secp256k1Signature::check_malleability(&self.to_bytes())?;
        let msg = H256::from_slice(message.to_vec().as_slice());
        ethkey::verify_public(&public_key.0, &self.0, &msg)?;
        Ok(())
    }

    /// Checks that `self` is valid for an arbitrary &[u8] `message` using
    /// `public_key`. Outside of this crate, this particular function should
    /// only be used for native signature verification in move
    fn verify_arbitrary_msg(
        &self, message: &[u8], public_key: &Secp256k1PublicKey,
    ) -> Result<()> {
        let msg = HashValue::from_slice(message)
            .expect("Error deserializing HashValue");
        self.verify(&msg, public_key)
    }

    fn to_bytes(&self) -> Vec<u8> { self.to_bytes().to_vec() }

    /// Batch signature verification as described in the original EdDSA article
    /// by Bernstein et al. "High-speed high-security signatures". Current
    /// implementation works for signatures on the same message and it
    /// checks for malleability.
    fn batch_verify_signatures(
        message: &HashValue,
        keys_and_signatures: Vec<(Self::VerifyingKeyMaterial, Self)>,
    ) -> Result<()>
    {
        for (pub_key, sig) in keys_and_signatures.iter() {
            Secp256k1Signature::check_malleability(&sig.to_bytes())?;
            sig.verify(message, pub_key)?;
        }
        Ok(())
    }
}

impl std::hash::Hash for Secp256k1Signature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = self.to_bytes();
        state.write(&encoded_pubkey);
    }
}

impl TryFrom<&[u8]> for Secp256k1Signature {
    type Error = CryptoMaterialError;

    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<Secp256k1Signature, CryptoMaterialError> {
        Secp256k1Signature::check_malleability(bytes)?;
        Secp256k1Signature::from_bytes_unchecked(bytes)
    }
}

// Those are required by the implementation of hash above
impl PartialEq for Secp256k1Signature {
    fn eq(&self, other: &Secp256k1Signature) -> bool {
        self.to_bytes().as_ref() == other.to_bytes().as_ref()
    }
}

impl Eq for Secp256k1Signature {}

//////////////////////////
// Compatibility Traits //
//////////////////////////

/// Those transitory traits are meant to help with the progressive
/// migration of the code base to the crypto module and will
/// disappear after
pub mod compat {
    use crate::secp256k1::*;
    #[cfg(feature = "fuzzing")]
    use proptest::strategy::LazyJust;
    #[cfg(feature = "fuzzing")]
    use proptest::{prelude::*, strategy::Strategy};

    impl Clone for Secp256k1PrivateKey {
        fn clone(&self) -> Self {
            let serialized: &[u8] = &(self.to_bytes());
            Secp256k1PrivateKey::try_from(serialized).unwrap()
        }
    }

    use crate::Uniform;
    use rand::{rngs::StdRng, SeedableRng};

    /// Generate an arbitrary key pair, with possible Rng input
    ///
    /// Warning: if you pass in None, this will not return distinct
    /// results every time! Should you want to write non-deterministic
    /// tests, look at libra_config::config_builder::util::get_test_config
    pub fn generate_keypair<'a, T>(
        opt_rng: T,
    ) -> (Secp256k1PrivateKey, Secp256k1PublicKey)
    where T: Into<Option<&'a mut StdRng>> + Sized {
        if let Some(rng_mut_ref) = opt_rng.into() {
            <(Secp256k1PrivateKey, Secp256k1PublicKey)>::generate_for_testing(
                rng_mut_ref,
            )
        } else {
            let mut rng = StdRng::from_seed(crate::test_utils::TEST_SEED);
            <(Secp256k1PrivateKey, Secp256k1PublicKey)>::generate_for_testing(
                &mut rng,
            )
        }
    }

    /// Used to produce keypairs from a seed for testing purposes
    #[cfg(feature = "fuzzing")]
    pub fn keypair_strategy(
    ) -> impl Strategy<Value = (Secp256k1PrivateKey, Secp256k1PublicKey)> {
        // The no_shrink is because keypairs should be fixed -- shrinking would
        // cause a different keypair to be generated, which appears to
        // not be very useful.
        any::<[u8; 32]>()
            .prop_map(|seed| {
                let mut rng: StdRng = SeedableRng::from_seed(seed);
                let (private_key, public_key) = generate_keypair(&mut rng);
                (private_key, public_key)
            })
            .no_shrink()
    }

    /// Generates a well-known keypair `(Secp256k1PrivateKey,
    /// Secp256k1PublicKey)` for special use in the genesis block. A genesis
    /// block is the first block of a blockchain and it is hardcoded as it's
    /// a special case in that it does not reference a previous block.
    pub fn generate_genesis_keypair(
    ) -> (Secp256k1PrivateKey, Secp256k1PublicKey) {
        let mut buf = [0u8; SECP256K1_PRIVATE_KEY_LENGTH];
        buf[SECP256K1_PRIVATE_KEY_LENGTH - 1] = 1;
        let private_key = Secp256k1PrivateKey::try_from(&buf[..]).unwrap();
        let public_key = (&private_key).into();
        (private_key, public_key)
    }

    #[cfg(feature = "fuzzing")]
    impl Arbitrary for Secp256k1PublicKey {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            LazyJust::new(|| generate_keypair(None).1).boxed()
        }
    }
}

//////////////////////////////
// Compact Serialization    //
//////////////////////////////
impl ser::Serialize for Secp256k1PrivateKey {
    fn serialize<S>(
        &self, serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where S: ser::Serializer {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl ser::Serialize for Secp256k1PublicKey {
    fn serialize<S>(
        &self, serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where S: ser::Serializer {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

impl ser::Serialize for Secp256k1Signature {
    fn serialize<S>(
        &self, serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where S: ser::Serializer {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

struct Secp256k1PrivateKeyVisitor;
struct Secp256k1PublicKeyVisitor;
struct Secp256k1SignatureVisitor;

impl<'de> de::Visitor<'de> for Secp256k1PrivateKeyVisitor {
    type Value = Secp256k1PrivateKey;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ed25519_dalek private key in bytes")
    }

    fn visit_bytes<E>(
        self, value: &[u8],
    ) -> std::result::Result<Secp256k1PrivateKey, E>
    where E: de::Error {
        Secp256k1PrivateKey::try_from(value).map_err(E::custom)
    }
}

impl<'de> de::Visitor<'de> for Secp256k1PublicKeyVisitor {
    type Value = Secp256k1PublicKey;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("public key in bytes")
    }

    fn visit_bytes<E>(
        self, value: &[u8],
    ) -> std::result::Result<Secp256k1PublicKey, E>
    where E: de::Error {
        Secp256k1PublicKey::try_from(value).map_err(E::custom)
    }
}

impl<'de> de::Visitor<'de> for Secp256k1SignatureVisitor {
    type Value = Secp256k1Signature;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ed25519_dalek signature in compact encoding")
    }

    fn visit_bytes<E>(
        self, value: &[u8],
    ) -> std::result::Result<Secp256k1Signature, E>
    where E: de::Error {
        Secp256k1Signature::try_from(value).map_err(E::custom)
    }
}

impl<'de> de::Deserialize<'de> for Secp256k1PrivateKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: de::Deserializer<'de> {
        deserializer.deserialize_bytes(Secp256k1PrivateKeyVisitor {})
    }
}

impl<'de> de::Deserialize<'de> for Secp256k1PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: de::Deserializer<'de> {
        deserializer.deserialize_bytes(Secp256k1PublicKeyVisitor {})
    }
}

impl<'de> de::Deserialize<'de> for Secp256k1Signature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where D: de::Deserializer<'de> {
        deserializer.deserialize_bytes(Secp256k1SignatureVisitor {})
    }
}
