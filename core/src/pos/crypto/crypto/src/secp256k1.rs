// Copyright 2019-2020 Conflux Foundation. All rights reserved.
// TreeGraph is free software and distributed under Apache License 2.0.
// See https://www.apache.org/licenses/LICENSE-2.0

//! # Examples

use crate::{
    hash::{CryptoHash, CryptoHasher},
    traits::*,
};
use anyhow::{bail, Result};
use cfx_types::{H256, H520};
use cfxkey::{
    Generator, Public, Random as EthkeyRandom, Secret,
    Signature as EthkeySignature, SECP256K1,
};
use core::convert::TryFrom;
use diem_crypto_derive::{
    DeserializeKey, SerializeKey, SilentDebug, SilentDisplay,
};
use mirai_annotations::*;
use secp256k1::key;
use serde::Serialize;

/// The length of the Secp256k1PrivateKey
pub const SECP256K1_PRIVATE_KEY_LENGTH: usize = 32;
/// The length of the Secp256k1PublicKey
pub const SECP256K1_PUBLIC_KEY_LENGTH: usize = 64;
/// The length of the Secp256k1Signature
pub const SECP256K1_SIGNATURE_LENGTH: usize = 65;

/// A private key
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
pub struct Secp256k1PrivateKey(Secret);

#[cfg(feature = "assert-private-keys-not-cloneable")]
static_assertions::assert_not_impl_any!(Secp256k1PrivateKey: Clone);

#[cfg(any(test, feature = "cloneable-private-keys"))]
impl Clone for Secp256k1PrivateKey {
    fn clone(&self) -> Self {
        let serialized: &[u8] = &(self.to_bytes());
        Secp256k1PrivateKey::try_from(serialized).unwrap()
    }
}
/// A public key
#[derive(DeserializeKey, Clone, Debug, SerializeKey)]
pub struct Secp256k1PublicKey(Public);

#[cfg(mirai)]
use crate::tags::ValidatedPublicKeyTag;
#[cfg(not(mirai))]
struct ValidatedPublicKeyTag {}

/// A signature
#[derive(DeserializeKey, Clone, Debug, SerializeKey)]
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

    /// Private function aimed at minimizing code duplication between sign
    /// methods of the SigningKey implementation. This should remain private.
    fn sign_arbitrary_message(&self, message: &[u8]) -> Secp256k1Signature {
        let secret = &self.0;
        let msg = H256::from_slice(message);
        let sig = cfxkey::sign(secret, &msg).expect("Error signing message");
        Secp256k1Signature(sig)
    }
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

    /// Generate Secp256k1PublicKey from Public.
    pub fn from_public(public: Public) -> Self { Self(public) }
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

    /// Generate Secp256k1PrivateKey from Secret
    pub fn from_signature(signature: EthkeySignature) -> Self {
        Self(signature)
    }

    /// Checks that `self` is valid for an arbitrary &[u8] `message` using
    /// `public_key`. Outside of this crate, this particular function should
    /// only be used for native signature verification in move
    fn verify_arbitrary_msg(
        &self, message: &[u8], public_key: &Secp256k1PublicKey,
    ) -> Result<()> {
        // Public keys should be validated to be safe against small subgroup
        // attacks, etc.
        precondition!(has_tag!(public_key, ValidatedPublicKeyTag));
        Secp256k1Signature::check_malleability(&self.to_bytes())?;
        let msg = H256::from_slice(message.to_vec().as_slice());
        let result = cfxkey::verify_public(&public_key.0, &self.0, &msg)?;
        if result {
            Ok(())
        } else {
            bail!("Incorrect signature");
        }
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

    fn sign<T: CryptoHash + Serialize>(
        &self, message: &T,
    ) -> Secp256k1Signature {
        let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| CryptoMaterialError::SerializationError)
            .expect("Serialization of signable material should not fail.");
        Secp256k1PrivateKey::sign_arbitrary_message(self, bytes.as_slice())
    }

    #[cfg(any(test, feature = "fuzzing"))]
    fn sign_arbitrary_message(&self, message: &[u8]) -> Secp256k1Signature {
        Secp256k1PrivateKey::sign_arbitrary_message(self, message)
    }
}

impl Uniform for Secp256k1PrivateKey {
    fn generate<R>(_rng: &mut R) -> Self
    where R: ::rand::RngCore + ::rand::CryptoRng {
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

impl Length for Secp256k1PrivateKey {
    fn length(&self) -> usize { SECP256K1_PRIVATE_KEY_LENGTH }
}

impl ValidCryptoMaterial for Secp256k1PrivateKey {
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
        let public_key = Secp256k1PublicKey::from_bytes_unchecked(bytes)?;
        add_tag!(&public_key, ValidatedPublicKeyTag); // This key has gone through validity checks.
        Ok(public_key)
    }
}

impl Length for Secp256k1PublicKey {
    fn length(&self) -> usize { SECP256K1_PUBLIC_KEY_LENGTH }
}

impl ValidCryptoMaterial for Secp256k1PublicKey {
    fn to_bytes(&self) -> Vec<u8> { self.0.as_bytes().to_vec() }
}

//////////////////////
// Signature Traits //
//////////////////////

impl Signature for Secp256k1Signature {
    type SigningKeyMaterial = Secp256k1PrivateKey;
    type VerifyingKeyMaterial = Secp256k1PublicKey;

    /// Verifies that the provided signature is valid for the provided
    /// message, according to the RFC8032 algorithm. This strict verification
    /// performs the recommended check of 5.1.7 §3, on top of the required
    /// RFC8032 verifications.
    fn verify<T: CryptoHash + Serialize>(
        &self, message: &T, public_key: &Secp256k1PublicKey,
    ) -> Result<()> {
        // Public keys should be validated to be safe against small subgroup
        // attacks, etc.
        precondition!(has_tag!(public_key, ValidatedPublicKeyTag));
        let mut bytes = <T::Hasher as CryptoHasher>::seed().to_vec();
        bcs::serialize_into(&mut bytes, &message)
            .map_err(|_| CryptoMaterialError::SerializationError)?;
        Secp256k1Signature::verify_arbitrary_msg(self, &bytes, public_key)
    }

    /// Checks that `self` is valid for an arbitrary &[u8] `message` using
    /// `public_key`. Outside of this crate, this particular function should
    /// only be used for native signature verification in move
    fn verify_arbitrary_msg(
        &self, message: &[u8], public_key: &Secp256k1PublicKey,
    ) -> Result<()> {
        Secp256k1Signature::verify_arbitrary_msg(self, message, public_key)
    }
}

impl Length for Secp256k1Signature {
    fn length(&self) -> usize { SECP256K1_SIGNATURE_LENGTH }
}

impl ValidCryptoMaterial for Secp256k1Signature {
    fn to_bytes(&self) -> Vec<u8> { self.to_bytes().to_vec() }
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

    use crate::Uniform;
    use rand::rngs::StdRng;

    /// Generate an arbitrary key pair, with possible Rng input
    ///
    /// Warning: if you pass in None, this will not return distinct
    /// results every time! Should you want to write non-deterministic
    /// tests, look at libra_config::config_builder::util::get_test_config
    pub fn generate_keypair<'a, T>(
        _opt_rng: T,
    ) -> (Secp256k1PrivateKey, Secp256k1PublicKey)
    where T: Into<Option<&'a mut StdRng>> + Sized {
        <(Secp256k1PrivateKey, Secp256k1PublicKey)>::generate_for_testing()
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
