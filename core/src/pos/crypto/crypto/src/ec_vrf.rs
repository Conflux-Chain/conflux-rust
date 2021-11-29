use crate::{
    CryptoMaterialError, HashValue, PrivateKey, PublicKey, Uniform,
    VRFPrivateKey, VRFProof, VRFPublicKey, ValidCryptoMaterial,
    ValidCryptoMaterialStringExt,
};
use anyhow::{anyhow, Result};
use diem_crypto_derive::{
    DeserializeKey, SerializeKey, SilentDebug, SilentDisplay,
};
use lazy_static::lazy_static;
use openssl::{ec, nid::Nid};
use parking_lot::Mutex;
use std::{
    convert::TryFrom,
    fmt::{self, Formatter},
};
use vrf::{
    openssl::{CipherSuite, ECVRF},
    VRF,
};

// TODO(lpl): Choose a curve;
lazy_static! {
    /// VRF Cipher context. Mutex is needed because functions require `&mut self`.
    pub static ref VRF_CONTEXT: Mutex<ECVRF> = Mutex::new(
        ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI)
            .expect("VRF context initialization error")
    );
}

/// Elliptic Curve VRF private key
#[derive(
    DeserializeKey,
    Clone,
    SerializeKey,
    SilentDebug,
    SilentDisplay,
    Eq,
    PartialEq,
)]
pub struct EcVrfPrivateKey(Vec<u8>);

/// Elliptic Curve VRF public key
#[derive(DeserializeKey, Clone, SerializeKey, Debug)]
pub struct EcVrfPublicKey(Vec<u8>);

/// Elliptic Curve VRF proof
#[derive(DeserializeKey, Clone, SerializeKey, Debug)]
pub struct EcVrfProof(Vec<u8>);

impl VRFPrivateKey for EcVrfPrivateKey {
    type ProofMaterial = EcVrfProof;
    type PublicKeyMaterial = EcVrfPublicKey;

    fn compute(&self, seed: &[u8]) -> Result<Self::ProofMaterial> {
        match VRF_CONTEXT.lock().prove(&self.0, seed) {
            Ok(proof) => Ok(EcVrfProof(proof)),
            Err(e) => Err(anyhow!(e)),
        }
    }
}

impl VRFPublicKey for EcVrfPublicKey {
    type PrivateKeyMaterial = EcVrfPrivateKey;
    type ProofMaterial = EcVrfProof;
}

impl VRFProof for EcVrfProof {
    type PrivateKeyMaterial = EcVrfPrivateKey;
    type PublicKeyMaterial = EcVrfPublicKey;

    fn to_hash(&self) -> Result<HashValue> {
        match VRF_CONTEXT.lock().proof_to_hash(&self.0) {
            Ok(h) => HashValue::from_slice(&h).map_err(|e| anyhow!(e)),
            Err(e) => Err(anyhow!(e)),
        }
    }

    fn verify(
        &self, seed: &[u8], public_key: &Self::PublicKeyMaterial,
    ) -> Result<HashValue> {
        match VRF_CONTEXT.lock().verify(&public_key.0, &self.0, seed) {
            Ok(h) => HashValue::from_slice(&h).map_err(|e| anyhow!(e)),
            Err(e) => Err(anyhow!(e)),
        }
    }
}

impl PrivateKey for EcVrfPrivateKey {
    type PublicKeyMaterial = EcVrfPublicKey;
}

impl PublicKey for EcVrfPublicKey {
    type PrivateKeyMaterial = EcVrfPrivateKey;
}

impl fmt::Display for EcVrfPublicKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_encoded_string().map_err(|_| fmt::Error)?)
    }
}

impl From<Vec<u8>> for EcVrfPublicKey {
    fn from(raw: Vec<u8>) -> Self { EcVrfPublicKey(raw) }
}

impl From<&EcVrfPrivateKey> for EcVrfPublicKey {
    fn from(private_key: &EcVrfPrivateKey) -> Self {
        EcVrfPublicKey(
            VRF_CONTEXT
                .lock()
                .derive_public_key(&private_key.0)
                .expect("VRF derive public key error"),
        )
    }
}

impl TryFrom<&[u8]> for EcVrfPrivateKey {
    type Error = CryptoMaterialError;

    /// Deserialize an EcVrfPrivateKey. This method will also check for key
    /// validity.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<EcVrfPrivateKey, CryptoMaterialError> {
        // TODO(lpl): Check validation.
        Ok(EcVrfPrivateKey(bytes.to_vec()))
    }
}

impl TryFrom<&[u8]> for EcVrfPublicKey {
    type Error = CryptoMaterialError;

    /// Deserialize an EcVrfPrivateKey. This method will also check for key
    /// validity.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<EcVrfPublicKey, CryptoMaterialError> {
        // TODO(lpl): Check validation
        Ok(EcVrfPublicKey(bytes.to_vec()))
    }
}

impl TryFrom<&[u8]> for EcVrfProof {
    type Error = CryptoMaterialError;

    /// Deserialize an EcVrfPrivateKey. This method will also check for key
    /// validity.
    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<EcVrfProof, CryptoMaterialError> {
        // TODO(lpl): Check validation
        Ok(EcVrfProof(bytes.to_vec()))
    }
}

impl std::hash::Hash for EcVrfPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = self.to_bytes();
        state.write(&encoded_pubkey);
    }
}

impl PartialEq for EcVrfPublicKey {
    fn eq(&self, other: &EcVrfPublicKey) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl std::hash::Hash for EcVrfProof {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = ValidCryptoMaterial::to_bytes(self);
        state.write(&encoded_pubkey);
    }
}

impl PartialEq for EcVrfProof {
    fn eq(&self, other: &EcVrfProof) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl fmt::Display for EcVrfProof {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_encoded_string().map_err(|_| fmt::Error)?)
    }
}

impl Eq for EcVrfPublicKey {}

impl Eq for EcVrfProof {}

impl ValidCryptoMaterial for EcVrfPrivateKey {
    fn to_bytes(&self) -> Vec<u8> { self.0.clone() }
}

impl ValidCryptoMaterial for EcVrfPublicKey {
    fn to_bytes(&self) -> Vec<u8> { self.0.clone() }
}

impl ValidCryptoMaterial for EcVrfProof {
    fn to_bytes(&self) -> Vec<u8> { self.0.clone() }
}

// TODO(lpl): Double check the correctness of key generation.
// Reuse ec group in VRF_CONTEXT?
impl Uniform for EcVrfPrivateKey {
    fn generate<R>(_rng: &mut R) -> Self
    where R: ::rand::RngCore + ::rand::CryptoRng {
        let ec_group = ec::EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        Self(
            ec::EcKey::generate(&ec_group)
                .unwrap()
                .private_key()
                .to_vec(),
        )
    }
}

#[cfg(any(test, feature = "fuzzing"))]
use crate::test_utils::{self, KeyPair};

/// Produces a uniformly random bls keypair from a seed
#[cfg(any(test, feature = "fuzzing"))]
pub fn keypair_strategy(
) -> impl Strategy<Value = KeyPair<EcVrfPrivateKey, EcVrfPublicKey>> {
    test_utils::uniform_keypair_strategy::<EcVrfPrivateKey, EcVrfPublicKey>()
}

#[cfg(any(test, feature = "fuzzing"))]
use proptest::prelude::*;

#[cfg(any(test, feature = "fuzzing"))]
impl proptest::arbitrary::Arbitrary for EcVrfPublicKey {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
        crate::test_utils::uniform_keypair_strategy::<
            EcVrfPrivateKey,
            EcVrfPublicKey,
        >()
        .prop_map(|v| v.public_key)
        .boxed()
    }
}
