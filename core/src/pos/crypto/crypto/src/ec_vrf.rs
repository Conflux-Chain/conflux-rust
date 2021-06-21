use crate::{
    CryptoMaterialError, HashValue, PrivateKey, PublicKey, VRFPrivateKey,
    VRFProof, VRFPublicKey, ValidCryptoMaterial, ValidCryptoMaterialStringExt,
};
use anyhow::{anyhow, Result};
use diem_crypto_derive::{
    DeserializeKey, SerializeKey, SilentDebug, SilentDisplay,
};
use lazy_static::lazy_static;
use parking_lot::Mutex;
use std::convert::TryFrom;
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

#[cfg(not(mirai))]
struct ValidatedPublicKeyTag {}

/// Elliptic Curve VRF private key
#[derive(DeserializeKey, SerializeKey, SilentDebug, SilentDisplay)]
pub struct EcVrfPrivateKey(Vec<u8>);

/// Elliptic Curve VRF public key
#[derive(DeserializeKey, Clone, SerializeKey, Debug, PartialEq)]
pub struct EcVrfPublicKey(Vec<u8>);

/// Elliptic Curve VRF proof
#[derive(DeserializeKey, Clone, SerializeKey, Debug, PartialEq)]
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

impl std::hash::Hash for EcVrfProof {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_pubkey = ValidCryptoMaterial::to_bytes(self);
        state.write(&encoded_pubkey);
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
