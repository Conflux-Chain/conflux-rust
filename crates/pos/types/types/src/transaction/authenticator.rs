// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::account_address::AccountAddress;
use anyhow::{bail, ensure, Error, Result};
use diem_crypto::{
    bls::{
        BLSPublicKey, BLSPublicKeyUnchecked, BLSSignature,
        BLSSignatureUnchecked,
    },
    hash::CryptoHash,
    multi_bls::MultiBLSSignature,
    traits::Signature,
    CryptoMaterialError, HashValue, ValidCryptoMaterial,
    ValidCryptoMaterialStringExt,
};
use diem_crypto_derive::{CryptoHasher, DeserializeKey, SerializeKey};
#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt, str::FromStr};

/// A `TransactionAuthenticator` is an abstraction of a signature scheme. It
/// verifies a signature against the signed message and exposes the raw
/// public key bytes used to build an `AuthenticationKeyPreimage` when the
/// variant has per-transaction public key material.
/// Conflux PoS does not store Diem-style authentication keys on chain. For
/// BLS PoS transactions entering the mempool (locally submitted or
/// peer-broadcast), validation binds `sender` to the BLS key carried by the
/// authenticator via `PosState::check_sender_owns_auth_key`.
/// Signature well-formedness is checked by `TransactionAuthenticator::verify`
/// (via `SignedTransaction::verify_signature`); sender-to-key binding is
/// enforced separately in the mempool `TransactionValidator` /
/// `PosState::check_sender_owns_auth_key`, which requires the authenticator's
/// BLS public key to equal `node_map[sender].public_key`. There is no
/// executor-side preimage-hash-to-auth-key match.

// TODO: in the future, can tie these to the TransactionAuthenticator enum directly with https://github.com/rust-lang/rust/issues/60553
//
// Discriminants must mirror the matching `TransactionAuthenticator` BCS
// tag — `AuthenticationKeyPreimage::new` appends `scheme as u8`.
#[derive(Debug)]
#[repr(u8)]
#[non_exhaustive]
pub enum Scheme {
    /// BCS tag 0 (ex-Ed25519, never used in Conflux PoS).
    ReservedEd25519 = 0,
    /// BCS tag 1 (ex-MultiEd25519, never used in Conflux PoS).
    ReservedMultiEd25519 = 1,
    BLS = 2,
    MultiBLS = 3,
    // ... add more schemes here
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let display = match self {
            Scheme::ReservedEd25519 => "reserved_ed25519",
            Scheme::ReservedMultiEd25519 => "reserved_multi_ed25519",
            Scheme::BLS => "bls",
            Scheme::MultiBLS => "multi_bls",
        };
        write!(f, "Scheme::{}", display)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum TransactionAuthenticator {
    /// Reserved (was Ed25519, never used in Conflux PoS). Kept for BCS index
    /// compat.
    _ReservedEd25519,
    /// Reserved (was MultiEd25519, never used in Conflux PoS). Kept for BCS
    /// index compat.
    _ReservedMultiEd25519,
    /// BLS signature
    BLS {
        public_key: BLSPublicKey,
        signature: BLSSignature,
    },
    MultiBLS {
        signature: MultiBLSSignature,
    }, // ... add more schemes here
}

#[derive(Deserialize)]
pub enum TransactionAuthenticatorUnchecked {
    /// Reserved (was Ed25519, never used in Conflux PoS). Kept for BCS index
    /// compat.
    _ReservedEd25519,
    /// Reserved (was MultiEd25519, never used in Conflux PoS). Kept for BCS
    /// index compat.
    _ReservedMultiEd25519,
    BLS {
        public_key: BLSPublicKeyUnchecked,
        signature: BLSSignatureUnchecked,
    },
    MultiBLS {
        signature: MultiBLSSignature,
    },
}

impl From<TransactionAuthenticatorUnchecked> for TransactionAuthenticator {
    fn from(t: TransactionAuthenticatorUnchecked) -> Self {
        match t {
            TransactionAuthenticatorUnchecked::_ReservedEd25519 => {
                Self::_ReservedEd25519
            }
            TransactionAuthenticatorUnchecked::_ReservedMultiEd25519 => {
                Self::_ReservedMultiEd25519
            }
            TransactionAuthenticatorUnchecked::BLS {
                public_key,
                signature,
            } => Self::BLS {
                public_key: public_key.into(),
                signature: signature.into(),
            },
            TransactionAuthenticatorUnchecked::MultiBLS { signature } => {
                Self::MultiBLS { signature }
            }
        }
    }
}

impl TransactionAuthenticator {
    /// Unique identifier for the signature scheme.
    pub fn scheme(&self) -> Scheme {
        match self {
            Self::_ReservedEd25519 => Scheme::ReservedEd25519,
            Self::_ReservedMultiEd25519 => Scheme::ReservedMultiEd25519,
            Self::BLS { .. } => Scheme::BLS,
            Self::MultiBLS { .. } => Scheme::MultiBLS,
        }
    }

    pub fn bls(public_key: BLSPublicKey, signature: BLSSignature) -> Self {
        Self::BLS {
            public_key,
            signature,
        }
    }

    pub fn multi_bls(signature: MultiBLSSignature) -> Self {
        Self::MultiBLS { signature }
    }

    /// Return Ok if the authenticator's public key matches its signature, Err
    /// otherwise. Reserved variants always return Err (Byzantine input
    /// must not crash the executor).
    pub fn verify<T: Serialize + CryptoHash>(&self, message: &T) -> Result<()> {
        match self {
            Self::_ReservedEd25519 | Self::_ReservedMultiEd25519 => {
                bail!("reserved authenticator variant has no signature")
            }
            Self::BLS {
                public_key,
                signature,
            } => signature.verify(message, public_key),
            Self::MultiBLS { .. } => {
                // we will verify this case in pos state
                Ok(())
            }
        }
    }

    /// Return the raw bytes of `self.public_key`. MultiBLS has no per-tx
    /// pubkey (the verifying set lives on the committee); Reserved
    /// variants have no signature material at all.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::_ReservedEd25519 | Self::_ReservedMultiEd25519 => Vec::new(),
            Self::BLS { public_key, .. } => public_key.to_bytes().to_vec(),
            Self::MultiBLS { .. } => Vec::new(),
        }
    }

    /// Return the raw bytes of `self.signature`
    pub fn signature_bytes(&self) -> Vec<u8> {
        match self {
            Self::_ReservedEd25519 | Self::_ReservedMultiEd25519 => Vec::new(),
            Self::BLS { signature, .. } => signature.to_bytes().to_vec(),
            Self::MultiBLS { signature } => signature.to_bytes(),
        }
    }

    /// Return an authentication key preimage derived from `self`'s public key
    /// and scheme id
    pub fn authentication_key_preimage(&self) -> AuthenticationKeyPreimage {
        AuthenticationKeyPreimage::new(self.public_key_bytes(), self.scheme())
    }

    /// Return an authentication key derived from `self`'s public key and scheme
    /// id
    pub fn authentication_key(&self) -> AuthenticationKey {
        AuthenticationKey::from_preimage(&self.authentication_key_preimage())
    }
}

/// A struct that represents an account authentication key. An account's address
/// is the last 16 bytes of authentication key used to create it
#[derive(
    Clone,
    Copy,
    CryptoHasher,
    Debug,
    DeserializeKey,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    SerializeKey,
)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct AuthenticationKey([u8; AuthenticationKey::LENGTH]);

impl AuthenticationKey {
    /// The number of bytes in an authentication key.
    pub const LENGTH: usize = 32;

    /// Create an authentication key from `bytes`
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self { Self(bytes) }

    /// Create an authentication key from a preimage by taking its sha3 hash
    pub fn from_preimage(
        preimage: &AuthenticationKeyPreimage,
    ) -> AuthenticationKey {
        AuthenticationKey::new(*HashValue::sha3_256_of(&preimage.0).as_ref())
    }

    /// Return an address derived from the last `AccountAddress::LENGTH` bytes
    /// of this authentication key.
    pub fn derived_address(&self) -> AccountAddress {
        // keep only last 16 bytes
        let mut array = [0u8; AccountAddress::LENGTH];
        array.copy_from_slice(&self.0[Self::LENGTH - AccountAddress::LENGTH..]);
        AccountAddress::new(array)
    }

    /// Return the first AccountAddress::LENGTH bytes of this authentication key
    pub fn prefix(&self) -> [u8; AccountAddress::LENGTH] {
        let mut array = [0u8; AccountAddress::LENGTH];
        array.copy_from_slice(&self.0[..AccountAddress::LENGTH]);
        array
    }

    /// Construct a vector from this authentication key
    pub fn to_vec(&self) -> Vec<u8> { self.0.to_vec() }

    /// Create a random authentication key. For testing only
    pub fn random() -> Self {
        let mut rng = OsRng;
        let buf: [u8; Self::LENGTH] = rng.gen();
        AuthenticationKey::new(buf)
    }
}

impl ValidCryptoMaterial for AuthenticationKey {
    fn to_bytes(&self) -> Vec<u8> { self.to_vec() }
}

/// A value that can be hashed to produce an authentication key
pub struct AuthenticationKeyPreimage(Vec<u8>);

impl AuthenticationKeyPreimage {
    /// Return bytes for (public_key | scheme_id)
    fn new(mut public_key_bytes: Vec<u8>, scheme: Scheme) -> Self {
        public_key_bytes.push(scheme as u8);
        Self(public_key_bytes)
    }

    /// Construct a vector from this authentication key
    pub fn into_vec(self) -> Vec<u8> { self.0 }
}

impl fmt::Display for TransactionAuthenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TransactionAuthenticator[scheme id: {:?}, public key: {}, signature: {}]",
            self.scheme(),
            hex::encode(&self.public_key_bytes()),
            hex::encode(&self.signature_bytes())
        )
    }
}

impl TryFrom<&[u8]> for AuthenticationKey {
    type Error = CryptoMaterialError;

    fn try_from(
        bytes: &[u8],
    ) -> std::result::Result<AuthenticationKey, CryptoMaterialError> {
        if bytes.len() != Self::LENGTH {
            return Err(CryptoMaterialError::WrongLengthError);
        }
        let mut addr = [0u8; Self::LENGTH];
        addr.copy_from_slice(bytes);
        Ok(AuthenticationKey(addr))
    }
}

impl TryFrom<Vec<u8>> for AuthenticationKey {
    type Error = CryptoMaterialError;

    fn try_from(
        bytes: Vec<u8>,
    ) -> std::result::Result<AuthenticationKey, CryptoMaterialError> {
        AuthenticationKey::try_from(&bytes[..])
    }
}

impl FromStr for AuthenticationKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        ensure!(
            !s.is_empty(),
            "authentication key string should not be empty.",
        );
        let bytes_out = ::hex::decode(s)?;
        let key = AuthenticationKey::try_from(bytes_out.as_slice())?;
        Ok(key)
    }
}

impl AsRef<[u8]> for AuthenticationKey {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl fmt::LowerHex for AuthenticationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl fmt::Display for AuthenticationKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> std::fmt::Result {
        // Forward to the LowerHex impl with a "0x" prepended (the # flag).
        write!(f, "{:#x}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::{Scheme, TransactionAuthenticator};
    use crate::{
        account_address::AccountAddress,
        transaction::{
            authenticator::AuthenticationKey, RawTransaction, RetirePayload,
        },
    };
    use std::str::FromStr;

    #[test]
    fn test_from_str_should_not_panic_by_given_empty_string() {
        assert!(AuthenticationKey::from_str("").is_err());
    }

    // Regression: a Byzantine PoS proposer can BCS-decode a block
    // payload into a `_Reserved*` variant; `verify()` must Err, not
    // panic.
    #[test]
    fn reserved_authenticator_verify_returns_err_not_panic() {
        let raw_txn = RawTransaction::new_retire(
            AccountAddress::ZERO,
            RetirePayload {
                node_id: AccountAddress::ZERO,
                votes: 0,
            },
        );

        for auth in [
            TransactionAuthenticator::_ReservedEd25519,
            TransactionAuthenticator::_ReservedMultiEd25519,
        ] {
            let err = auth.verify(&raw_txn).unwrap_err();
            assert!(
                err.to_string().contains("reserved"),
                "expected 'reserved' in error, got: {}",
                err,
            );
        }
    }

    #[test]
    fn reserved_authenticator_accessors_are_panic_free() {
        let auth_a = TransactionAuthenticator::_ReservedEd25519;
        let auth_b = TransactionAuthenticator::_ReservedMultiEd25519;

        // Distinct scheme bytes keep preimages distinct across variants.
        assert!(matches!(auth_a.scheme(), Scheme::ReservedEd25519));
        assert!(matches!(auth_b.scheme(), Scheme::ReservedMultiEd25519));
        assert_ne!(auth_a.scheme() as u8, auth_b.scheme() as u8);
        assert!(auth_a.public_key_bytes().is_empty());
        assert!(auth_a.signature_bytes().is_empty());
        assert!(auth_b.public_key_bytes().is_empty());
        assert!(auth_b.signature_bytes().is_empty());
    }
}
