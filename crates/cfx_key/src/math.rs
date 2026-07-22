// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

use super::{Error, Public, Secret};
use cfx_types::{BigEndianHash as _, H256, U256};
use secp256k1::{
    constants::{CURVE_ORDER, GENERATOR_X, GENERATOR_Y},
    PublicKey, Scalar, SECP256K1,
};

/// Whether the public key is valid (parses as a non-infinity secp256k1 point).
pub fn public_is_valid(public: &Public) -> bool {
    public_to_pubkey(public).is_ok()
}

/// Inplace multiply public key by secret key (EC point * scalar)
pub fn public_mul_secret(
    public: &mut Public, secret: &Secret,
) -> Result<(), Error> {
    let key_secret = secret.to_secp256k1_secret()?;
    let key_public = public_to_pubkey(public)?;
    let res = key_public.mul_tweak(SECP256K1, &Scalar::from(key_secret))?;
    *public = pubkey_to_public(&res);
    Ok(())
}

/// Inplace add one public key to another (EC point + EC point)
pub fn public_add(public: &mut Public, other: &Public) -> Result<(), Error> {
    let key_public = public_to_pubkey(public)?;
    let other_public = public_to_pubkey(other)?;
    let res = key_public.combine(&other_public)?;
    *public = pubkey_to_public(&res);
    Ok(())
}

/// Inplace sub one public key from another (EC point - EC point)
pub fn public_sub(public: &mut Public, other: &Public) -> Result<(), Error> {
    let key_other = public_to_pubkey(other)?;
    let key_public = public_to_pubkey(public)?;
    let res = key_public.combine(&key_other.negate(SECP256K1))?;
    *public = pubkey_to_public(&res);
    Ok(())
}

/// Replace public key with its negation (EC point = - EC point)
pub fn public_negate(public: &mut Public) -> Result<(), Error> {
    let key_public = public_to_pubkey(public)?;
    *public = pubkey_to_public(&key_public.negate(SECP256K1));
    Ok(())
}

/// Return base point of secp256k1
pub fn generation_point() -> Public {
    let mut public_sec_raw = [0u8; 65];
    public_sec_raw[0] = 4;
    public_sec_raw[1..33].copy_from_slice(&GENERATOR_X);
    public_sec_raw[33..65].copy_from_slice(&GENERATOR_Y);

    let public_key = PublicKey::from_slice(&public_sec_raw)
        .expect("constructing using predefined constants; qed");
    pubkey_to_public(&public_key)
}

/// Return secp256k1 elliptic curve order
pub fn curve_order() -> U256 { H256::from_slice(&CURVE_ORDER).into_uint() }

/// Convert a Conflux 64-byte uncompressed public key into a libsecp256k1
/// `PublicKey` by prepending the SEC1 `0x04` tag.
pub(crate) fn public_to_pubkey(public: &Public) -> Result<PublicKey, Error> {
    let mut buf = [4u8; 65];
    buf[1..65].copy_from_slice(&public[0..64]);
    Ok(PublicKey::from_slice(&buf)?)
}

/// Serialize a libsecp256k1 `PublicKey` into a Conflux 64-byte uncompressed
/// `Public` (drops the leading SEC1 tag).
pub(crate) fn pubkey_to_public(pk: &PublicKey) -> Public {
    let serialized = pk.serialize_uncompressed();
    let mut public = Public::default();
    public.as_bytes_mut().copy_from_slice(&serialized[1..65]);
    public
}

#[cfg(test)]
mod tests {
    use super::{
        super::{KeyPairGenerator, Public, Random},
        public_add, public_is_valid, public_sub,
    };

    #[test]
    fn zero_public_is_rejected() {
        // The zero (64-byte) public maps to the SEC1-uncompressed point
        // (x=0, y=0), which does not satisfy y² = x³ + 7 (mod p) and is
        // therefore not on the secp256k1 curve. libsecp256k1 must reject it
        // — confirming that `public_is_valid` does not need an explicit
        // zero-byte check on top of `PublicKey::from_slice`.
        assert!(!public_is_valid(&Public::zero()));
    }

    #[test]
    fn public_addition_is_commutative() {
        let public1 = Random.generate().unwrap().public().clone();
        let public2 = Random.generate().unwrap().public().clone();

        let mut left = public1.clone();
        public_add(&mut left, &public2).unwrap();

        let mut right = public2.clone();
        public_add(&mut right, &public1).unwrap();

        assert_eq!(left, right);
    }

    #[test]
    fn public_addition_is_reversible_with_subtraction() {
        let public1 = Random.generate().unwrap().public().clone();
        let public2 = Random.generate().unwrap().public().clone();

        let mut sum = public1.clone();
        public_add(&mut sum, &public2).unwrap();
        public_sub(&mut sum, &public2).unwrap();

        assert_eq!(sum, public1);
    }
}
