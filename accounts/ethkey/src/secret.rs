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

use ethereum_types::H256;
use rustc_hex::ToHex;
use secp256k1::{constants::SECRET_KEY_SIZE as SECP256K1_SECRET_KEY_SIZE, key};
use std::{fmt, ops::Deref, str::FromStr};
use zeroize::Zeroize;
use Error;
use SECP256K1;

#[derive(Clone, PartialEq, Eq)]
pub struct Secret {
    inner: H256,
}

impl Drop for Secret {
    fn drop(&mut self) { self.inner.0.zeroize() }
}

impl ToHex for Secret {
    fn to_hex(&self) -> String { format!("{:x}", self.inner) }
}

impl fmt::LowerHex for Secret {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(fmt)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(fmt)
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "Secret: 0x{:x}{:x}..{:x}{:x}",
            self.inner[0], self.inner[1], self.inner[30], self.inner[31]
        )
    }
}

impl Secret {
    /// Creates a `Secret` from the given slice, returning `None` if the slice
    /// length != 32.
    pub fn from_slice(key: &[u8]) -> Option<Self> {
        if key.len() != 32 {
            return None;
        }
        let mut h = H256::zero();
        h.as_bytes_mut().copy_from_slice(&key[0..32]);
        Some(Secret { inner: h })
    }

    /// Creates zero key, which is invalid for crypto operations, but valid for
    /// math operation.
    pub fn zero() -> Self {
        Secret {
            inner: H256::zero(),
        }
    }

    /// Imports and validates the key.
    pub fn from_unsafe_slice(key: &[u8]) -> Result<Self, Error> {
        let secret = key::SecretKey::from_slice(&super::SECP256K1, key)?;
        Ok(secret.into())
    }

    /// Checks validity of this key.
    pub fn check_validity(&self) -> Result<(), Error> {
        self.to_secp256k1_secret().map(|_| ())
    }

    /// Inplace add one secret key to another (scalar + scalar)
    pub fn add(&mut self, other: &Secret) -> Result<(), Error> {
        match (self.is_zero(), other.is_zero()) {
            (true, true) | (false, true) => Ok(()),
            (true, false) => {
                *self = other.clone();
                Ok(())
            }
            (false, false) => {
                let mut key_secret = self.to_secp256k1_secret()?;
                let other_secret = other.to_secp256k1_secret()?;
                key_secret.add_assign(&SECP256K1, &other_secret)?;

                *self = key_secret.into();
                Ok(())
            }
        }
    }

    /// Inplace subtract one secret key from another (scalar - scalar)
    pub fn sub(&mut self, other: &Secret) -> Result<(), Error> {
        match (self.is_zero(), other.is_zero()) {
            (true, true) | (false, true) => Ok(()),
            (true, false) => {
                *self = other.clone();
                self.neg()
            }
            (false, false) => {
                let mut key_secret = self.to_secp256k1_secret()?;
                let mut other_secret = other.to_secp256k1_secret()?;
                other_secret.mul_assign(&SECP256K1, &key::MINUS_ONE_KEY)?;
                key_secret.add_assign(&SECP256K1, &other_secret)?;

                *self = key_secret.into();
                Ok(())
            }
        }
    }

    /// Inplace decrease secret key (scalar - 1)
    pub fn dec(&mut self) -> Result<(), Error> {
        match self.is_zero() {
            true => {
                *self = key::MINUS_ONE_KEY.into();
                Ok(())
            }
            false => {
                let mut key_secret = self.to_secp256k1_secret()?;
                key_secret.add_assign(&SECP256K1, &key::MINUS_ONE_KEY)?;

                *self = key_secret.into();
                Ok(())
            }
        }
    }

    /// Inplace multiply one secret key to another (scalar * scalar)
    pub fn mul(&mut self, other: &Secret) -> Result<(), Error> {
        match (self.is_zero(), other.is_zero()) {
            (true, true) | (true, false) => Ok(()),
            (false, true) => {
                *self = Self::zero();
                Ok(())
            }
            (false, false) => {
                let mut key_secret = self.to_secp256k1_secret()?;
                let other_secret = other.to_secp256k1_secret()?;
                key_secret.mul_assign(&SECP256K1, &other_secret)?;

                *self = key_secret.into();
                Ok(())
            }
        }
    }

    /// Inplace negate secret key (-scalar)
    pub fn neg(&mut self) -> Result<(), Error> {
        match self.is_zero() {
            true => Ok(()),
            false => {
                let mut key_secret = self.to_secp256k1_secret()?;
                key_secret.mul_assign(&SECP256K1, &key::MINUS_ONE_KEY)?;

                *self = key_secret.into();
                Ok(())
            }
        }
    }

    /// Inplace inverse secret key (1 / scalar)
    pub fn inv(&mut self) -> Result<(), Error> {
        let mut key_secret = self.to_secp256k1_secret()?;
        key_secret.inv_assign(&SECP256K1)?;

        *self = key_secret.into();
        Ok(())
    }

    /// Compute power of secret key inplace (secret ^ pow).
    /// This function is not intended to be used with large powers.
    pub fn pow(&mut self, pow: usize) -> Result<(), Error> {
        if self.is_zero() {
            return Ok(());
        }

        match pow {
            0 => *self = key::ONE_KEY.into(),
            1 => (),
            _ => {
                let c = self.clone();
                for _ in 1..pow {
                    self.mul(&c)?;
                }
            }
        }

        Ok(())
    }

    /// Create `secp256k1::key::SecretKey` based on this secret
    pub fn to_secp256k1_secret(&self) -> Result<key::SecretKey, Error> {
        Ok(key::SecretKey::from_slice(&SECP256K1, &self[..])?)
    }
}

impl FromStr for Secret {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(H256::from_str(s)
            .map_err(|e| Error::Custom(format!("{:?}", e)))?
            .into())
    }
}

impl From<[u8; 32]> for Secret {
    fn from(k: [u8; 32]) -> Self { Secret { inner: H256(k) } }
}

impl From<H256> for Secret {
    fn from(s: H256) -> Self { s.0.into() }
}

impl From<&'static str> for Secret {
    fn from(s: &'static str) -> Self {
        s.parse().expect(&format!(
            "invalid string literal for {}: '{}'",
            stringify!(Self),
            s
        ))
    }
}

impl From<key::SecretKey> for Secret {
    fn from(key: key::SecretKey) -> Self {
        let mut a = [0; SECP256K1_SECRET_KEY_SIZE];
        a.copy_from_slice(&key[0..SECP256K1_SECRET_KEY_SIZE]);
        a.into()
    }
}

impl Deref for Secret {
    type Target = H256;

    fn deref(&self) -> &Self::Target { &self.inner }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{Generator, Random},
        Secret,
    };
    use std::str::FromStr;

    #[test]
    fn multiplicating_secret_inversion_with_secret_gives_one() {
        let secret = Random.generate().unwrap().secret().clone();
        let mut inversion = secret.clone();
        inversion.inv().unwrap();
        inversion.mul(&secret).unwrap();
        assert_eq!(inversion, Secret::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap());
    }

    #[test]
    fn secret_inversion_is_reversible_with_inversion() {
        let secret = Random.generate().unwrap().secret().clone();
        let mut inversion = secret.clone();
        inversion.inv().unwrap();
        inversion.inv().unwrap();
        assert_eq!(inversion, secret);
    }

    #[test]
    fn secret_pow() {
        let secret = Random.generate().unwrap().secret().clone();

        let mut pow0 = secret.clone();
        pow0.pow(0).unwrap();
        assert_eq!(pow0, Secret::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap());

        let mut pow1 = secret.clone();
        pow1.pow(1).unwrap();
        assert_eq!(pow1, secret);

        let mut pow2 = secret.clone();
        pow2.pow(2).unwrap();
        let mut pow2_expected = secret.clone();
        pow2_expected.mul(&secret).unwrap();
        assert_eq!(pow2, pow2_expected);

        let mut pow3 = secret.clone();
        pow3.pow(3).unwrap();
        let mut pow3_expected = secret.clone();
        pow3_expected.mul(&secret).unwrap();
        pow3_expected.mul(&secret).unwrap();
        assert_eq!(pow3, pow3_expected);
    }
}
