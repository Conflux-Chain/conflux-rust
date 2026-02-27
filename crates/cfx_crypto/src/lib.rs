// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.
//
// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2020 Parity Technologies
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub mod crypto;

use lazy_static::lazy_static;

lazy_static! {
    pub static ref SECP256K1: secp256k1::Secp256k1 =
        secp256k1::Secp256k1::new();
}

/// Trait for secret key types used in cryptographic operations.
pub trait SecretKey: AsRef<[u8]> {
    /// Create a secret key from an unsafe slice (may not be validated).
    /// Returns an error if the slice is invalid.
    fn from_unsafe_slice(bytes: &[u8]) -> Result<Self, crypto::Error>
    where Self: Sized;
}

/// Trait for keypair types that can generate random keypairs.
pub trait KeyPair {
    type Secret: SecretKey;
    type Public: AsRef<[u8]>;

    /// Get the secret key.
    fn secret(&self) -> &Self::Secret;
    /// Get the public key.
    fn public(&self) -> &Self::Public;
}

/// Trait for generating random keypairs.
pub trait RandomKeyPairGenerator {
    type KeyPair: KeyPair;
    type Error;

    /// Generate a random keypair.
    fn generate(&mut self) -> Result<Self::KeyPair, Self::Error>;
}
