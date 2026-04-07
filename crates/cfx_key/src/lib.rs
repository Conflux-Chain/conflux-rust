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

// #![warn(missing_docs)]

mod brain;
mod brain_prefix;
mod error;
mod extended;
mod keypair;
mod password;
mod prefix;
mod random;
mod secret;
mod signature;

pub mod brain_recover;
pub mod crypto;
pub mod math;

use cfx_crypto::{
    KeyPair as CryptoKeyPair,
    RandomKeyPairGenerator as CryptoRandomKeyPairGenerator,
};

use lazy_static::lazy_static;
pub use parity_wordlist::Error as WordlistError;

pub use self::{
    brain::Brain,
    brain_prefix::BrainPrefix,
    error::Error,
    extended::{
        Derivation, DerivationError, ExtendedKeyPair, ExtendedPublic,
        ExtendedSecret,
    },
    keypair::{is_compatible_public, public_to_address, KeyPair},
    math::public_is_valid,
    password::Password,
    prefix::Prefix,
    random::Random,
    secret::Secret,
    signature::{recover, sign, verify_address, verify_public, Signature},
    KeyPairGenerator as Generator,
};

use cfx_types::H256;

pub use cfx_types::{Address, Public};
pub type Message = H256;

lazy_static! {
    pub static ref SECP256K1: secp256k1::Secp256k1 =
        secp256k1::Secp256k1::new();
}

/// Uninstantiatable error type for infallible generators.
#[derive(Debug)]
pub enum Void {}

/// Generates new keypair.
pub trait KeyPairGenerator {
    type Error;

    /// Should be called to generate new keypair.
    fn generate(&mut self) -> Result<KeyPair, Self::Error>;
}

// Implement crypto traits for our types
// Note: CryptoSecretKey is implemented in secret.rs to avoid conflicts
// Note: We can't implement CryptoPublicKey for Public directly due to orphan
// rules, so we'll use a wrapper approach in the crypto compatibility layer

impl CryptoKeyPair for KeyPair {
    type Public = Public;
    type Secret = Secret;

    fn secret(&self) -> &Self::Secret { self.secret() }

    fn public(&self) -> &Self::Public { self.public() }
}

impl CryptoRandomKeyPairGenerator for Random {
    type Error = std::io::Error;
    type KeyPair = KeyPair;

    fn generate(&mut self) -> Result<Self::KeyPair, Self::Error> {
        KeyPairGenerator::generate(self)
    }
}
