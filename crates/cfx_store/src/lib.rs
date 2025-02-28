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

//! Ethereum key-management.

#![warn(missing_docs)]

pub use parity_crypto as crypto;
pub use parity_wordlist::random_phrase;

mod account;
pub mod accounts_dir;
pub mod cfxkey;
mod cfxstore;
mod error;
mod import;
mod json;
mod presale;
mod random;
mod secret_store;

pub use self::{
    account::{Crypto, SafeAccount},
    cfxstore::{CfxMultiStore, CfxStore},
    error::Error,
    import::{import_account, import_accounts, read_geth_accounts},
    json::OpaqueKeyFile as KeyFile,
    presale::PresaleWallet,
    random::random_string,
    secret_store::{
        Derivation, IndexDerivation, SecretStore, SecretVaultRef,
        SimpleSecretStore, StoreAccountRef,
    },
};

/// An opaque wrapper for secret.
pub struct OpaqueSecret(::cfxkey::Secret);
