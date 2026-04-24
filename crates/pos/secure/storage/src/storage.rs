// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/
use crate::{
    CryptoStorage, Error, GetResponse, InMemoryStorage, KVStorage,
    OnDiskStorage, PublicKeyResponse,
};
use diem_types::validator_config::{
    ConsensusPrivateKey, ConsensusPublicKey, ConsensusSignature,
};
use enum_dispatch::enum_dispatch;
use serde::{de::DeserializeOwned, Serialize};

/// This is the Diem interface into secure storage. Any storage engine
/// implementing this trait should support both key/value operations (e.g., get,
/// set and create) and cryptographic key operations (e.g., generate_key, sign
/// and rotate_key).
///
/// `InMemoryStorage` is only here for tests that instantiate
/// `Storage::from(InMemoryStorage::new())` directly; production uses
/// `OnDiskStorage`.
#[enum_dispatch(KVStorage, CryptoStorage)]
pub enum Storage {
    InMemoryStorage(InMemoryStorage),
    OnDiskStorage(OnDiskStorage),
}
