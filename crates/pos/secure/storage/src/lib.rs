// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

extern crate rand_08 as rand;

mod crypto_kv_storage;
mod crypto_storage;
mod error;
mod kv_storage;
mod on_disk;

pub use crate::{
    crypto_kv_storage::CryptoKVStorage,
    crypto_storage::{CryptoStorage, PublicKeyResponse},
    error::Error,
    kv_storage::{GetResponse, KVStorage},
    on_disk::OnDiskStorage,
};

// Some common serializations for interacting with bytes these must be manually
// added to types via: #[serde(serialize_with = "to_base64", deserialize_with =
// "from_base64")] some_value: Vec<u8>

pub fn to_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where S: serde::Serializer {
    serializer.serialize_str(&base64::encode(bytes))
}

pub fn from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where D: serde::Deserializer<'de> {
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    base64::decode(s).map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests;
