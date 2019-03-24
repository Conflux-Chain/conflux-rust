// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{Address, H256};
use hash::keccak;
use std::{convert::AsRef, vec::Vec};

// TODO: from storage_key, recover the db_key for snapshot.
pub enum StorageKey {
    AccountKey(Vec<u8>),
    StorageKey(Vec<u8>),
    CodeKey(Vec<u8>),
}

impl StorageKey {
    const ACCOUNT_BYTES: usize = 20;
    pub const ACCOUNT_HASH_BYTES: usize = 32;
    const ACCOUNT_PADDING_BYTES: usize = 12;
    const CODE_HASH_BYTES: usize = 32;
    const CODE_PREFIX: &'static [u8] = b"code";
    const KEY_BYTES: usize = 32;
    const STORAGE_PREFIX: &'static [u8] = b"data";

    fn new_buffer(uninitialized_size: usize) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(uninitialized_size);
        unsafe { buffer.set_len(uninitialized_size) }

        buffer
    }

    fn compute_address_hash(
        address: &Address,
    ) -> [u8; Self::ACCOUNT_HASH_BYTES] {
        // TODO(yz): change hash padding per snapshot.
        let padding = [0u8; Self::ACCOUNT_PADDING_BYTES];

        // Manually asserting the size.
        let mut padded =
            Self::new_buffer(Self::ACCOUNT_BYTES + Self::ACCOUNT_PADDING_BYTES);
        padded[0..Self::ACCOUNT_PADDING_BYTES].copy_from_slice(&padding);
        padded[Self::ACCOUNT_PADDING_BYTES
            ..Self::ACCOUNT_BYTES + Self::ACCOUNT_PADDING_BYTES]
            .copy_from_slice(address.as_ref());

        let mut address_hash = [0u8; Self::ACCOUNT_HASH_BYTES];
        address_hash[0..Self::ACCOUNT_PADDING_BYTES]
            .copy_from_slice(&keccak(padded)[0..Self::ACCOUNT_PADDING_BYTES]);
        address_hash[Self::ACCOUNT_PADDING_BYTES..Self::ACCOUNT_HASH_BYTES]
            .copy_from_slice(address.as_ref());

        address_hash
    }

    fn extend_address(key: &mut Vec<u8>, address: &Address) {
        let hash = Self::compute_address_hash(address);

        key.extend_from_slice(hash.as_ref());
    }

    pub fn new_account_key(address: &Address) -> StorageKey {
        let mut key = Vec::with_capacity(Self::ACCOUNT_HASH_BYTES);
        Self::extend_address(&mut key, address);

        StorageKey::AccountKey(key)
    }

    fn extend_storage_root(key: &mut Vec<u8>, address: &Address) {
        Self::extend_address(key, address);
        key.extend_from_slice(Self::STORAGE_PREFIX);
    }

    pub fn new_storage_root_key(address: &Address) -> StorageKey {
        let mut key = Vec::with_capacity(
            Self::ACCOUNT_HASH_BYTES + Self::STORAGE_PREFIX.len(),
        );
        Self::extend_storage_root(&mut key, address);

        StorageKey::StorageKey(key)
    }

    pub fn new_storage_key(
        address: &Address, storage_key: &H256,
    ) -> StorageKey {
        let mut key = Vec::with_capacity(
            Self::ACCOUNT_HASH_BYTES
                + Self::STORAGE_PREFIX.len()
                + Self::KEY_BYTES,
        );
        Self::extend_storage_root(&mut key, address);
        key.extend_from_slice(storage_key.as_ref());

        StorageKey::StorageKey(key)
    }

    fn extend_code_root(key: &mut Vec<u8>, address: &Address) {
        Self::extend_address(key, address);
        key.extend_from_slice(Self::CODE_PREFIX);
    }

    pub fn new_code_root_key(address: &Address) -> StorageKey {
        let mut key = Vec::with_capacity(
            Self::ACCOUNT_HASH_BYTES + Self::STORAGE_PREFIX.len(),
        );
        Self::extend_code_root(&mut key, address);

        StorageKey::CodeKey(key)
    }

    pub fn new_code_key(address: &Address, code_hash: &H256) -> StorageKey {
        let mut key = Vec::with_capacity(
            Self::ACCOUNT_HASH_BYTES
                + Self::CODE_PREFIX.len()
                + Self::CODE_HASH_BYTES,
        );
        Self::extend_code_root(&mut key, address);
        key.extend_from_slice(code_hash.as_ref());

        StorageKey::CodeKey(key)
    }
}

impl AsRef<[u8]> for StorageKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            StorageKey::AccountKey(key) => key.as_slice(),
            StorageKey::StorageKey(key) => key.as_slice(),
            StorageKey::CodeKey(key) => key.as_slice(),
        }
    }
}
