// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// The original StorageKeys unprocessed, in contrary to StorageKey which is
// processed to use in DeltaMpt.
#[derive(Debug, Clone, Copy)]
pub enum StorageKey<'a> {
    AccountKey(&'a Address),
    StorageRootKey(&'a Address),
    StorageKey {
        address: &'a Address,
        storage_key: &'a [u8],
    },
    CodeRootKey(&'a Address),
    CodeKey {
        address: &'a Address,
        code_hash: &'a H256,
    },
}

impl<'a> StorageKey<'a> {
    pub fn new_account_key(address: &'a Address) -> Self {
        StorageKey::AccountKey(address)
    }

    pub fn new_storage_root_key(address: &'a Address) -> Self {
        StorageKey::StorageRootKey(address)
    }

    pub fn new_storage_key(
        address: &'a Address, storage_key: &'a [u8],
    ) -> Self {
        StorageKey::StorageKey {
            address,
            storage_key,
        }
    }

    pub fn new_code_root_key(address: &'a Address) -> Self {
        StorageKey::CodeRootKey(address)
    }

    pub fn new_code_key(address: &'a Address, code_hash: &'a H256) -> Self {
        StorageKey::CodeKey { address, code_hash }
    }
}

// Conversion methods.
impl<'a> StorageKey<'a> {
    const ACCOUNT_BYTES: usize = 20;
    const CODE_HASH_BYTES: usize = 32;
    const CODE_HASH_PREFIX: &'static [u8] = b"code";
    const STORAGE_PREFIX: &'static [u8] = b"data";

    pub fn to_delta_mpt_key_bytes(&self, padding: &KeyPadding) -> Vec<u8> {
        match self {
            StorageKey::AccountKey(address) => {
                delta_mpt_storage_key::new_account_key(address, padding)
            }
            StorageKey::StorageRootKey(address) => {
                delta_mpt_storage_key::new_storage_root_key(address, padding)
            }
            StorageKey::StorageKey {
                address,
                storage_key,
            } => delta_mpt_storage_key::new_storage_key(
                address,
                storage_key,
                padding,
            ),
            StorageKey::CodeRootKey(address) => {
                delta_mpt_storage_key::new_code_root_key(address, padding)
            }
            StorageKey::CodeKey { address, code_hash } => {
                delta_mpt_storage_key::new_code_key(address, code_hash, padding)
            }
        }
    }

    pub fn to_key_bytes(&self) -> Vec<u8> {
        match self {
            StorageKey::AccountKey(address) => {
                let mut key = Vec::with_capacity(Self::ACCOUNT_BYTES);
                key.extend_from_slice(&address.0);

                key
            }
            StorageKey::StorageRootKey(address) => {
                let mut key = Vec::with_capacity(
                    Self::ACCOUNT_BYTES + Self::STORAGE_PREFIX.len(),
                );
                key.extend_from_slice(&address.0);
                key.extend_from_slice(Self::STORAGE_PREFIX);

                key
            }
            StorageKey::StorageKey {
                address,
                storage_key,
            } => {
                let mut key = Vec::with_capacity(
                    Self::ACCOUNT_BYTES
                        + Self::STORAGE_PREFIX.len()
                        + storage_key.len(),
                );
                key.extend_from_slice(&address.0);
                key.extend_from_slice(Self::STORAGE_PREFIX);
                key.extend_from_slice(storage_key);

                key
            }
            StorageKey::CodeRootKey(address) => {
                let mut key = Vec::with_capacity(
                    Self::ACCOUNT_BYTES + Self::CODE_HASH_PREFIX.len(),
                );
                key.extend_from_slice(&address.0);
                key.extend_from_slice(Self::CODE_HASH_PREFIX);

                key
            }
            StorageKey::CodeKey { address, code_hash } => {
                let mut key = Vec::with_capacity(
                    Self::ACCOUNT_BYTES
                        + Self::CODE_HASH_PREFIX.len()
                        + Self::CODE_HASH_BYTES,
                );
                key.extend_from_slice(&address.0);
                key.extend_from_slice(Self::CODE_HASH_PREFIX);
                key.extend_from_slice(&code_hash.0);

                key
            }
        }
    }

    // FIXME: in order to support this method, all refs kept must be &[u8]
    pub fn from_key_bytes(_bytes: &[u8]) -> Self { unimplemented!() }
}

/// The padding is uniquely generated for DeltaMPT at each intermediate epoch,
/// and it's used to compute padding bytes for address and storage_key. The
/// padding setup is against an attack where adversary artificially build deep
/// paths in MPT.
pub type KeyPadding = [u8; delta_mpt_storage_key::KEY_PADDING_BYTES];
pub use delta_mpt_storage_key::KEY_PADDING_BYTES;
lazy_static! {
    pub static ref GENESIS_DELTA_MPT_KEY_PADDING: KeyPadding =
        DeltaMpt::padding(&MERKLE_NULL_NODE, &MERKLE_NULL_NODE);
}

mod delta_mpt_storage_key {
    use super::*;
    use cfx_types::{Address, H160};

    impl<'a> StorageKey<'a> {
        pub fn from_delta_mpt_key(_delta_mpt_key: &'a [u8]) -> StorageKey<'a> {
            unimplemented!()
        }
    }

    pub const ACCOUNT_KEYPART_BYTES: usize = 32;
    const ACCOUNT_PADDING_BYTES: usize = 12;
    pub const KEY_PADDING_BYTES: usize = 32;

    fn new_buffer(uninitialized_size: usize) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(uninitialized_size);
        unsafe { buffer.set_len(uninitialized_size) }

        buffer
    }

    fn compute_address_keypart(
        address: &Address, padding: &KeyPadding,
    ) -> [u8; ACCOUNT_KEYPART_BYTES] {
        // Manually asserting the size by using new_buffer instead of
        // Vec#extend_from_slice.
        let mut padded =
            new_buffer(StorageKey::ACCOUNT_BYTES + ACCOUNT_PADDING_BYTES);
        padded[0..ACCOUNT_PADDING_BYTES].copy_from_slice(&padding[..]);
        padded[ACCOUNT_PADDING_BYTES
            ..StorageKey::ACCOUNT_BYTES + ACCOUNT_PADDING_BYTES]
            .copy_from_slice(address.as_ref());

        let mut address_hash = [0u8; ACCOUNT_KEYPART_BYTES];
        address_hash[0..ACCOUNT_PADDING_BYTES]
            .copy_from_slice(&keccak(padded)[0..ACCOUNT_PADDING_BYTES]);
        address_hash[ACCOUNT_PADDING_BYTES..ACCOUNT_KEYPART_BYTES]
            .copy_from_slice(address.as_ref());

        address_hash
    }

    // FIXME: use it.
    #[allow(unused)]
    fn unchecked_address_keypart_to_address(address_keypart: &[u8]) -> Address {
        let mut address = [0u8; StorageKey::ACCOUNT_BYTES];
        address[0..StorageKey::ACCOUNT_BYTES]
            .copy_from_slice(&address_keypart[ACCOUNT_PADDING_BYTES..]);

        H160(address)
    }

    fn compute_storage_key_padding(
        storage_key: &[u8], padding: &KeyPadding,
    ) -> KeyPadding {
        let mut padded =
            Vec::with_capacity(KEY_PADDING_BYTES + storage_key.len());
        padded.extend_from_slice(padding);
        padded.extend_from_slice(storage_key);

        keccak(padded).0
    }

    fn extend_address(
        key: &mut Vec<u8>, address: &Address, padding: &KeyPadding,
    ) {
        let hash = compute_address_keypart(address, padding);

        key.extend_from_slice(hash.as_ref());
    }

    pub fn new_account_key(address: &Address, padding: &KeyPadding) -> Vec<u8> {
        let mut key = Vec::with_capacity(ACCOUNT_KEYPART_BYTES);
        extend_address(&mut key, address, padding);

        key
    }

    fn extend_storage_root(
        key: &mut Vec<u8>, address: &Address, padding: &KeyPadding,
    ) {
        extend_address(key, address, padding);
        key.extend_from_slice(StorageKey::STORAGE_PREFIX);
    }

    fn extend_storage_key(
        key: &mut Vec<u8>, storage_key: &[u8], padding: &KeyPadding,
    ) {
        key.extend_from_slice(
            &compute_storage_key_padding(storage_key, padding)
                [StorageKey::STORAGE_PREFIX.len()..],
        );
        key.extend_from_slice(storage_key);
    }

    pub fn new_storage_root_key(
        address: &Address, padding: &KeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES + StorageKey::STORAGE_PREFIX.len(),
        );
        extend_storage_root(&mut key, address, padding);

        key
    }

    pub fn new_storage_key(
        address: &Address, storage_key: &[u8], padding: &KeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES
                + StorageKey::STORAGE_PREFIX.len()
                + KEY_PADDING_BYTES
                + storage_key.len(),
        );
        extend_storage_root(&mut key, address, padding);
        extend_storage_key(&mut key, storage_key, padding);

        key
    }

    fn extend_code_root(
        key: &mut Vec<u8>, address: &Address, padding: &KeyPadding,
    ) {
        extend_address(key, address, padding);
        key.extend_from_slice(StorageKey::CODE_HASH_PREFIX);
    }

    pub fn new_code_root_key(
        address: &Address, padding: &KeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES + StorageKey::STORAGE_PREFIX.len(),
        );
        extend_code_root(&mut key, address, padding);

        key
    }

    pub fn new_code_key(
        address: &Address, code_hash: &H256, padding: &KeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES
                + StorageKey::CODE_HASH_PREFIX.len()
                + StorageKey::CODE_HASH_BYTES,
        );
        extend_code_root(&mut key, address, padding);
        key.extend_from_slice(code_hash.as_ref());

        key
    }
}

use super::DeltaMpt;
use cfx_types::{Address, H256};
use hash::keccak;
use primitives::MERKLE_NULL_NODE;
use std::{convert::AsRef, vec::Vec};
