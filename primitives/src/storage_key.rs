// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// The original StorageKeys unprocessed, in contrary to StorageKey which is
// processed to use in DeltaMpt.

use std::hint::unreachable_unchecked;

#[derive(Debug, Clone, Copy)]
pub enum StorageKey<'a> {
    AccountKey(&'a [u8]),
    StorageRootKey(&'a [u8]),
    StorageKey {
        address_bytes: &'a [u8],
        storage_key: &'a [u8],
    },
    CodeRootKey(&'a [u8]),
    CodeKey {
        address_bytes: &'a [u8],
        code_hash_bytes: &'a [u8],
    },
}

impl<'a> StorageKey<'a> {
    pub fn new_account_key(address: &'a Address) -> Self {
        StorageKey::AccountKey(&address.0)
    }

    pub fn new_storage_root_key(address: &'a Address) -> Self {
        StorageKey::StorageRootKey(&address.0)
    }

    pub fn new_storage_key(
        address: &'a Address, storage_key: &'a [u8],
    ) -> Self {
        StorageKey::StorageKey {
            address_bytes: &address.0,
            storage_key,
        }
    }

    pub fn new_code_root_key(address: &'a Address) -> Self {
        StorageKey::CodeRootKey(&address.0)
    }

    pub fn new_code_key(address: &'a Address, code_hash: &'a H256) -> Self {
        StorageKey::CodeKey {
            address_bytes: &address.0,
            code_hash_bytes: &code_hash.0,
        }
    }
}

// Conversion methods.
impl<'a> StorageKey<'a> {
    pub const ACCOUNT_BYTES: usize = 20;
    const CODE_HASH_BYTES: usize = 32;
    const CODE_HASH_PREFIX: &'static [u8] = b"code";
    const CODE_HASH_PREFIX_LEN: usize = 4;
    const STORAGE_PREFIX: &'static [u8] = b"data";
    const STORAGE_PREFIX_LEN: usize = 4;

    pub fn to_delta_mpt_key_bytes(
        &self, padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        match self {
            StorageKey::AccountKey(address_bytes) => {
                if address_bytes.len() == Self::ACCOUNT_BYTES {
                    delta_mpt_storage_key::new_account_key(
                        address_bytes,
                        padding,
                    )
                } else if cfg!(feature = "test_no_account_length_check") {
                    // The branch is test only. When an address with incomplete
                    // length, it's passed to DeltaMPT directly.
                    let mut x = Vec::with_capacity(address_bytes.len());
                    x.extend_from_slice(address_bytes);

                    x
                } else {
                    unsafe { unreachable_unchecked() }
                }
            }
            StorageKey::StorageRootKey(address_bytes) => {
                delta_mpt_storage_key::new_storage_root_key(
                    address_bytes,
                    padding,
                )
            }
            StorageKey::StorageKey {
                address_bytes,
                storage_key,
            } => delta_mpt_storage_key::new_storage_key(
                address_bytes,
                storage_key,
                padding,
            ),
            StorageKey::CodeRootKey(address_bytes) => {
                delta_mpt_storage_key::new_code_root_key(address_bytes, padding)
            }
            StorageKey::CodeKey {
                address_bytes,
                code_hash_bytes,
            } => delta_mpt_storage_key::new_code_key(
                address_bytes,
                code_hash_bytes,
                padding,
            ),
        }
    }

    pub fn to_key_bytes(&self) -> Vec<u8> {
        match self {
            StorageKey::AccountKey(address_bytes) => {
                let mut key = Vec::with_capacity(Self::ACCOUNT_BYTES);
                key.extend_from_slice(address_bytes);

                key
            }
            StorageKey::StorageRootKey(address_bytes) => {
                let mut key = Vec::with_capacity(
                    Self::ACCOUNT_BYTES + Self::STORAGE_PREFIX_LEN,
                );
                key.extend_from_slice(address_bytes);
                key.extend_from_slice(Self::STORAGE_PREFIX);

                key
            }
            StorageKey::StorageKey {
                address_bytes,
                storage_key,
            } => {
                let mut key = Vec::with_capacity(
                    Self::ACCOUNT_BYTES
                        + Self::STORAGE_PREFIX_LEN
                        + storage_key.len(),
                );
                key.extend_from_slice(address_bytes);
                key.extend_from_slice(Self::STORAGE_PREFIX);
                key.extend_from_slice(storage_key);

                key
            }
            StorageKey::CodeRootKey(address_bytes) => {
                let mut key = Vec::with_capacity(
                    Self::ACCOUNT_BYTES + Self::CODE_HASH_PREFIX_LEN,
                );
                key.extend_from_slice(address_bytes);
                key.extend_from_slice(Self::CODE_HASH_PREFIX);

                key
            }
            StorageKey::CodeKey {
                address_bytes,
                code_hash_bytes,
            } => {
                let mut key = Vec::with_capacity(
                    Self::ACCOUNT_BYTES
                        + Self::CODE_HASH_PREFIX_LEN
                        + Self::CODE_HASH_BYTES,
                );
                key.extend_from_slice(address_bytes);
                key.extend_from_slice(Self::CODE_HASH_PREFIX);
                key.extend_from_slice(code_hash_bytes);

                key
            }
        }
    }

    pub fn from_key_bytes(mut bytes: &'a [u8]) -> Self {
        if bytes.len() <= Self::ACCOUNT_BYTES {
            StorageKey::AccountKey(bytes)
        } else {
            let address_bytes = &bytes[0..Self::ACCOUNT_BYTES];
            bytes = &bytes[Self::ACCOUNT_BYTES..];
            if bytes.starts_with(Self::STORAGE_PREFIX) {
                let bytes = &bytes[Self::STORAGE_PREFIX_LEN..];
                if bytes.len() > 0 {
                    StorageKey::StorageKey {
                        address_bytes,
                        storage_key: bytes,
                    }
                } else {
                    StorageKey::StorageRootKey(address_bytes)
                }
            } else if bytes.starts_with(Self::CODE_HASH_PREFIX) {
                let bytes = &bytes[Self::CODE_HASH_PREFIX_LEN..];
                if bytes.len() > 0 {
                    StorageKey::CodeKey {
                        address_bytes,
                        code_hash_bytes: bytes,
                    }
                } else {
                    StorageKey::CodeRootKey(address_bytes)
                }
            } else {
                unreachable!(
                    "Invalid key format. Unrecognized: {:?}, account: {:?}",
                    bytes, address_bytes
                );
            }
        }
    }
}

/// The padding is uniquely generated for DeltaMPT at each intermediate epoch,
/// and it's used to compute padding bytes for address and storage_key. The
/// padding setup is against an attack where adversary artificially build deep
/// paths in MPT.
pub type DeltaMptKeyPadding = [u8; delta_mpt_storage_key::KEY_PADDING_BYTES];
pub use delta_mpt_storage_key::KEY_PADDING_BYTES as DELTA_MPT_KEY_PADDING_BYTES;
lazy_static! {
    pub static ref GENESIS_DELTA_MPT_KEY_PADDING: DeltaMptKeyPadding =
        StorageKey::delta_mpt_padding(&MERKLE_NULL_NODE, &MERKLE_NULL_NODE);
}

mod delta_mpt_storage_key {
    use super::*;

    pub const ACCOUNT_KEYPART_BYTES: usize = 32;
    const ACCOUNT_PADDING_BYTES: usize = 12;
    pub const KEY_PADDING_BYTES: usize = 32;

    fn new_buffer(uninitialized_size: usize) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(uninitialized_size);
        unsafe { buffer.set_len(uninitialized_size) }

        buffer
    }

    fn compute_address_keypart(
        address: &[u8], padding: &DeltaMptKeyPadding,
    ) -> [u8; ACCOUNT_KEYPART_BYTES] {
        // Manually asserting the size by using new_buffer instead of
        // Vec#extend_from_slice.
        let mut padded = new_buffer(ACCOUNT_KEYPART_BYTES);
        padded[..ACCOUNT_PADDING_BYTES]
            .copy_from_slice(&padding[..ACCOUNT_PADDING_BYTES]);
        padded[ACCOUNT_PADDING_BYTES..].copy_from_slice(address);

        let mut address_hash = [0u8; ACCOUNT_KEYPART_BYTES];
        address_hash[..ACCOUNT_PADDING_BYTES]
            .copy_from_slice(&keccak(padded)[..ACCOUNT_PADDING_BYTES]);
        address_hash[ACCOUNT_PADDING_BYTES..].copy_from_slice(address);

        address_hash
    }

    fn unchecked_address_keypart_to_address(
        address_keypart: &[u8], address_bytes: &mut [u8],
    ) {
        address_bytes[0..StorageKey::ACCOUNT_BYTES]
            .copy_from_slice(&address_keypart[ACCOUNT_PADDING_BYTES..])
    }

    fn compute_storage_key_padding(
        storage_key: &[u8], padding: &DeltaMptKeyPadding,
    ) -> DeltaMptKeyPadding {
        let mut padded =
            Vec::with_capacity(KEY_PADDING_BYTES + storage_key.len());
        padded.extend_from_slice(padding);
        padded.extend_from_slice(storage_key);

        keccak(padded).0
    }

    fn extend_address(
        key: &mut Vec<u8>, address: &[u8], padding: &DeltaMptKeyPadding,
    ) {
        let hash = compute_address_keypart(address, padding);

        key.extend_from_slice(hash.as_ref());
    }

    pub fn new_account_key(
        address: &[u8], padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(ACCOUNT_KEYPART_BYTES);
        extend_address(&mut key, address, padding);

        key
    }

    fn extend_storage_root(
        key: &mut Vec<u8>, address: &[u8], padding: &DeltaMptKeyPadding,
    ) {
        extend_address(key, address, padding);
        key.extend_from_slice(StorageKey::STORAGE_PREFIX);
    }

    fn extend_storage_key(
        key: &mut Vec<u8>, storage_key: &[u8], padding: &DeltaMptKeyPadding,
    ) {
        key.extend_from_slice(
            &compute_storage_key_padding(storage_key, padding)
                [StorageKey::STORAGE_PREFIX_LEN..],
        );
        key.extend_from_slice(storage_key);
    }

    pub fn new_storage_root_key(
        address: &[u8], padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES + StorageKey::STORAGE_PREFIX_LEN,
        );
        extend_storage_root(&mut key, address, padding);

        key
    }

    pub fn new_storage_key(
        address: &[u8], storage_key: &[u8], padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES + KEY_PADDING_BYTES + storage_key.len(),
        );
        extend_storage_root(&mut key, address, padding);
        extend_storage_key(&mut key, storage_key, padding);

        key
    }

    fn extend_code_root(
        key: &mut Vec<u8>, address: &[u8], padding: &DeltaMptKeyPadding,
    ) {
        extend_address(key, address, padding);
        key.extend_from_slice(StorageKey::CODE_HASH_PREFIX);
    }

    pub fn new_code_root_key(
        address: &[u8], padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES + StorageKey::STORAGE_PREFIX_LEN,
        );
        extend_code_root(&mut key, address, padding);

        key
    }

    pub fn new_code_key(
        address: &[u8], code_hash: &[u8], padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES
                + StorageKey::CODE_HASH_PREFIX_LEN
                + StorageKey::CODE_HASH_BYTES,
        );
        extend_code_root(&mut key, address, padding);
        key.extend_from_slice(code_hash);

        key
    }

    impl<'a> StorageKey<'a> {
        pub fn delta_mpt_padding(
            snapshot_root: &MerkleHash, intermediate_delta_root: &MerkleHash,
        ) -> DeltaMptKeyPadding {
            let mut buffer = Vec::with_capacity(
                snapshot_root.0.len() + intermediate_delta_root.0.len(),
            );
            buffer.extend_from_slice(&snapshot_root.0);
            buffer.extend_from_slice(&intermediate_delta_root.0);
            keccak(&buffer).0
        }

        pub fn from_delta_mpt_key(
            delta_mpt_key: &'a [u8], address_bytes: &'a mut [u8],
        ) -> StorageKey<'a> {
            let mut remaining_bytes = delta_mpt_key;
            let bytes_len = remaining_bytes.len();
            if bytes_len < ACCOUNT_KEYPART_BYTES {
                unreachable!(
                    "Invalid delta mpt key format. Unrecognized: {:?}",
                    remaining_bytes
                );
            } else {
                unchecked_address_keypart_to_address(
                    &remaining_bytes[0..ACCOUNT_KEYPART_BYTES],
                    address_bytes,
                );
                if bytes_len == ACCOUNT_KEYPART_BYTES {
                    return StorageKey::AccountKey(address_bytes);
                }
                remaining_bytes = &remaining_bytes[ACCOUNT_KEYPART_BYTES..];
                if remaining_bytes.starts_with(Self::STORAGE_PREFIX) {
                    let bytes = &remaining_bytes[KEY_PADDING_BYTES..];
                    if bytes.len() > 0 {
                        StorageKey::StorageKey {
                            address_bytes,
                            storage_key: bytes,
                        }
                    } else {
                        StorageKey::StorageRootKey(address_bytes)
                    }
                } else if remaining_bytes.starts_with(Self::CODE_HASH_PREFIX) {
                    let bytes = &remaining_bytes[Self::CODE_HASH_PREFIX_LEN..];
                    if bytes.len() > 0 {
                        StorageKey::CodeKey {
                            address_bytes,
                            code_hash_bytes: bytes,
                        }
                    } else {
                        StorageKey::CodeRootKey(address_bytes)
                    }
                } else {
                    unreachable!(
                        "Invalid key format. Unrecognized: {:?}, account: {:?}",
                        remaining_bytes, address_bytes
                    );
                }
            }
        }
    }
}

use super::{MerkleHash, MERKLE_NULL_NODE};
use cfx_types::{Address, H256};
use hash::keccak;
use std::{convert::AsRef, vec::Vec};
