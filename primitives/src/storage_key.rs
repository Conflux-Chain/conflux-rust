// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::static_bool::{self, StaticBool};

pub type CheckInput = static_bool::Yes;
pub type SkipInputCheck = static_bool::No;

pub trait ConditionalReturnValue<'a> {
    type Output;

    fn from_key(k: StorageKeyWithSpace<'a>) -> Self::Output;
    fn from_result(r: Result<StorageKeyWithSpace<'a>, String>) -> Self::Output;
}

pub struct FromKeyBytesResult<ShouldCheckInput: StaticBool> {
    phantom: std::marker::PhantomData<ShouldCheckInput>,
}

impl<'a> ConditionalReturnValue<'a> for FromKeyBytesResult<SkipInputCheck> {
    type Output = StorageKeyWithSpace<'a>;

    fn from_key(k: StorageKeyWithSpace<'a>) -> Self::Output { k }

    fn from_result(
        _r: Result<StorageKeyWithSpace<'a>, String>,
    ) -> Self::Output {
        unreachable!()
    }
}

impl<'a> ConditionalReturnValue<'a> for FromKeyBytesResult<CheckInput> {
    type Output = Result<StorageKeyWithSpace<'a>, String>;

    fn from_key(k: StorageKeyWithSpace<'a>) -> Self::Output { Ok(k) }

    fn from_result(r: Result<StorageKeyWithSpace<'a>, String>) -> Self::Output {
        r
    }
}

// The original StorageKeys unprocessed, in contrary to StorageKey which is
// processed to use in DeltaMpt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    DepositListKey(&'a [u8]),
    VoteListKey(&'a [u8]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StorageKeyWithSpace<'a> {
    pub key: StorageKey<'a>,
    pub space: Space,
}

impl<'a> StorageKey<'a> {
    pub fn with_space(self, space: Space) -> StorageKeyWithSpace<'a> {
        StorageKeyWithSpace { key: self, space }
    }

    pub fn with_native_space(self) -> StorageKeyWithSpace<'a> {
        self.with_space(Space::Native)
    }

    pub fn with_evm_space(self) -> StorageKeyWithSpace<'a> {
        self.with_space(Space::Ethereum)
    }

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

    pub fn new_deposit_list_key(address: &'a Address) -> Self {
        StorageKey::DepositListKey(&address.0)
    }

    pub fn new_vote_list_key(address: &'a Address) -> Self {
        StorageKey::VoteListKey(&address.0)
    }
}

impl<'a> StorageKey<'a> {
    // Compatible interface with rpc
    pub fn to_key_bytes(&self) -> Vec<u8> {
        self.clone().with_native_space().to_key_bytes()
    }
}

// Conversion methods.
impl<'a> StorageKeyWithSpace<'a> {
    pub const ACCOUNT_BYTES: usize = 20;
    const CODE_HASH_BYTES: usize = 32;
    const CODE_HASH_PREFIX: &'static [u8] = b"code";
    const CODE_HASH_PREFIX_LEN: usize = 4;
    const DEPOSIT_LIST_LEN: usize = 7;
    const DEPOSIT_LIST_PREFIX: &'static [u8] = b"deposit";
    pub const EVM_SPACE_TYPE: &'static [u8] = b"\x81";
    const STORAGE_PREFIX: &'static [u8] = b"data";
    const STORAGE_PREFIX_LEN: usize = 4;
    const VOTE_LIST_LEN: usize = 4;
    const VOTE_LIST_PREFIX: &'static [u8] = b"vote";

    pub fn to_delta_mpt_key_bytes(
        &self, padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let key_bytes = match self.key {
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

                    return x;
                } else {
                    unsafe { unreachable_unchecked() }
                    /*
                    unreachable!(
                        "Invalid account key. Unrecognized: {:?}",
                        address_bytes
                    );
                    */
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
            StorageKey::DepositListKey(address_bytes) => {
                delta_mpt_storage_key::new_deposit_list_key(
                    address_bytes,
                    padding,
                )
            }
            StorageKey::VoteListKey(address_bytes) => {
                delta_mpt_storage_key::new_vote_list_key(address_bytes, padding)
            }
        };

        return if self.space == Space::Native {
            key_bytes
        } else {
            // Insert "0x81" at the position 32.
            [
                &key_bytes[..ACCOUNT_KEYPART_BYTES],
                Self::EVM_SPACE_TYPE,
                &key_bytes[ACCOUNT_KEYPART_BYTES..],
            ]
            .concat()
        };
    }

    pub fn to_key_bytes(&self) -> Vec<u8> {
        let key_bytes = match self.key {
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
            StorageKey::DepositListKey(address_bytes) => {
                let mut key = Vec::with_capacity(
                    Self::ACCOUNT_BYTES + Self::DEPOSIT_LIST_LEN,
                );
                key.extend_from_slice(address_bytes);
                key.extend_from_slice(Self::DEPOSIT_LIST_PREFIX);

                key
            }
            StorageKey::VoteListKey(address_bytes) => {
                let mut key = Vec::with_capacity(
                    Self::ACCOUNT_BYTES + Self::VOTE_LIST_LEN,
                );
                key.extend_from_slice(address_bytes);
                key.extend_from_slice(Self::VOTE_LIST_PREFIX);

                key
            }
        };

        return if self.space == Space::Native {
            key_bytes
        } else {
            // Insert "0x81" at the position 20.
            [
                &key_bytes[..Self::ACCOUNT_BYTES],
                Self::EVM_SPACE_TYPE,
                &key_bytes[Self::ACCOUNT_BYTES..],
            ]
            .concat()
        };
    }

    // from_key_bytes::<CheckInput>(...) returns Result<StorageKey, String>
    // from_key_bytes::<SkipInputCheck>(...) returns StorageKey, crashes on
    // error
    pub fn from_key_bytes<ShouldCheckInput: StaticBool>(
        bytes: &'a [u8],
    ) -> <FromKeyBytesResult<ShouldCheckInput> as ConditionalReturnValue<'a>>::Output
where FromKeyBytesResult<ShouldCheckInput>: ConditionalReturnValue<'a>{
        let key = if bytes.len() <= Self::ACCOUNT_BYTES {
            StorageKey::AccountKey(bytes).with_native_space()
        } else if bytes.len() == Self::ACCOUNT_BYTES + 1 {
            StorageKey::AccountKey(&bytes[..Self::ACCOUNT_BYTES])
                .with_evm_space()
        } else {
            let address_bytes = &bytes[0..Self::ACCOUNT_BYTES];

            let extension_bit: bool = bytes[Self::ACCOUNT_BYTES] & 0x80 != 0;
            let bytes = if extension_bit {
                // check for incorrect extension byte
                if ShouldCheckInput::value() == CheckInput::value()
                    && bytes[Self::ACCOUNT_BYTES] != Self::EVM_SPACE_TYPE[0]
                {
                    return <FromKeyBytesResult<ShouldCheckInput> as ConditionalReturnValue<'a>>::from_result(
                        Err(format!("Unexpected extension byte: {:?}", bytes[Self::ACCOUNT_BYTES]))
                    );
                }

                // with `SkipInputCheck`, crash on incorrect extension byte
                assert_eq!(bytes[Self::ACCOUNT_BYTES], Self::EVM_SPACE_TYPE[0]);
                &bytes[(Self::ACCOUNT_BYTES + 1)..]
            } else {
                &bytes[Self::ACCOUNT_BYTES..]
            };

            let storage_key_no_space = if bytes
                .starts_with(Self::STORAGE_PREFIX)
            {
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
            } else if bytes.starts_with(Self::DEPOSIT_LIST_PREFIX) {
                StorageKey::DepositListKey(address_bytes)
            } else if bytes.starts_with(Self::VOTE_LIST_PREFIX) {
                StorageKey::VoteListKey(address_bytes)
            }
            // unknown key format => we report an error or crash
            // depending on the generic parameter
            else if ShouldCheckInput::value() == CheckInput::value() {
                return <FromKeyBytesResult<ShouldCheckInput> as ConditionalReturnValue<'a>>::from_result(
                    Err(format!("Unable to parse storage key: {:?} - {:?}", address_bytes, bytes))
                );
            } else {
                if cfg!(debug_assertions) {
                    unreachable!(
                        "Invalid key format. Unrecognized: {:?}, account: {:?}",
                        bytes, address_bytes
                    );
                } else {
                    unsafe { unreachable_unchecked() }
                }
            };

            let space = if extension_bit {
                Space::Ethereum
            } else {
                Space::Native
            };

            storage_key_no_space.with_space(space)
        };

        <FromKeyBytesResult<ShouldCheckInput> as ConditionalReturnValue<'a>>::from_key(key)
    }
}

/// The padding is uniquely generated for DeltaMPT at each intermediate epoch,
/// and it's used to compute padding bytes for address and storage_key. The
/// padding setup is against an attack where adversary artificially build deep
/// paths in MPT.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaMptKeyPadding([u8; delta_mpt_storage_key::KEY_PADDING_BYTES]);

pub use delta_mpt_storage_key::KEY_PADDING_BYTES as DELTA_MPT_KEY_PADDING_BYTES;
lazy_static! {
    pub static ref GENESIS_DELTA_MPT_KEY_PADDING: DeltaMptKeyPadding =
        StorageKeyWithSpace::delta_mpt_padding(
            &MERKLE_NULL_NODE,
            &MERKLE_NULL_NODE
        );
}

impl Deref for DeltaMptKeyPadding {
    type Target = [u8; delta_mpt_storage_key::KEY_PADDING_BYTES];

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for DeltaMptKeyPadding {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

impl Encodable for DeltaMptKeyPadding {
    fn rlp_append(&self, s: &mut RlpStream) { s.append_internal(&&self[..]); }
}

impl Decodable for DeltaMptKeyPadding {
    fn decode(rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        let v = rlp.as_val::<Vec<u8>>()?;
        let mut array = DeltaMptKeyPadding::default();
        if v.len() != delta_mpt_storage_key::KEY_PADDING_BYTES {
            Err(DecoderError::RlpInconsistentLengthAndData)
        } else {
            array[..].copy_from_slice(&v);
            Ok(array)
        }
    }
}

mod delta_mpt_storage_key {
    use super::*;
    use std::hint::unreachable_unchecked;

    pub const ACCOUNT_KEYPART_BYTES: usize = 32;
    const ACCOUNT_PADDING_BYTES: usize = 12;
    pub const KEY_PADDING_BYTES: usize = 32;

    fn new_buffer(uninitialized_size: usize) -> Vec<u8> {
        vec![0; uninitialized_size]

        // The previous implementation make this function unsafe.
        // However, the performance gain (avoid initializing a buffer of 32
        // bytes) is negligible since calling this function is followed by a
        // hash computation.
        //
        // let mut buffer = Vec::with_capacity(uninitialized_size);
        // unsafe { buffer.set_len(uninitialized_size) }
        //
        // buffer
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

    fn compute_storage_key_padding(
        storage_key: &[u8], padding: &DeltaMptKeyPadding,
    ) -> DeltaMptKeyPadding {
        let mut padded =
            Vec::with_capacity(KEY_PADDING_BYTES + storage_key.len());
        padded.extend_from_slice(&padding.0);
        padded.extend_from_slice(storage_key);

        DeltaMptKeyPadding(keccak(padded).0)
    }

    fn extend_address(
        key: &mut Vec<u8>, address: &[u8], padding: &DeltaMptKeyPadding,
    ) {
        let padded_address = compute_address_keypart(address, padding);

        key.extend_from_slice(padded_address.as_ref());
    }

    fn extend_key_with_prefix(
        key: &mut Vec<u8>, address: &[u8], padding: &DeltaMptKeyPadding,
        prefix: &[u8],
    )
    {
        extend_address(key, address, padding);
        key.extend_from_slice(prefix);
    }

    pub fn new_account_key(
        address: &[u8], padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(ACCOUNT_KEYPART_BYTES);
        extend_address(&mut key, address, padding);

        key
    }

    fn extend_storage_key(
        key: &mut Vec<u8>, storage_key: &[u8], padding: &DeltaMptKeyPadding,
    ) {
        key.extend_from_slice(
            &compute_storage_key_padding(storage_key, padding)
                [StorageKeyWithSpace::STORAGE_PREFIX_LEN..],
        );
        key.extend_from_slice(storage_key);
    }

    pub fn new_storage_root_key(
        address: &[u8], padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES + StorageKeyWithSpace::STORAGE_PREFIX_LEN,
        );
        extend_key_with_prefix(
            &mut key,
            address,
            padding,
            StorageKeyWithSpace::STORAGE_PREFIX,
        );

        key
    }

    pub fn new_storage_key(
        address: &[u8], storage_key: &[u8], padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES + KEY_PADDING_BYTES + storage_key.len(),
        );
        extend_key_with_prefix(
            &mut key,
            address,
            padding,
            StorageKeyWithSpace::STORAGE_PREFIX,
        );
        extend_storage_key(&mut key, storage_key, padding);

        key
    }

    pub fn new_code_root_key(
        address: &[u8], padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES + StorageKeyWithSpace::STORAGE_PREFIX_LEN,
        );
        extend_key_with_prefix(
            &mut key,
            address,
            padding,
            &StorageKeyWithSpace::CODE_HASH_PREFIX,
        );

        key
    }

    pub fn new_code_key(
        address: &[u8], code_hash: &[u8], padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES
                + StorageKeyWithSpace::CODE_HASH_PREFIX_LEN
                + StorageKeyWithSpace::CODE_HASH_BYTES,
        );
        extend_key_with_prefix(
            &mut key,
            address,
            padding,
            &StorageKeyWithSpace::CODE_HASH_PREFIX,
        );
        key.extend_from_slice(code_hash);

        key
    }

    pub fn new_deposit_list_key(
        address: &[u8], padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES + StorageKeyWithSpace::DEPOSIT_LIST_LEN,
        );
        extend_key_with_prefix(
            &mut key,
            address,
            padding,
            &StorageKeyWithSpace::DEPOSIT_LIST_PREFIX,
        );
        key
    }

    pub fn new_vote_list_key(
        address: &[u8], padding: &DeltaMptKeyPadding,
    ) -> Vec<u8> {
        let mut key = Vec::with_capacity(
            ACCOUNT_KEYPART_BYTES + StorageKeyWithSpace::VOTE_LIST_LEN,
        );
        extend_key_with_prefix(
            &mut key,
            address,
            padding,
            &StorageKeyWithSpace::VOTE_LIST_PREFIX,
        );
        key
    }

    impl<'a> StorageKeyWithSpace<'a> {
        pub fn delta_mpt_padding(
            snapshot_root: &MerkleHash, intermediate_delta_root: &MerkleHash,
        ) -> DeltaMptKeyPadding {
            let mut buffer = Vec::with_capacity(
                snapshot_root.0.len() + intermediate_delta_root.0.len(),
            );
            buffer.extend_from_slice(&snapshot_root.0);
            buffer.extend_from_slice(&intermediate_delta_root.0);
            DeltaMptKeyPadding(keccak(&buffer).0)
        }

        pub fn from_delta_mpt_key(
            delta_mpt_key: &'a [u8],
        ) -> StorageKeyWithSpace<'a> {
            let remaining_bytes = delta_mpt_key;
            let bytes_len = remaining_bytes.len();
            if bytes_len < ACCOUNT_KEYPART_BYTES {
                if cfg!(feature = "test_no_account_length_check") {
                    // The branch is test only. When an address with incomplete
                    // length, it's passed to DeltaMPT directly.
                    return StorageKey::AccountKey(remaining_bytes)
                        .with_native_space();
                } else {
                    if cfg!(debug_assertions) {
                        unreachable!(
                            "Invalid delta mpt key format. Unrecognized: {:?}",
                            remaining_bytes
                        );
                    } else {
                        unsafe { unreachable_unchecked() }
                    }
                }
            } else {
                let address_bytes = &remaining_bytes
                    [ACCOUNT_PADDING_BYTES..ACCOUNT_KEYPART_BYTES];
                if bytes_len == ACCOUNT_KEYPART_BYTES {
                    return StorageKey::AccountKey(address_bytes)
                        .with_native_space();
                }
                if bytes_len == ACCOUNT_KEYPART_BYTES + 1 {
                    return StorageKey::AccountKey(address_bytes)
                        .with_evm_space();
                }
                let extension_bit =
                    remaining_bytes[ACCOUNT_KEYPART_BYTES] & 0x80 != 0;

                let remaining_bytes = if extension_bit {
                    assert_eq!(
                        remaining_bytes[ACCOUNT_KEYPART_BYTES],
                        StorageKeyWithSpace::EVM_SPACE_TYPE[0]
                    );
                    &remaining_bytes[(ACCOUNT_KEYPART_BYTES + 1)..]
                } else {
                    &remaining_bytes[ACCOUNT_KEYPART_BYTES..]
                };

                let storage_key_no_space = if remaining_bytes
                    .starts_with(StorageKeyWithSpace::STORAGE_PREFIX)
                {
                    if remaining_bytes.len()
                        == StorageKeyWithSpace::STORAGE_PREFIX_LEN
                    {
                        StorageKey::StorageRootKey(address_bytes)
                    } else {
                        StorageKey::StorageKey {
                            address_bytes,
                            storage_key: &remaining_bytes[KEY_PADDING_BYTES..],
                        }
                    }
                } else if remaining_bytes
                    .starts_with(StorageKeyWithSpace::CODE_HASH_PREFIX)
                {
                    let bytes = &remaining_bytes
                        [StorageKeyWithSpace::CODE_HASH_PREFIX_LEN..];
                    if bytes.len() > 0 {
                        StorageKey::CodeKey {
                            address_bytes,
                            code_hash_bytes: bytes,
                        }
                    } else {
                        StorageKey::CodeRootKey(address_bytes)
                    }
                } else if remaining_bytes
                    .starts_with(StorageKeyWithSpace::DEPOSIT_LIST_PREFIX)
                {
                    StorageKey::DepositListKey(address_bytes)
                } else if remaining_bytes
                    .starts_with(StorageKeyWithSpace::VOTE_LIST_PREFIX)
                {
                    StorageKey::VoteListKey(address_bytes)
                } else {
                    if cfg!(debug_assertions) {
                        unreachable!(
                            "Invalid delta mpt key format. Address {:?}, Unrecognized: {:?}",
                            address_bytes, remaining_bytes
                        );
                    } else {
                        unsafe { unreachable_unchecked() }
                    }
                };

                let space = if extension_bit {
                    Space::Ethereum
                } else {
                    Space::Native
                };
                storage_key_no_space.with_space(space)
            }
        }
    }
}

use super::{MerkleHash, MERKLE_NULL_NODE};
use crate::storage_key::delta_mpt_storage_key::ACCOUNT_KEYPART_BYTES;
use cfx_types::{Address, Space, H256};
use hash::keccak;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use std::{
    convert::AsRef,
    hint::unreachable_unchecked,
    ops::{Deref, DerefMut},
    vec::Vec,
};

#[cfg(test)]
mod tests {
    use super::{delta_mpt_storage_key::*, DeltaMptKeyPadding, StorageKey};
    use crate::StorageKeyWithSpace;
    use cfx_types::{Address, H256};

    #[test]
    fn test_delta_mpt_account_key() {
        let padding = DeltaMptKeyPadding([0; KEY_PADDING_BYTES]);

        let address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6"
            .parse::<Address>()
            .unwrap();

        let key = StorageKey::new_account_key(&address).with_native_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);

        let key = StorageKey::new_account_key(&address).with_evm_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_delta_mpt_storage_root_key() {
        let padding = DeltaMptKeyPadding([0; KEY_PADDING_BYTES]);

        let address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6"
            .parse::<Address>()
            .unwrap();

        let key =
            StorageKey::new_storage_root_key(&address).with_native_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);

        let key = StorageKey::new_storage_root_key(&address).with_evm_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_delta_mpt_storage_key() {
        let padding = DeltaMptKeyPadding([0; KEY_PADDING_BYTES]);

        let address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6"
            .parse::<Address>()
            .unwrap();

        let storage_key = &[99; 32];

        let key = StorageKey::new_storage_key(&address, storage_key)
            .with_native_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);

        let key =
            StorageKey::new_storage_key(&address, storage_key).with_evm_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_delta_mpt_code_root_key() {
        let padding = DeltaMptKeyPadding([0; KEY_PADDING_BYTES]);

        let address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6"
            .parse::<Address>()
            .unwrap();

        let key = StorageKey::new_code_root_key(&address).with_native_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);

        let key = StorageKey::new_code_root_key(&address).with_evm_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_delta_mpt_code_key() {
        let padding = DeltaMptKeyPadding([0; KEY_PADDING_BYTES]);

        let address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6"
            .parse::<Address>()
            .unwrap();

        let code_hash =
            "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec66d2d6c7b5ec66d2d6c7b5ec6"
                .parse::<H256>()
                .unwrap();

        let key =
            StorageKey::new_code_key(&address, &code_hash).with_native_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);

        let key =
            StorageKey::new_code_key(&address, &code_hash).with_evm_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_delta_mpt_deposit_list_key() {
        let padding = DeltaMptKeyPadding([0; KEY_PADDING_BYTES]);

        let address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6"
            .parse::<Address>()
            .unwrap();

        let key =
            StorageKey::new_deposit_list_key(&address).with_native_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);

        let key = StorageKey::new_deposit_list_key(&address).with_evm_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);
    }

    #[test]
    fn test_delta_mpt_vote_list_key() {
        let padding = DeltaMptKeyPadding([0; KEY_PADDING_BYTES]);

        let address = "0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6"
            .parse::<Address>()
            .unwrap();

        let key = StorageKey::new_vote_list_key(&address).with_native_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);

        let key = StorageKey::new_vote_list_key(&address).with_evm_space();
        let bytes = key.to_delta_mpt_key_bytes(&padding);
        let key2 = StorageKeyWithSpace::from_delta_mpt_key(&bytes[..]);
        assert_eq!(key, key2);
    }
}
