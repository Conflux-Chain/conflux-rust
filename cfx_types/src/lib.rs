// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate ethereum_types;

pub use ethereum_types::{
    Address, BigEndianHash, Bloom, BloomInput, Public, Secret, Signature, H128,
    H160, H256, H512, H520, H64, U128, U256, U512, U64,
};
use std::collections::BTreeMap;

/// The KECCAK hash of an empty bloom filter (0x00 * 256)
pub const KECCAK_EMPTY_BLOOM: H256 = H256([
    0xd3, 0x97, 0xb3, 0xb0, 0x43, 0xd8, 0x7f, 0xcd, 0x6f, 0xad, 0x12, 0x91,
    0xff, 0x0b, 0xfd, 0x16, 0x40, 0x1c, 0x27, 0x48, 0x96, 0xd8, 0xc6, 0x3a,
    0x92, 0x37, 0x27, 0xf0, 0x77, 0xb8, 0xe0, 0xb5,
]);

pub fn hexstr_to_h256(hex_str: &str) -> H256 {
    assert_eq!(hex_str.len(), 64);
    let mut bytes: [u8; 32] = Default::default();

    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).unwrap();
    }

    H256::from(bytes)
}

pub trait AddressUtil {
    fn type_bits(&self) -> u8;

    fn is_valid<T>(&self, builtin_map: &BTreeMap<Address, T>) -> bool;

    fn is_contract(&self) -> bool;

    fn is_payment(&self) -> bool;

    fn is_builtin<T>(&self, builtin_map: &BTreeMap<Address, T>) -> bool;

    fn converted_to_contract(&mut self);
}

impl AddressUtil for Address {
    fn type_bits(&self) -> u8 { self.as_fixed_bytes()[0] & 0xf0 }

    fn is_valid<T>(&self, builtin_map: &BTreeMap<Address, T>) -> bool {
        self.is_contract() || self.is_payment() || self.is_builtin(builtin_map)
    }

    /// Should keep this consistent with `converted_to_contract()`.
    fn is_contract(&self) -> bool { self.type_bits() == 0x80 }

    fn is_payment(&self) -> bool { self.type_bits() == 0x10 }

    fn is_builtin<T>(&self, builtin_map: &BTreeMap<Address, T>) -> bool {
        self.type_bits() == 0x0 && builtin_map.contains_key(&self)
    }

    fn converted_to_contract(&mut self) {
        self.as_bytes_mut()[0] &= 0x0f;
        self.as_bytes_mut()[0] |= 0x80;
    }
}
