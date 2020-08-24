// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate ethereum_types;

pub use ethereum_types::{
    Address, BigEndianHash, Bloom, BloomInput, Public, Secret, Signature, H128,
    H160, H256, H512, H520, H64, U128, U256, U512, U64,
};

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

pub mod address_util {
    use super::Address;

    pub const TYPE_BITS_BUILTIN: u8 = 0x00;
    pub const TYPE_BITS_CONTRACT: u8 = 0x80;
    pub const TYPE_BITS_USER_ACCOUNT: u8 = 0x10;

    pub trait AddressUtil: Sized + Ord {
        fn type_byte(&self) -> &u8;

        fn type_byte_mut(&mut self) -> &mut u8;

        fn is_null_address(&self) -> bool;

        #[inline]
        fn address_type_bits(&self) -> u8 { self.type_byte() & 0xf0 }

        #[inline]
        fn set_address_type_bits(&mut self, type_bits: u8) {
            let type_byte = self.type_byte_mut();
            *type_byte &= 0x0f;
            *type_byte |= type_bits;
        }

        #[inline]
        fn is_valid_address(&self) -> bool {
            self.is_contract_address()
                || self.is_user_account_address()
                || self.is_builtin_address()
                || self.is_null_address()
        }

        #[inline]
        fn is_contract_address(&self) -> bool {
            self.address_type_bits() == TYPE_BITS_CONTRACT
        }

        #[inline]
        fn is_user_account_address(&self) -> bool {
            self.address_type_bits() == TYPE_BITS_USER_ACCOUNT
        }

        #[inline]
        fn is_builtin_address(&self) -> bool {
            self.address_type_bits() == TYPE_BITS_BUILTIN
                && !self.is_null_address()
        }

        #[inline]
        fn set_contract_type_bits(&mut self) {
            self.set_address_type_bits(TYPE_BITS_CONTRACT);
        }

        #[inline]
        fn set_user_account_type_bits(&mut self) {
            self.set_address_type_bits(TYPE_BITS_USER_ACCOUNT);
        }
    }

    impl AddressUtil for Address {
        #[inline]
        fn type_byte(&self) -> &u8 { &self.as_fixed_bytes()[0] }

        #[inline]
        fn type_byte_mut(&mut self) -> &mut u8 {
            &mut self.as_fixed_bytes_mut()[0]
        }

        #[inline]
        fn is_null_address(&self) -> bool { self.is_zero() }
    }

    impl AddressUtil for &[u8] {
        #[inline]
        fn type_byte(&self) -> &u8 { &self[0] }

        #[inline]
        fn type_byte_mut(&mut self) -> &mut u8 { unreachable!() }

        #[inline]
        fn is_null_address(&self) -> bool {
            self.iter().all(|&byte| byte == 0u8)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{Address, AddressUtil};

        #[test]
        fn test_set_type_bits() {
            let mut address = Address::default();

            address.set_contract_type_bits();
            assert!(address.is_contract_address());
            assert!(!address.is_user_account_address());

            address.set_user_account_type_bits();
            assert!(address.is_user_account_address());

            for types in 0..16 {
                let type_bits = types << 4;
                address.set_address_type_bits(type_bits);
                assert_eq!(address.address_type_bits(), type_bits);
            }
        }
    }
}
