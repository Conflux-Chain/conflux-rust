use super::Address;
use crate::{space_util::AddressSpaceUtil, AddressWithSpace};
use keccak_hash::keccak;

pub const TYPE_BITS_BUILTIN: u8 = 0x00;
pub const TYPE_BITS_CONTRACT: u8 = 0x80;
pub const TYPE_BITS_USER_ACCOUNT: u8 = 0x10;

pub trait AddressUtil: Sized + Ord {
    fn type_byte(&self) -> &u8;

    fn type_byte_mut(&mut self) -> &mut u8;

    fn is_null_address(&self) -> bool;

    fn evm_map(&self) -> AddressWithSpace;

    #[inline]
    fn address_type_bits(&self) -> u8 { self.type_byte() & 0xf0 }

    #[inline]
    fn set_address_type_bits(&mut self, type_bits: u8) {
        let type_byte = self.type_byte_mut();
        *type_byte &= 0x0f;
        *type_byte |= type_bits;
    }

    #[cfg(feature = "storage_benchmark_no_account_space_check")]
    #[inline]
    fn is_genesis_valid_address(&self) -> bool { true }

    #[cfg(not(feature = "storage_benchmark_no_account_space_check"))]
    #[inline]
    fn is_genesis_valid_address(&self) -> bool {
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
        self.address_type_bits() == TYPE_BITS_BUILTIN && !self.is_null_address()
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
    fn type_byte_mut(&mut self) -> &mut u8 { &mut self.as_fixed_bytes_mut()[0] }

    #[inline]
    fn is_null_address(&self) -> bool { self.is_zero() }

    #[inline]
    fn evm_map(&self) -> AddressWithSpace {
        Address::from(keccak(&self)).with_evm_space()
    }
}

impl AddressUtil for &[u8] {
    #[inline]
    fn type_byte(&self) -> &u8 { &self[0] }

    #[inline]
    fn type_byte_mut(&mut self) -> &mut u8 { unreachable!() }

    #[inline]
    fn is_null_address(&self) -> bool { self.iter().all(|&byte| byte == 0u8) }

    #[inline]
    fn evm_map(&self) -> AddressWithSpace {
        Address::from(keccak(&self)).with_evm_space()
    }
}

// parse hex string(support 0x prefix) to Address
// Address::from_str does not support 0x prefix
pub fn hex_to_address(hex_literal: &str) -> Result<Address, hex::FromHexError> {
    let hex_literal = hex_literal.strip_prefix("0x").unwrap_or(hex_literal);
    let raw_bytes = hex::decode(hex_literal)?;
    Ok(Address::from_slice(&raw_bytes))
}

#[cfg(test)]
mod tests {
    use super::{hex_to_address, Address, AddressUtil};

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

    #[test]
    fn test_address_util() {
        let addr =
            hex_to_address("0000000000000000000000000000000000000000").unwrap();
        assert_eq!(addr, Address::zero());

        let addr_err = hex_to_address("123");
        assert!(addr_err.is_err());

        let addr = hex_to_address("0x0000000000000000000000000000000000000000")
            .unwrap();
        assert_eq!(addr, Address::zero());

        use std::str::FromStr;
        let addr =
            Address::from_str("1234567890AbcdEF1234567890aBcdef12345678")
                .unwrap();
        let addr2 =
            hex_to_address("0x1234567890abcdef1234567890abcdef12345678")
                .unwrap();
        assert_eq!(addr, addr2);
    }
}
