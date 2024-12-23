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
