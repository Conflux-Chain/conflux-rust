// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{utils::abi_require, ABIDecodeError, ABIVariable, LinkedBytes};
use cfx_types::{Address, H256, U256};

impl ABIVariable for Address {
    const BASIC_TYPE: bool = true;
    const STATIC_LENGTH: Option<usize> = Some(32);

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        abi_require(data.len() == 32, "Invalid call data length")?;
        Ok(Address::from_slice(&data[12..32]))
    }

    fn to_abi(&self) -> LinkedBytes {
        let mut answer = vec![0u8; 12];
        answer.extend_from_slice(self.as_bytes());
        LinkedBytes::from_bytes(answer)
    }

    fn to_packed_abi(&self) -> LinkedBytes {
        LinkedBytes::from_bytes(self.to_fixed_bytes().into())
    }
}

impl ABIVariable for U256 {
    const BASIC_TYPE: bool = true;
    const STATIC_LENGTH: Option<usize> = Some(32);

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        abi_require(data.len() == 32, "Invalid call data length")?;
        Ok(U256::from_big_endian(&data))
    }

    fn to_abi(&self) -> LinkedBytes {
        let mut answer = vec![0u8; 32];
        self.to_big_endian(&mut answer);
        LinkedBytes::from_bytes(answer)
    }

    fn to_packed_abi(&self) -> LinkedBytes { self.to_abi() }
}

impl ABIVariable for H256 {
    const BASIC_TYPE: bool = <[u8; 32]>::BASIC_TYPE;
    const STATIC_LENGTH: Option<usize> = <[u8; 32]>::STATIC_LENGTH;

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        Ok(H256::from(<[u8; 32]>::from_abi(data)?))
    }

    fn to_abi(&self) -> LinkedBytes { self.0.to_abi() }

    fn to_packed_abi(&self) -> LinkedBytes { self.0.to_packed_abi() }
}

impl ABIVariable for bool {
    const BASIC_TYPE: bool = true;
    const STATIC_LENGTH: Option<usize> = Some(32);

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        abi_require(data.len() == 32, "Invalid call data length")?;
        Ok(data[31] != 0)
    }

    fn to_abi(&self) -> LinkedBytes {
        let mut answer = vec![0u8; 32];
        answer[31] = *self as u8;
        LinkedBytes::from_bytes(answer)
    }

    fn to_packed_abi(&self) -> LinkedBytes {
        LinkedBytes::from_bytes(vec![*self as u8])
    }
}

macro_rules! impl_abi_variable_for_primitive {
    () => {};
    ($ty: ident) => {impl_abi_variable_for_primitive!($ty,);};
    ($ty: ident, $($rest: ident),*) => {
        impl ABIVariable for $ty {
            const BASIC_TYPE: bool = true;
            const STATIC_LENGTH: Option<usize> = Some(32);

            fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
                const BYTES: usize = ($ty::BITS/8) as usize;
                abi_require(data.len() == 32, "Invalid call data length")?;
                let mut bytes = [0u8; BYTES];
                bytes.copy_from_slice(&data[32 - BYTES..]);
                Ok($ty::from_be_bytes(bytes))
            }

            fn to_abi(&self) -> LinkedBytes {
                const BYTES: usize = ($ty::BITS/8) as usize;
                let mut answer = vec![0u8; 32];
                answer[32 - BYTES..].copy_from_slice(&self.to_be_bytes());
                LinkedBytes::from_bytes(answer)
            }

            fn to_packed_abi(&self) -> LinkedBytes {
                LinkedBytes::from_bytes(self.to_be_bytes().to_vec())
            }
        }

        impl_abi_variable_for_primitive!($($rest),*);
    }
}

impl_abi_variable_for_primitive!(U8, u16, u32, u64, u128);

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct U8(u8);

impl U8 {
    const BITS: usize = 8;

    fn to_be_bytes(self) -> [u8; 1] { [self.0] }

    fn from_be_bytes(input: [u8; 1]) -> Self { U8(input[0]) }
}
