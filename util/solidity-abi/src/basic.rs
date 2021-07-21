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

impl ABIVariable for u64 {
    const BASIC_TYPE: bool = true;
    const STATIC_LENGTH: Option<usize> = Some(32);

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        abi_require(data.len() == 32, "Invalid call data length")?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[32 - 8..]);
        Ok(u64::from_be_bytes(bytes))
    }

    fn to_abi(&self) -> LinkedBytes {
        let mut answer = vec![0u8; 32];
        answer[32 - 8..].copy_from_slice(&self.to_be_bytes());
        LinkedBytes::from_bytes(answer)
    }

    fn to_packed_abi(&self) -> LinkedBytes {
        LinkedBytes::from_bytes(self.to_be_bytes().to_vec())
    }
}
