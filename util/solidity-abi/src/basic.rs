// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{utils::abi_require, ABIDecodeError, ABIVariable, LinkedBytes};
use cfx_types::{Address, U256};

impl ABIVariable for Address {
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
}

impl ABIVariable for U256 {
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
}

impl ABIVariable for bool {
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
}
