use super::{utils::abi_require, ABIDecodeError, ABIVariable};
use cfx_types::{Address, U256};

impl ABIVariable for Address {
    fn static_length() -> Option<usize> { Some(32) }

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        abi_require(data.len() == 32, "Invalid call data length")?;
        Ok(Address::from_slice(&data[12..32]))
    }

    fn to_abi(&self) -> Vec<u8> {
        let mut head = vec![0u8; 12];
        head.extend_from_slice(self.as_bytes());
        head
    }
}

impl ABIVariable for U256 {
    fn static_length() -> Option<usize> { Some(32) }

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        abi_require(data.len() == 32, "Invalid call data length")?;
        Ok(U256::from_big_endian(&data))
    }

    fn to_abi(&self) -> Vec<u8> {
        let mut head = vec![0u8; 32];
        self.to_big_endian(&mut head);
        head
    }
}

impl ABIVariable for bool {
    fn static_length() -> Option<usize> { Some(32) }

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        abi_require(data.len() == 32, "Invalid call data length")?;
        Ok(data[31] != 0)
    }

    fn to_abi(&self) -> Vec<u8> {
        let mut head = vec![0u8; 32];
        head[31] = *self as u8;
        head
    }
}
