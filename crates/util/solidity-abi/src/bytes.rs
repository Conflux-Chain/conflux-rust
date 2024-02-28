// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    utils::{padded_big_endian, pull_slice, LinkedBytes},
    ABIDecodeError, ABIVariable,
};

pub(super) type Bytes = Vec<u8>;

use cfx_types::U256;
use std::convert::TryInto;

impl ABIVariable for Bytes {
    const BASIC_TYPE: bool = false;
    const STATIC_LENGTH: Option<usize> = None;

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        let pointer = &mut data.iter();

        let expected_length = U256::from_big_endian(pull_slice(
            pointer,
            32,
            "Incomplete length for byte array",
        )?);
        let data_without_length = pointer.as_slice();
        if U256::from(data_without_length.len()) < expected_length {
            Err(ABIDecodeError("Invalid length in byte array"))
        } else {
            let length = expected_length.as_usize();
            Ok(data_without_length[0..length].to_vec())
        }
    }

    fn to_abi(&self) -> LinkedBytes {
        let mut result = padded_big_endian(self.len());
        result.extend_from_slice(self);
        result.extend_from_slice(&vec![0u8; 31 - (self.len() + 31) % 32]);
        LinkedBytes::from_bytes(result)
    }

    fn to_packed_abi(&self) -> LinkedBytes {
        LinkedBytes::from_bytes(self.clone())
    }
}

impl<const N: usize> ABIVariable for [u8; N]
where [u8; N]: SolidityBytes
{
    const BASIC_TYPE: bool = true;
    // We only implement for N<=32. These fixed length bytes are padded with
    // zeros.
    const STATIC_LENGTH: Option<usize> = Some(32);

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        let pointer = &mut data.iter();

        let data_without_length = pointer.as_slice();
        if data_without_length.len() < N {
            Err(ABIDecodeError("Invalid length in byte array"))
        } else {
            Ok(data_without_length[0..N]
                .try_into()
                .expect("Length must correct"))
        }
    }

    fn to_abi(&self) -> LinkedBytes {
        let mut result = vec![0u8; 32];
        result[0..N].copy_from_slice(self);
        LinkedBytes::from_bytes(result)
    }

    fn to_packed_abi(&self) -> LinkedBytes {
        LinkedBytes::from_bytes(self.to_vec())
    }
}

pub trait SolidityBytes {}

macro_rules! mark_solidity_bytes {
    ($($idx:tt),*) => {
        $(impl SolidityBytes for [u8;$idx] {})*
    }
}
mark_solidity_bytes!(
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
    23, 24, 25, 26, 27, 28, 29, 30, 31, 32
);
