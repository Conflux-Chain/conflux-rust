// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    utils::{padded_big_endian, pull_slice, LinkedBytes},
    ABIDecodeError, ABIVariable,
};

pub(super) type Bytes = Vec<u8>;

use cfx_types::U256;

impl ABIVariable for Bytes {
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
}
