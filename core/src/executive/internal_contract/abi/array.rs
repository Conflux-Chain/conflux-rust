// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{
    utils::{
        padded_big_endian, pull_slice, read_abi_list, ABIListWriter,
        LinkedBytes,
    },
    ABIDecodeError, ABIVariable,
};

use cfx_types::U256;

impl<T: ABIVariable> ABIVariable for Vec<T> {
    const STATIC_LENGTH: Option<usize> = None;

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        let pointer = &mut data.iter();

        let expected_length = U256::from_big_endian(pull_slice(pointer, 32)?);
        let data_without_length = pointer.as_slice();
        let mut i = U256::zero();
        let mut results = Vec::new();
        while i < expected_length {
            results.push(read_abi_list::<T>(data_without_length, pointer)?);
            i = i + 1;
        }
        Ok(results)
    }

    fn to_abi(&self) -> LinkedBytes {
        let length = LinkedBytes::from_bytes(padded_big_endian(self.len()));
        let mut recorder = ABIListWriter::with_heads_length(
            T::STATIC_LENGTH.unwrap_or(32) * self.len(),
        );

        for item in self {
            recorder.write_down(item);
        }
        let mut answer = length;
        answer.append(&mut recorder.into_linked_bytes());
        answer
    }
}
