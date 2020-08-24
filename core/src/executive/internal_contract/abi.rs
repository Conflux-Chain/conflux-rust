// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use cfx_types::{Address, U256};
use std::slice::Iter;

pub struct ABIDecodeError;

/// Decode ABI function call
pub trait ABIDecodable: Sized {
    fn extract_from_bytes(bytes: &mut Iter<u8>)
        -> Result<Self, ABIDecodeError>;
}

pub trait ABIEncodable: Sized {
    fn write_to_bytes(&self) -> Vec<u8>;
}

macro_rules! pull_bytes_function {
    ($name:ident, $n:tt) => {
        fn $name<'a>(
            bytes: &mut Iter<'a, u8>,
        ) -> Result<[u8; $n], ABIDecodeError> {
            const LEN: usize = $n;
            if bytes.len() >= LEN {
                let slice = bytes.as_slice();
                let mut result = [0u8; LEN];
                result.clone_from_slice(&slice[0..LEN]);
                *bytes = slice[LEN..].iter();
                Ok(result)
            } else {
                Err(ABIDecodeError)
            }
        }
    };
}

pull_bytes_function!(pull_4_bytes, 4);
pull_bytes_function!(pull_32_bytes, 32);

impl ABIDecodable for () {
    fn extract_from_bytes(_: &mut Iter<u8>) -> Result<Self, ABIDecodeError> {
        Ok(())
    }
}

impl ABIDecodable for Address {
    fn extract_from_bytes(
        bytes: &mut Iter<u8>,
    ) -> Result<Self, ABIDecodeError> {
        Ok(Address::from_slice(&pull_32_bytes(bytes)?[12..32]))
    }
}

impl ABIDecodable for U256 {
    fn extract_from_bytes(
        bytes: &mut Iter<u8>,
    ) -> Result<Self, ABIDecodeError> {
        Ok(U256::from(pull_32_bytes(bytes)?))
    }
}

impl ABIDecodable for bool {
    fn extract_from_bytes(
        bytes: &mut Iter<u8>,
    ) -> Result<Self, ABIDecodeError> {
        Ok(pull_32_bytes(bytes)?[31] != 0)
    }
}

impl<T: ABIDecodable, U: ABIDecodable> ABIDecodable for (T, U) {
    fn extract_from_bytes(
        bytes: &mut Iter<u8>,
    ) -> Result<Self, ABIDecodeError> {
        Ok((T::extract_from_bytes(bytes)?, U::extract_from_bytes(bytes)?))
    }
}

impl ABIDecodable for Vec<Address> {
    fn extract_from_bytes(
        bytes: &mut Iter<u8>,
    ) -> Result<Self, ABIDecodeError> {
        let location = U256::from(pull_32_bytes(bytes)?);
        if location != U256::from(32) {
            return Err(ABIDecodeError);
        }
        let expected_length = U256::from(pull_32_bytes(bytes)?);
        let mut i = U256::zero();
        let mut results = Vec::new();
        while i < expected_length {
            results.push(Address::extract_from_bytes(bytes)?);
            i = i + 1;
        }
        Ok(results)
    }
}

pub struct ABIReader<'a> {
    data_iter: Iter<'a, u8>,
}

impl<'a> ABIReader<'a> {
    pub fn new(data_iter: Iter<'a, u8>) -> Self { ABIReader { data_iter } }

    pub fn pull_parameters<T: ABIDecodable>(
        mut self,
    ) -> Result<T, ABIDecodeError> {
        let parameters = T::extract_from_bytes(&mut self.data_iter)?;
        self.require_empty()?;
        Ok(parameters)
    }

    pub fn pull_sig(&mut self) -> Result<[u8; 4], ABIDecodeError> {
        pull_4_bytes(&mut self.data_iter)
    }

    pub fn require_empty(mut self) -> Result<(), ABIDecodeError> {
        if self.data_iter.next().is_some() {
            Err(ABIDecodeError)
        } else {
            Ok(())
        }
    }
}

impl ABIEncodable for () {
    fn write_to_bytes(&self) -> Vec<u8> { Vec::new() }
}

impl ABIEncodable for Address {
    fn write_to_bytes(&self) -> Vec<u8> {
        vec![0u8; 12]
            .iter()
            .chain(self.as_bytes())
            .cloned()
            .collect::<Vec<u8>>()
    }
}

impl ABIEncodable for U256 {
    fn write_to_bytes(&self) -> Vec<u8> {
        let mut ans = vec![0u8; 32];
        self.to_big_endian(&mut ans);
        ans
    }
}

impl ABIEncodable for bool {
    fn write_to_bytes(&self) -> Vec<u8> {
        let mut ans = vec![0u8; 32];
        ans[31] = *self as u8;
        ans
    }
}

impl<T: ABIEncodable, U: ABIEncodable> ABIEncodable for (T, U) {
    fn write_to_bytes(&self) -> Vec<u8> {
        self.0
            .write_to_bytes()
            .iter()
            .chain(self.1.write_to_bytes().iter())
            .cloned()
            .collect::<Vec<u8>>()
    }
}
