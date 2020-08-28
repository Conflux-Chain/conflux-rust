// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::{ABIDecodeError, ABIVariable};
use cfx_types::U256;
use std::{collections::LinkedList, slice::Iter};

pub struct LinkedBytes {
    length: usize,
    data: LinkedList<Vec<u8>>,
}

pub fn padded_big_endian(length: usize) -> Vec<u8> {
    let mut bytes = [0u8; 32];
    U256::from(length).to_big_endian(&mut bytes);
    bytes.to_vec()
}

impl LinkedBytes {
    pub fn new() -> Self {
        Self {
            length: 0,
            data: LinkedList::new(),
        }
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let mut answer = Self::new();
        answer.length = bytes.len();
        answer.data.push_back(bytes);
        answer
    }

    pub fn append(&mut self, other: &mut Self) {
        self.length += other.length;
        self.data.append(&mut other.data);
        other.length = 0;
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut answer = Vec::new();
        for slice in &self.data {
            answer.extend_from_slice(&slice)
        }
        answer
    }

    pub fn len(&self) -> usize { self.length }
}

pub(crate) fn read_abi_list<T: ABIVariable>(
    data: &[u8], pointer: &mut Iter<u8>,
) -> Result<T, ABIDecodeError> {
    let res = if let Some(len) = T::STATIC_LENGTH {
        pull_slice(pointer, len)?
    } else {
        let location = U256::from_big_endian(pull_slice(pointer, 32)?);
        abi_require(
            location < U256::from(data.len()),
            "Location out of bounds",
        )?;
        let loc = location.as_u64() as usize;
        &data[loc..]
    };
    T::from_abi(res)
}

pub(super) struct ABIListWriter {
    heads_length: usize,
    heads: LinkedBytes,
    tails: LinkedBytes,
}

impl ABIListWriter {
    pub(super) fn with_heads_length(heads_length: usize) -> Self {
        Self {
            heads_length,
            heads: LinkedBytes::new(),
            tails: LinkedBytes::new(),
        }
    }

    pub(super) fn write_down<T: ABIVariable>(&mut self, input: &T) {
        let mut encoded = input.to_abi();
        if let Some(len) = T::STATIC_LENGTH {
            assert_eq!(encoded.len(), len);
            self.heads.append(&mut encoded);
        } else {
            let mut location = LinkedBytes::from_bytes(padded_big_endian(
                self.tails.len() + self.heads_length,
            ));
            self.heads.append(&mut location);
            self.tails.append(&mut encoded);
        }
    }

    pub(super) fn into_linked_bytes(mut self) -> LinkedBytes {
        assert_eq!(self.heads.len(), self.heads_length);
        self.heads.append(&mut self.tails);
        self.heads
    }
}

#[inline]
pub fn abi_require(
    claim: bool, desc: &'static str,
) -> Result<(), ABIDecodeError> {
    if !claim {
        Err(ABIDecodeError(desc))
    } else {
        Ok(())
    }
}

#[inline]
pub fn pull_slice<'a>(
    iter: &mut Iter<'a, u8>, n: usize,
) -> Result<&'a [u8], ABIDecodeError> {
    abi_require(iter.len() >= n, "Invalid call data length")?;

    let slice = iter.as_slice();
    let result = &slice[0..n];
    *iter = slice[n..].iter();
    Ok(result)
}
