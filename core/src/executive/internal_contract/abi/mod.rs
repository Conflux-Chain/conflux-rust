pub mod utils; // Copyright 2020 Conflux Foundation. All rights reserved.
               // Conflux is free software and distributed under GNU General Public License.
               // See http://www.gnu.org/licenses/

mod array;
mod basic;
mod tuple;

use self::utils::{abi_require, pull_slice, to_big_endian};
use cfx_types::U256;
use std::slice::Iter;

pub struct ABIDecodeError(pub &'static str);

pub trait ABIDecodable: Sized {
    fn abi_decode(data: &[u8]) -> Result<Self, ABIDecodeError>;
}

pub trait ABIEncodable: Sized {
    fn abi_encode(&self) -> Vec<u8>;
}

pub trait ABIVariable: Sized {
    fn static_length() -> Option<usize>;
    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError>;
    fn to_abi(&self) -> Vec<u8>;
}

fn read_abi_variable<T: ABIVariable>(
    data: &[u8], pointer: &mut Iter<u8>,
) -> Result<T, ABIDecodeError> {
    let res = if let Some(len) = T::static_length() {
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

#[derive(Default)]
struct ListRecorder {
    prefix: Vec<u8>,
    heads: Vec<u8>,
    tails: Vec<u8>,
}

impl ListRecorder {
    fn with_prefix(prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            heads: Vec::new(),
            tails: Vec::new(),
        }
    }

    fn write_down<T: ABIVariable>(&mut self, input: &T) {
        let encoded = input.to_abi();
        if let Some(len) = T::static_length() {
            assert_eq!(encoded.len(), len);
            self.heads.extend_from_slice(&encoded);
        } else {
            self.heads.extend_from_slice(&to_big_endian(encoded.len()));
            self.tails.extend_from_slice(&encoded);
        }
    }

    fn into_vec(mut self) -> Vec<u8> {
        self.prefix.extend_from_slice(&self.heads);
        self.prefix.extend_from_slice(&self.tails);
        self.prefix
    }
}
