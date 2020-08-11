// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod array;
mod basic;
mod tuple;
pub mod utils;

#[cfg(test)]
mod tests;

use self::utils::LinkedBytes;

#[derive(Debug, PartialEq)]
pub struct ABIDecodeError(pub &'static str);

pub trait ABIDecodable: Sized {
    fn abi_decode(data: &[u8]) -> Result<Self, ABIDecodeError>;
}

pub trait ABIEncodable: Sized {
    fn abi_encode(&self) -> Vec<u8>;
}

pub trait ABIVariable: Sized {
    const STATIC_LENGTH: Option<usize>;
    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError>;
    fn to_abi(&self) -> LinkedBytes;
}
