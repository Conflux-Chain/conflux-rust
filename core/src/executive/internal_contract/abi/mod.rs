// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod array;
mod basic;
pub mod utils;

#[cfg(test)]
mod tests;

use self::utils::{read_abi_list, ABIListWriter, LinkedBytes};

#[derive(Debug, PartialEq)]
pub struct ABIDecodeError(pub &'static str);

/// A type implements `ABIDecodable` must be a tuple of types implement
/// `ABIVariable`. For convenient, for the tuple with only one element like
/// `(U256,)`, we implement `ABIDecodable` for `U256` instead.
pub trait ABIDecodable: Sized {
    fn abi_decode(data: &[u8]) -> Result<Self, ABIDecodeError>;
}

/// A type implements `ABIEncodable` must be a tuple of types implement
/// `ABIVariable`. For convenient, for the tuple with only one element like
/// `(U256,)`, we implement `ABIDecodable` for `U256` instead.
pub trait ABIEncodable: Sized {
    fn abi_encode(&self) -> Vec<u8>;
}

pub trait ABIVariable: Sized + Default {
    const STATIC_LENGTH: Option<usize>;
    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError>;
    fn to_abi(&self) -> LinkedBytes;
}

impl ABIDecodable for () {
    fn abi_decode(_: &[u8]) -> Result<Self, ABIDecodeError> { Ok(()) }
}

impl ABIEncodable for () {
    fn abi_encode(&self) -> Vec<u8> { Vec::new() }
}

impl<T: ABIVariable> ABIDecodable for T {
    fn abi_decode(data: &[u8]) -> Result<Self, ABIDecodeError> {
        Ok(read_abi_list::<T>(data, &mut data.iter())?)
    }
}

impl<T: ABIVariable> ABIEncodable for T {
    fn abi_encode(&self) -> Vec<u8> {
        let mut recorder =
            ABIListWriter::with_heads_length(T::STATIC_LENGTH.unwrap_or(32));
        recorder.write_down(self);
        recorder.into_linked_bytes().to_vec()
    }
}

macro_rules! impl_abi_serde {
    ($( ($idx:tt => $name:ident) ),* ) => {
        impl<$($name:ABIVariable),*> ABIDecodable for ($($name),* ) {
            fn abi_decode(data: &[u8]) -> Result<Self, ABIDecodeError> {
                let mut pointer = data.iter();
                Ok((
                    $(read_abi_list::<$name>(data, &mut pointer)?),*
                ))
            }
        }

        impl<$($name:ABIVariable),*> ABIEncodable for ($($name),*) {
            fn abi_encode(&self) -> Vec<u8> {
                let heads_length: usize = 0 $( + $name::STATIC_LENGTH.unwrap_or(32) )* ;
                let mut recorder = ABIListWriter::with_heads_length(heads_length);
                $(recorder.write_down(&self.$idx);)*
                recorder.into_linked_bytes().to_vec()
            }
        }
    };
}

// Now we supply a function with at most four parameters
impl_abi_serde!((0=>A),(1=>B));
impl_abi_serde!((0=>A),(1=>B),(2=>C));
impl_abi_serde!((0=>A),(1=>B),(2=>C),(3=>D));
