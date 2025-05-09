// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod array;
mod basic;
mod bytes;
mod string;

#[cfg(test)]
mod tests;
mod utils;

pub use self::utils::{
    read_abi_list, string_revert_reason_decode, ABIListWriter, LinkedBytes,
};
use cfx_types::H256;
use keccak_hash::keccak;

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
/// `(U256,)`, we implement `ABIEncodable` for `U256` instead.
pub trait ABIEncodable: Sized {
    fn abi_encode(&self) -> Vec<u8>;
}

/// A type implements `ABIPackedEncodable` must be a tuple of types implement
/// `ABIVariable`. For convenient, for the tuple with only one element like
/// `(U256,)`, we implement `ABIPackedEncodable` for `U256` instead.
pub trait ABIPackedEncodable: Sized {
    fn abi_packed_encode(&self) -> Vec<u8>;
}

/// A type implements `EventIndexEncodable` must be a tuple of types implement
/// `EventIndexEncodable`. For convenient, for the tuple with only one element
/// like `(U256,)`, we implement `EventIndexEncodable` for `U256` instead.
pub trait EventIndexEncodable: Sized {
    fn indexed_event_encode(&self) -> Vec<H256>;
}

pub trait ABIVariable: Sized {
    const BASIC_TYPE: bool;
    const STATIC_LENGTH: Option<usize>;

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError>;
    fn to_abi(&self) -> LinkedBytes;
    fn to_packed_abi(&self) -> LinkedBytes;
}

impl ABIDecodable for () {
    fn abi_decode(_: &[u8]) -> Result<Self, ABIDecodeError> { Ok(()) }
}

impl ABIEncodable for () {
    fn abi_encode(&self) -> Vec<u8> { Vec::new() }
}

impl ABIPackedEncodable for () {
    fn abi_packed_encode(&self) -> Vec<u8> { Vec::new() }
}

impl EventIndexEncodable for () {
    fn indexed_event_encode(&self) -> Vec<H256> { Vec::new() }
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

impl<T: ABIVariable> ABIPackedEncodable for T {
    fn abi_packed_encode(&self) -> Vec<u8> { self.to_packed_abi().to_vec() }
}

impl<T: ABIVariable> EventIndexEncodable for T {
    fn indexed_event_encode(&self) -> Vec<H256> {
        let answer = if T::BASIC_TYPE {
            H256::from_slice(&self.to_abi().to_vec())
        } else {
            keccak(self.abi_packed_encode())
        };
        vec![answer]
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

        impl<$($name:ABIVariable),*> ABIPackedEncodable for ($($name),*) {
            fn abi_packed_encode(&self) -> Vec<u8> {
                let mut recorder = LinkedBytes::new();
                $(recorder.append(&mut self.$idx.to_packed_abi());)*
                recorder.to_vec()
            }
        }

        impl<$($name:ABIVariable),*> EventIndexEncodable for ($($name),*) {
            fn indexed_event_encode(&self) -> Vec<H256> {
                let mut answer = Vec::new();
                $(answer.push(if $name::BASIC_TYPE {
                    H256::from_slice(&self.$idx.to_abi().to_vec())
                } else {
                    keccak(self.$idx.abi_packed_encode())
                });)*
                answer
            }
        }
    };
}

// Now we supply a function/events with at most five parameters
impl_abi_serde!((0=>A),(1=>B));
impl_abi_serde!((0=>A),(1=>B),(2=>C));
impl_abi_serde!((0=>A),(1=>B),(2=>C),(3=>D));
impl_abi_serde!((0=>A),(1=>B),(2=>C),(3=>D),(4=>E));
