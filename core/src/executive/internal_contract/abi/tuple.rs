use super::{
    utils::{read_abi_list, ABIListWriter},
    ABIDecodable, ABIDecodeError, ABIEncodable, ABIVariable,
};

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

impl_abi_serde!((0=>A),(1=>B));
// impl_abi_serde!((0=>A),(1=>B),(2=>C));
// impl_abi_serde!((0=>A),(1=>B),(2=>C),(3=>D));
