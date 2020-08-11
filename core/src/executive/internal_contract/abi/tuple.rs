use super::{
    read_abi_variable, ABIDecodable, ABIDecodeError, ABIEncodable, ABIVariable,
    ListRecorder,
};

macro_rules! impl_abi_serde {
    ($( ($idx:tt => $name:ident) ),* ) => {
        impl<$($name:ABIVariable),*> ABIDecodable for ($($name),* ) {
            fn abi_decode(data: &[u8]) -> Result<Self, ABIDecodeError> {
                let mut pointer = data.iter();
                Ok((
                    $(read_abi_variable::<$name>(data, &mut pointer)?),*
                ))
            }
        }

        impl<$($name:ABIVariable),*> ABIEncodable for ($($name),*) {
            fn abi_encode(&self) -> Vec<u8> {
                let mut recorder = ListRecorder::default();
                $(recorder.write_down(&self.$idx);)*
                recorder.into_vec()
            }
        }
    };
}

impl ABIEncodable for () {
    fn abi_encode(&self) -> Vec<u8> { Vec::new() }
}

impl ABIDecodable for () {
    fn abi_decode(_: &[u8]) -> Result<Self, ABIDecodeError> { Ok(()) }
}

impl<T: ABIVariable> ABIEncodable for T {
    fn abi_encode(&self) -> Vec<u8> {
        let mut recorder = ListRecorder::default();
        recorder.write_down(self);
        recorder.into_vec()
    }
}

impl<T: ABIVariable> ABIDecodable for T {
    fn abi_decode(data: &[u8]) -> Result<Self, ABIDecodeError> {
        Ok(read_abi_variable::<T>(data, &mut data.iter())?)
    }
}

// impl_abi_serde!(0=>A, 1=>B, 2=>C, 3=>D, 4=>E, 5=>F, 6=>G, 7=>H, 8=>I, 9=>J);
impl_abi_serde!((0=>A),(1=>B));
