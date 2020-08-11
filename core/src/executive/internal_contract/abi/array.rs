use super::{
    read_abi_variable,
    utils::{pull_slice, to_big_endian},
    ABIDecodeError, ABIVariable, ListRecorder,
};

use cfx_types::U256;

impl<T: ABIVariable> ABIVariable for Vec<T> {
    fn static_length() -> Option<usize> { None }

    fn from_abi(data: &[u8]) -> Result<Self, ABIDecodeError> {
        let pointer = &mut data.iter();

        let expected_length = U256::from_big_endian(pull_slice(pointer, 32)?);
        let mut i = U256::zero();
        let mut results = Vec::new();
        while i < expected_length {
            results.push(read_abi_variable(data, pointer)?);
            i = i + 1;
        }
        Ok(results)
    }

    fn to_abi(&self) -> Vec<u8> {
        let length = to_big_endian(self.len()).to_vec();
        let mut recorder = ListRecorder::with_prefix(length);

        for item in self {
            recorder.write_down(item);
        }
        recorder.into_vec()
    }
}
