use super::{ABIEncodable, ABIVariable};
use cfx_types::{Address, H256};

pub trait IndexedArg {
    fn to_indexed_arg(&self) -> H256;
}

pub trait NonIndexedArgs {
    fn to_non_indexed_args(&self) -> Vec<u8>;
}

impl IndexedArg for Address {
    fn to_indexed_arg(&self) -> H256 {
        H256::from_slice(&self.to_abi().to_vec())
    }
}

impl<T: ABIEncodable> NonIndexedArgs for T {
    fn to_non_indexed_args(&self) -> Vec<u8> { self.abi_encode() }
}
