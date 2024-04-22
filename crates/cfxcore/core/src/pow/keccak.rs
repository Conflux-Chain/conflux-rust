pub type H256 = [u8; 32];

pub mod keccak_512 {
    use crate::hash;

    pub use self::hash::keccak_512 as write;
}

pub mod keccak_256 {
    use crate::hash;

    pub use self::hash::keccak_256 as write;
}
