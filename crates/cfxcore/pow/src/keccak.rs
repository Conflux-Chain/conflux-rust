pub type H256 = [u8; 32];

pub mod keccak_512 {
    use keccak_hash as hash;

    pub use self::hash::keccak_512 as write;
}

pub mod keccak_256 {
    use keccak_hash as hash;

    pub use self::hash::keccak_256 as write;
}
