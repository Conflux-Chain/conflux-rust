use cfx_types::U256;
use keccak_hash::keccak;

// General function for solidity storage rule
pub fn mapping_slot(base: U256, index: U256) -> U256 {
    let mut input = [0u8; 64];
    base.to_big_endian(&mut input[32..]);
    index.to_big_endian(&mut input[..32]);
    let hash = keccak(input);
    U256::from_big_endian(hash.as_ref())
}

#[allow(dead_code)]
// General function for solidity storage rule
pub fn vector_slot(base: U256, index: usize, size: usize) -> U256 {
    let start_slot = dynamic_slot(base);
    return array_slot(start_slot, index, size);
}

pub fn dynamic_slot(base: U256) -> U256 {
    let mut input = [0u8; 32];
    base.to_big_endian(&mut input);
    let hash = keccak(input);
    return U256::from_big_endian(hash.as_ref());
}

// General function for solidity storage rule
pub fn array_slot(base: U256, index: usize, element_size: usize) -> U256 {
    // Solidity will apply an overflowing add here.
    // However, if this function is used correctly, the overflowing will
    // happen with a negligible exception, so we let it panic when
    // overflowing happen.
    base + index * element_size
}

pub fn u256_to_array(input: U256) -> [u8; 32] {
    let mut answer = [0u8; 32];
    input.to_big_endian(answer.as_mut());
    answer
}
