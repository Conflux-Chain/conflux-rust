use cfx_types::U256;
use keccak_hash::keccak;

// General function for solidity storage rule
pub fn mapping_slot(base: U256, index: U256) -> U256 {
    let mut input = [0u8; 64];
    input[32..].copy_from_slice(&base.to_big_endian());
    input[..32].copy_from_slice(&index.to_big_endian());
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
    let hash = keccak(base.to_big_endian());
    return U256::from_big_endian(hash.as_ref());
}

// General function for solidity storage rule
pub fn array_slot(base: U256, index: usize, element_size: usize) -> U256 {
    // Solidity will apply an overflowing add here.
    let (offset, _) =
        U256::from(index).overflowing_mul(U256::from(element_size));
    base.overflowing_add(offset).0
}

pub fn u256_to_array(input: U256) -> [u8; 32] { input.to_big_endian() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn array_slot_wraps_like_solidity() {
        assert_eq!(array_slot(U256::MAX, 1, 1), U256::zero());
    }
}
