extern crate cfx_types;
extern crate num;
#[cfg(test)]
extern crate static_assertions;
extern crate typenum;
extern crate unroll;

pub mod nth_root;

pub use nth_root::{nth_inv_root, nth_root};

use cfx_types::U256;
use num::integer::Roots;

pub fn sqrt_u256(input: U256) -> U256 {
    let bits = input.bits();
    if bits <= 64 {
        return input.as_u64().sqrt().into();
    }

    /************************************************************
    * Step 1: pick the most significant 64 bits and estimate an
    * approximate root.
    ===========================================================*/
    let significant_bits = 64 - bits % 2;
    // The `rest_bits` must be even number.
    let rest_bits = bits - significant_bits;
    // The `input >> rest_bits` has `significant_bits`
    let significant_word = (input >> rest_bits).as_u64();
    // The `init_root` is slightly larger than the correct root.
    let init_root =
        U256::from(significant_word.sqrt() + 1u64) << (rest_bits / 2);

    /*=================================================================
    * Step 2: use the Newton's method to estimate the accurate value.
    =================================================================*/
    let mut root = init_root;
    // Will iterate for at most 4 rounds.
    while root * root > input {
        root = (input / root + root) / 2;
    }

    root
}

pub fn power_two_fractional(ratio: u64, increase: bool, precision: u8) -> U256 {
    assert!(precision <= 127);

    let mut base = U256::one();
    base <<= 254usize;

    for i in 0..64u64 {
        if ratio & (1 << i) != 0 {
            if increase {
                base <<= 1usize;
            } else {
                base >>= 1usize;
            }
        }
        base = sqrt_u256(base);
        base <<= 127usize;
    }

    base >>= (254 - precision) as usize;
    // Computing error < 5.2 * 2 ^ -127
    base
}
