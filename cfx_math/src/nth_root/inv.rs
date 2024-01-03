use cfx_types::U256;
use std::ops::{Shl, Shr};
use typenum::Unsigned;

use super::{nth_root, NthRoot, RootDegree, RootInvParams};

pub fn nth_inv_root<N: RootDegree, P: Unsigned>(input: U256) -> U256
where (N, P): RootInvParams {
    if input.is_zero() {
        return U256::MAX;
    }
    let min_bits = N::USIZE * P::USIZE + 1;

    let bits = input.bits();
    let ideal_bits = min_bits + (bits - 1) % N::USIZE;

    let adjusted_input =
        rotate_right(input, bits as isize - ideal_bits as isize);
    let back_rotate = (bits as isize - ideal_bits as isize) / N::ISIZE;

    let root = nth_root::<N, _>(adjusted_input);
    let root_bits = root.bits();

    if root_bits + P::USIZE <= 64 {
        rotate_right(U256::from(u64::MAX / root.low_u64()), back_rotate - 192)
    } else if root_bits + P::USIZE <= 128 {
        rotate_right(U256::from(u128::MAX / root.low_u128()), back_rotate - 128)
    } else {
        rotate_right(U256::MAX / root, back_rotate)
    }
}

#[inline]
fn rotate_right<I: Shr<usize, Output = I> + Shl<usize, Output = I>>(
    input: I, bits: isize,
) -> I {
    if bits >= 0 {
        input >> bits as usize
    } else {
        input << (-bits) as usize
    }
}
