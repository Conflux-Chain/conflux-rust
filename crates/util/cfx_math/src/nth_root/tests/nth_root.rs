use crate::nth_root::NthRoot;

use super::super::{compute::pow, const_generic::SubU1, nth_root, RootDegree};
use cfx_types::{U256, U512};
use typenum::{U10, U11, U12, U2, U3, U4, U5, U6, U7, U8, U9};

fn test_different_data<I: NthRoot>(input: I) {
    for i in 0..I::BITS {
        test_multiple_const(input >> i);
        test_multiple_const(I::MAX - (input >> i));
    }
}

fn test_border_case<I: NthRoot>() {
    for i in 0..I::BITS {
        test_multiple_const(I::MAX >> i);
        test_multiple_const((I::MAX >> i) - I::from(1));
        if i != 0 {
            test_multiple_const((I::MAX >> i) + I::from(1));
            test_multiple_const((I::MAX >> i) + I::from(2));
        }
    }
}

fn test_multiple_const<I: NthRoot>(input: I) {
    test_nth_root_single::<U2, _>(input);
    test_nth_root_single::<U3, _>(input);
    test_nth_root_single::<U4, _>(input);
    test_nth_root_single::<U5, _>(input);
    test_nth_root_single::<U6, _>(input);
    test_nth_root_single::<U7, _>(input);
    test_nth_root_single::<U8, _>(input);
    test_nth_root_single::<U9, _>(input);
    test_nth_root_single::<U10, _>(input);
    test_nth_root_single::<U11, _>(input);
    test_nth_root_single::<U12, _>(input);
}

fn test_nth_root_single<N: RootDegree, I: NthRoot>(input: I) {
    let one = I::from(1);
    let output = nth_root::<N, _>(input);

    let output_pow = pow::<N, _>(output);

    assert!(output_pow <= input);
    assert!(pow::<<N as SubU1>::Output, _>(output + one)
        .checked_mul(output + one)
        .map_or(true, |x| x > input));

    assert_eq!(nth_root::<N, _>(output_pow), output);
    if output > I::from(0) {
        assert_eq!(nth_root::<N, _>(output_pow + one), output);
        assert_eq!(nth_root::<N, _>(output_pow - one), output - one);
    }
}

#[test]
fn test_nth_root_u64() {
    test_border_case::<u64>();
    for _ in 0..100_000 {
        test_different_data(rand::random::<u64>());
    }
}

#[test]
fn test_nth_root_u128() {
    test_border_case::<u128>();
    for _ in 0..12_000 {
        test_different_data(rand::random::<u128>());
    }
}

#[test]
fn test_nth_root_u256() {
    test_border_case::<U256>();
    for _ in 0..900 {
        test_different_data(U256(rand::random::<[u64; 4]>()));
    }
}

#[test]
fn test_nth_root_u512() {
    test_border_case::<U512>();
    for _ in 0..150 {
        test_different_data(U512(rand::random::<[u64; 8]>()));
    }
}
