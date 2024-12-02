use std::convert::TryInto;

use super::{super::inv::nth_inv_root, RootDegree, RootInvParams};
use cfx_types::{U256, U512};
use typenum::*;

fn test_different_data() {
    let input = U256(rand::random::<[u64; 4]>());
    for i in 0..256 {
        test_multiple_const(input >> i);
        test_multiple_const(U256::MAX - (input >> i));
        test_multiple_const(U256::MAX >> i);
        test_multiple_const((U256::MAX >> i).saturating_add(1.into()));
        test_multiple_const((U256::MAX >> i).saturating_add(2.into()));
        test_multiple_const((U256::MAX >> i).saturating_sub(1.into()));
    }
}

fn test_multiple_const(input: U256) {
    normal_tasks(input);
    u256_max_persicion_tasks(input);
    // u512_max_persicion_tasks(input);
}

fn normal_tasks(input: U256) {
    test_nth_root_inv::<U2, U16>(input);
    test_nth_root_inv::<U3, U16>(input);
    test_nth_root_inv::<U4, U16>(input);
    test_nth_root_inv::<U5, U16>(input);
    test_nth_root_inv::<U6, U16>(input);
    test_nth_root_inv::<U7, U16>(input);
    test_nth_root_inv::<U8, U16>(input);
    test_nth_root_inv::<U9, U16>(input);
    test_nth_root_inv::<U10, U16>(input);
    test_nth_root_inv::<U11, U16>(input);
    test_nth_root_inv::<U12, U16>(input);
}

fn u256_max_persicion_tasks(input: U256) {
    test_nth_root_inv::<U2, U127>(input);
    test_nth_root_inv::<U3, U84>(input);
    test_nth_root_inv::<U4, U63>(input);
    test_nth_root_inv::<U5, U50>(input);
    test_nth_root_inv::<U6, U41>(input);
    test_nth_root_inv::<U7, U35>(input);
    test_nth_root_inv::<U8, U31>(input);
    test_nth_root_inv::<U9, U27>(input);
    test_nth_root_inv::<U10, U24>(input);
    test_nth_root_inv::<U11, U22>(input);
    test_nth_root_inv::<U12, U20>(input);
}

// fn u512_max_persicion_tasks(input: U256) {
//     test_nth_root_inv::<U2, U255>(input);
//     test_nth_root_inv::<U3, U169>(input);
//     test_nth_root_inv::<U4, U127>(input);
//     test_nth_root_inv::<U5, U101>(input);
//     test_nth_root_inv::<U6, U84>(input);
//     test_nth_root_inv::<U7, U72>(input);
//     test_nth_root_inv::<U8, U63>(input);
//     test_nth_root_inv::<U9, U55>(input);
//     test_nth_root_inv::<U10, U50>(input);
//     test_nth_root_inv::<U11, U45>(input);
//     test_nth_root_inv::<U12, U41>(input);
// }

fn test_nth_root_inv<N: RootDegree, P: Unsigned>(input: U256)
where (N, P): RootInvParams {
    if input.is_zero() {
        return;
    }

    let output = nth_inv_root::<N, P>(input);
    let error = (output >> P::USIZE) + 1;

    if output > error {
        let estimate_input = estimate_input::<N>(output - error);
        // println!("Estimate(+): {}", estimate_input);
        assert!(estimate_input >= input);
    }
    if output <= U256::MAX - error {
        let estimate_input = estimate_input::<N>(output + error);
        // println!("Estimate(-): {}", estimate_input);
        assert!(estimate_input <= input);
    }
}

fn estimate_input<N: RootDegree>(output: U256) -> U256 {
    let mut power = U512::from(output) << 256;
    for _ in 0..(N::USIZE - 1) {
        power = full_mul_round(power, output);
    }

    let output = U512::MAX / U512::from(power);
    if output.bits() > 256 {
        U256::MAX
    } else {
        output.try_into().unwrap()
    }
}

fn full_mul_round(a: U512, b: U256) -> U512 {
    let lo: U256 = (a & U512::from(U256::MAX)).try_into().unwrap();
    let hi: U256 = (a >> 256).try_into().unwrap();
    let lo_mul = lo.full_mul(b);
    let hi_mul = hi.full_mul(b);
    hi_mul + (lo_mul >> 256)
}

#[test]
fn test_inv_root() {
    for _ in 0..150 {
        test_different_data()
    }
}
