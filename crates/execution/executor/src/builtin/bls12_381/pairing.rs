// This file is derived from revm (MIT licensed)
// Copyright (c) 2021-2025 draganrakita
// Modified by Conflux Foundation 2025

use crate::builtin::Pricer;

use super::{
    consts::{
        G1_INPUT_ITEM_LENGTH, G2_INPUT_ITEM_LENGTH, PAIRING_INPUT_LENGTH,
        PAIRING_PAIRING_MULTIPLIER_BASE, PAIRING_PAIRING_OFFSET_BASE,
    },
    g1::extract_g1_input,
    g2::extract_g2_input,
};
use blst::{
    blst_final_exp, blst_fp12, blst_fp12_is_one, blst_fp12_mul,
    blst_miller_loop,
};
use cfx_types::U256;

/// Pairing call expects 384*k (k being a positive integer) bytes as an inputs
/// that is interpreted as byte concatenation of k slices. Each slice has the
/// following structure:
///    * 128 bytes of G1 point encoding
///    * 256 bytes of G2 point encoding
///
/// Each point is expected to be in the subgroup of order q.
/// Output is 32 bytes where first 31 bytes are equal to 0x00 and the last byte
/// is 0x01 if pairing result is equal to the multiplicative identity in a
/// pairing target field and 0x00 otherwise.
///
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-pairing>
pub(super) fn pairing(input: &[u8]) -> Result<Vec<u8>, String> {
    let input_len = input.len();
    if input_len == 0 || input_len % PAIRING_INPUT_LENGTH != 0 {
        return Err(format!(
            "Pairing input length should be multiple of {PAIRING_INPUT_LENGTH}, was {input_len}"
        ));
    }

    let k = input.len() / PAIRING_INPUT_LENGTH;

    // Accumulator for the fp12 multiplications of the miller loops.
    let mut acc = blst_fp12::default();
    for i in 0..k {
        // NB: Scalar multiplications, MSMs and pairings MUST perform a subgroup
        // check.
        //
        // So we set the subgroup_check flag to `true`
        let p1_aff = &extract_g1_input(
            &input[i * PAIRING_INPUT_LENGTH
                ..i * PAIRING_INPUT_LENGTH + G1_INPUT_ITEM_LENGTH],
            true,
        )?;

        // NB: Scalar multiplications, MSMs and pairings MUST perform a subgroup
        // check.
        //
        // So we set the subgroup_check flag to `true`
        let p2_aff = &extract_g2_input(
            &input[i * PAIRING_INPUT_LENGTH + G1_INPUT_ITEM_LENGTH
                ..i * PAIRING_INPUT_LENGTH
                    + G1_INPUT_ITEM_LENGTH
                    + G2_INPUT_ITEM_LENGTH],
            true,
        )?;

        if i > 0 {
            // After the first slice (i>0) we use cur_ml to store the current
            // miller loop and accumulate with the previous results using a fp12
            // multiplication.
            let mut cur_ml = blst_fp12::default();
            let mut res = blst_fp12::default();
            // SAFETY: `res`, `acc`, `cur_ml`, `p1_aff` and `p2_aff` are blst
            // values.
            unsafe {
                blst_miller_loop(&mut cur_ml, p2_aff, p1_aff);
                blst_fp12_mul(&mut res, &acc, &cur_ml);
            }
            acc = res;
        } else {
            // On the first slice (i==0) there is no previous results and no
            // need to accumulate.
            // SAFETY: `acc`, `p1_aff` and `p2_aff` are blst values.
            unsafe {
                blst_miller_loop(&mut acc, p2_aff, p1_aff);
            }
        }
    }

    // SAFETY: `ret` and `acc` are blst values.
    let mut ret = blst_fp12::default();
    unsafe {
        blst_final_exp(&mut ret, &acc);
    }

    let mut result: u8 = 0;
    // SAFETY: `ret` is a blst value.
    unsafe {
        if blst_fp12_is_one(&ret) {
            result = 1;
        }
    }

    let mut res = [0u8; 32];
    res[31] = result;
    Ok(res.into())
}

pub struct PairingPricer {
    base: u64,
    item_price: u64,
}

impl Pricer for PairingPricer {
    fn cost(&self, input: &[u8]) -> cfx_types::U256 {
        let k = input.len() / PAIRING_INPUT_LENGTH;
        let required_gas: u64 = self.item_price * k as u64 + self.base;
        U256::from(required_gas)
    }
}

pub fn pairing_gas() -> impl Pricer {
    PairingPricer {
        base: PAIRING_PAIRING_OFFSET_BASE,
        item_price: PAIRING_PAIRING_MULTIPLIER_BASE,
    }
}
