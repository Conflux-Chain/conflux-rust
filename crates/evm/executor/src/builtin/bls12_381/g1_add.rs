// This file is derived from revm (MIT licensed)
// Copyright (c) 2021-2025 draganrakita
// Modified by Conflux Foundation 2025

use crate::builtin::{ConstPricer, Pricer};

use super::{
    consts::{G1_ADD_BASE_GAS_FEE, G1_ADD_INPUT_LENGTH, G1_INPUT_ITEM_LENGTH},
    g1::{encode_g1_point, extract_g1_input},
};
use blst::{
    blst_p1, blst_p1_add_or_double_affine, blst_p1_affine, blst_p1_from_affine,
    blst_p1_to_affine,
};

/// G1 addition call expects `256` bytes as an input that is interpreted as byte
/// concatenation of two G1 points (`128` bytes each).
/// Output is an encoding of addition operation result - single G1 point (`128`
/// bytes).
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g1-addition>
pub(super) fn g1_add(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() != G1_ADD_INPUT_LENGTH {
        return Err(format!(
            "G1ADD input should be {G1_ADD_INPUT_LENGTH} bytes, was {}",
            input.len()
        ));
    }

    // NB: There is no subgroup check for the G1 addition precompile.
    //
    // So we set the subgroup checks here to `false`
    let a_aff = &extract_g1_input(&input[..G1_INPUT_ITEM_LENGTH], false)?;
    let b_aff = &extract_g1_input(&input[G1_INPUT_ITEM_LENGTH..], false)?;

    let mut b = blst_p1::default();
    // SAFETY: `b` and `b_aff` are blst values.
    unsafe { blst_p1_from_affine(&mut b, b_aff) };

    let mut p = blst_p1::default();
    // SAFETY: `p`, `b` and `a_aff` are blst values.
    unsafe { blst_p1_add_or_double_affine(&mut p, &b, a_aff) };

    let mut p_aff = blst_p1_affine::default();
    // SAFETY: `p_aff` and `p`` are blst values.
    unsafe { blst_p1_to_affine(&mut p_aff, &p) };

    let out = encode_g1_point(&p_aff);
    Ok(out)
}

pub(super) fn g1_add_gas() -> impl Pricer {
    ConstPricer::new(G1_ADD_BASE_GAS_FEE)
}
