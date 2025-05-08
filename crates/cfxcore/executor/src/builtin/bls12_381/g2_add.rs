// This file is derived from revm (MIT licensed)
// Copyright (c) 2021-2025 draganrakita
// Modified by Conflux Foundation 2025

use crate::builtin::{ConstPricer, Pricer};

use super::{
    consts::{G2_ADD_BASE_GAS_FEE, G2_ADD_INPUT_LENGTH, G2_INPUT_ITEM_LENGTH},
    g2::{encode_g2_point, extract_g2_input},
};
use blst::{
    blst_p2, blst_p2_add_or_double_affine, blst_p2_affine, blst_p2_from_affine,
    blst_p2_to_affine,
};

/// G2 addition call expects `512` bytes as an input that is interpreted as byte
/// concatenation of two G2 points (`256` bytes each).
///
/// Output is an encoding of addition operation result - single G2 point (`256`
/// bytes).
/// See also <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g2-addition>
pub(super) fn g2_add(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() != G2_ADD_INPUT_LENGTH {
        return Err(format!(
            "G2ADD input should be {G2_ADD_INPUT_LENGTH} bytes, was {}",
            input.len()
        ));
    }

    // NB: There is no subgroup check for the G2 addition precompile.
    //
    // So we set the subgroup checks here to `false`
    let a_aff = &extract_g2_input(&input[..G2_INPUT_ITEM_LENGTH], false)?;
    let b_aff = &extract_g2_input(&input[G2_INPUT_ITEM_LENGTH..], false)?;

    let mut b = blst_p2::default();
    // SAFETY: `b` and `b_aff` are blst values.
    unsafe { blst_p2_from_affine(&mut b, b_aff) };

    let mut p = blst_p2::default();
    // SAFETY: `p`, `b` and `a_aff` are blst values.
    unsafe { blst_p2_add_or_double_affine(&mut p, &b, a_aff) };

    let mut p_aff = blst_p2_affine::default();
    // SAFETY: `p_aff` and `p` are blst values.
    unsafe { blst_p2_to_affine(&mut p_aff, &p) };

    let out = encode_g2_point(&p_aff);
    Ok(out)
}

pub(super) fn g2_add_gas() -> impl Pricer {
    ConstPricer::new(G2_ADD_BASE_GAS_FEE)
}
