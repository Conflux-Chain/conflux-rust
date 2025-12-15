// This file is derived from revm (MIT licensed)
// Copyright (c) 2021-2025 draganrakita
// Modified by Conflux Foundation 2025

use crate::builtin::{ConstPricer, Pricer};

use super::{
    consts::{MAP_FP2_TO_G2_BASE_GAS_FEE, PADDED_FP2_LENGTH, PADDED_FP_LENGTH},
    g2::{check_canonical_fp2, encode_g2_point},
    utils::remove_padding,
};
use blst::{blst_map_to_g2, blst_p2, blst_p2_affine, blst_p2_to_affine};

/// Field-to-curve call expects 128 bytes as an input that is interpreted as
/// an element of Fp2. Output of this call is 256 bytes and is an encoded G2
/// point.
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-mapping-fp2-element-to-g2-point>
pub(super) fn map_fp2_to_g2(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() != PADDED_FP2_LENGTH {
        return Err(format!(
            "MAP_FP2_TO_G2 input should be {PADDED_FP2_LENGTH} bytes, was {}",
            input.len()
        ));
    }

    let input_p0_x = remove_padding(&input[..PADDED_FP_LENGTH])?;
    let input_p0_y =
        remove_padding(&input[PADDED_FP_LENGTH..PADDED_FP2_LENGTH])?;
    let fp2 = check_canonical_fp2(input_p0_x, input_p0_y)?;

    let mut p = blst_p2::default();
    // SAFETY: `p` and `fp2` are blst values.
    // Third argument is unused if null.
    unsafe { blst_map_to_g2(&mut p, &fp2, core::ptr::null()) };

    let mut p_aff = blst_p2_affine::default();
    // SAFETY: `p_aff` and `p` are blst values.
    unsafe { blst_p2_to_affine(&mut p_aff, &p) };

    let out = encode_g2_point(&p_aff);
    Ok(out)
}

pub(super) fn map_fp2_to_g2_gas() -> impl Pricer {
    ConstPricer::new(MAP_FP2_TO_G2_BASE_GAS_FEE)
}
