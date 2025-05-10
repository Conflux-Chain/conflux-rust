// This file is derived from revm (MIT licensed)
// Copyright (c) 2021-2025 draganrakita
// Modified by Conflux Foundation 2025

use crate::builtin::{ConstPricer, Pricer};

use super::{
    consts::{MAP_FP_TO_G1_BASE_GAS_FEE, PADDED_FP_LENGTH},
    g1::encode_g1_point,
    utils::{fp_from_bendian, remove_padding},
};
use blst::{blst_map_to_g1, blst_p1, blst_p1_affine, blst_p1_to_affine};

/// Field-to-curve call expects 64 bytes as an input that is interpreted as an
/// element of Fp. Output of this call is 128 bytes and is an encoded G1 point.
/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-mapping-fp-element-to-g1-point>
pub(super) fn map_fp_to_g1(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() != PADDED_FP_LENGTH {
        return Err(format!(
            "MAP_FP_TO_G1 input should be {PADDED_FP_LENGTH} bytes, was {}",
            input.len()
        ));
    }

    let input_p0 = remove_padding(input)?;
    let fp = fp_from_bendian(input_p0)?;

    let mut p = blst_p1::default();
    // SAFETY: `p` and `fp` are blst values.
    // Third argument is unused if null.
    unsafe { blst_map_to_g1(&mut p, &fp, core::ptr::null()) };

    let mut p_aff = blst_p1_affine::default();
    // SAFETY: `p_aff` and `p` are blst values.
    unsafe { blst_p1_to_affine(&mut p_aff, &p) };

    let out = encode_g1_point(&p_aff);
    Ok(out)
}

pub(super) fn map_fp_to_g1_gas() -> impl Pricer {
    ConstPricer::new(MAP_FP_TO_G1_BASE_GAS_FEE)
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn sanity_test() {
        let input = hex!("000000000000000000000000000000006900000000000000636f6e7472616374595a603f343061cd305a03f40239f5ffff31818185c136bc2595f2aa18e08f17");
        let fail = map_fp_to_g1(&input);
        assert_eq!(fail, Err("non-canonical fp value".to_string()));
    }
}
