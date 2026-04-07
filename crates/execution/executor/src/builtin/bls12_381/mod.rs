// This file is derived from revm (MIT licensed)
// Copyright (c) 2021-2025 draganrakita
// Modified by Conflux Foundation 2025

use super::{Precompile, PricePlan, StaticPlan};

mod consts;
mod g1;
pub mod g1_add;
pub mod g1_msm;
mod g2;
pub mod g2_add;
pub mod g2_msm;
pub mod map_fp2_to_g2;
pub mod map_fp_to_g1;
mod msm_gas;
pub mod pairing;
mod utils;

pub struct Bls12Wrapper<F>(F);

impl<F: Send + Sync + Fn(&[u8]) -> Result<Vec<u8>, String>> Precompile
    for Bls12Wrapper<F>
{
    fn execute(
        &self, input: &[u8], output: &mut cfx_bytes::BytesRef,
    ) -> Result<(), super::Error> {
        let res = (self.0)(input)?;
        output.write(0, &res[..]);
        Ok(())
    }
}

pub fn bls12_builtin_factory(name: &str) -> Box<dyn Precompile> {
    match name {
        "bls12_g1add" => Box::new(Bls12Wrapper(g1_add::g1_add)),
        "bls12_g1msm" => Box::new(Bls12Wrapper(g1_msm::g1_msm)),
        "bls12_g2add" => Box::new(Bls12Wrapper(g2_add::g2_add)),
        "bls12_g2msm" => Box::new(Bls12Wrapper(g2_msm::g2_msm)),
        "bls12_pairing_check" => Box::new(Bls12Wrapper(pairing::pairing)),
        "bls12_map_fp_to_g1" => {
            Box::new(Bls12Wrapper(map_fp_to_g1::map_fp_to_g1))
        }
        "bls12_map_fp2_to_g2" => {
            Box::new(Bls12Wrapper(map_fp2_to_g2::map_fp2_to_g2))
        }
        _ => panic!("Unsupported BLS12 precompile function: {}", name),
    }
}

macro_rules! bls12_precompile {
    ($address:expr, $price_fn:path, $impl_fn:path) => {
        (
            $address,
            Box::new(StaticPlan($price_fn())),
            Box::new(Bls12Wrapper($impl_fn)),
        )
    };
}

pub fn build_bls12_builtin_map(
) -> Vec<(u64, Box<dyn PricePlan>, Box<dyn Precompile>)> {
    use consts::*;
    vec![
        bls12_precompile!(G1_ADD_ADDRESS, g1_add::g1_add_gas, g1_add::g1_add),
        bls12_precompile!(G1_MSM_ADDRESS, g1_msm::g1_msm_gas, g1_msm::g1_msm),
        bls12_precompile!(G2_ADD_ADDRESS, g2_add::g2_add_gas, g2_add::g2_add),
        bls12_precompile!(G2_MSM_ADDRESS, g2_msm::g2_msm_gas, g2_msm::g2_msm),
        bls12_precompile!(
            PAIRING_ADDRESS,
            pairing::pairing_gas,
            pairing::pairing
        ),
        bls12_precompile!(
            MAP_FP_TO_G1_ADDRESS,
            map_fp_to_g1::map_fp_to_g1_gas,
            map_fp_to_g1::map_fp_to_g1
        ),
        bls12_precompile!(
            MAP_FP2_TO_G2_ADDRESS,
            map_fp2_to_g2::map_fp2_to_g2_gas,
            map_fp2_to_g2::map_fp2_to_g2
        ),
    ]
}
