// This file is derived from revm (MIT licensed)
// Copyright (c) 2021-2025 draganrakita
// Modified by Conflux Foundation 2025

use cfx_types::U256;

use crate::builtin::Pricer;

use super::consts::MSM_MULTIPLIER;

/// Implements the gas schedule for G1/G2 Multiscalar-multiplication assuming 30
/// MGas/second, see also: <https://eips.ethereum.org/EIPS/eip-2537#g1g2-multiexponentiation>
#[inline]
pub fn msm_required_gas(
    k: usize, discount_table: &[u16], multiplication_cost: u64,
) -> u64 {
    if k == 0 {
        return 0;
    }

    let index = core::cmp::min(k - 1, discount_table.len() - 1);
    let discount = discount_table[index] as u64;

    (k as u64 * discount * multiplication_cost) / MSM_MULTIPLIER
}

pub struct MsmPricer {
    input_length: usize,
    discount_table: &'static [u16],
    base_fee: u64,
}

impl MsmPricer {
    pub const fn new(
        input_length: usize, discount_table: &'static [u16], base_fee: u64,
    ) -> Self {
        Self {
            input_length,
            discount_table,
            base_fee,
        }
    }
}

impl Pricer for MsmPricer {
    fn cost(&self, input: &[u8]) -> cfx_types::U256 {
        let input_len = input.len();

        let k = input_len / self.input_length;
        let required_gas =
            msm_required_gas(k, self.discount_table, self.base_fee);
        U256::from(required_gas)
    }
}
