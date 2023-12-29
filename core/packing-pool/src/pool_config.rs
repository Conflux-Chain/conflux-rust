use cfx_math::nth_inv_root;
use cfx_types::U256;
use typenum::{U12, U15, U2, U3, U4, U5};

use crate::transaction::PackingPoolTransaction;
use malloc_size_of_derive::MallocSizeOf;

#[derive(Default, MallocSizeOf, Clone, Copy)]
pub struct PackingPoolConfig {
    pub(crate) address_gas_limit: U256,
    pub(crate) address_tx_count: usize,

    pub(crate) loss_ratio_degree: u8,
}

impl PackingPoolConfig {
    pub fn new(
        address_gas_limit: U256, address_tx_count: usize, loss_ratio_degree: u8,
    ) -> Self {
        assert!(loss_ratio_degree > 0 && loss_ratio_degree <= 5);
        Self {
            address_gas_limit,
            address_tx_count,
            loss_ratio_degree,
        }
    }

    #[cfg(test)]
    pub fn new_for_test() -> Self { Self::new(3_000_000.into(), 20, 4) }

    #[inline]
    pub(crate) fn check_acceptable_batch<TX: PackingPoolTransaction>(
        &self, txs: &Vec<TX>, replaced: Option<(&TX, usize)>,
    ) -> (usize, U256) {
        let mut total_gas_limit = U256::zero();
        for (idx, tx) in txs.iter().enumerate() {
            if idx >= self.address_tx_count {
                return (idx, total_gas_limit);
            }

            let tx_gas = replaced
                .filter(|(_, i)| idx == *i)
                .map_or(tx.gas_limit(), |(r, _)| r.gas_limit());

            if total_gas_limit + tx_gas > self.address_gas_limit {
                if idx == 0 {
                    // If there is only one tx, it can exceed address_gas_limit
                    return (1, tx_gas);
                } else {
                    return (idx, total_gas_limit);
                }
            }
            total_gas_limit += tx_gas;
        }
        (txs.len(), total_gas_limit)
    }

    pub(crate) fn loss_ratio(&self, gas_price: U256) -> U256 {
        if gas_price.is_zero() {
            return U256::one() << 128;
        }

        (match self.loss_ratio_degree {
            1 => U256::MAX / gas_price,
            2 => nth_inv_root::<U2, U15>(gas_price),
            3 => nth_inv_root::<U3, U15>(gas_price),
            4 => nth_inv_root::<U4, U15>(gas_price),
            5 => nth_inv_root::<U5, U12>(gas_price),
            _ => unreachable!(),
        }) >> 128
    }
}
