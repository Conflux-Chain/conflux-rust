use cfx_math::nth_inv_root;
use cfx_types::U256;
use typenum::{U12, U15, U2, U3, U4, U5};

use crate::transaction::PackingPoolTransaction;

pub struct PackingPoolConfig {
    pub(crate) address_gas_limit: U256,
    pub(crate) address_tx_count: usize,

    pub(crate) gas_increase_percentage: u8,
    pub(crate) loss_ratio_degree: u8,
}

impl PackingPoolConfig {
    pub fn new(
        address_gas_limit: U256, address_tx_count: usize,
        gas_increase_percentage: u8, loss_ratio_degree: u8,
    ) -> Self
    {
        assert!(loss_ratio_degree > 0 && loss_ratio_degree <= 5);
        Self {
            address_gas_limit,
            address_tx_count,
            gas_increase_percentage,
            loss_ratio_degree,
        }
    }

    #[inline]
    pub(crate) fn next_gas_price(&self, gas_price: U256) -> U256 {
        if gas_price < U256::from(100) {
            gas_price + 1
        } else {
            gas_price.saturating_add(
                (gas_price / 100) * self.gas_increase_percentage,
            )
        }
    }

    #[inline]
    pub(crate) fn check_address_gas_limit<TX: PackingPoolTransaction>(
        &self, txs: &Vec<TX>, replaced_tx: &TX, replaced_idx: usize,
    ) -> (usize, U256) {
        let mut total_gas_limit = U256::zero();
        for (idx, txs) in txs.iter().enumerate() {
            let tx_gas = if idx == replaced_idx {
                replaced_tx.gas_limit()
            } else {
                txs.gas_limit()
            };
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
