use cfx_math::nth_inv_root;
use cfx_types::U256;
use typenum::{U12, U15, U2, U3, U4, U5};

use crate::transaction::PackingPoolTransaction;
use malloc_size_of_derive::MallocSizeOf;

/// Configuration settings for a [`PackingBatch`][crate::PackingBatch].
#[derive(Default, MallocSizeOf, Clone, Copy)]
pub struct PackingPoolConfig {
    /// The maximum gas limit for a packing batch. If there is only a single
    /// transaction, this limit is not enforced.
    pub(crate) address_gas_limit: U256,
    ///  The maximum number of transactions allowed in a packing batch.
    pub(crate) address_tx_count: usize,
    /// The degree parameter used in the random packing algorithm, with
    /// supported values ranging from 1 to 5.
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

    /// Calculates the longest acceptable prefix of transactions in the provided
    /// list.
    ///
    /// This function determines the maximum number of consecutive transactions
    /// starting from the beginning of `txs` that can be accepted based on
    /// their cumulative gas limit and other criteria. It returns the index
    /// of the first transaction that is not acceptable and the total gas limit
    /// of the acceptable portion.
    ///
    /// # Parameters
    /// - `txs`: A reference to a vector of transactions to be evaluated.
    /// - `replaced`: An optional parameter that, if provided, indicates a
    ///   specific transaction and its position in `txs` that should be
    ///   considered as replaced for the purpose of this calculation. This is
    ///   used to simulate the effect of replacing a transaction within `txs`.
    ///
    /// # Returns
    /// Returns a tuple containing:
    /// - The index of the first transaction in `txs` that is not acceptable. If
    ///   all transactions are acceptable, this will be the length of `txs`.
    /// - The total gas limit of the acceptable portion of `txs`.
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

    /// Calculates the loss ratio for the random packing algorithm.
    ///
    /// The loss ratio is defined as the reciprocal of `gas_price` raised to the
    /// power of the `degree` (a configuration parameter). Since this value
    /// is less than 1, the function represents 1 as 2^128, thereby
    /// preserving 128 binary digits of precision in the result.
    ///
    /// Note that the precision of the returned value is limited:
    /// - For `degree = 5`, the precision is 12 bits.
    /// - For other values of `degree`, the precision is 15 bits.
    /// This limited precision is by design, as the packing pool does not
    /// require high precision and this approach helps in saving
    /// computational resources.
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
