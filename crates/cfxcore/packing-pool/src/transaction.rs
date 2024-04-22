use std::{fmt::Debug, hash::Hash, sync::Arc};

use cfx_types::{AddressWithSpace, U256};
use primitives::SignedTransaction;

/// Trait representing a transaction processed by the `PackingPool`.
pub trait PackingPoolTransaction: Clone {
    type Sender: Default + Ord + Hash + Copy + Debug;
    fn sender(&self) -> Self::Sender;

    fn nonce(&self) -> U256;

    fn gas_price(&self) -> U256;

    fn gas_limit(&self) -> U256;
}

impl PackingPoolTransaction for Arc<SignedTransaction> {
    type Sender = AddressWithSpace;

    #[inline]
    fn sender(&self) -> AddressWithSpace { SignedTransaction::sender(&self) }

    #[inline]
    fn nonce(&self) -> U256 { *SignedTransaction::nonce(&self) }

    #[inline]
    fn gas_price(&self) -> U256 { *SignedTransaction::gas_price(&self) }

    #[inline]
    fn gas_limit(&self) -> U256 { *SignedTransaction::gas_limit(&self) }
}
