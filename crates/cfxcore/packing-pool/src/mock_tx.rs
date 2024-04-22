use crate::transaction::PackingPoolTransaction;

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, Hash)]
/// A minimal implementation of the [`PackingPoolTransaction`] trait for testing
/// purposes.
pub struct MockTransaction {
    pub id: usize,
    pub sender: u64,
    pub nonce: u64,
    pub gas_price: u64,
    pub gas_limit: u64,
}

impl PartialOrd for MockTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MockTransaction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.id.cmp(&other.id) }
}

impl PackingPoolTransaction for MockTransaction {
    type Sender = u64;

    fn sender(&self) -> Self::Sender { self.sender }

    fn nonce(&self) -> cfx_types::U256 { self.nonce.into() }

    fn gas_price(&self) -> cfx_types::U256 { self.gas_price.into() }

    fn gas_limit(&self) -> cfx_types::U256 { self.gas_limit.into() }
}
