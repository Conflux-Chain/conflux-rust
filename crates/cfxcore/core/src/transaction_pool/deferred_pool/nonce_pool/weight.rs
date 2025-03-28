use cfx_types::U256;
use malloc_size_of_derive::MallocSizeOf;

use treap_map::ConsoliableWeight;

use super::TxWithReadyInfo;

/// Accumulable weight for Nonce Pool Treap
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, MallocSizeOf)]
pub(super) struct NoncePoolWeight {
    /// number of unpacked transactions
    pub unpacked_size: u32,
    /// sum of cost of transactions
    pub cost: U256,
    /// number of transactions
    pub size: u32,
    /// max unpacked nonce
    pub max_unpackd_nonce: Option<U256>,
}

impl ConsoliableWeight for NoncePoolWeight {
    #[inline]
    fn empty() -> Self { Self::default() }

    #[inline]
    fn consolidate(a: &Self, b: &Self) -> Self {
        if a == &Self::empty() {
            return *b;
        }
        Self {
            unpacked_size: a.unpacked_size + b.unpacked_size,
            cost: a.cost + b.cost,
            size: a.size + b.size,
            max_unpackd_nonce: consolidate_max_nonce(
                a.max_unpackd_nonce,
                b.max_unpackd_nonce,
            ),
        }
    }

    #[inline]
    fn accure(&mut self, other: &Self) {
        self.unpacked_size += other.unpacked_size;
        self.cost += other.cost;
        self.size += other.size;
        self.max_unpackd_nonce = consolidate_max_nonce(
            self.max_unpackd_nonce,
            other.max_unpackd_nonce,
        );
    }
}

impl NoncePoolWeight {
    pub fn from_tx_info(tx_info: &TxWithReadyInfo) -> Self {
        if tx_info.packed {
            Self {
                unpacked_size: 0,
                cost: tx_info.get_tx_cost(),
                size: 1,
                max_unpackd_nonce: None,
            }
        } else {
            Self {
                unpacked_size: 1,
                cost: tx_info.get_tx_cost(),
                size: 1,
                max_unpackd_nonce: Some(*tx_info.transaction.nonce()),
            }
        }
    }
}

#[inline]
fn consolidate_max_nonce(a: Option<U256>, b: Option<U256>) -> Option<U256> {
    match (a, b) {
        (None, None) => None,
        (None, Some(b)) => Some(b),
        (Some(a), None) => Some(a),
        (Some(a), Some(b)) => Some(U256::max(a, b)),
    }
}
