use cfx_types::U256;
use malloc_size_of_derive::MallocSizeOf;

use treap_map::WeightConsolidate;

use super::TxWithReadyInfo;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, MallocSizeOf)]
pub(super) struct NoncePoolWeight {
    /// number of unpacked transactions in subtree
    pub subtree_unpacked: u32,
    /// sum of cost of transaction in subtree
    pub subtree_cost: U256,
    /// number of transaction in subtree
    pub subtree_size: u32,
    /// max unpacked nonce
    pub max_unpackd_nonce: Option<U256>,
}

impl WeightConsolidate for NoncePoolWeight {
    #[inline]
    fn empty() -> Self { Self::default() }

    #[inline]
    fn consolidate(a: &Self, b: &Self) -> Self {
        if a == &Self::empty() {
            return *b;
        }
        Self {
            subtree_unpacked: a.subtree_unpacked + b.subtree_unpacked,
            subtree_cost: a.subtree_cost + b.subtree_cost,
            subtree_size: a.subtree_size + b.subtree_size,
            max_unpackd_nonce: consolidate_max_nonce(
                a.max_unpackd_nonce,
                b.max_unpackd_nonce,
            ),
        }
    }

    #[inline]
    fn accure(&mut self, other: &Self) {
        self.subtree_unpacked += other.subtree_unpacked;
        self.subtree_cost += other.subtree_cost;
        self.subtree_size += other.subtree_size;
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
                subtree_unpacked: 0,
                subtree_cost: tx_info.calc_tx_cost(),
                subtree_size: 1,
                max_unpackd_nonce: None,
            }
        } else {
            Self {
                subtree_unpacked: 1,
                subtree_cost: tx_info.calc_tx_cost(),
                subtree_size: 1,
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
