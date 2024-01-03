use cfx_types::U256;
use malloc_size_of_derive::MallocSizeOf;
use treap_map::ConsoliableWeight;

#[derive(Default, Clone, Eq, PartialEq, MallocSizeOf, Debug)]
pub struct PackingPoolWeight {
    pub gas_limit: U256,
    pub weighted_loss_ratio: U256,
    pub max_loss_ratio: U256,
}

impl ConsoliableWeight for PackingPoolWeight {
    #[inline]
    fn empty() -> Self { Self::default() }

    fn consolidate(a: &Self, b: &Self) -> Self {
        Self {
            gas_limit: a.gas_limit + b.gas_limit,
            weighted_loss_ratio: a.weighted_loss_ratio + b.weighted_loss_ratio,
            max_loss_ratio: U256::max(a.max_loss_ratio, b.max_loss_ratio),
        }
    }

    fn accure(&mut self, other: &Self) {
        self.gas_limit += other.gas_limit;
        self.weighted_loss_ratio += other.weighted_loss_ratio;
        self.max_loss_ratio =
            U256::max(self.max_loss_ratio, other.max_loss_ratio)
    }
}
