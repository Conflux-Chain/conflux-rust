use cfx_types::U256;
use malloc_size_of_derive::MallocSizeOf;
use treap_map::ConsoliableWeight;

#[derive(Default, Clone, Eq, PartialEq, MallocSizeOf, Debug)]
pub struct PackingPoolWeight {
    pub gas_limit: U256,
    pub min_gas_price: U256,
    pub weighted_loss_ratio: U256,
    pub max_loss_ratio: U256,
}

impl ConsoliableWeight for PackingPoolWeight {
    #[inline]
    fn empty() -> Self {
        Self {
            min_gas_price: U256::max_value(),
            ..Default::default()
        }
    }

    fn consolidate(a: &Self, b: &Self) -> Self {
        Self {
            gas_limit: a.gas_limit + b.gas_limit,
            min_gas_price: U256::min(a.min_gas_price, b.min_gas_price),
            weighted_loss_ratio: a.weighted_loss_ratio + b.weighted_loss_ratio,
            max_loss_ratio: U256::max(a.max_loss_ratio, b.max_loss_ratio),
        }
    }

    fn accure(&mut self, other: &Self) {
        self.gas_limit += other.gas_limit;
        self.weighted_loss_ratio += other.weighted_loss_ratio;
        self.max_loss_ratio =
            U256::max(self.max_loss_ratio, other.max_loss_ratio);
        self.min_gas_price = U256::min(self.min_gas_price, other.min_gas_price);
    }
}
