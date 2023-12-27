use cfx_types::U256;
use heap_map::HeapMap;
use rand::RngCore;
use treap_map;

use crate::{
    transaction::PackingPoolTransaction, treapmap_config::PackingPoolMap,
};

pub struct TxSampler<'a, 'b, TX: PackingPoolTransaction, R: RngCore> {
    iter: treap_map::Iter<'a, PackingPoolMap<TX>>,
    alter_address: HeapMap<TX::Sender, CandidateAddress<'a, TX>>,
    loss_base: U256,
    rng: &'b mut R,
}

impl<'a, 'b, TX: PackingPoolTransaction, R: RngCore> TxSampler<'a, 'b, TX, R> {
    pub(crate) fn new(
        iter: treap_map::Iter<'a, PackingPoolMap<TX>>, loss_base: U256,
        rng: &'b mut R,
    ) -> Self
    {
        Self {
            iter,
            alter_address: Default::default(),
            loss_base,
            rng,
        }
    }
}

impl<'a, 'b, TX: PackingPoolTransaction, R: RngCore> Iterator
    for TxSampler<'a, 'b, TX, R>
{
    type Item = (TX::Sender, &'a [TX]);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(node) = self.iter.next() {
                if self.loss_base.is_zero() {
                    // Packing pool is not full
                    return Some((node.key, &node.value));
                }
                let loss_threshold =
                    ((self.loss_base * node.weight.max_loss_ratio) >> 192)
                        .as_u64();
                let sampled = self.rng.next_u64();
                if sampled >= loss_threshold {
                    return Some((node.key, &node.value));
                } else {
                    self.alter_address.insert(
                        &node.key,
                        CandidateAddress {
                            node,
                            priority: (sampled as f64)
                                / (loss_threshold as f64),
                        },
                    );
                }
            } else if let Some((address, node)) = self.alter_address.pop() {
                return Some((address, &node.node.value));
            } else {
                return None;
            }
        }
    }
}

#[derive(Clone)]
pub struct CandidateAddress<'a, TX: PackingPoolTransaction> {
    node: &'a treap_map::Node<PackingPoolMap<TX>>,
    priority: f64,
}

impl<'a, TX: PackingPoolTransaction> std::cmp::PartialEq
    for CandidateAddress<'a, TX>
{
    fn eq(&self, other: &Self) -> bool { self.priority.eq(&other.priority) }
}

impl<'a, TX: PackingPoolTransaction> std::cmp::PartialOrd
    for CandidateAddress<'a, TX>
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a, TX: PackingPoolTransaction> std::cmp::Eq for CandidateAddress<'a, TX> {}

impl<'a, TX: PackingPoolTransaction> std::cmp::Ord
    for CandidateAddress<'a, TX>
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.partial_cmp(&other.priority).unwrap()
    }
}
