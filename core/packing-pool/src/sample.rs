use cfx_types::U256;
use heap_map::HeapMap;
use rand::RngCore;
use treap_map;

use crate::{
    transaction::PackingPoolTransaction, treapmap_config::PackingPoolMap,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleTag {
    PriceDesc,
    RandomPick,
    CandidateAddress,
}

pub struct TxSampler<'a, 'b, TX: PackingPoolTransaction, R: RngCore> {
    iter: treap_map::Iter<'a, PackingPoolMap<TX>>,
    first_unsample: Option<&'a treap_map::Node<PackingPoolMap<TX>>>,
    random_sample_phase: bool,
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
            random_sample_phase: true,
            first_unsample: None,
            alter_address: Default::default(),
            loss_base,
            rng,
        }
    }

    #[inline]
    fn price_desc_sample(
        &mut self,
    ) -> Option<(TX::Sender, &'a [TX], SampleTag)> {
        if let Some(node) = self.first_unsample {
            self.first_unsample = None;
            return Some((node.key, &node.value.txs[..], SampleTag::PriceDesc));
        }
        self.iter
            .next()
            .map(|node| (node.key, &node.value.txs[..], SampleTag::PriceDesc))
    }

    #[inline]
    fn alternative_sample(
        &mut self,
    ) -> Option<(TX::Sender, &'a [TX], SampleTag)> {
        self.alter_address.pop().map(|(addr, candidate)| {
            (
                addr,
                &candidate.node.value.txs[..],
                SampleTag::CandidateAddress,
            )
        })
    }

    #[inline]
    fn random_sample(&mut self) -> Option<(TX::Sender, &'a [TX], SampleTag)> {
        while let Some(node) = self.iter.next() {
            let loss_threshold = if let Some(x) =
                self.loss_base.checked_mul(node.weight.max_loss_ratio)
            {
                (x >> 192).as_u64()
            } else {
                self.random_sample_phase = false;
                self.first_unsample = Some(node);
                return None;
            };

            let sampled = self.rng.next_u64();
            if sampled >= loss_threshold {
                return Some((
                    node.key,
                    &node.value.txs,
                    SampleTag::RandomPick,
                ));
            } else {
                self.alter_address.insert(
                    &node.key,
                    CandidateAddress {
                        node,
                        priority: (sampled as f64) / (loss_threshold as f64),
                    },
                );
            }
        }
        None
    }
}

impl<'a, 'b, TX: PackingPoolTransaction, R: RngCore> Iterator
    for TxSampler<'a, 'b, TX, R>
{
    type Item = (TX::Sender, &'a [TX], SampleTag);

    fn next(&mut self) -> Option<Self::Item> {
        // Packing pool is not full
        if self.loss_base.is_zero() {
            return self.price_desc_sample();
        }

        if self.random_sample_phase {
            let res = self.random_sample();
            if res.is_some() {
                return res;
            }
        }

        let res = self.alternative_sample();
        if res.is_some() {
            return res;
        }
        self.price_desc_sample()
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
