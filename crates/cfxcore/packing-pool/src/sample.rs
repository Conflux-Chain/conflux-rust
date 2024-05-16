use cfx_types::U256;
use heap_map::HeapMap;
use rand::RngCore;
use treap_map;

use crate::{
    transaction::PackingPoolTransaction, treapmap_config::PackingPoolMap,
};

/// Enum representing the phase in which a transaction was selected during the
/// sampling process. See [`TxSampler`] for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleTag {
    /// Transaction was picked during the Random Sampling Phase.
    RandomPick,
    /// Transaction was picked during the Candidate Queue Phase.
    CandidateAddress,
    /// Transaction was picked during the Remaining Transactions Phase.
    PriceDesc,
}

/// An iterator for sampling transactions from a packing pool.
///
/// `TxSampler` iterates over addresses, returning lists of transactions that
/// come from the same sender, have continuous nonces, and pass
/// [`PackingBatch`][crate::PackingBatch] and readiness checks.
///
/// The iterator operates in three phases:
/// 1. **Random Sampling Phase**: Based on the random packing algorithm,
/// addresses are selected from high    to low gas prices of their first
/// transaction. The probability of inclusion is determined by the algorithm.
/// Transactions not selected    are placed in a candidate queue.
/// 2. **Candidate Queue Phase**: Transactions from the candidate queue are
/// output in a random order. Transactions    with a higher probability in the
/// first phase have a greater chance of appearing earlier in this phase.
/// 3. **Remaining Transactions Phase**: Remaining addresses are output in
/// descending order of their first transaction gas prices.
///
/// If the block's gas limit can accommodate all transactions in the packing
/// pool, the iterator directly enters the third phase.
pub struct TxSampler<'a, 'b, TX: PackingPoolTransaction, R: RngCore> {
    iter: treap_map::Iter<'a, PackingPoolMap<TX>>,
    /// A intermediated variable, record the first node that not considered in
    /// the Random Sampling Phase.
    first_unsample: Option<&'a treap_map::Node<PackingPoolMap<TX>>>,
    /// If the iterator in the Random Sampling Phase.
    random_sample_phase: bool,
    /// The candidate quese
    candidate_queue: HeapMap<TX::Sender, CandidateAddress<'a, TX>>,
    /// A parameter from packing algorithm
    loss_base: U256,
    /// Random source
    rng: &'b mut R,
}

impl<'a, 'b, TX: PackingPoolTransaction, R: RngCore> TxSampler<'a, 'b, TX, R> {
    pub(crate) fn new(
        iter: treap_map::Iter<'a, PackingPoolMap<TX>>, loss_base: U256,
        rng: &'b mut R,
    ) -> Self {
        Self {
            iter,
            random_sample_phase: true,
            first_unsample: None,
            candidate_queue: Default::default(),
            loss_base,
            rng,
        }
    }

    /// Iter in the **Remaining Transactions Phase**
    #[inline]
    fn price_desc_next(&mut self) -> Option<(TX::Sender, &'a [TX], SampleTag)> {
        if let Some(node) = self.first_unsample {
            self.first_unsample = None;
            return Some((node.key, &node.value.txs[..], SampleTag::PriceDesc));
        }
        self.iter
            .next()
            .map(|node| (node.key, &node.value.txs[..], SampleTag::PriceDesc))
    }

    /// Iter in the **Candidate Queue Phase**
    #[inline]
    fn candidate_next(&mut self) -> Option<(TX::Sender, &'a [TX], SampleTag)> {
        self.candidate_queue.pop().map(|(addr, candidate)| {
            (
                addr,
                &candidate.node.value.txs[..],
                SampleTag::CandidateAddress,
            )
        })
    }

    /// Iter in the **Random Sampling Phase**
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

            let target_quality = (u64::MAX - loss_threshold).saturating_add(1);
            let sampled = self.rng.next_u64();
            if sampled < target_quality {
                return Some((
                    node.key,
                    &node.value.txs,
                    SampleTag::RandomPick,
                ));
            } else {
                self.candidate_queue.insert(
                    &node.key,
                    CandidateAddress {
                        node,
                        priority: (target_quality as f64)
                            / ((sampled + 1) as f64),
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
            return self.price_desc_next();
        }

        if self.random_sample_phase {
            let res = self.random_sample();
            if res.is_some() {
                return res;
            }
        }

        let res = self.candidate_next();
        if res.is_some() {
            return res;
        }
        self.price_desc_next()
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
