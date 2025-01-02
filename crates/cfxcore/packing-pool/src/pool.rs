use std::convert::Infallible;

use crate::{
    packing_batch::{InsertError, PackInfo, PackingBatch, RemoveError},
    sample::{SampleTag, TxSampler},
    weight::PackingPoolWeight,
    PackingPoolConfig,
};

use super::{
    transaction::PackingPoolTransaction, treapmap_config::PackingPoolMap,
};
use cfx_types::U256;
use malloc_size_of::MallocSizeOf;
use primitives::block_header::{compute_next_price, estimate_max_possible_gas};
use rand::RngCore;
use treap_map::{
    ApplyOpOutcome, ConsoliableWeight, Node, SearchDirection, SearchResult,
    TreapMap,
};

/// A `PackingPool` implementing random packing algorithm and supporting packing
/// a series of transactions with the same nonce.
pub struct PackingPool<TX: PackingPoolTransaction> {
    treap_map: TreapMap<PackingPoolMap<TX>>,
    config: PackingPoolConfig,
}

impl<TX: PackingPoolTransaction> PackingPool<TX> {
    pub fn new(config: PackingPoolConfig) -> Self {
        Self {
            treap_map: TreapMap::new(),
            config,
        }
    }

    pub fn config(&self) -> &PackingPoolConfig { &self.config }

    pub fn len(&self) -> usize { self.treap_map.len() }

    pub fn iter(&self) -> impl Iterator<Item = &[TX]> + '_ {
        self.treap_map.values().map(|x| &x.txs[..])
    }

    pub fn contains(&self, addr: &TX::Sender) -> bool {
        self.treap_map.contains_key(addr)
    }

    pub fn get_transactions(&self, addr: &TX::Sender) -> Option<&[TX]> {
        Some(&self.treap_map.get(addr)?.txs)
    }

    pub fn clear(&mut self) { self.treap_map = TreapMap::new(); }

    #[inline]
    pub fn insert(&mut self, tx: TX) -> (Vec<TX>, Result<(), InsertError>) {
        let config = &self.config;
        let tx_clone = tx.clone();
        let sender = tx.sender();

        let update = move |node: &mut Node<PackingPoolMap<TX>>| -> Result<_, Infallible> {
            let old_info = node.value.pack_info();
            let out = node.value.insert(tx, config);
            let new_info = node.value.pack_info();

            Ok(make_apply_outcome(old_info, new_info, node, config, out))
        };

        let insert = move |rng: &mut dyn RngCore| {
            let node = PackingBatch::new(tx_clone).make_node(config, rng);
            Ok((node, (vec![], Ok(()))))
        };

        self.treap_map.update(&sender, update, insert).unwrap()
    }

    pub fn replace(&mut self, mut packing_batch: PackingBatch<TX>) -> Vec<TX> {
        let config = &self.config;
        let sender = packing_batch.sender();
        let packing_batch_clone = packing_batch.clone();

        let update = move |node: &mut Node<PackingPoolMap<TX>>| -> Result<_, Infallible> {
            let old_info = node.value.pack_info();
            std::mem::swap(&mut packing_batch, &mut node.value);
            let new_info = node.value.pack_info();
            let out = std::mem::take(&mut packing_batch.txs);

            Ok(make_apply_outcome(old_info, new_info, node, config, out))
        };

        let insert = move |rng: &mut dyn RngCore| {
            let node = packing_batch_clone.make_node(config, rng);
            Ok((node, vec![]))
        };

        self.treap_map.update(&sender, update, insert).unwrap()
    }

    pub fn remove(&mut self, sender: TX::Sender) -> Vec<TX> {
        self.split_off_suffix(sender, &U256::zero())
    }

    pub fn split_off_suffix(
        &mut self, sender: TX::Sender, start_nonce: &U256,
    ) -> Vec<TX> {
        self.split_off(sender, start_nonce, true)
    }

    pub fn split_off_prefix(
        &mut self, sender: TX::Sender, start_nonce: &U256,
    ) -> Vec<TX> {
        self.split_off(sender, start_nonce, false)
    }

    fn split_off(
        &mut self, sender: TX::Sender, start_nonce: &U256, keep_prefix: bool,
    ) -> Vec<TX> {
        let config = &self.config;
        let update = move |node: &mut Node<PackingPoolMap<TX>>| {
            let old_info = node.value.pack_info();

            let out =
                match node.value.split_off_by_nonce(start_nonce, keep_prefix) {
                    Ok(out) => out,
                    Err(RemoveError::ShouldDelete) => {
                        return Ok(node.value.make_outcome_on_delete());
                    }
                };

            let new_info = node.value.pack_info();

            Ok(make_apply_outcome(old_info, new_info, node, config, out))
        };
        self.treap_map
            .update(&sender, update, |_| Err(()))
            .unwrap_or(vec![])
    }

    pub fn tx_sampler<'a, 'b, R: RngCore>(
        &'a self, rng: &'b mut R, block_gas_limit: U256,
    ) -> impl Iterator<Item = (TX::Sender, &'a [TX], SampleTag)> + 'b
    where 'a: 'b {
        let global_loss_base =
            if let Some(r) = self.truncate_loss_ratio(block_gas_limit) {
                // It can never be zero.
                U256::MAX / r
            } else {
                U256::zero()
            };
        TxSampler::<'a, 'b, TX, R>::new(
            self.treap_map.iter(),
            global_loss_base,
            rng,
        )
    }

    /// The maximum loss ratio that a gas_price is considered in random packing
    /// algorithm. If the return value is `None`, all the transactions can
    /// not fulfill the given `block_gas_limit`.
    pub fn truncate_loss_ratio(&self, block_gas_limit: U256) -> Option<U256> {
        let ret = self.treap_map.search(|left_weight, node| {
            if !can_sample(left_weight, block_gas_limit) {
                return SearchDirection::Left;
            }
            let right_weight =
                PackingPoolWeight::consolidate(left_weight, &node.weight);
            if !can_sample(&right_weight, block_gas_limit) {
                return SearchDirection::Stop;
            } else {
                return SearchDirection::Right(right_weight);
            }
        });
        match ret {
            Some(
                SearchResult::Found { base_weight, .. }
                | SearchResult::RightMost(base_weight),
            ) if base_weight.gas_limit > block_gas_limit => Some(
                base_weight.weighted_loss_ratio
                    / (base_weight.gas_limit - block_gas_limit),
            ),
            _ => None,
        }
    }

    pub fn estimate_packing_gas_limit(
        &self, gas_target: U256, parent_base_price: U256, min_base_price: U256,
    ) -> U256 {
        let ret = self.treap_map.search(|left_weight, node| {
            let can_sample = |weight| {
                can_sample_within_1559(
                    weight,
                    gas_target,
                    parent_base_price,
                    min_base_price,
                )
            };

            if !can_sample(&left_weight) {
                return SearchDirection::Left;
            }
            let right_weight =
                PackingPoolWeight::consolidate(left_weight, &node.weight);
            if !can_sample(&right_weight) {
                return SearchDirection::Stop;
            } else {
                return SearchDirection::Right(right_weight);
            }
        });
        match ret {
            Some(
                SearchResult::Found { base_weight, .. }
                | SearchResult::RightMost(base_weight),
            ) => {
                let gas_limit = estimate_max_possible_gas(
                    gas_target,
                    base_weight.min_gas_price,
                    parent_base_price,
                );
                if cfg!(test) {
                    // Guarantee the searched result can be packed
                    let next_price = compute_next_price(
                        gas_target,
                        gas_limit,
                        parent_base_price,
                        min_base_price,
                    );
                    assert!(base_weight.min_gas_price >= next_price);
                }
                gas_limit
            }
            _ => U256::zero(),
        }
    }

    #[cfg(test)]
    fn assert_consistency(&self) {
        self.treap_map.assert_consistency();
        for node in self.treap_map.iter() {
            let weight = &node.weight;
            let packing_batch = &node.value;
            packing_batch.assert_constraints();
            let loss_ratio =
                self.config.loss_ratio(packing_batch.first_gas_price());
            let gas_limit = packing_batch.total_gas_limit();
            assert_eq!(gas_limit, weight.gas_limit);
            assert_eq!(loss_ratio, weight.max_loss_ratio);
            assert_eq!(loss_ratio * gas_limit, weight.weighted_loss_ratio);
        }
    }
}

fn make_apply_outcome<TX: PackingPoolTransaction, T>(
    old_info: PackInfo, new_info: PackInfo,
    node: &mut Node<PackingPoolMap<TX>>, config: &PackingPoolConfig, out: T,
) -> ApplyOpOutcome<T> {
    let change_gas_price = old_info.first_gas_price != new_info.first_gas_price;
    let change_gas_limit = old_info.total_gas_limit != new_info.total_gas_limit;

    let mut update_weight = false;
    let mut update_key = false;

    if change_gas_price {
        let gas_price = new_info.first_gas_price;
        node.sort_key = gas_price;
        node.weight.max_loss_ratio = config.loss_ratio(gas_price);
        node.weight.gas_limit = new_info.total_gas_limit;
        node.weight.weighted_loss_ratio =
            new_info.total_gas_limit * node.weight.max_loss_ratio;

        update_key = true;
        update_weight = true;
    } else if change_gas_limit {
        node.weight.gas_limit = new_info.total_gas_limit;
        node.weight.weighted_loss_ratio =
            new_info.total_gas_limit * node.weight.max_loss_ratio;

        update_weight = true;
    }

    ApplyOpOutcome {
        out,
        update_key,
        update_weight,
        delete_item: false,
    }
}
fn can_sample(weight: &PackingPoolWeight, gas_limit: U256) -> bool {
    if weight.gas_limit <= gas_limit {
        return true;
    }
    weight
        .max_loss_ratio
        .saturating_mul(weight.gas_limit - gas_limit)
        < weight.weighted_loss_ratio
}

fn can_sample_within_1559(
    weight: &PackingPoolWeight, gas_target: U256, parent_base_price: U256,
    min_base_price: U256,
) -> bool {
    if weight.min_gas_price < min_base_price {
        return false;
    }

    let max_target_gas_used = estimate_max_possible_gas(
        gas_target,
        weight.min_gas_price,
        parent_base_price,
    );

    if max_target_gas_used.is_zero() {
        return false;
    }

    if weight.gas_limit <= max_target_gas_used {
        return true;
    }

    weight
        .max_loss_ratio
        .saturating_mul(weight.gas_limit - max_target_gas_used)
        < weight.weighted_loss_ratio
}

impl<TX> MallocSizeOf for PackingPool<TX>
where
    TX: PackingPoolTransaction + MallocSizeOf,
    TX::Sender: MallocSizeOf,
{
    fn size_of(&self, ops: &mut malloc_size_of::MallocSizeOfOps) -> usize {
        self.treap_map.size_of(ops) + self.config.size_of(ops)
    }
}

#[cfg(test)]
mod pool_tests {
    use std::{collections::HashSet, sync::atomic::AtomicUsize};

    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use crate::{
        mock_tx::MockTransaction, transaction::PackingPoolTransaction,
        PackingBatch, PackingPool, PackingPoolConfig, SampleTag,
    };

    fn default_pool(
        len: usize, accounts: usize,
    ) -> PackingPool<MockTransaction> {
        let config = PackingPoolConfig::new_for_test();
        let mut pool = PackingPool::new(config);
        for accound_id in 0u64..accounts as u64 {
            let mut batch = PackingBatch::new(default_tx(accound_id, 2));
            for i in 3..(len as u64 + 2) {
                batch.insert(default_tx(accound_id, i), &config).1.unwrap();
            }
            pool.replace(batch);
        }
        pool.assert_consistency();
        assert_eq!(pool.treap_map.len(), accounts);
        pool
    }

    fn default_tx(sender: u64, i: u64) -> MockTransaction {
        static ID: AtomicUsize = AtomicUsize::new(0);
        MockTransaction {
            sender,
            nonce: i,
            gas_price: i,
            gas_limit: i,
            id: ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        }
    }

    #[allow(dead_code)]
    fn same_price_txs() -> PackingPool<MockTransaction> {
        let config = PackingPoolConfig::new_for_test();
        let mut pool = PackingPool::new(config);

        static ID: AtomicUsize = AtomicUsize::new(0);
        for i in 1000..2000 {
            let (_, res) = pool.insert(MockTransaction {
                sender: i,
                nonce: 0,
                gas_price: 20,
                gas_limit: 1,
                id: ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            });
            res.unwrap();
        }
        pool
    }

    #[test]
    fn test_split_in_middle() {
        let mut pool = default_pool(5, 10);
        let txs = pool.split_off_prefix(2, &4.into());
        pool.assert_consistency();
        assert_eq!(pool.treap_map.len(), 10);
        assert_eq!(txs.len(), 2);
        for (idx, tx) in txs.into_iter().enumerate() {
            assert_eq!(tx.sender(), 2);
            assert_eq!(tx.nonce(), (2 + idx).into());
        }
        assert_eq!(pool.iter().into_iter().flatten().count(), 48);
    }

    #[test]
    fn test_split_all() {
        let mut pool = default_pool(5, 10);
        let txs = pool.split_off_suffix(2, &2.into());
        pool.assert_consistency();
        assert_eq!(pool.treap_map.len(), 9);
        assert!(!pool.treap_map.contains_key(&2));
        assert_eq!(txs.len(), 5);
        for (idx, tx) in txs.into_iter().enumerate() {
            assert_eq!(tx.sender(), 2);
            assert_eq!(tx.nonce(), (2 + idx).into());
        }

        let txs = pool.remove(3);
        pool.assert_consistency();
        assert_eq!(pool.treap_map.len(), 8);
        assert!(!pool.treap_map.contains_key(&3));
        assert_eq!(txs.len(), 5);
        for (idx, tx) in txs.into_iter().enumerate() {
            assert_eq!(tx.sender(), 3);
            assert_eq!(tx.nonce(), (2 + idx).into());
        }
        assert_eq!(pool.iter().into_iter().flatten().count(), 40);
    }

    #[test]
    fn test_change_price() {
        let mut pool = default_pool(5, 10);
        let mut new_tx = default_tx(2, 2);
        new_tx.gas_price = 10;
        let (tx, res) = pool.insert(new_tx);
        assert_eq!(tx.first().unwrap().nonce(), 2.into());
        res.unwrap();
        pool.assert_consistency();
        assert_eq!(pool.treap_map.len(), 10);
        let first = pool.treap_map.iter().next().unwrap();
        assert_eq!(first.value.sender(), 2);
        assert_eq!(pool.iter().into_iter().flatten().count(), 46);
    }

    #[test]
    fn test_change_limit() {
        let mut pool = default_pool(5, 10);
        let mut new_tx = default_tx(2, 2);
        new_tx.gas_limit = 10;
        let (tx, res) = pool.insert(new_tx);
        assert_eq!(tx.first().unwrap().nonce(), 2.into());
        res.unwrap();
        pool.assert_consistency();
        assert_eq!(pool.treap_map.len(), 10);
        assert_eq!(pool.iter().into_iter().flatten().count(), 50);
    }

    #[test]
    fn test_insert_empty_sender() {
        let mut pool = default_pool(5, 10);
        let new_tx = default_tx(11, 2);
        let (_tx, res) = pool.insert(new_tx);
        res.unwrap();
        pool.assert_consistency();
        assert_eq!(pool.treap_map.len(), 11);
        assert_eq!(pool.iter().into_iter().flatten().count(), 51);
    }

    #[test]
    fn test_replace() {
        let mut pool = default_pool(5, 10);
        let mut batch = PackingBatch::new(default_tx(2, 12));
        for i in 13..18 {
            batch.insert(default_tx(2, i), &pool.config).1.unwrap();
        }
        let txs = pool.replace(batch);
        for (idx, tx) in txs.into_iter().enumerate() {
            assert_eq!(tx.sender(), 2);
            assert_eq!(tx.nonce(), (2 + idx).into());
        }
        pool.assert_consistency();
        assert_eq!(pool.treap_map.len(), 10);
        assert_eq!(pool.iter().into_iter().flatten().count(), 51);
    }

    #[test]
    fn test_same_price() {
        let pool = default_pool(5, 100000);

        let pack_txs = || {
            let mut rng = XorShiftRng::from_entropy();

            let mut packed = HashSet::new();
            for (_, txs, tag) in pool.tx_sampler(&mut rng, 40000.into()) {
                if packed.len() < 8000 {
                    // This assertation may fails with a small probability
                    // (~2^-64) even if every thing is correct.
                    assert_eq!(tag, SampleTag::RandomPick);
                }

                for tx in txs {
                    packed.insert(tx.clone());
                }
                if packed.len() >= 10000 {
                    break;
                }
            }
            packed
        };

        let base_pack = pack_txs();
        let mut total_same_set = 0usize;

        for _ in 0..5 {
            total_same_set += pack_txs().intersection(&base_pack).count();
        }
        // This assertation may fails with a small probability (~2^-110) even if
        // every thing is correct.
        assert!(total_same_set < 2000);
    }
}

#[cfg(test)]
mod sample_tests {
    use std::{cmp::Reverse, collections::HashSet, sync::atomic::AtomicUsize};

    use crate::{
        mock_tx::MockTransaction, sample::SampleTag,
        transaction::PackingPoolTransaction, PackingPool, PackingPoolConfig,
    };
    use cfx_types::U256;
    use rand::{distributions::Uniform, Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;

    #[derive(Default)]
    struct MockPriceBook(Vec<MockTransaction>);
    impl MockPriceBook {
        fn truncate_loss_ratio(&self, block_limit: usize) -> Option<U256> {
            let config = PackingPoolConfig::new_for_test();
            let mut total_gas_limit = U256::zero();
            let mut total_weighted_loss = U256::zero();
            let mut last_ans = None;
            for tx in self.0.iter() {
                total_gas_limit += tx.gas_limit();
                let loss_ratio = config.loss_ratio(tx.gas_price());
                total_weighted_loss += loss_ratio * tx.gas_limit();
                if let Some(quot) =
                    total_gas_limit.checked_sub(block_limit.into())
                {
                    if quot * loss_ratio >= total_weighted_loss {
                        return Some(last_ans.unwrap());
                    }
                    if quot > U256::zero() {
                        last_ans = Some(total_weighted_loss / quot);
                    }
                }
            }
            last_ans
        }
    }

    fn default_tx(
        sender: u64, gas_limit: u64, gas_price: u64,
    ) -> MockTransaction {
        static ID: AtomicUsize = AtomicUsize::new(0);
        MockTransaction {
            sender,
            nonce: 0,
            gas_price,
            gas_limit,
            id: ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        }
    }

    #[test]
    fn test_truncate_price_and_sample() {
        let mut rand = XorShiftRng::from_entropy();
        let mut pool = PackingPool::new(PackingPoolConfig::new_for_test());
        let mut mock_pool = MockPriceBook::default();
        for i in 0..1000 {
            let mut gas_limit = 1.01f64.powf(2000.0 + i as f64) as u64;
            gas_limit -= gas_limit / rand.sample(Uniform::new(50, 200));
            let mut gas_price = 1.01f64.powf(3000.0 - i as f64) as u64;
            gas_price -= gas_price / rand.sample(Uniform::new(50, 200));

            let tx = default_tx(i, gas_limit, gas_price);

            mock_pool.0.push(tx);
            let (_, res) = pool.insert(tx);
            res.unwrap();
        }
        mock_pool.0.sort_by_key(|x| Reverse(x.gas_price()));
        pool.assert_consistency();
        for i in 1900..3500 {
            let mut total_gas_limit = 1.01f64.powf(i as f64) as u64;
            total_gas_limit -=
                total_gas_limit / rand.sample(Uniform::new(50, 200));
            assert_eq!(
                pool.truncate_loss_ratio(total_gas_limit.into()),
                mock_pool.truncate_loss_ratio(total_gas_limit as usize)
            );

            let truncate_loss_ratio =
                pool.truncate_loss_ratio(total_gas_limit.into());
            let mut last_loss_ratio = truncate_loss_ratio;
            // // Debug info
            // eprintln!("===== Limit Level {} =======", i);
            // if let Some(x) = truncate_loss_ratio {
            //     let r = (u64::MAX as f64).log(1.01) - ((x>>64).as_u64() as
            // f64).log(1.01);     let r = r *
            // pool.config().loss_ratio_degree as f64;     eprintln!
            // (">> Truncate price {:.2}", r); }
            let mut packing_set = HashSet::new();
            for (_, txs, tag) in
                pool.tx_sampler(&mut rand, total_gas_limit.into())
            {
                let tx = txs.first().unwrap();
                let loss_ratio = pool.config().loss_ratio(tx.gas_price());
                if tag != SampleTag::PriceDesc {
                    assert!(loss_ratio < truncate_loss_ratio.unwrap());
                } else if let Some(r) = last_loss_ratio {
                    assert!(loss_ratio >= r);
                    last_loss_ratio = Some(loss_ratio);
                }
                packing_set.insert(tx.clone());

                // let price_level = (tx.gas_price as f64).log(1.01);
                // let limit_level = (tx.gas_limit as f64).log(1.01);
                // eprintln!("{:?}: Price: {:.2}, Limit: {:.1}, Sender {}", tag,
                // price_level, limit_level, tx.sender);
            }
            assert_eq!(packing_set.len(), 1000);
            // eprintln!("");
        }
    }
}
