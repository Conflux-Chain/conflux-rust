use std::convert::Infallible;

use crate::{
    packing_batch::{InsertError, PackInfo, PackingBatch, RemoveError},
    sample::TxSampler,
    weight::PackingPoolWeight,
    PackingPoolConfig,
};

use super::{
    transaction::PackingPoolTransaction, treapmap_config::PackingPoolMap,
};
use cfx_types::U256;
use malloc_size_of::MallocSizeOf;
use rand::RngCore;
use treap_map::{
    ApplyOpOutcome, Node, SearchDirection, SearchResult, TreapMap,
    WeightConsolidate,
};

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

    pub fn insert(&mut self, tx: TX) -> Result<Vec<TX>, ()> {
        let config = &self.config;
        let tx_clone = tx.clone();
        let sender = tx.sender();

        let update = move |node: &mut Node<PackingPoolMap<TX>>| {
            let old_info = node.value.pack_info();

            let out = match node.value.insert(tx, config) {
                Ok(out) => out,
                Err(InsertError::Replace(_, index)) => {
                    match node.value.split_off_suffix(index) {
                        Ok(out) => out,
                        Err(RemoveError::ShouldDelete) => {
                            return Ok(node.value.make_outcome_on_delete());
                        }
                    }
                }
                _ => {
                    return Err(());
                }
            };

            let new_info = node.value.pack_info();

            Ok(make_apply_outcome(old_info, new_info, node, config, out))
        };

        let insert = move |rng: &mut dyn RngCore| {
            let node = PackingBatch::new(tx_clone).make_node(config, rng);
            Ok((node, vec![]))
        };

        self.treap_map.update(&sender, update, insert)
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
    ) -> impl Iterator<Item = (TX::Sender, &'a [TX])> + 'b
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
        if let Some(SearchResult::Found { base_weight, .. }) = ret {
            Some(
                base_weight.weighted_loss_ratio
                    / (base_weight.gas_limit - block_gas_limit),
            )
        } else {
            None
        }
    }
}

fn make_apply_outcome<TX: PackingPoolTransaction>(
    old_info: PackInfo, new_info: PackInfo,
    node: &mut Node<PackingPoolMap<TX>>, config: &PackingPoolConfig,
    out: Vec<TX>,
) -> ApplyOpOutcome<Vec<TX>>
{
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

impl<TX> MallocSizeOf for PackingPool<TX>
where
    TX: PackingPoolTransaction + MallocSizeOf,
    TX::Sender: MallocSizeOf,
{
    fn size_of(&self, ops: &mut malloc_size_of::MallocSizeOfOps) -> usize {
        self.treap_map.size_of(ops) + self.config.size_of(ops)
    }
}
