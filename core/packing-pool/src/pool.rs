use crate::{sample::TxSampler, weight::PackingPoolWeight, PackingPoolConfig};

use super::{
    transaction::PackingPoolTransaction, treapmap_config::PackingPoolMap,
};
use cfx_types::U256;
use rand::RngCore;
use treap_map::{
    ApplyOpOutcome, Node, SearchDirection, SearchResult, TreapMap,
    WeightConsolidate,
};

pub struct PackingPool<TX: PackingPoolTransaction> {
    treap_map: TreapMap<PackingPoolMap<TX>>,
    config: PackingPoolConfig,
}

pub enum InsertError {
    SmallNonce,
    LargeNonce,
    ExceedAddrGasLimit,
    ExceedAddrTxCount,
    DecreasingGasPrice,
    NotEnoughReplaceGasPrice,
}

impl<TX: PackingPoolTransaction> PackingPool<TX> {
    pub fn new(config: PackingPoolConfig) -> Self {
        Self {
            treap_map: TreapMap::new(),
            config,
        }
    }

    pub fn insert(&mut self, tx: TX) -> Result<Vec<TX>, InsertError> {
        let config = &self.config;
        let tx_clone = tx.clone();

        self.treap_map.update(
            &tx.sender(),
            move |node| {
                let mut update_weight = false;
                let mut update_key = false;
                let out = insert_tx_on_node(
                    config,
                    node,
                    tx,
                    &mut update_weight,
                    &mut update_key,
                )?;
                Ok(ApplyOpOutcome {
                    out,
                    update_key,
                    update_weight,
                    delete_item: false,
                })
            },
            move |rng| {
                let node = make_node(config, tx_clone, rng);
                Ok((node, vec![]))
            },
        )
    }

    pub fn remove(&mut self, sender: TX::Sender, retain_nonce: U256) {
        let config = &self.config;

        let _ = self.treap_map.update(
            &sender,
            |node| {
                let mut update_weight = false;
                let mut update_key = false;
                let mut delete_item = false;
                remove_tx_on_node(
                    config,
                    node,
                    retain_nonce,
                    &mut update_weight,
                    &mut update_key,
                    &mut delete_item,
                );
                Ok(ApplyOpOutcome {
                    out: (),
                    update_key,
                    update_weight,
                    delete_item,
                })
            },
            |_| Err(()),
        );
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

fn make_node<TX: PackingPoolTransaction>(
    config: &PackingPoolConfig, tx: TX, rng: &mut dyn RngCore,
) -> Node<PackingPoolMap<TX>> {
    let key = tx.sender();
    let sort_key = tx.gas_price();
    let loss_ratio = config.loss_ratio(tx.gas_price());
    let weight = PackingPoolWeight {
        gas_limit: tx.gas_limit(),
        weighted_loss_ratio: loss_ratio * tx.gas_limit(),
        max_loss_ratio: loss_ratio,
    };
    let value = vec![tx];
    Node::new(key, value, sort_key, weight, rng.next_u64())
}

fn insert_tx_on_node<TX: PackingPoolTransaction>(
    config: &PackingPoolConfig, node: &mut Node<PackingPoolMap<TX>>,
    mut tx: TX, update_weight: &mut bool, update_key: &mut bool,
) -> Result<Vec<TX>, InsertError>
{
    use self::InsertError::*;

    let txs = &mut node.value;

    let n_txs = txs.len();
    assert!(n_txs > 0);
    let start_nonce = txs.first().unwrap().nonce();

    if tx.nonce() < start_nonce {
        return Err(SmallNonce);
    }

    if tx.nonce() > start_nonce + n_txs {
        return Err(LargeNonce);
    }

    if tx.nonce() == start_nonce + n_txs {
        // Insert tx
        if n_txs >= config.address_tx_count {
            return Err(ExceedAddrTxCount);
        }

        if txs.last().unwrap().gas_price() > tx.gas_price() {
            return Err(DecreasingGasPrice);
        }
        if config.address_gas_limit
            < node.weight.gas_limit.saturating_add(tx.gas_limit())
        {
            return Err(ExceedAddrGasLimit);
        }

        node.weight.gas_limit += tx.gas_limit();
        node.weight.weighted_loss_ratio +=
            tx.gas_limit() * node.weight.max_loss_ratio;

        *update_weight = true;
        txs.push(tx);

        Ok(vec![])
    } else {
        // Replace
        let to_replaced_idx = (tx.nonce() - start_nonce).as_usize();
        let to_replaced_tx = &txs[to_replaced_idx];
        if tx.gas_price() < config.next_gas_price(to_replaced_tx.gas_price()) {
            return Err(NotEnoughReplaceGasPrice);
        }
        if to_replaced_idx > 0
            && tx.gas_price() < txs[to_replaced_idx - 1].gas_price()
        {
            return Err(DecreasingGasPrice);
        }

        let (truncate_idx, addr_gas_limit) = config.check_address_gas_limit(
            &*txs,
            to_replaced_tx,
            to_replaced_idx,
        );
        if truncate_idx >= to_replaced_idx {
            return Err(ExceedAddrGasLimit);
        }

        let change_gas_limit = tx.gas_limit() != to_replaced_tx.gas_limit();
        let gas_price = tx.gas_price();
        std::mem::swap(&mut txs[to_replaced_idx], &mut tx);

        let mut res = vec![tx];
        res.extend(txs.split_off(truncate_idx));

        if to_replaced_idx == 0 {
            // Replace on the first place
            node.sort_key = gas_price;
            node.weight.max_loss_ratio = config.loss_ratio(gas_price);
            node.weight.gas_limit += addr_gas_limit;
            node.weight.weighted_loss_ratio +=
                addr_gas_limit * node.weight.max_loss_ratio;

            *update_weight = true;
            *update_key = true;
        } else {
            // Replace on the other place
            if change_gas_limit {
                node.weight.gas_limit = addr_gas_limit;
                node.weight.weighted_loss_ratio =
                    addr_gas_limit * node.weight.max_loss_ratio;
                *update_weight = true;
            }
        }
        Ok(res)
    }
}

fn remove_tx_on_node<TX: PackingPoolTransaction>(
    config: &PackingPoolConfig, node: &mut Node<PackingPoolMap<TX>>,
    retain_nonce: U256, update_weight: &mut bool, update_key: &mut bool, delete_item: &mut bool,
) 
{
    let txs = &mut node.value;
    let n_txs = txs.len();
    assert!(n_txs > 0);
    let start_nonce = txs.first().unwrap().nonce();

    if retain_nonce <= start_nonce {
        *delete_item = true;
    }

    if retain_nonce >= start_nonce + n_txs {
        return;
    }

    let retain_idx = (retain_nonce - start_nonce).as_usize();

    let old_gas_price = txs.first().unwrap().gas_price();
    let new_gas_price = txs[retain_idx].gas_price();

    *txs = txs.split_off(retain_idx);
    let total_gas_limit: U256 = txs
        .iter()
        .map(|x| x.gas_limit())
        .fold(U256::zero(), |acc, e| acc + e);

    if old_gas_price != new_gas_price {
        // Replace on the first place
        node.sort_key = new_gas_price;
        node.weight.max_loss_ratio = config.loss_ratio(new_gas_price);
        node.weight.gas_limit += total_gas_limit;
        node.weight.weighted_loss_ratio +=
            total_gas_limit * node.weight.max_loss_ratio;

        *update_weight = true;
        *update_key = true;
    } else {
        // Replace on the other place

        node.weight.gas_limit = total_gas_limit;
        node.weight.weighted_loss_ratio =
            total_gas_limit * node.weight.max_loss_ratio;
        *update_weight = true;
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
