use super::{
    nonce_pool::{InsertResult, NoncePool, TxWithReadyInfo},
    pool_metrics::pool_inner_metrics::*,
};

use crate::verification::PackingCheckResult;
use cfx_packing_pool::{PackingPool, PackingPoolConfig};

use cfx_rpc_cfx_types::PendingReason;
use cfx_types::{AddressWithSpace, Space, SpaceMap, H256, U256};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use primitives::{block_header::compute_next_price, SignedTransaction};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

#[cfg(test)]
mod tests;

/// The `DeferredPool` is designed to organize transactions for each address
/// based on their nonce. It efficiently maintains and queries transactions even
/// when received nonces are non-sequential. In addition, it calculates
/// transactions that are ready to be packed for each address and stores them in
/// the `packing_pool`. The transactions in the `packing_pool` should always be
/// a subset of the transactions in the nonce pools for all addresses.
#[derive(DeriveMallocSizeOf)]
pub struct DeferredPool {
    /// Store transactions organized in binary balanced trees keyed by nonce
    /// for each address.
    buckets: HashMap<AddressWithSpace, NoncePool>,
    /// Store transactions that are ready to be packed for each address, and
    /// implements random sampling logic.
    packing_pool: SpaceMap<PackingPool<Arc<SignedTransaction>>>,
}

impl DeferredPool {
    pub fn new(config: PackingPoolConfig) -> Self {
        DeferredPool {
            buckets: Default::default(),
            packing_pool: SpaceMap::new(
                PackingPool::new(config),
                PackingPool::new(config),
            ),
        }
    }

    #[cfg(test)]
    pub fn new_for_test() -> Self {
        let config = PackingPoolConfig::new(3_000_000.into(), 20, 4);
        DeferredPool {
            buckets: Default::default(),
            packing_pool: SpaceMap::new(
                PackingPool::new(config),
                PackingPool::new(config),
            ),
        }
    }

    pub fn clear(&mut self) {
        self.buckets.clear();
        self.packing_pool.apply_all(|x| x.clear());
    }

    pub fn get_bucket(&self, addr: &AddressWithSpace) -> Option<&NoncePool> {
        self.buckets.get(addr)
    }

    pub fn estimate_packing_gas_limit(
        &self, space: Space, gas_target: U256, parent_base_price: U256,
        min_base_price: U256,
    ) -> (U256, U256) {
        let estimated_gas_limit = self
            .packing_pool
            .in_space(space)
            .estimate_packing_gas_limit(
                gas_target,
                parent_base_price,
                min_base_price,
            );
        let packing_gas_limit = U256::min(gas_target * 2, estimated_gas_limit);
        let price_limit = compute_next_price(
            gas_target,
            packing_gas_limit,
            parent_base_price,
            min_base_price,
        );
        (packing_gas_limit, price_limit)
    }

    #[inline]
    pub fn packing_sampler<
        'a,
        F: Fn(&SignedTransaction) -> PackingCheckResult,
    >(
        &'a mut self, space: Space, block_gas_limit: U256,
        block_size_limit: usize, tx_num_limit: usize, tx_min_price: U256,
        validity: F,
    ) -> (Vec<Arc<SignedTransaction>>, U256, usize) {
        if block_gas_limit.is_zero()
            || block_size_limit == 0
            || tx_num_limit == 0
        {
            return (vec![], 0.into(), 0);
        }

        debug!(
            "txpool::packing_sampler start space={:?} block_gas_limit={} block_size_limit={} tx_limit={} min_price={}",
            space,
            block_gas_limit,
            block_size_limit,
            tx_num_limit,
            tx_min_price
        );

        let mut to_pack_txs = Vec::new();
        let mut to_drop_txs = Vec::new();

        let mut minimum_unit_gas_limit = U256::from(21000);
        let mut minimum_unit_tx_size = 80;

        let mut rng = XorShiftRng::from_os_rng();

        // When a sampled transaction exceeds the remaining capacity (gas limit
        // or size) in a block, we skip it and look for the next transaction.
        // However, if the remaining space is too small, we might sample a large
        // number of transactions and still fail to find one that meets the
        // criteria.

        // Here, we maintain a threshold. When the remaining capacity is less
        // than the threshold, the packing process stopped. The threshold
        // increases by 1/16 for each fail due to insufficient capacity. This
        // way, the packing process can always stop after a finite number of
        // failures.

        let mut rest_size_limit = block_size_limit;
        let mut rest_gas_limit = block_gas_limit;

        'all: for (sender, sender_txs, _) in self
            .packing_pool
            .in_space_mut(space)
            .tx_sampler(&mut rng, block_gas_limit.into())
        {
            'sender: for tx in sender_txs.iter() {
                if tx.gas_price() < &tx_min_price {
                    debug!(
                        "txpool::packing_sampler skip sender={:?} nonce={} reason=low_price tx_price={} min_price={}",
                        sender,
                        tx.nonce(),
                        tx.gas_price(),
                        tx_min_price
                    );
                    break 'sender;
                }
                match validity(&*tx) {
                    PackingCheckResult::Pack => {}
                    PackingCheckResult::Pending => {
                        debug!(
                            "txpool::packing_sampler stop sender={:?} nonce={} reason=pending",
                            sender,
                            tx.nonce()
                        );
                        break 'sender;
                    }
                    PackingCheckResult::Drop => {
                        to_drop_txs.push(tx.clone());
                        debug!(
                            "txpool::packing_sampler drop sender={:?} nonce={} reason=invalid",
                            sender,
                            tx.nonce()
                        );
                        break 'sender;
                    }
                }

                let gas_limit = *tx.gas_limit();
                if gas_limit > rest_gas_limit {
                    if gas_limit >= minimum_unit_gas_limit {
                        minimum_unit_gas_limit += minimum_unit_gas_limit >> 4;
                        debug!(
                            "txpool::packing_sampler sender={:?} nonce={} gas_limit={} exceeds remaining_gas={} adjust_threshold={}",
                            sender,
                            tx.nonce(),
                            gas_limit,
                            rest_gas_limit,
                            minimum_unit_gas_limit
                        );
                        break 'sender;
                    } else {
                        debug!(
                            "txpool::packing_sampler stop all space={:?} reason=gas_exhausted remaining_gas={} next_gas_limit={}",
                            space,
                            rest_gas_limit,
                            gas_limit
                        );
                        break 'all;
                    }
                }

                let tx_size = tx.rlp_size();
                if tx_size > rest_size_limit {
                    if tx_size >= minimum_unit_tx_size {
                        minimum_unit_tx_size += minimum_unit_tx_size >> 4;
                        debug!(
                            "txpool::packing_sampler sender={:?} nonce={} tx_size={} exceeds remaining_size={} adjust_threshold_size={}",
                            sender,
                            tx.nonce(),
                            tx_size,
                            rest_size_limit,
                            minimum_unit_tx_size
                        );
                        break 'sender;
                    } else {
                        debug!(
                            "txpool::packing_sampler stop all space={:?} reason=size_exhausted remaining_size={} next_size={}",
                            space,
                            rest_size_limit,
                            tx_size
                        );
                        break 'all;
                    }
                }

                rest_gas_limit -= gas_limit;
                rest_size_limit -= tx_size;

                to_pack_txs.push(tx.clone());
                debug!(
                    "txpool::packing_sampler select sender={:?} nonce={} remaining_gas={} remaining_size={} count={}",
                    sender,
                    tx.nonce(),
                    rest_gas_limit,
                    rest_size_limit,
                    to_pack_txs.len()
                );
                if to_pack_txs.len() >= tx_num_limit {
                    debug!(
                        "txpool::packing_sampler reached tx limit {}",
                        tx_num_limit
                    );
                    break 'all;
                }
            }
        }

        // Maybe we can remove to drop txs from deferred pool. But removing them
        // directly may break gc logic. So we only update packing
        // pool now.
        for tx in to_drop_txs {
            debug!(
                "txpool::packing_sampler prune sender={:?} nonce={}",
                tx.sender(),
                tx.nonce()
            );
            self.packing_pool
                .in_space_mut(space)
                .split_off_suffix(tx.sender(), tx.nonce());
        }

        let gas_used = block_gas_limit - rest_gas_limit;
        let size_used = block_size_limit - rest_size_limit;
        debug!(
            "txpool::packing_sampler finish space={:?}  packed={} gas_used={} size_used={}",
            space,
            to_pack_txs.len(),
            gas_used,
            size_used
        );
        if to_pack_txs.is_empty() && self.packing_pool.in_space(space).len() > 0
        {
            debug!(
                "txpool::packing_sampler no_tx_selected space={:?} ready_entries={} block_gas_limit={} block_size_limit={} tx_limit={} remaining_gas={} remaining_size={}",
                space,
                self.packing_pool.in_space(space).len(),
                block_gas_limit,
                block_size_limit,
                tx_num_limit,
                rest_gas_limit,
                rest_size_limit
            );
        }
        (to_pack_txs, gas_used, size_used)
    }

    pub fn insert(&mut self, tx: TxWithReadyInfo, force: bool) -> InsertResult {
        let bucket = self
            .buckets
            .entry(tx.sender())
            .or_insert_with(|| NoncePool::new());

        let res = bucket.insert(&tx, force);
        if matches!(res, InsertResult::Updated(_)) {
            // The transactions in the packing_pool must be consistent with the
            // nonce pool. However, the replaced transactions have not undergone
            // a readiness check, so we will temporarily remove them from the
            // packing_pool.
            self.packing_pool
                .in_space_mut(tx.space())
                .split_off_suffix(tx.sender(), tx.nonce());
        }
        res
    }

    pub fn mark_packed(
        &mut self, addr: AddressWithSpace, nonce: &U256, packed: bool,
    ) -> bool {
        if let Some(bucket) = self.buckets.get_mut(&addr) {
            bucket.mark_packed(&nonce, packed)
        } else {
            false
        }
    }

    pub fn contain_address(&self, addr: &AddressWithSpace) -> bool {
        self.buckets.contains_key(addr)
    }

    pub fn check_sender_and_nonce_exists(
        &self, sender: &AddressWithSpace, nonce: &U256,
    ) -> bool {
        if let Some(bucket) = self.buckets.get(sender) {
            bucket.check_nonce_exists(nonce)
        } else {
            false
        }
    }

    pub fn count_less(&self, sender: &AddressWithSpace, nonce: &U256) -> usize {
        if let Some(bucket) = self.buckets.get(sender) {
            bucket.count_less(nonce)
        } else {
            0
        }
    }

    pub fn remove_lowest_nonce(
        &mut self, addr: &AddressWithSpace,
    ) -> Option<TxWithReadyInfo> {
        let bucket = self.buckets.get_mut(addr)?;
        let ret = bucket.remove_lowest_nonce();
        if bucket.is_empty() {
            self.buckets.remove(addr);
            self.packing_pool.in_space_mut(addr.space).remove(*addr);
            return ret;
        }

        let tx = ret.as_ref()?;
        let removed_tx = self
            .packing_pool
            .in_space_mut(addr.space)
            .split_off_prefix(tx.sender(), &(tx.nonce() + 1));
        if let Some(removed_tx) = removed_tx.first() {
            if removed_tx.nonce() < tx.nonce() {
                warn!("Internal Issue: Packing pool has inconsistent tranaction with nonce pool.");
            } else if removed_tx.nonce() == tx.nonce() {
                // TODO: remove the lowest nonce makes the rest nonce
                info!("a ready tx is garbage-collected");
                GC_READY_COUNTER.inc(1);
            }
        }

        ret
    }

    #[inline]
    pub fn get_lowest_nonce(&self, addr: &AddressWithSpace) -> Option<&U256> {
        Some(self.get_lowest_nonce_tx(addr)?.nonce())
    }

    pub fn get_lowest_nonce_tx(
        &self, addr: &AddressWithSpace,
    ) -> Option<&SignedTransaction> {
        self.buckets.get(addr)?.get_lowest_nonce_tx()
    }

    pub fn recalculate_readiness_with_local_info(
        &mut self, addr: &AddressWithSpace, nonce: U256, balance: U256,
    ) -> Option<Arc<SignedTransaction>> {
        let bucket = match self.buckets.get_mut(addr) {
            Some(bucket) => bucket,
            None => {
                debug!(
                    "txpool::packing readiness addr={:?} missing bucket",
                    addr
                );
                return None;
            }
        };
        let pack_info =
            bucket.recalculate_readiness_with_local_info(nonce, balance);

        let (first_tx, last_valid_nonce) = if let Some(info) = pack_info {
            info
        } else {
            debug!(
                "txpool::packing readiness addr={:?} no contiguous unpaid tx (nonce={:?}, balance={:?})",
                addr, nonce, balance
            );
            // If cannot found such transaction, clear item in packing pool
            let _ = self.packing_pool.in_space_mut(addr.space).remove(*addr);
            return None;
        };

        debug!(
            "txpool::packing readiness addr={:?} candidate window start_nonce={:?} last_valid_nonce={:?} first_tx_hash={:?}",
            addr,
            first_tx.nonce(),
            last_valid_nonce,
            first_tx.transaction.hash()
        );

        let first_valid_nonce = *first_tx.nonce();
        let current_txs = if let Some(txs) = self
            .packing_pool
            .in_space(addr.space)
            .get_transactions(addr)
            .filter(|txs| txs.first().unwrap().nonce() <= &first_valid_nonce)
        {
            txs
        } else {
            // If one of the following condition happens, we organize a new
            // batch
            //  1. the packing batch is absent
            //  2. the nonce of first valid transaction becomes smaller
            // (unlikely happens unless execution revert)
            let config = self.packing_pool.in_space(addr.space).config();
            let batch =
                bucket.make_packing_batch(first_tx, config, last_valid_nonce);
            let _ = self.packing_pool.in_space_mut(addr.space).replace(batch);
            return Some(first_tx.transaction.clone());
        };

        let current_first_nonce = *current_txs.first().unwrap().nonce();
        let current_last_nonce = *current_txs.last().unwrap().nonce();
        // There must be current_first_nonce <= first_valid_nonce
        if current_first_nonce < first_valid_nonce {
            let dropped = self
                .packing_pool
                .in_space_mut(addr.space)
                .split_off_prefix(*addr, &first_valid_nonce);
            if !dropped.is_empty() {
                debug!(
                    "txpool::packing readiness addr={:?} dropped {} txs with nonce < {:?}",
                    addr,
                    dropped.len(),
                    first_valid_nonce
                );
            }
        }

        if current_last_nonce > last_valid_nonce {
            let dropped = self
                .packing_pool
                .in_space_mut(addr.space)
                .split_off_suffix(*addr, &(last_valid_nonce + 1));
            if !dropped.is_empty() {
                debug!(
                    "txpool::packing readiness addr={:?} dropped {} txs with nonce > {:?}",
                    addr,
                    dropped.len(),
                    last_valid_nonce
                );
            }
        } else if current_last_nonce < last_valid_nonce {
            for tx in bucket.iter_tx_by_nonce(&current_last_nonce) {
                if tx.nonce() > &last_valid_nonce {
                    break;
                }
                let (evicted, res) = self
                    .packing_pool
                    .in_space_mut(addr.space)
                    .insert(tx.transaction.clone());
                match &res {
                    Ok(_) => {
                        debug!(
                            "txpool::packing readiness addr={:?} promoted tx hash={:?} nonce={:?} evicted={}",
                            addr,
                            tx.transaction.hash(),
                            tx.nonce(),
                            evicted.len()
                        );
                    }
                    Err(e) => {
                        debug!(
                            "txpool::packing readiness addr={:?} failed to promote tx hash={:?} nonce={:?} err={:?}",
                            addr,
                            tx.transaction.hash(),
                            tx.nonce(),
                            e
                        );
                    }
                }

                if res.is_err() {
                    break;
                }
            }
        }

        return Some(first_tx.transaction.clone());
    }

    pub fn get_pending_info(
        &self, addr: &AddressWithSpace, nonce: &U256,
    ) -> Option<(usize, Arc<SignedTransaction>)> {
        if let Some(bucket) = self.buckets.get(addr) {
            bucket.get_pending_info(nonce)
        } else {
            None
        }
    }

    pub fn get_pending_transactions<'a>(
        &'a self, addr: &AddressWithSpace, start_nonce: &U256,
        local_nonce: &U256, local_balance: &U256,
    ) -> (Vec<&'a TxWithReadyInfo>, Option<PendingReason>) {
        match self.buckets.get(addr) {
            Some(bucket) => {
                let pending_txs = bucket.get_pending_transactions(start_nonce);
                let pending_reason = pending_txs.first().and_then(|tx| {
                    bucket.check_pending_reason_with_local_info(
                        *local_nonce,
                        *local_balance,
                        &tx.transaction.as_ref(),
                    )
                });
                (pending_txs, pending_reason)
            }
            None => (Vec::new(), None),
        }
    }

    pub fn eth_content<F>(
        &self, space: Option<Space>, get_nonce_and_balance: F,
    ) -> (
        BTreeMap<AddressWithSpace, BTreeMap<U256, Arc<SignedTransaction>>>,
        BTreeMap<AddressWithSpace, BTreeMap<U256, Arc<SignedTransaction>>>,
    )
    where F: Fn(&AddressWithSpace) -> (U256, U256) {
        let mut total_pending = BTreeMap::new();
        let mut total_queued = BTreeMap::new();
        for (addr, pool) in self.buckets.iter() {
            if let Some(addr_space) = space {
                if addr_space != addr.space {
                    continue;
                }
            }
            let (nonce, balance) = get_nonce_and_balance(addr);
            let (pending, queued) = pool.eth_content(nonce, balance);
            total_pending.insert(*addr, pending);
            total_queued.insert(*addr, queued);
        }
        (total_pending, total_queued)
    }

    pub fn eth_content_from(
        &self, address: AddressWithSpace, local_nonce: U256,
        local_balance: U256,
    ) -> (
        BTreeMap<U256, Arc<SignedTransaction>>,
        BTreeMap<U256, Arc<SignedTransaction>>,
    ) {
        if let Some(nonce_pool) = self.buckets.get(&address) {
            nonce_pool.eth_content(local_nonce, local_balance)
        } else {
            (Default::default(), Default::default())
        }
    }

    pub fn check_tx_packed(&self, addr: AddressWithSpace, nonce: U256) -> bool {
        if let Some(bucket) = self.buckets.get(&addr) {
            if let Some(tx_with_ready_info) = bucket.get_tx_by_nonce(nonce) {
                tx_with_ready_info.is_already_packed()
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn last_succ_nonce(
        &self, addr: AddressWithSpace, from_nonce: U256,
    ) -> Option<U256> {
        let bucket = self.buckets.get(&addr)?;
        let mut next_nonce = from_nonce;
        loop {
            let nonce = bucket.succ_nonce(&next_nonce);
            if nonce.is_none() {
                break;
            }
            if nonce.unwrap() > next_nonce {
                break;
            }
            next_nonce += 1.into();
        }
        Some(next_nonce)
    }

    pub fn ready_account_number(&self, space: Space) -> usize {
        self.packing_pool.in_space(space).len()
    }

    pub fn ready_transaction_hashes(
        &self, space: Space,
    ) -> impl Iterator<Item = H256> + '_ {
        self.ready_transactions_by_space(space).map(|x| x.hash())
    }

    pub fn ready_transactions_by_space(
        &self, space: Space,
    ) -> impl Iterator<Item = &Arc<SignedTransaction>> + '_ {
        self.packing_pool
            .in_space(space)
            .iter()
            .map(|txs| txs.iter())
            .flatten()
    }

    pub fn has_ready_tx(&self, addr: &AddressWithSpace) -> bool {
        self.packing_pool.in_space(addr.space).contains(addr)
    }

    pub fn ready_transactions_by_address(
        &self, address: AddressWithSpace,
    ) -> Option<&[Arc<SignedTransaction>]> {
        self.packing_pool
            .in_space(address.space)
            .get_transactions(&address)
    }

    pub fn all_ready_transactions(
        &self,
    ) -> impl Iterator<Item = &Arc<SignedTransaction>> + '_ {
        self.ready_transactions_by_space(Space::Native)
            .chain(self.ready_transactions_by_space(Space::Ethereum))
    }

    pub fn pending_tx_number<F>(
        &self, space: Option<Space>, get_nonce_and_balance: F,
    ) -> u64
    where F: Fn(&AddressWithSpace) -> (U256, U256) {
        self.buckets
            .iter()
            .filter(|item| {
                if let Some(space) = space {
                    item.0.space == space
                } else {
                    true
                }
            })
            .map(|(addr, nonce_pool)| {
                let (nonce, balance) = get_nonce_and_balance(addr);
                if let Some((tx, nonce)) = nonce_pool
                    .recalculate_readiness_with_local_info(nonce, balance)
                {
                    (nonce - tx.nonce() + 1).as_u64()
                } else {
                    0u64
                }
            })
            .sum()
    }
}
