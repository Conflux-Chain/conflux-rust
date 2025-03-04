mod nonce_pool;

pub use nonce_pool::{InsertResult, NoncePool, TxWithReadyInfo};

use super::pool_metrics::pool_inner_metrics::*;

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

        let mut to_pack_txs = Vec::new();
        let mut to_drop_txs = Vec::new();

        let mut minimum_unit_gas_limit = U256::from(21000);
        let mut minimum_unit_tx_size = 80;

        let mut rng = XorShiftRng::from_entropy();

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

        'all: for (_, sender_txs, _) in self
            .packing_pool
            .in_space_mut(space)
            .tx_sampler(&mut rng, block_gas_limit.into())
        {
            'sender: for tx in sender_txs.iter() {
                if tx.gas_price() < &tx_min_price {
                    break 'sender;
                }
                match validity(&*tx) {
                    PackingCheckResult::Pack => {}
                    PackingCheckResult::Pending => {
                        break 'sender;
                    }
                    PackingCheckResult::Drop => {
                        to_drop_txs.push(tx.clone());
                        break 'sender;
                    }
                }

                let gas_limit = *tx.gas_limit();
                if gas_limit > rest_gas_limit {
                    if gas_limit >= minimum_unit_gas_limit {
                        minimum_unit_gas_limit += minimum_unit_gas_limit >> 4;
                        break 'sender;
                    } else {
                        break 'all;
                    }
                } else {
                    rest_gas_limit -= gas_limit;
                }

                let tx_size = tx.rlp_size();
                if tx_size > rest_size_limit {
                    if tx_size >= minimum_unit_tx_size {
                        minimum_unit_tx_size += minimum_unit_tx_size >> 4;
                        break 'sender;
                    } else {
                        break 'all;
                    }
                } else {
                    rest_size_limit -= tx_size;
                }

                to_pack_txs.push(tx.clone());
                if to_pack_txs.len() >= tx_num_limit {
                    break 'all;
                }
            }
        }

        // Maybe we can remove to drop txs from deferred pool. But removing them
        // directly may break gc logic. So we only update packing
        // pool now.
        for tx in to_drop_txs {
            self.packing_pool
                .in_space_mut(space)
                .split_off_suffix(tx.sender(), tx.nonce());
        }

        let gas_used = block_gas_limit - rest_gas_limit;
        let size_used = block_size_limit - rest_size_limit;
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
        let bucket = self.buckets.get_mut(addr)?;
        let pack_info =
            bucket.recalculate_readiness_with_local_info(nonce, balance);

        let (first_tx, last_valid_nonce) = if let Some(info) = pack_info {
            info
        } else {
            // If cannot found such transaction, clear item in packing pool
            let _ = self.packing_pool.in_space_mut(addr.space).remove(*addr);
            return None;
        };

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
            self.packing_pool
                .in_space_mut(addr.space)
                .split_off_prefix(*addr, &first_valid_nonce);
        }

        if current_last_nonce > last_valid_nonce {
            self.packing_pool
                .in_space_mut(addr.space)
                .split_off_suffix(*addr, &(last_valid_nonce + 1));
        } else if current_last_nonce < last_valid_nonce {
            for tx in bucket.iter_tx_by_nonce(&current_last_nonce) {
                if tx.nonce() > &last_valid_nonce {
                    break;
                }
                let (_, res) = self
                    .packing_pool
                    .in_space_mut(addr.space)
                    .insert(tx.transaction.clone());
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

    pub fn ready_transactions_by_address<'a>(
        &'a self, address: AddressWithSpace,
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

#[cfg(test)]
mod tests {
    use crate::transaction_pool::TransactionPoolError;

    use super::{DeferredPool, InsertResult, TxWithReadyInfo};
    use crate::keylib::{Generator, KeyPair, Random};
    use cfx_types::{Address, AddressSpaceUtil, Space, U256};
    use primitives::{
        transaction::{
            native_transaction::NativeTransaction, Eip155Transaction,
        },
        Action, SignedTransaction, Transaction,
    };
    use std::sync::Arc;

    fn new_test_tx(
        sender: &KeyPair, nonce: usize, gas_price: usize, gas: usize,
        value: usize, space: Space,
    ) -> Arc<SignedTransaction> {
        let tx: Transaction = match space {
            Space::Native => NativeTransaction {
                nonce: U256::from(nonce),
                gas_price: U256::from(gas_price),
                gas: U256::from(gas),
                action: Action::Call(Address::random()),
                value: U256::from(value),
                storage_limit: 0,
                epoch_height: 0,
                chain_id: 1,
                data: Vec::new(),
            }
            .into(),
            Space::Ethereum => Eip155Transaction {
                nonce: U256::from(nonce),
                gas_price: U256::from(gas_price),
                gas: U256::from(gas),
                action: Action::Call(Address::random()),
                value: U256::from(value),
                chain_id: Some(1),
                data: Vec::new(),
            }
            .into(),
        };
        Arc::new(tx.sign(sender.secret()))
    }

    fn new_test_tx_with_ready_info(
        sender: &KeyPair, nonce: usize, gas_price: usize, value: usize,
        packed: bool,
    ) -> TxWithReadyInfo {
        let gas = 50000;
        let transaction =
            new_test_tx(sender, nonce, gas_price, gas, value, Space::Native);
        TxWithReadyInfo::new(transaction, packed, U256::from(0), 0)
    }

    #[test]
    fn test_deferred_pool_insert_and_remove() {
        let mut deferred_pool = DeferredPool::new_for_test();

        // insert txs of same sender
        let alice = Random.generate().unwrap();
        let alice_addr_s = alice.address().with_native_space();
        let bob = Random.generate().unwrap();
        let bob_addr_s = bob.address().with_native_space();
        let eva = Random.generate().unwrap();
        let eva_addr_s = eva.address().with_native_space();

        let alice_tx1 = new_test_tx_with_ready_info(
            &alice, 5, 10, 100, false, /* packed */
        );
        let alice_tx2 = new_test_tx_with_ready_info(
            &alice, 6, 10, 100, false, /* packed */
        );
        let bob_tx1 = new_test_tx_with_ready_info(
            &bob, 1, 10, 100, false, /* packed */
        );
        let bob_tx2 = new_test_tx_with_ready_info(
            &bob, 2, 10, 100, false, /* packed */
        );
        let bob_tx2_new = new_test_tx_with_ready_info(
            &bob, 2, 11, 100, false, /* packed */
        );

        assert_eq!(
            deferred_pool.insert(alice_tx1.clone(), false /* force */),
            InsertResult::NewAdded
        );

        assert_eq!(deferred_pool.contain_address(&alice_addr_s), true);

        assert_eq!(deferred_pool.contain_address(&eva_addr_s), false);

        assert_eq!(deferred_pool.remove_lowest_nonce(&eva_addr_s), None);

        assert_eq!(deferred_pool.contain_address(&bob_addr_s), false);

        assert_eq!(
            deferred_pool.insert(alice_tx2.clone(), false /* force */),
            InsertResult::NewAdded
        );

        assert_eq!(deferred_pool.remove_lowest_nonce(&bob_addr_s), None);

        assert_eq!(
            deferred_pool.insert(bob_tx1.clone(), false /* force */),
            InsertResult::NewAdded
        );

        assert_eq!(deferred_pool.contain_address(&bob_addr_s), true);

        assert_eq!(
            deferred_pool.insert(bob_tx2.clone(), false /* force */),
            InsertResult::NewAdded
        );

        assert_eq!(
            deferred_pool.insert(bob_tx2_new.clone(), false /* force */),
            InsertResult::Updated(bob_tx2.clone())
        );

        assert_eq!(
            deferred_pool.insert(bob_tx2.clone(), false /* force */),
            InsertResult::Failed(TransactionPoolError::HigherGasPriceNeeded {
                expected: *bob_tx2_new.gas_price() + U256::one()
            })
        );

        assert_eq!(
            deferred_pool.get_lowest_nonce(&bob_addr_s),
            Some(&(1.into()))
        );

        assert_eq!(
            deferred_pool.remove_lowest_nonce(&bob_addr_s),
            Some(bob_tx1.clone())
        );

        assert_eq!(
            deferred_pool.get_lowest_nonce(&bob_addr_s),
            Some(&(2.into()))
        );

        assert_eq!(deferred_pool.contain_address(&bob_addr_s), true);

        assert_eq!(
            deferred_pool.remove_lowest_nonce(&bob_addr_s),
            Some(bob_tx2_new.clone())
        );

        assert_eq!(deferred_pool.get_lowest_nonce(&bob_addr_s), None);

        assert_eq!(deferred_pool.contain_address(&bob_addr_s), false);
    }

    #[test]
    fn test_deferred_pool_recalculate_readiness() {
        let mut deferred_pool = super::DeferredPool::new_for_test();

        let alice = Random.generate().unwrap();
        let alice_addr_s = alice.address().with_native_space();

        let gas = 50000;
        let tx1 = new_test_tx_with_ready_info(
            &alice, 5, 10, 10000, true, /* packed */
        );
        let tx2 = new_test_tx_with_ready_info(
            &alice, 6, 10, 10000, true, /* packed */
        );
        let tx3 = new_test_tx_with_ready_info(
            &alice, 7, 10, 10000, true, /* packed */
        );
        let tx4 = new_test_tx_with_ready_info(
            &alice, 8, 10, 10000, false, /* packed */
        );
        let tx5 = new_test_tx_with_ready_info(
            &alice, 9, 10, 10000, false, /* packed */
        );
        let exact_cost = 4 * (gas * 10 + 10000);

        deferred_pool.insert(tx1.clone(), false /* force */);
        deferred_pool.insert(tx2.clone(), false /* force */);
        deferred_pool.insert(tx4.clone(), false /* force */);
        deferred_pool.insert(tx5.clone(), false /* force */);

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice_addr_s,
                5.into(),
                exact_cost.into(),
            ),
            None
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice_addr_s,
                7.into(),
                exact_cost.into(),
            ),
            None
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice_addr_s,
                8.into(),
                exact_cost.into(),
            ),
            Some(tx4.transaction.clone())
        );

        deferred_pool.insert(tx3.clone(), false /* force */);
        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice_addr_s,
                4.into(),
                exact_cost.into(),
            ),
            None
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice_addr_s,
                5.into(),
                exact_cost.into(),
            ),
            Some(tx4.transaction.clone())
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice_addr_s,
                7.into(),
                exact_cost.into(),
            ),
            Some(tx4.transaction.clone())
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice_addr_s,
                8.into(),
                exact_cost.into(),
            ),
            Some(tx4.transaction.clone())
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice_addr_s,
                9.into(),
                exact_cost.into(),
            ),
            Some(tx5.transaction.clone())
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice_addr_s,
                10.into(),
                exact_cost.into(),
            ),
            None
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice_addr_s,
                5.into(),
                (exact_cost - 1).into(),
            ),
            None
        );
    }
}
