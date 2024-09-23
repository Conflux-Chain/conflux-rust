use super::{
    account_cache::AccountCache,
    garbage_collector::GarbageCollector,
    nonce_pool::{InsertResult, NoncePool, TxWithReadyInfo},
    TransactionPoolError,
};

use crate::verification::{PackingCheckResult, VerificationConfig};
use cfx_executor::machine::Machine;
use cfx_packing_pool::{PackingPool, PackingPoolConfig};
use cfx_parameters::{
    block::cspace_block_gas_limit_after_cip1559,
    consensus_internal::ELASTICITY_MULTIPLIER,
    staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT,
};

pub use cfx_rpc_cfx_types::{PendingReason, TransactionStatus};
use cfx_statedb::Result as StateDbResult;
use cfx_types::{
    address_util::AddressUtil, AddressWithSpace, Space, SpaceMap, H256, U128,
    U256, U512,
};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use metrics::{
    register_meter_with_group, Counter, CounterUsize, Meter, MeterTimer,
};
use primitives::{
    block_header::compute_next_price, Account, Action, SignedTransaction,
    Transaction, TransactionWithSignature,
};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use rlp::*;
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

lazy_static! {
    pub static ref MAX_WEIGHT: U256 = u128::max_value().into();
}

const FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET: u32 = 2000;

lazy_static! {
    static ref TX_POOL_RECALCULATE: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::recalculate");
    static ref TX_POOL_INNER_INSERT_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::inner_insert");
    static ref DEFERRED_POOL_INNER_INSERT: Arc<dyn Meter> =
        register_meter_with_group("timer", "deferred_pool::inner_insert");
    pub static ref TX_POOL_GET_STATE_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::get_nonce_and_storage");
    static ref TX_POOL_INNER_WITHOUTCHECK_INSERT_TIMER: Arc<dyn Meter> =
        register_meter_with_group(
            "timer",
            "tx_pool::inner_without_check_inert"
        );
    static ref GC_UNEXECUTED_COUNTER: Arc<dyn Counter<usize>> =
        CounterUsize::register_with_group("txpool", "gc_unexecuted");
    static ref GC_READY_COUNTER: Arc<dyn Counter<usize>> =
        CounterUsize::register_with_group("txpool", "gc_ready");
    static ref GC_METER: Arc<dyn Meter> =
        register_meter_with_group("txpool", "gc_txs_tps");
}

/// The `DeferredPool` is designed to organize transactions for each address
/// based on their nonce. It efficiently maintains and queries transactions even
/// when received nonces are non-sequential. In addition, it calculates
/// transactions that are ready to be packed for each address and stores them in
/// the `packing_pool`. The transactions in the `packing_pool` should always be
/// a subset of the transactions in the nonce pools for all addresses.
#[derive(DeriveMallocSizeOf)]
struct DeferredPool {
    /// Store transactions organized in binary balanced trees keyed by nonce
    /// for each address.
    buckets: HashMap<AddressWithSpace, NoncePool>,
    /// Store transactions that are ready to be packed for each address, and
    /// implements random sampling logic.
    packing_pool: SpaceMap<PackingPool<Arc<SignedTransaction>>>,
}

impl DeferredPool {
    fn new(config: PackingPoolConfig) -> Self {
        DeferredPool {
            buckets: Default::default(),
            packing_pool: SpaceMap::new(
                PackingPool::new(config),
                PackingPool::new(config),
            ),
        }
    }

    #[cfg(test)]
    fn new_for_test() -> Self {
        let config = PackingPoolConfig::new(3_000_000.into(), 20, 4);
        DeferredPool {
            buckets: Default::default(),
            packing_pool: SpaceMap::new(
                PackingPool::new(config),
                PackingPool::new(config),
            ),
        }
    }

    fn clear(&mut self) {
        self.buckets.clear();
        self.packing_pool.apply_all(|x| x.clear());
    }

    fn estimate_packing_gas_limit(
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
    fn packing_sampler<'a, F: Fn(&SignedTransaction) -> PackingCheckResult>(
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

    fn insert(&mut self, tx: TxWithReadyInfo, force: bool) -> InsertResult {
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

    fn mark_packed(
        &mut self, addr: AddressWithSpace, nonce: &U256, packed: bool,
    ) -> bool {
        if let Some(bucket) = self.buckets.get_mut(&addr) {
            bucket.mark_packed(&nonce, packed)
        } else {
            false
        }
    }

    fn contain_address(&self, addr: &AddressWithSpace) -> bool {
        self.buckets.contains_key(addr)
    }

    fn check_sender_and_nonce_exists(
        &self, sender: &AddressWithSpace, nonce: &U256,
    ) -> bool {
        if let Some(bucket) = self.buckets.get(sender) {
            bucket.check_nonce_exists(nonce)
        } else {
            false
        }
    }

    fn count_less(&self, sender: &AddressWithSpace, nonce: &U256) -> usize {
        if let Some(bucket) = self.buckets.get(sender) {
            bucket.count_less(nonce)
        } else {
            0
        }
    }

    fn remove_lowest_nonce(
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
    fn get_lowest_nonce(&self, addr: &AddressWithSpace) -> Option<&U256> {
        Some(self.get_lowest_nonce_tx(addr)?.nonce())
    }

    fn get_lowest_nonce_tx(
        &self, addr: &AddressWithSpace,
    ) -> Option<&SignedTransaction> {
        self.buckets.get(addr)?.get_lowest_nonce_tx()
    }

    fn recalculate_readiness_with_local_info(
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

    fn get_pending_info(
        &self, addr: &AddressWithSpace, nonce: &U256,
    ) -> Option<(usize, Arc<SignedTransaction>)> {
        if let Some(bucket) = self.buckets.get(addr) {
            bucket.get_pending_info(nonce)
        } else {
            None
        }
    }

    fn get_pending_transactions<'a>(
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

    fn check_tx_packed(&self, addr: AddressWithSpace, nonce: U256) -> bool {
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

    fn last_succ_nonce(
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

    fn ready_account_number(&self, space: Space) -> usize {
        self.packing_pool.in_space(space).len()
    }

    fn ready_transaction_hashes(
        &self, space: Space,
    ) -> impl Iterator<Item = H256> + '_ {
        self.ready_transactions_by_space(space).map(|x| x.hash())
    }

    fn ready_transactions_by_space(
        &self, space: Space,
    ) -> impl Iterator<Item = &Arc<SignedTransaction>> + '_ {
        self.packing_pool
            .in_space(space)
            .iter()
            .map(|txs| txs.iter())
            .flatten()
    }

    fn has_ready_tx(&self, addr: &AddressWithSpace) -> bool {
        self.packing_pool.in_space(addr.space).contains(addr)
    }

    fn ready_transactions_by_address<'a>(
        &'a self, address: AddressWithSpace,
    ) -> Option<&[Arc<SignedTransaction>]> {
        self.packing_pool
            .in_space(address.space)
            .get_transactions(&address)
    }

    fn all_ready_transactions(
        &self,
    ) -> impl Iterator<Item = &Arc<SignedTransaction>> + '_ {
        self.ready_transactions_by_space(Space::Native)
            .chain(self.ready_transactions_by_space(Space::Ethereum))
    }
}

#[derive(Default, DeriveMallocSizeOf)]
pub struct TransactionSet {
    inner: HashMap<H256, Arc<SignedTransaction>>,
    count: SpaceMap<usize>,
}

impl TransactionSet {
    fn get(&self, tx_hash: &H256) -> Option<&Arc<SignedTransaction>> {
        self.inner.get(tx_hash)
    }

    fn values(
        &self,
    ) -> std::collections::hash_map::Values<'_, H256, Arc<SignedTransaction>>
    {
        self.inner.values()
    }

    fn insert(
        &mut self, tx_hash: H256, tx: Arc<SignedTransaction>,
    ) -> Option<Arc<SignedTransaction>> {
        *self.count.in_space_mut(tx.space()) += 1;
        let res = self.inner.insert(tx_hash, tx);
        if let Some(ref tx) = res {
            *self.count.in_space_mut(tx.space()) -= 1;
        }
        res
    }

    fn remove(&mut self, tx_hash: &H256) -> Option<Arc<SignedTransaction>> {
        let res = self.inner.remove(tx_hash);
        if let Some(ref tx) = res {
            *self.count.in_space_mut(tx.space()) -= 1;
        }
        res
    }

    fn clear(&mut self) {
        self.inner.clear();
        self.count.apply_all(|x| *x = 0);
    }
}

#[derive(DeriveMallocSizeOf)]
pub struct TransactionPoolInner {
    capacity: usize,
    total_received_count: usize,
    unpacked_transaction_count: usize,
    /// Tracks all transactions in the transaction pool by account and nonce.
    /// Packed and executed transactions will eventually be garbage collected.
    deferred_pool: DeferredPool,
    /// The cache of the latest nonce and balance in the state.
    /// Updated with the storage data after a block is processed in consensus
    /// (set_tx_packed), after epoch execution, or during transaction
    /// insertion.
    ready_nonces_and_balances: HashMap<AddressWithSpace, (U256, U256)>,
    garbage_collector: SpaceMap<GarbageCollector>,
    /// Keeps all transactions in the transaction pool.
    /// It should contain the same transaction set as `deferred_pool`.
    txs: TransactionSet,
}

impl TransactionPoolInner {
    pub fn new(
        capacity: usize, max_packing_batch_gas_limit: usize,
        max_packing_batch_size: usize, packing_pool_degree: u8,
    ) -> Self {
        let config = PackingPoolConfig::new(
            max_packing_batch_gas_limit.into(),
            max_packing_batch_size,
            packing_pool_degree,
        );
        TransactionPoolInner {
            capacity,
            total_received_count: 0,
            unpacked_transaction_count: 0,
            deferred_pool: DeferredPool::new(config),
            ready_nonces_and_balances: HashMap::new(),
            garbage_collector: SpaceMap::default(),
            txs: TransactionSet::default(),
        }
    }

    #[cfg(test)]
    pub fn new_for_test() -> Self { Self::new(50_000, 3_000_000, 50, 4) }

    pub fn clear(&mut self) {
        self.deferred_pool.clear();
        self.ready_nonces_and_balances.clear();
        self.garbage_collector.apply_all(|x| x.clear());
        self.txs.clear();
        self.total_received_count = 0;
        self.unpacked_transaction_count = 0;
    }

    pub fn total_deferred(&self, space: Option<Space>) -> usize {
        match space {
            Some(space) => *self.txs.count.in_space(space),
            None => self.txs.count.map_sum(|x| *x),
        }
    }

    pub fn ready_transacton_hashes_in_evm_pool(&self) -> BTreeSet<H256> {
        self.deferred_pool
            .ready_transaction_hashes(Space::Ethereum)
            .collect()
    }

    pub fn ready_transacton_hashes_in_native_pool(&self) -> BTreeSet<H256> {
        self.deferred_pool
            .ready_transaction_hashes(Space::Native)
            .collect()
    }

    pub fn total_ready_accounts(&self) -> usize {
        self.deferred_pool.ready_account_number(Space::Ethereum)
            + self.deferred_pool.ready_account_number(Space::Native)
    }

    pub fn total_received(&self) -> usize { self.total_received_count }

    pub fn total_unpacked(&self) -> usize { self.unpacked_transaction_count }

    pub fn get(&self, tx_hash: &H256) -> Option<Arc<SignedTransaction>> {
        self.txs.get(tx_hash).map(|x| x.clone())
    }

    pub fn get_by_address2nonce(
        &self, address: AddressWithSpace, nonce: U256,
    ) -> Option<Arc<SignedTransaction>> {
        let bucket = self.deferred_pool.buckets.get(&address)?;
        bucket.get_tx_by_nonce(nonce).map(|tx| tx.transaction)
    }

    pub fn is_full(&self, space: Space) -> bool {
        return self.total_deferred(Some(space)) >= self.capacity;
    }

    pub fn get_current_timestamp(&self) -> u64 {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
        since_the_epoch.as_secs()
    }

    /// A sender has a transaction which is garbage collectable if
    ///    1. there is at least a transaction whose nonce is less than
    /// `ready_nonce`
    ///    2. the nonce of all transactions are greater than or equal to
    /// `ready_nonce` and it is not garbage collected during the last
    /// `TIME_WINDOW` seconds
    ///
    /// We will pick a sender who has maximum number of transactions which are
    /// garbage collectable. And if there is a tie, the one who has minimum
    /// timestamp will be picked.
    pub fn collect_garbage(&mut self, new_tx: &SignedTransaction) {
        let space = new_tx.space();
        let count_before_gc = self.total_deferred(Some(space));
        let mut skipped_self_node = None;
        while self.is_full(space)
            && !self.garbage_collector.in_space(space).is_empty()
        {
            let current_timestamp = self.get_current_timestamp();
            let (victim_address, victim) =
                self.garbage_collector.in_space(space).top().unwrap();
            // Accounts which are not in `deferred_pool` may be inserted
            // into `garbage_collector`, we can just ignore them.
            if !self.deferred_pool.contain_address(victim_address) {
                self.garbage_collector.in_space_mut(space).pop();
                continue;
            }

            // `count == 0` means all transactions are not executed, so there is
            // no unconditional garbage collection to conduct and we need to
            // check if we should replace one unexecuted tx.
            if victim.count == 0 {
                if *victim_address == new_tx.sender() {
                    // We do not GC a not-executed transaction from the same
                    // sender, so save it and try another account.
                    let (victim_address, victim) = self
                        .garbage_collector
                        .in_space_mut(space)
                        .pop()
                        .unwrap();
                    skipped_self_node = Some((victim_address, victim));
                    continue;
                } else if victim.has_ready_tx
                    && victim.first_tx_gas_price >= *new_tx.gas_price()
                {
                    // If all transactions are not executed but some accounts
                    // are not ready to be packed, we directly replace a
                    // not-ready transaction (with the least gas_price in
                    // garbage_collector). If all accounts
                    // are ready, we check if the new tx has larger gas price
                    // than some.
                    trace!("txpool::collect_garbage fails, victim={:?} new_tx={:?} \
                    new_tx_gas_price={:?}", victim, new_tx.hash(), new_tx.gas_price());
                    return;
                }
            }

            // victim is now chosen to be evicted.
            let (victim_address, victim) =
                self.garbage_collector.in_space_mut(space).pop().unwrap();

            let (ready_nonce, _) = self
                .get_local_nonce_and_balance(&victim_address)
                .unwrap_or((0.into(), 0.into()));

            let tx_with_ready_info = self
                .deferred_pool
                .remove_lowest_nonce(&victim_address)
                .unwrap();
            let to_remove_tx = tx_with_ready_info.get_arc_tx().clone();

            // We have to garbage collect an unexecuted transaction.
            // TODO: Implement more heuristic strategies
            if *to_remove_tx.nonce() >= ready_nonce {
                assert_eq!(victim.count, 0);
                GC_UNEXECUTED_COUNTER.inc(1);
                warn!("an unexecuted tx is garbage-collected.");
            }

            if !tx_with_ready_info.is_already_packed() {
                self.unpacked_transaction_count = self
                    .unpacked_transaction_count
                    .checked_sub(1)
                    .unwrap_or_else(|| {
                        error!("unpacked_transaction_count under-flows.");
                        0
                    });
            }

            // maintain ready info
            if !self.deferred_pool.contain_address(&victim_address) {
                self.ready_nonces_and_balances.remove(&victim_address);
            // The picked sender has no transactions now, and has been popped
            // from `garbage_collector`.
            } else {
                let has_ready_tx =
                    self.deferred_pool.has_ready_tx(&victim_address);
                let first_tx_gas_price = *self
                    .deferred_pool
                    .get_lowest_nonce_tx(&victim_address)
                    .expect("addr exist")
                    .gas_price();
                let count = if victim.count > 0 {
                    victim.count - 1
                } else {
                    0
                };
                self.garbage_collector.in_space_mut(space).insert(
                    &victim_address,
                    count,
                    current_timestamp,
                    has_ready_tx,
                    first_tx_gas_price,
                );
            }

            // maintain txs
            self.txs.remove(&to_remove_tx.hash());
        }

        // Insert back skipped nodes to keep `garbage_collector`
        // unchanged.
        if let Some((addr, node)) = skipped_self_node {
            self.garbage_collector.in_space_mut(space).insert(
                &addr,
                node.count,
                node.timestamp,
                node.has_ready_tx,
                node.first_tx_gas_price,
            );
        }
        GC_METER.mark(count_before_gc - self.total_deferred(Some(space)));
    }

    /// Collect garbage and return the remaining quota of the pool to insert new
    /// transactions.
    pub fn remaining_quota(&self) -> usize {
        let len = self.total_deferred(None);
        self.garbage_collector.size() * self.capacity - len
            + self.garbage_collector.map_sum(|x| x.gc_size())
    }

    pub fn capacity(&self) -> usize { self.capacity }

    #[cfg(test)]
    fn insert_transaction_for_test(
        &mut self, transaction: Arc<SignedTransaction>, sender_nonce: U256,
    ) -> InsertResult {
        let sender = transaction.sender();
        let res = self.insert_transaction_without_readiness_check(
            transaction,
            false,
            true,
            (sender_nonce, U256::from(u64::MAX)),
            (0.into(), 0),
        );
        self.recalculate_readiness(&sender, sender_nonce, U256::from(u64::MAX));
        res
    }

    // the new inserting will fail if tx_pool is full (even if `force` is true)
    fn insert_transaction_without_readiness_check(
        &mut self, transaction: Arc<SignedTransaction>, packed: bool,
        force: bool, state_nonce_and_balance: (U256, U256),
        (sponsored_gas, sponsored_storage): (U256, u64),
    ) -> InsertResult {
        let _timer = MeterTimer::time_func(
            TX_POOL_INNER_WITHOUTCHECK_INSERT_TIMER.as_ref(),
        );
        if !self.deferred_pool.check_sender_and_nonce_exists(
            &transaction.sender(),
            &transaction.nonce(),
        ) {
            self.collect_garbage(transaction.as_ref());
            if self.is_full(transaction.space()) {
                return InsertResult::Failed(TransactionPoolError::TxPoolFull);
            }
        }
        let result = {
            let _timer =
                MeterTimer::time_func(DEFERRED_POOL_INNER_INSERT.as_ref());
            self.deferred_pool.insert(
                TxWithReadyInfo::new(
                    transaction.clone(),
                    packed,
                    sponsored_gas,
                    sponsored_storage,
                ),
                force,
            )
        };

        match &result {
            InsertResult::NewAdded => {
                let (state_nonce, state_balance) = state_nonce_and_balance;
                self.update_nonce_and_balance(
                    &transaction.sender(),
                    state_nonce,
                    state_balance,
                );
                // GarbageCollector will be updated by the caller.
                self.txs.insert(transaction.hash(), transaction.clone());
                if !packed {
                    self.unpacked_transaction_count += 1;
                }
            }
            InsertResult::Failed(_) => {}
            InsertResult::Updated(replaced_tx) => {
                if !replaced_tx.is_already_packed() {
                    self.unpacked_transaction_count = self
                        .unpacked_transaction_count
                        .checked_sub(1)
                        .unwrap_or_else(|| {
                            error!("unpacked_transaction_count under-flows.");
                            0
                        });
                }
                self.txs.remove(&replaced_tx.hash());
                self.txs.insert(transaction.hash(), transaction.clone());
                if !packed {
                    self.unpacked_transaction_count += 1;
                }
            }
        }

        result
    }

    #[allow(dead_code)]
    fn mark_packed(&mut self, tx: &SignedTransaction, packed: bool) {
        let changed =
            self.deferred_pool
                .mark_packed(tx.sender(), tx.nonce(), packed);
        if changed {
            if packed {
                if self.unpacked_transaction_count == 0 {
                    error!("unpacked_transaction_count under-flows.");
                } else {
                    self.unpacked_transaction_count -= 1;
                }
            } else {
                self.unpacked_transaction_count += 1;
            }
        }
    }

    pub fn get_account_pending_info(
        &self, address: &AddressWithSpace,
    ) -> Option<(U256, U256, U256, H256)> {
        let (local_nonce, _local_balance) = self
            .get_local_nonce_and_balance(address)
            .unwrap_or((U256::from(0), U256::from(0)));
        match self.deferred_pool.get_pending_info(address, &local_nonce) {
            Some((pending_count, pending_tx)) => Some((
                local_nonce,
                U256::from(pending_count),
                *pending_tx.nonce(),
                pending_tx.hash(),
            )),
            None => {
                Some((local_nonce, U256::from(0), U256::from(0), H256::zero()))
            }
        }
    }

    pub fn get_account_pending_transactions(
        &self, address: &AddressWithSpace, maybe_start_nonce: Option<U256>,
        maybe_limit: Option<usize>,
    ) -> (
        Vec<Arc<SignedTransaction>>,
        Option<TransactionStatus>,
        usize,
    ) {
        let (local_nonce, local_balance) = self
            .get_local_nonce_and_balance(address)
            .unwrap_or((U256::from(0), U256::from(0)));
        let start_nonce = maybe_start_nonce.unwrap_or(local_nonce);
        let (pending_txs, pending_reason) =
            self.deferred_pool.get_pending_transactions(
                address,
                &start_nonce,
                &local_nonce,
                &local_balance,
            );
        if pending_txs.is_empty() {
            return (Vec::new(), None, 0);
        }
        let first_tx_status = match pending_reason {
            None => TransactionStatus::Ready,
            Some(reason) => TransactionStatus::Pending(reason),
        };
        let pending_count = pending_txs.len();
        let limit = maybe_limit.unwrap_or(usize::MAX);
        (
            pending_txs
                .into_iter()
                .map(|x| x.transaction.clone())
                .take(limit)
                .collect(),
            Some(first_tx_status),
            pending_count,
        )
    }

    pub fn get_local_nonce_and_balance(
        &self, address: &AddressWithSpace,
    ) -> Option<(U256, U256)> {
        self.ready_nonces_and_balances.get(address).map(|x| *x)
    }

    fn update_nonce_and_balance(
        &mut self, address: &AddressWithSpace, nonce: U256, balance: U256,
    ) {
        if !self.deferred_pool.contain_address(address) {
            return;
        }
        self.ready_nonces_and_balances
            .insert((*address).clone(), (nonce, balance));
    }

    fn get_and_update_nonce_and_balance_from_storage(
        &mut self, address: &AddressWithSpace, state: &AccountCache,
    ) -> StateDbResult<(U256, U256)> {
        let nonce_and_balance = state.get_nonce_and_balance(address)?;
        if !self.deferred_pool.contain_address(address) {
            return Ok(nonce_and_balance);
        }
        self.ready_nonces_and_balances
            .insert((*address).clone(), nonce_and_balance);

        Ok(nonce_and_balance)
    }

    pub fn get_lowest_nonce(&self, addr: &AddressWithSpace) -> U256 {
        let mut ret = 0.into();
        if let Some((nonce, _)) = self.get_local_nonce_and_balance(addr) {
            ret = nonce;
        }
        if let Some(nonce) = self.deferred_pool.get_lowest_nonce(addr) {
            if *nonce < ret {
                ret = *nonce;
            }
        }
        ret
    }

    pub fn get_next_nonce(
        &self, address: &AddressWithSpace, state_nonce: U256,
    ) -> U256 {
        self.deferred_pool
            .last_succ_nonce(*address, state_nonce)
            .unwrap_or(state_nonce)
    }

    #[allow(dead_code)]
    fn recalculate_readiness_with_local_info(
        &mut self, addr: &AddressWithSpace,
    ) {
        let (nonce, balance) = self
            .get_local_nonce_and_balance(addr)
            .unwrap_or((0.into(), 0.into()));
        self.recalculate_readiness(addr, nonce, balance);
    }

    fn recalculate_readiness_with_fixed_info(
        &mut self, addr: &AddressWithSpace, nonce: U256, balance: U256,
    ) {
        self.update_nonce_and_balance(addr, nonce, balance);
        self.recalculate_readiness(addr, nonce, balance);
    }

    fn recalculate_readiness_with_state(
        &mut self, addr: &AddressWithSpace, account_cache: &AccountCache,
    ) -> StateDbResult<()> {
        let _timer = MeterTimer::time_func(TX_POOL_RECALCULATE.as_ref());
        let (nonce, balance) = self
            .get_and_update_nonce_and_balance_from_storage(
                addr,
                account_cache,
            )?;
        self.recalculate_readiness(addr, nonce, balance);
        Ok(())
    }

    fn recalculate_readiness(
        &mut self, addr: &AddressWithSpace, nonce: U256, balance: U256,
    ) {
        let space = addr.space;
        let ret = self
            .deferred_pool
            .recalculate_readiness_with_local_info(addr, nonce, balance);
        // If addr is not in `deferred_pool`, it should have also been removed
        // from garbage_collector
        if let Some(tx) = self.deferred_pool.get_lowest_nonce_tx(addr) {
            let count = self.deferred_pool.count_less(addr, &nonce);
            let timestamp = self
                .garbage_collector
                .in_space(space)
                .get_timestamp(addr)
                .unwrap_or(self.get_current_timestamp());
            self.garbage_collector.in_space_mut(space).insert(
                addr,
                count,
                timestamp,
                ret.is_some(),
                *tx.gas_price(),
            );
        } else {
            // An account is only removed from `deferred_pool` in GC,
            // so this is not likely to happen.
            // One possible reason is that an transactions not in txpool is
            // executed and passed to notify_modified_accounts.
            debug!(
                "recalculate_readiness called for missing account: addr={:?}",
                addr
            );
        }
    }

    pub fn check_tx_packed_in_deferred_pool(&self, tx_hash: &H256) -> bool {
        match self.txs.get(tx_hash) {
            Some(tx) => {
                self.deferred_pool.check_tx_packed(tx.sender(), *tx.nonce())
            }
            None => false,
        }
    }

    /// pack at most num_txs transactions randomly
    pub fn pack_transactions<'a>(
        &mut self, num_txs: usize, block_gas_limit: U256, evm_gas_limit: U256,
        block_size_limit: usize, best_epoch_height: u64,
        best_block_number: u64, verification_config: &VerificationConfig,
        machine: &Machine,
    ) -> Vec<Arc<SignedTransaction>> {
        let mut packed_transactions: Vec<Arc<SignedTransaction>> = Vec::new();
        if num_txs == 0 {
            return packed_transactions;
        }

        let spec = machine.spec(best_block_number, best_epoch_height);
        let transitions = &machine.params().transition_heights;

        let validity = |tx: &SignedTransaction| {
            verification_config.fast_recheck(
                tx,
                best_epoch_height,
                transitions,
                &spec,
            )
        };

        let (sampled_tx, used_gas, used_size) =
            self.deferred_pool.packing_sampler(
                Space::Ethereum,
                std::cmp::min(block_gas_limit, evm_gas_limit),
                block_size_limit,
                num_txs,
                U256::zero(),
                validity,
            );
        packed_transactions.extend_from_slice(&sampled_tx);

        let (sampled_tx, _, _) = self.deferred_pool.packing_sampler(
            Space::Native,
            block_gas_limit - used_gas,
            block_size_limit - used_size,
            num_txs - sampled_tx.len(),
            U256::zero(),
            validity,
        );
        packed_transactions.extend_from_slice(&sampled_tx);

        if log::max_level() >= log::Level::Debug {
            let mut rlp_s = RlpStream::new();
            for tx in &packed_transactions {
                rlp_s.append::<TransactionWithSignature>(&**tx);
            }
            debug!(
                "After packing packed_transactions: {}, rlp size: {}",
                packed_transactions.len(),
                rlp_s.out().len(),
            );
        }

        packed_transactions
    }

    pub fn pack_transactions_1559<'a>(
        &mut self, num_txs: usize, block_gas_limit: U256,
        parent_base_price: SpaceMap<U256>, block_size_limit: usize,
        best_epoch_height: u64, machine: &Machine,
        validity: impl Fn(&SignedTransaction) -> PackingCheckResult,
    ) -> (Vec<Arc<SignedTransaction>>, SpaceMap<U256>) {
        let mut packed_transactions: Vec<Arc<SignedTransaction>> = Vec::new();
        if num_txs == 0 {
            return (packed_transactions, parent_base_price);
        }

        debug!(
            "Packing transaction for 1559, parent base price {:?}",
            parent_base_price
        );

        let mut block_base_price = parent_base_price.clone();

        let can_pack_evm =
            machine.params().can_pack_evm_transaction(best_epoch_height);

        let (evm_packed_tx_num, evm_used_size) = if can_pack_evm {
            let gas_target = block_gas_limit * 5 / 10 / ELASTICITY_MULTIPLIER;
            let parent_base_price = parent_base_price[Space::Ethereum];
            let min_base_price =
                machine.params().min_base_price()[Space::Ethereum];

            let (packing_gas_limit, tx_min_price) =
                self.deferred_pool.estimate_packing_gas_limit(
                    Space::Ethereum,
                    gas_target,
                    parent_base_price,
                    min_base_price,
                );
            debug!(
                "Packing plan (espace): gas limit: {:?}, tx min price: {:?}",
                packing_gas_limit, tx_min_price
            );
            let (sampled_tx, used_gas, used_size) =
                self.deferred_pool.packing_sampler(
                    Space::Ethereum,
                    packing_gas_limit,
                    block_size_limit,
                    num_txs,
                    tx_min_price,
                    &validity,
                );

            // Recompute the base price, it should be <= estimated base price,
            // since the actual used gas is <= estimated limit
            let base_price = compute_next_price(
                gas_target,
                used_gas,
                parent_base_price,
                min_base_price,
            );

            if base_price <= tx_min_price {
                debug!(
                    "Packing result (espace): gas used: {:?}, base price: {:?}",
                    used_gas, base_price
                );
                block_base_price[Space::Ethereum] = base_price;
                packed_transactions.extend_from_slice(&sampled_tx);

                (sampled_tx.len(), used_size)
            } else {
                // Should be unreachable
                warn!(
                    "Inconsistent packing result (espace): gas used: {:?}, base price: {:?}", 
                    used_gas, base_price
                );
                block_base_price[Space::Ethereum] = compute_next_price(
                    gas_target,
                    U256::zero(),
                    parent_base_price,
                    min_base_price,
                );
                (0, 0)
            }
        } else {
            (0, 0)
        };

        {
            let gas_target =
                cspace_block_gas_limit_after_cip1559(block_gas_limit)
                    / ELASTICITY_MULTIPLIER;
            let parent_base_price = parent_base_price[Space::Native];
            let min_base_price =
                machine.params().min_base_price()[Space::Native];

            let (packing_gas_limit, tx_min_price) =
                self.deferred_pool.estimate_packing_gas_limit(
                    Space::Native,
                    gas_target,
                    parent_base_price,
                    min_base_price,
                );

            debug!(
                "Packing plan (core space): gas limit: {:?}, tx min price: {:?}",
                packing_gas_limit, tx_min_price
            );

            let (sampled_tx, used_gas, _) = self.deferred_pool.packing_sampler(
                Space::Native,
                packing_gas_limit,
                block_size_limit - evm_used_size,
                num_txs - evm_packed_tx_num,
                tx_min_price,
                &validity,
            );

            // Recompute the base price, it should be <= estimated base price,
            // since the actual used gas is <= estimated limit
            let base_price = compute_next_price(
                gas_target,
                used_gas,
                parent_base_price,
                min_base_price,
            );

            if base_price <= tx_min_price {
                debug!(
                    "Packing result (core space): gas used: {:?}, base price: {:?}",
                    used_gas, base_price
                );
                block_base_price[Space::Native] = base_price;
                packed_transactions.extend_from_slice(&sampled_tx);
            } else {
                // Should be unreachable
                warn!(
                    "Inconsistent packing result (core space): gas used: {:?}, base price: {:?}", 
                    used_gas, base_price
                );
                block_base_price[Space::Native] = compute_next_price(
                    gas_target,
                    U256::zero(),
                    parent_base_price,
                    min_base_price,
                );
            }
        }

        if log::max_level() >= log::Level::Debug {
            let mut rlp_s = RlpStream::new();
            for tx in &packed_transactions {
                rlp_s.append::<TransactionWithSignature>(&**tx);
            }
            debug!(
                "After packing packed_transactions: {}, rlp size: {}",
                packed_transactions.len(),
                rlp_s.out().len(),
            );
        }

        (packed_transactions, block_base_price)
    }

    pub fn notify_modified_accounts(
        &mut self, accounts_from_execution: Vec<Account>,
    ) {
        for account in &accounts_from_execution {
            self.recalculate_readiness_with_fixed_info(
                account.address(),
                account.nonce,
                account.balance,
            );
        }
    }

    /// content retrieves the ready and deferred transactions.
    pub fn content(
        &self, address: Option<AddressWithSpace>,
    ) -> (Vec<Arc<SignedTransaction>>, Vec<Arc<SignedTransaction>>) {
        let ready_txs = match address {
            Some(addr) => self
                .deferred_pool
                .ready_transactions_by_address(addr)
                .map_or(vec![], |x| x.to_vec()),
            None => self
                .deferred_pool
                .all_ready_transactions()
                .cloned()
                .collect(),
        };

        let deferred_txs = self
            .txs
            .values()
            .filter(|tx| address == None || tx.sender() == address.unwrap())
            .map(|v| v.clone())
            .collect();

        (ready_txs, deferred_txs)
    }

    // Add transaction into deferred pool and maintain its readiness
    // the packed tag provided
    // if force tag is true, the replacement in nonce pool must be happened
    pub fn insert_transaction_with_readiness_check(
        &mut self, account_cache: &AccountCache,
        transaction: Arc<SignedTransaction>, packed: bool, force: bool,
    ) -> Result<(), TransactionPoolError> {
        let _timer = MeterTimer::time_func(TX_POOL_INNER_INSERT_TIMER.as_ref());
        let (sponsored_gas, sponsored_storage) =
            self.get_sponsored_gas_and_storage(account_cache, &transaction)?;

        let (state_nonce, state_balance) =
            account_cache.get_nonce_and_balance(&transaction.sender())?;

        if transaction.hash[0] & 254 == 0 {
            trace!(
                "Transaction {:?} sender: {:?} current nonce: {:?}, state nonce:{:?}",
                transaction.hash, transaction.sender, transaction.nonce(), state_nonce
            );
        }
        if *transaction.nonce()
            >= state_nonce
                + U256::from(FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET)
        {
            trace!(
                "Transaction {:?} is discarded due to in too distant future",
                transaction.hash()
            );
            return Err(TransactionPoolError::NonceTooDistant {
                hash: transaction.hash(),
                nonce: *transaction.nonce(),
            });
        } else if !packed /* Because we may get slightly out-dated state for transaction pool, we should allow transaction pool to set already past-nonce transactions to packed. */
            && *transaction.nonce() < state_nonce
        {
            trace!(
                "Transaction {:?} is discarded due to a too stale nonce, self.nonce()={}, state_nonce={}",
                transaction.hash(), transaction.nonce(), state_nonce,
            );
            return Err(TransactionPoolError::NonceTooStale {
                hash: transaction.hash(),
                nonce: *transaction.nonce(),
            });
        }

        // check balance
        if !packed && !force {
            let mut need_balance = U256::from(0);
            let estimate_gas_fee = Self::estimated_gas_fee(
                transaction.gas().clone(),
                transaction.gas_price().clone(),
            );
            match transaction.unsigned {
                Transaction::Native(ref utx) => {
                    need_balance += utx.value().clone();
                    if sponsored_gas == U256::from(0) {
                        need_balance += estimate_gas_fee;
                    }
                    if sponsored_storage == 0 {
                        need_balance += U256::from(*utx.storage_limit())
                            * *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
                    }
                }
                Transaction::Ethereum(ref utx) => {
                    need_balance += utx.value().clone();
                    need_balance += estimate_gas_fee;
                }
            }

            if need_balance > state_balance {
                let msg = format!(
                    "Transaction {:?} is discarded due to out of balance, needs {:?} but account balance is {:?}",
                    transaction.hash(),
                    need_balance,
                    state_balance
                );
                trace!("{}", msg);
                return Err(TransactionPoolError::OutOfBalance {
                    need: need_balance,
                    have: state_balance,
                    hash: transaction.hash(),
                });
            }
        }

        let result = self.insert_transaction_without_readiness_check(
            transaction.clone(),
            packed,
            force,
            (state_nonce, state_balance),
            (sponsored_gas, sponsored_storage),
        );
        if let InsertResult::Failed(err) = result {
            return Err(err);
        }

        self.recalculate_readiness_with_state(
            &transaction.sender(),
            account_cache,
        )?;

        Ok(())
    }

    fn estimated_gas_fee(gas: U256, gas_price: U256) -> U256 {
        let estimated_gas_u512 = gas.full_mul(gas_price);
        // Normally, it is less than 2^128
        let estimated_gas =
            if estimated_gas_u512 > U512::from(U128::max_value()) {
                U256::from(U128::max_value())
            } else {
                gas * gas_price
            };
        estimated_gas
    }

    pub fn get_sponsored_gas_and_storage(
        &self, account_cache: &AccountCache, transaction: &SignedTransaction,
    ) -> StateDbResult<(U256, u64)> {
        let sender = transaction.sender();

        // Filter out espace transactions
        let utx = if let Transaction::Native(ref utx) = transaction.unsigned {
            utx
        } else {
            return Ok(Default::default());
        };

        // Keep contract call only
        let contract_address = match utx.action() {
            Action::Call(callee) if callee.is_contract_address() => *callee,
            _ => {
                return Ok(Default::default());
            }
        };

        // Get sponsor info
        let sponsor_info = if let Some(sponsor_info) =
            account_cache.get_sponsor_info(&contract_address)?
        {
            sponsor_info
        } else {
            return Ok(Default::default());
        };

        // Check if sender is eligible for sponsor
        if !account_cache
            .check_commission_privilege(&contract_address, &sender.address)?
        {
            return Ok(Default::default());
        }

        // Detailed logics
        let estimated_gas = Self::estimated_gas_fee(
            transaction.gas().clone(),
            transaction.gas_price().clone(),
        );
        let sponsored_gas = if estimated_gas <= sponsor_info.sponsor_gas_bound
            && estimated_gas <= sponsor_info.sponsor_balance_for_gas
        {
            utx.gas().clone()
        } else {
            0.into()
        };

        let estimated_collateral = U256::from(*utx.storage_limit())
            * *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
        let sponsored_collateral = if estimated_collateral
            <= sponsor_info.sponsor_balance_for_collateral
                + sponsor_info.unused_storage_points()
        {
            *utx.storage_limit()
        } else {
            0
        };

        Ok((sponsored_gas, sponsored_collateral))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        transaction_pool::TransactionPoolError,
        verification::PackingCheckResult,
    };

    use super::{
        DeferredPool, InsertResult, TransactionPoolInner, TxWithReadyInfo,
    };
    use cfx_executor::{
        machine::{Machine, VmFactory},
        spec::CommonParams,
    };
    use cfx_parameters::block::{
        cspace_block_gas_limit_after_cip1559, espace_block_gas_limit,
    };
    use cfx_types::{Address, AddressSpaceUtil, Space, SpaceMap, U256};
    use itertools::Itertools;
    use keylib::{Generator, KeyPair, Random};
    use primitives::{
        block_header::compute_next_price_tuple,
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

    fn new_test_tx_with_read_info(
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

        let alice_tx1 = new_test_tx_with_read_info(
            &alice, 5, 10, 100, false, /* packed */
        );
        let alice_tx2 = new_test_tx_with_read_info(
            &alice, 6, 10, 100, false, /* packed */
        );
        let bob_tx1 = new_test_tx_with_read_info(
            &bob, 1, 10, 100, false, /* packed */
        );
        let bob_tx2 = new_test_tx_with_read_info(
            &bob, 2, 10, 100, false, /* packed */
        );
        let bob_tx2_new = new_test_tx_with_read_info(
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
        let tx1 = new_test_tx_with_read_info(
            &alice, 5, 10, 10000, true, /* packed */
        );
        let tx2 = new_test_tx_with_read_info(
            &alice, 6, 10, 10000, true, /* packed */
        );
        let tx3 = new_test_tx_with_read_info(
            &alice, 7, 10, 10000, true, /* packed */
        );
        let tx4 = new_test_tx_with_read_info(
            &alice, 8, 10, 10000, false, /* packed */
        );
        let tx5 = new_test_tx_with_read_info(
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

    fn pack_transactions_1559_checked(
        pool: &mut TransactionPoolInner, machine: &Machine,
    ) {
        let parent_base_price = SpaceMap::new(100, 200).map_all(U256::from);
        let block_gas_limit = U256::from(6000);
        let best_epoch_height = 20;

        let (txs, base_price) = pool.pack_transactions_1559(
            usize::MAX,
            block_gas_limit,
            parent_base_price,
            usize::MAX,
            best_epoch_height,
            machine,
            |_| PackingCheckResult::Pack,
        );

        let params = machine.params();

        let core_gas_limit =
            cspace_block_gas_limit_after_cip1559(block_gas_limit);
        let eth_gas_limit = espace_block_gas_limit(
            params.can_pack_evm_transaction(best_epoch_height),
            block_gas_limit,
        );

        let gas_target =
            SpaceMap::new(core_gas_limit, eth_gas_limit).map_all(|x| x / 2);

        let mut gas_used = SpaceMap::default();
        let mut min_gas_price =
            SpaceMap::new(U256::max_value(), U256::max_value());

        for tx in txs {
            gas_used[tx.space()] += *tx.gas_limit();
            min_gas_price[tx.space()] =
                min_gas_price[tx.space()].min(*tx.gas_price());
        }

        let min_base_price = params.min_base_price();

        let expected_base_price = SpaceMap::zip4(
            gas_target,
            gas_used,
            parent_base_price,
            min_base_price,
        )
        .map_all(compute_next_price_tuple);

        assert_eq!(expected_base_price, base_price);
        assert!(gas_used[Space::Native] <= core_gas_limit);
        assert!(gas_used[Space::Ethereum] <= eth_gas_limit);

        for space in [Space::Native, Space::Ethereum] {
            assert!(base_price[space] <= min_gas_price[space]);
        }
    }

    #[test]
    fn test_pack_eip1559_transactions() {
        let mut pool = TransactionPoolInner::new_for_test();

        let mut params = CommonParams::default();
        params.min_base_price = SpaceMap::new(100, 200).map_all(U256::from);

        let machine = Arc::new(Machine::new(params, VmFactory::default()));

        let test_block_limit = SpaceMap::new(5400, 3000);

        let senders: Vec<_> = (0..20)
            .into_iter()
            .map(|_| Random.generate().unwrap())
            .collect();

        let tasks = [1, 2, 3]
            .into_iter()
            .cartesian_product(
                /* gas_price */ [50usize, 95, 100, 105, 150, 1000],
            )
            .cartesian_product(
                /* gas_limit_percent */ [5usize, 10, 40, 60, 100],
            )
            .cartesian_product(/* price_increasing */ [0usize, 1]);

        for (((space_bits, gas_price), gas_limit_percent), price_inc) in tasks {
            let tx_gas_limit =
                test_block_limit.map_all(|x| x * gas_limit_percent / 100);

            for (idx, sender) in senders.iter().enumerate() {
                let gas_price = gas_price + idx * price_inc;

                if space_bits & 0x1 != 0 {
                    let tx = new_test_tx(
                        sender,
                        0,
                        gas_price,
                        tx_gas_limit[Space::Native],
                        0,
                        Space::Native,
                    );
                    pool.insert_transaction_for_test(tx, U256::zero());
                }

                if space_bits & 0x2 != 0 {
                    let tx = new_test_tx(
                        sender,
                        0,
                        gas_price * 2,
                        tx_gas_limit[Space::Ethereum],
                        0,
                        Space::Ethereum,
                    );
                    pool.insert_transaction_for_test(tx, U256::zero());
                }
            }
            pack_transactions_1559_checked(&mut pool, &machine);
            pool.clear();
        }
    }
}
