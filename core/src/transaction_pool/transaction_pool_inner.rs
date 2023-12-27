use super::{
    account_cache::AccountCache,
    garbage_collector::GarbageCollector,
    impls::TreapMap,
    nonce_pool::{InsertResult, NoncePool, TxWithReadyInfo},
};
use crate::verification::{PackingCheckResult, VerificationConfig};
use cfx_executor::machine::Machine;
use cfx_parameters::staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT;
use cfx_statedb::Result as StateDbResult;
use cfx_types::{
    address_util::AddressUtil, Address, AddressWithSpace, Space, SpaceMap,
    H256, U128, U256, U512,
};
use heap_map::HeapMap;
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use metrics::{
    register_meter_with_group, Counter, CounterUsize, Meter, MeterTimer,
};
use primitives::{
    Account, Action, SignedTransaction, Transaction, TransactionWithSignature,
};
use rlp::*;
use serde::Serialize;
use std::{
    cmp::{Ordering, Reverse},
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

type WeightType = u128;
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

#[derive(DeriveMallocSizeOf)]
struct DeferredPool {
    buckets: HashMap<AddressWithSpace, NoncePool>,
}

impl DeferredPool {
    fn new() -> Self {
        DeferredPool {
            buckets: Default::default(),
        }
    }

    fn clear(&mut self) { self.buckets.clear() }

    fn insert(&mut self, tx: TxWithReadyInfo, force: bool) -> InsertResult {
        // It's safe to create a new bucket, cause inserting to a empty bucket
        // will always be success
        let bucket =
            self.buckets.entry(tx.sender()).or_insert(NoncePool::new());
        bucket.insert(&tx, force)
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
        match self.buckets.get_mut(addr) {
            None => None,
            Some(bucket) => {
                let ret = bucket.remove_lowest_nonce();
                if bucket.is_empty() {
                    self.buckets.remove(addr);
                }
                ret
            }
        }
    }

    fn get_lowest_nonce(&self, addr: &AddressWithSpace) -> Option<&U256> {
        self.buckets
            .get(addr)
            .and_then(|bucket| bucket.get_lowest_nonce_tx().map(|r| r.nonce()))
    }

    fn get_lowest_nonce_tx(
        &self, addr: &AddressWithSpace,
    ) -> Option<&SignedTransaction> {
        self.buckets
            .get(addr)
            .and_then(|bucket| bucket.get_lowest_nonce_tx())
    }

    fn recalculate_readiness_with_local_info(
        &mut self, addr: &AddressWithSpace, nonce: U256, balance: U256,
    ) -> Option<Arc<SignedTransaction>> {
        if let Some(bucket) = self.buckets.get(addr) {
            bucket.recalculate_readiness_with_local_info(nonce, balance)
        } else {
            None
        }
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

    fn get_pending_transactions(
        &self, addr: &AddressWithSpace, start_nonce: &U256, local_nonce: &U256,
        local_balance: &U256,
    ) -> (Vec<Arc<SignedTransaction>>, Option<PendingReason>)
    {
        match self.buckets.get(addr) {
            Some(bucket) => {
                let pending_txs = bucket.get_pending_transactions(start_nonce);
                let pending_reason = pending_txs.first().and_then(|tx| {
                    bucket.check_pending_reason_with_local_info(
                        *local_nonce,
                        *local_balance,
                        tx.as_ref(),
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
}

#[derive(DeriveMallocSizeOf, Clone)]
struct PriceOrderedTransaction(Arc<SignedTransaction>);

impl PartialEq for PriceOrderedTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.0.gas_price().eq(other.0.gas_price())
    }
}

impl Eq for PriceOrderedTransaction {}

impl PartialOrd for PriceOrderedTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriceOrderedTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.gas_price().cmp(other.0.gas_price())
    }
}

/// `ReadyAccountPool` maintains all ready transactions, and a subset with high
/// gas prices will be sampled for packing. Each account has at most one ready
/// transaction, and a ready account/transaction is either in `packing_pool` or
/// `waiting_pool`. All transactions in `packing_pool` have no less gas price
/// than the ones in `waiting_pool`. When `packing_pool` has an available
/// capacity, we will try to move the highest gas price transactions from
/// `waiting_pool` to `packing_pool`.
#[derive(DeriveMallocSizeOf)]
struct SpacedReadyAccountPool {
    /// Keeps all high gas price transactions that can be sampled for packing.
    packing_pool: PackingPool,
    /// Keeps all low gas price transactions.
    waiting_pool: HeapMap<Address, PriceOrderedTransaction>,
}

impl SpacedReadyAccountPool {
    fn new(
        tx_weight_scaling: u64, tx_weight_exp: u8, total_gas_capacity: U256,
    ) -> Self {
        Self {
            packing_pool: PackingPool::new(
                tx_weight_scaling,
                tx_weight_exp,
                total_gas_capacity,
            ),
            waiting_pool: HeapMap::new(),
        }
    }

    fn update(
        &mut self, address: &Address, tx: Option<Arc<SignedTransaction>>,
    ) {
        if let Some(tx) = tx {
            if tx.hash[0] & 254 == 0 {
                debug!("Sampled transaction {:?} in ready pool", tx.hash);
            }
            self.insert(tx);
        } else {
            self.remove(address)
        };
    }

    fn insert(&mut self, tx: Arc<SignedTransaction>) {
        // We always replace the old tx from the same sender, so we remove it
        // from `waiting_pool` first to avoid having transactions from
        // the same sender to exist in both `packing_pool` and `waiting_pool`.
        self.waiting_pool.remove(&tx.sender().address);
        self.packing_pool.insert(tx);
        self.try_shrink_packing_pool();
    }

    fn remove(&mut self, address: &Address) {
        self.packing_pool.remove(address);
        self.waiting_pool.remove(address);
        self.try_fill_packing_pool();
    }

    fn sample_pop(&mut self) -> Option<Arc<SignedTransaction>> {
        let popped_tx = self.packing_pool.sample_pop();
        self.try_fill_packing_pool();
        popped_tx
    }

    fn sample_peek(&self) -> Option<Arc<SignedTransaction>> {
        self.packing_pool.sample_peek()
    }

    fn try_shrink_packing_pool(&mut self) {
        while self.packing_pool.total_gas > self.packing_pool.total_gas_capacity
        {
            let tx = self.packing_pool.pop().unwrap();
            self.waiting_pool
                .insert(&tx.sender().address, PriceOrderedTransaction(tx));
        }
    }

    fn try_fill_packing_pool(&mut self) {
        while self.packing_pool.total_gas < self.packing_pool.total_gas_capacity
        {
            let top_waiting_gas = match self.waiting_pool.top() {
                None => break,
                Some((_, tx)) => *tx.0.gas(),
            };
            if top_waiting_gas + self.packing_pool.total_gas
                > self.packing_pool.total_gas_capacity
            {
                break;
            }

            let tx = (self.waiting_pool.pop().unwrap().1).0;
            self.packing_pool.insert(tx);
        }
    }

    fn clear(&mut self) {
        self.packing_pool.clear();
        self.waiting_pool.clear();
    }

    fn get(&self, address: &Address) -> Option<Arc<SignedTransaction>> {
        self.waiting_pool
            .get(address)
            .map(|tx| tx.0.clone())
            .or_else(|| self.packing_pool.get(address))
    }

    fn len(&self) -> usize { self.packing_pool.len() + self.waiting_pool.len() }

    fn get_all_transaction_hashes(&self) -> BTreeSet<H256> {
        self.waiting_pool
            .iter()
            .map(|f| f.0.hash())
            .collect::<BTreeSet<_>>()
            .union(&self.packing_pool.get_all_transaction_hashes())
            .cloned()
            .collect()
    }

    #[cfg(test)]
    fn top(&self) -> Option<Arc<SignedTransaction>> { self.packing_pool.top() }
}

#[derive(DeriveMallocSizeOf)]
struct PackingPool {
    /// A balance tree used to randomly sample transactions with `gas_price` as
    /// a sampling weight.
    treap: TreapMap<Address, Arc<SignedTransaction>, WeightType>,
    /// A priority queue to order transactions based on their gas_price.
    heap_map: HeapMap<Address, Reverse<PriceOrderedTransaction>>,
    tx_weight_scaling: u64,
    tx_weight_exp: u8,

    /// U256 should be sufficient since txpool the limits `max_tx_gas`.
    /// This limits the number of transactions in the packing pool with their
    /// gas limits.
    total_gas_capacity: U256,
    /// The total gas limit of all transactions in this packing pool.
    total_gas: U256,
}

impl PackingPool {
    fn new(
        tx_weight_scaling: u64, tx_weight_exp: u8, total_gas_capacity: U256,
    ) -> Self {
        PackingPool {
            treap: TreapMap::new(),
            heap_map: HeapMap::new(),
            tx_weight_scaling,
            tx_weight_exp,
            total_gas_capacity,
            total_gas: 0.into(),
        }
    }

    fn clear(&mut self) {
        while self.len() != 0 {
            self.sample_pop();
        }
        self.heap_map.clear()
    }

    fn len(&self) -> usize { self.treap.len() }

    fn get_all_transaction_hashes(&self) -> BTreeSet<H256> {
        self.treap.iter().map(|v| v.1.hash()).collect()
    }

    fn get(&self, address: &Address) -> Option<Arc<SignedTransaction>> {
        self.heap_map.get(address).map(|tx| (tx.0).0.clone())
    }

    fn remove(&mut self, address: &Address) -> Option<Arc<SignedTransaction>> {
        let tx = (self.heap_map.remove(address)?.0).0;
        self.treap.remove(address);
        self.total_gas -= *tx.gas();
        Some(tx)
    }

    /// If the insertion replaces an old transaction of the same
    /// sender, it will be returned.
    fn insert(
        &mut self, tx: Arc<SignedTransaction>,
    ) -> Option<Arc<SignedTransaction>> {
        let scaled_weight = tx.gas_price() / self.tx_weight_scaling;
        let base_weight = if scaled_weight == U256::zero() {
            0
        } else if scaled_weight >= *MAX_WEIGHT {
            u128::max_value()
        } else {
            scaled_weight.as_u128()
        };

        let mut weight = 1;
        for _ in 0..self.tx_weight_exp {
            weight *= base_weight;
        }

        self.heap_map.insert(
            &tx.sender().address,
            Reverse(PriceOrderedTransaction(tx.clone())),
        );
        self.total_gas += *tx.gas();
        let replaced_tx = self.treap.insert(tx.sender().address, tx, weight);
        if let Some(replaced_tx) = replaced_tx.as_ref() {
            // an old transaction of the same sender is replaced.
            self.total_gas -= *replaced_tx.gas();
        };
        replaced_tx
    }

    fn sample_pop(&mut self) -> Option<Arc<SignedTransaction>> {
        if self.treap.len() == 0 {
            return None;
        }

        let sum_gas_price = self.treap.sum_weight();
        let mut rand_value = rand::random();
        rand_value = rand_value % sum_gas_price;

        let tx = self
            .treap
            .get_by_weight(rand_value)
            .expect("Failed to pick transaction by weight")
            .clone();
        trace!("Get transaction from ready pool. tx: {:?}", tx.clone());

        self.remove(&tx.sender().address)
    }

    fn sample_peek(&self) -> Option<Arc<SignedTransaction>> {
        if self.treap.len() == 0 {
            return None;
        }

        let sum_gas_price = self.treap.sum_weight();
        let mut rand_value = rand::random();
        rand_value = rand_value % sum_gas_price;

        Some(
            self.treap
                .get_by_weight(rand_value)
                .expect("Failed to pick transaction by weight")
                .clone(),
        )
    }

    fn pop(&mut self) -> Option<Arc<SignedTransaction>> {
        self.heap_map.pop().map(|(addr, tx)| {
            let tx = (tx.0).0;
            self.treap.remove(&addr);
            self.total_gas -= *tx.gas();
            tx
        })
    }

    #[cfg(test)]
    fn top(&self) -> Option<Arc<SignedTransaction>> {
        self.heap_map.top().map(|(_, tx)| (tx.0).0.clone())
    }
}

#[derive(DeriveMallocSizeOf)]
struct ReadyAccountPool {
    native_pool: SpacedReadyAccountPool,
    evm_pool: SpacedReadyAccountPool,
}

impl ReadyAccountPool {
    fn new(
        tx_weight_scaling: u64, tx_weight_exp: u8, total_gas_capacity: U256,
    ) -> Self {
        Self {
            native_pool: SpacedReadyAccountPool::new(
                tx_weight_scaling,
                tx_weight_exp,
                total_gas_capacity,
            ),
            evm_pool: SpacedReadyAccountPool::new(
                tx_weight_scaling,
                tx_weight_exp,
                total_gas_capacity,
            ),
        }
    }

    fn len(&self) -> usize { self.native_pool.len() + self.evm_pool.len() }

    fn get_transaction_hashes_in_evm_pool(&self) -> BTreeSet<H256> {
        self.evm_pool.get_all_transaction_hashes()
    }

    fn get_transaction_hashes_in_native_pool(&self) -> BTreeSet<H256> {
        self.native_pool.get_all_transaction_hashes()
    }

    fn get(
        &self, address: &AddressWithSpace,
    ) -> Option<Arc<SignedTransaction>> {
        match address.space {
            Space::Native => {
                self.native_pool.get(&address.address).map(|tx| tx.clone())
            }
            Space::Ethereum => {
                self.evm_pool.get(&address.address).map(|tx| tx.clone())
            }
        }
    }

    fn update(
        &mut self, address: &AddressWithSpace,
        tx: Option<Arc<SignedTransaction>>,
    )
    {
        match address.space {
            Space::Native => self.native_pool.update(&address.address, tx),
            Space::Ethereum => self.evm_pool.update(&address.address, tx),
        }
    }

    fn remove(&mut self, address: &AddressWithSpace) {
        match address.space {
            Space::Native => self.native_pool.remove(&address.address),
            Space::Ethereum => self.evm_pool.remove(&address.address),
        }
    }

    fn insert(&mut self, tx: Arc<SignedTransaction>) {
        match tx.sender().space {
            Space::Native => self.native_pool.insert(tx.clone()),
            Space::Ethereum => self.evm_pool.insert(tx.clone()),
        }
    }

    fn peek_native(&self) -> Option<Arc<SignedTransaction>> {
        self.native_pool.sample_peek()
    }

    fn peek_evm(&self) -> Option<Arc<SignedTransaction>> {
        self.evm_pool.sample_peek()
    }

    fn pop_native(&mut self) -> Option<Arc<SignedTransaction>> {
        self.native_pool.sample_pop()
    }

    #[allow(unused)]
    fn pop_evm(&mut self) -> Option<Arc<SignedTransaction>> {
        self.evm_pool.sample_pop()
    }

    fn pop(&mut self) -> Option<Arc<SignedTransaction>> {
        let tx_native_opt = self.peek_native();
        let tx_evm_opt = self.peek_evm();
        match (tx_native_opt, tx_evm_opt) {
            (None, None) => None,
            (None, Some(tx)) => {
                trace!(
                    "Get transaction from evm ready pool. tx: {:?}",
                    tx.clone()
                );
                self.remove(&tx.sender());
                self.evm_pool.try_fill_packing_pool();
                Some(tx)
            }
            (Some(tx), None) => {
                trace!(
                    "Get transaction from native ready pool. tx: {:?}",
                    tx.clone()
                );
                self.remove(&tx.sender());
                self.native_pool.try_fill_packing_pool();
                Some(tx)
            }
            (Some(tx_native), Some(tx_evm)) => {
                if tx_native.gas_price() > tx_evm.gas_price() {
                    trace!(
                        "Get transaction from native ready pool. tx: {:?}",
                        tx_native.clone()
                    );
                    self.remove(&tx_native.sender());
                    self.native_pool.try_fill_packing_pool();
                    Some(tx_native)
                } else {
                    trace!(
                        "Get transaction from evm ready pool. tx: {:?}",
                        tx_evm.clone()
                    );
                    self.remove(&tx_evm.sender());
                    self.evm_pool.try_fill_packing_pool();
                    Some(tx_evm)
                }
            }
        }
    }

    fn clear(&mut self) {
        self.native_pool.clear();
        self.evm_pool.clear();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TransactionStatus {
    Packed,
    Ready,
    Pending(PendingReason),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PendingReason {
    FutureNonce,
    NotEnoughCash,
    OldEpochHeight,
    // The tx status in the pool is inaccurate due to chain switch or sponsor
    // balance change. This tx will not be packed even if it should have
    // been ready, and the user needs to send a new transaction to trigger
    // the status change.
    OutdatedStatus,
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
    /// Tracks the first unpacked ready transaction for accounts.
    /// Updated together with `ready_nonces_and_balances`.
    /// Also updated after transaction packing.
    ready_account_pool: ReadyAccountPool,
    /// The cache of the latest nonce and balance in the state.
    /// Updated with the storage data after a block is processed in consensus
    /// (set_tx_packed), after epoch execution, or during transaction
    /// insertion.
    ready_nonces_and_balances: HashMap<AddressWithSpace, (U256, U256)>,
    garbage_collector: SpaceMap<GarbageCollector>,
    /// Keeps all transactions in the transaction pool.
    /// It should contain the same transaction set as `deferred_pool`.
    txs: TransactionSet,
    tx_sponsored_gas_map: HashMap<H256, (U256, u64)>,
}

impl TransactionPoolInner {
    pub fn new(
        capacity: usize, tx_weight_scaling: u64, tx_weight_exp: u8,
        total_gas_capacity: U256,
    ) -> Self
    {
        TransactionPoolInner {
            capacity,
            total_received_count: 0,
            unpacked_transaction_count: 0,
            deferred_pool: DeferredPool::new(),
            ready_account_pool: ReadyAccountPool::new(
                tx_weight_scaling,
                tx_weight_exp,
                total_gas_capacity,
            ),
            ready_nonces_and_balances: HashMap::new(),
            garbage_collector: SpaceMap::default(),
            txs: TransactionSet::default(),
            tx_sponsored_gas_map: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.deferred_pool.clear();
        self.ready_account_pool.clear();
        self.ready_nonces_and_balances.clear();
        self.garbage_collector.apply_all(|x| x.clear());
        self.txs.clear();
        self.tx_sponsored_gas_map.clear();
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
        self.ready_account_pool.get_transaction_hashes_in_evm_pool()
    }

    pub fn ready_transacton_hashes_in_native_pool(&self) -> BTreeSet<H256> {
        self.ready_account_pool
            .get_transaction_hashes_in_native_pool()
    }

    pub fn total_ready_accounts(&self) -> usize {
        self.ready_account_pool.len()
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

            // maintain ready account pool
            if let Some(ready_tx) = self.ready_account_pool.get(&victim_address)
            {
                if ready_tx.hash() == to_remove_tx.hash() {
                    warn!("a ready tx is garbage-collected");
                    GC_READY_COUNTER.inc(1);
                    self.ready_account_pool.remove(&victim_address);
                    if !victim.has_ready_tx {
                        // This should not happen! Means some inconsistency
                        // within `TransactionPoolInner`.
                        error!("Garbage collector marks no ready tx!!! tx_hash={:?}, victim={:?}", ready_tx.hash(), victim);
                    }
                }
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
                    self.ready_account_pool.get(&victim_address).is_some();
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
            self.tx_sponsored_gas_map.remove(&to_remove_tx.hash());
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

    // the new inserting will fail if tx_pool is full (even if `force` is true)
    fn insert_transaction_without_readiness_check(
        &mut self, transaction: Arc<SignedTransaction>, packed: bool,
        force: bool, state_nonce_and_balance: Option<(U256, U256)>,
        (sponsored_gas, sponsored_storage): (U256, u64),
    ) -> InsertResult
    {
        let _timer = MeterTimer::time_func(
            TX_POOL_INNER_WITHOUTCHECK_INSERT_TIMER.as_ref(),
        );
        if !self.deferred_pool.check_sender_and_nonce_exists(
            &transaction.sender(),
            &transaction.nonce(),
        ) {
            self.collect_garbage(transaction.as_ref());
            if self.is_full(transaction.space()) {
                return InsertResult::Failed("Transaction Pool is full".into());
            }
        }
        let result = {
            let _timer =
                MeterTimer::time_func(DEFERRED_POOL_INNER_INSERT.as_ref());
            self.deferred_pool.insert(
                TxWithReadyInfo {
                    transaction: transaction.clone(),
                    packed,
                    sponsored_gas,
                    sponsored_storage,
                },
                force,
            )
        };

        match &result {
            InsertResult::NewAdded => {
                // This will only happen when called by
                // `insert_transaction_with_readiness_check`, so
                // state_nonce_and_balance will never be `None`.
                let (state_nonce, state_balance) =
                    state_nonce_and_balance.unwrap();
                self.update_nonce_and_balance(
                    &transaction.sender(),
                    state_nonce,
                    state_balance,
                );
                // GarbageCollector will be updated by the caller.
                self.txs.insert(transaction.hash(), transaction.clone());
                self.tx_sponsored_gas_map.insert(
                    transaction.hash(),
                    (sponsored_gas, sponsored_storage),
                );
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
                self.tx_sponsored_gas_map.remove(&replaced_tx.hash());
                self.tx_sponsored_gas_map.insert(
                    transaction.hash(),
                    (sponsored_gas, sponsored_storage),
                );
                if !packed {
                    self.unpacked_transaction_count += 1;
                }
            }
        }

        result
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
    )
    {
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
            None => {
                // Sanity check with `ready_account_pool`.
                match self.ready_account_pool.get(address) {
                    None => {
                        error!(
                            "Ready tx not in ready_account_pool: tx={:?}",
                            pending_txs.first()
                        );
                    }
                    Some(ready_tx) => {
                        let first_tx = pending_txs.first().expect("not empty");
                        if ready_tx.hash() != first_tx.hash() {
                            error!("ready_account_pool and deferred_pool are inconsistent! ready_tx={:?} first_pending={:?}", ready_tx.hash(), first_tx.hash());
                        }
                    }
                }
                TransactionStatus::Ready
            }
            Some(reason) => TransactionStatus::Pending(reason),
        };
        let pending_count = pending_txs.len();
        let limit = maybe_limit.unwrap_or(usize::MAX);
        (
            pending_txs.into_iter().take(limit).collect(),
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
        self.ready_account_pool.update(addr, ret);
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
    ) -> Vec<Arc<SignedTransaction>>
    {
        let mut packed_transactions: Vec<Arc<SignedTransaction>> = Vec::new();
        if num_txs == 0 {
            return packed_transactions;
        }

        let mut total_tx_gas_limit: U256 = 0.into();
        let mut eth_total_tx_gas_limit: U256 = 0.into();
        let mut total_tx_size: usize = 0;

        let mut big_tx_resample_times_limit = 10;
        let mut eth_tx_resample_times_limit = 10;

        let mut sample_eth_tx = evm_gas_limit > U256::zero();
        let mut recycle_txs = Vec::new();

        let spec = machine.spec(best_block_number);
        let transitions = &machine.params().transition_heights;

        'out: while let Some(tx) = if sample_eth_tx {
            self.ready_account_pool.pop()
        } else {
            self.ready_account_pool.pop_native()
        } {
            let tx_size = tx.rlp_size();
            if block_gas_limit - total_tx_gas_limit < *tx.gas_limit()
                || block_size_limit - total_tx_size < tx_size
            {
                recycle_txs.push(tx.clone());
                if big_tx_resample_times_limit > 0 {
                    big_tx_resample_times_limit -= 1;
                    continue 'out;
                } else {
                    break 'out;
                }
            }
            if tx.space() == Space::Ethereum {
                if evm_gas_limit - eth_total_tx_gas_limit < *tx.gas_limit() {
                    recycle_txs.push(tx.clone());
                    if eth_tx_resample_times_limit > 0 {
                        eth_tx_resample_times_limit -= 1;
                    } else {
                        sample_eth_tx = false;
                    }
                    continue 'out;
                }
            }

            // The validity of a transaction may change during the time.
            match verification_config.fast_recheck(
                &tx,
                best_epoch_height,
                transitions,
                &spec,
            ) {
                PackingCheckResult::Pack => {}
                PackingCheckResult::Pending => {
                    recycle_txs.push(tx.clone());
                    continue 'out;
                }
                PackingCheckResult::Drop => {
                    continue 'out;
                }
            }

            total_tx_gas_limit += *tx.gas_limit();
            if tx.space() == Space::Ethereum {
                eth_total_tx_gas_limit += *tx.gas_limit();
            }
            total_tx_size += tx_size;

            packed_transactions.push(tx.clone());
            self.insert_transaction_without_readiness_check(
                tx.clone(),
                true, /* packed */
                true, /* force */
                None, /* state_nonce_and_balance */
                self.tx_sponsored_gas_map
                    .get(&tx.hash())
                    .map(|x| x.clone())
                    .unwrap_or((U256::from(0), 0)),
            );
            self.recalculate_readiness_with_local_info(&tx.sender());
            if packed_transactions.len() >= num_txs {
                break 'out;
            }
        }

        for tx in recycle_txs {
            // The other status of these transactions remain unchanged, so we do
            // not need to update other structures like `garbage_collector`.
            self.ready_account_pool.insert(tx);
        }

        // FIXME: to be optimized by only recalculating readiness once for one
        //  sender
        for tx in packed_transactions.iter().rev() {
            self.insert_transaction_without_readiness_check(
                tx.clone(),
                false, /* packed */
                true,  /* force */
                None,  /* state_nonce_and_balance */
                self.tx_sponsored_gas_map
                    .get(&tx.hash())
                    .map(|x| x.clone())
                    .unwrap_or((U256::from(0), 0)),
            );
            self.recalculate_readiness_with_local_info(&tx.sender());
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

        packed_transactions
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
            Some(addr) => {
                let spaced_pool = match addr.space {
                    Space::Native => &self.ready_account_pool.native_pool,
                    Space::Ethereum => &self.ready_account_pool.evm_pool,
                };
                spaced_pool
                    .packing_pool
                    .treap
                    .iter()
                    .filter(|address_tx| addr.address == *address_tx.0)
                    .map(|(_, tx)| tx.clone())
                    .collect()
            }
            None => self
                .ready_account_pool
                .native_pool
                .packing_pool
                .treap
                .iter()
                .chain(
                    self.ready_account_pool.evm_pool.packing_pool.treap.iter(),
                )
                .map(|(_, tx)| tx.clone())
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
    ) -> Result<(), String>
    {
        let _timer = MeterTimer::time_func(TX_POOL_INNER_INSERT_TIMER.as_ref());
        let (sponsored_gas, sponsored_storage) =
            self.get_sponsored_gas_and_storage(account_cache, &transaction)?;

        let (state_nonce, state_balance) = account_cache
            .get_nonce_and_balance(&transaction.sender())
            .map_err(|e| {
                format!("Failed to read account_cache from storage: {}", e)
            })?;

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
            return Err(format!(
                "Transaction {:?} is discarded due to in too distant future",
                transaction.hash()
            ));
        } else if !packed /* Because we may get slightly out-dated state for transaction pool, we should allow transaction pool to set already past-nonce transactions to packed. */
            && *transaction.nonce() < state_nonce
        {
            trace!(
                "Transaction {:?} is discarded due to a too stale nonce, self.nonce()={}, state_nonce={}",
                transaction.hash(), transaction.nonce(), state_nonce,
            );
            return Err(format!(
                "Transaction {:?} is discarded due to a too stale nonce",
                transaction.hash()
            ));
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
                    need_balance += utx.value.clone();
                    if sponsored_gas == U256::from(0) {
                        need_balance += estimate_gas_fee;
                    }
                    if sponsored_storage == 0 {
                        need_balance += U256::from(utx.storage_limit)
                            * *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
                    }
                }
                Transaction::Ethereum(ref utx) => {
                    need_balance += utx.value.clone();
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
                return Err(msg);
            }
        }

        let result = self.insert_transaction_without_readiness_check(
            transaction.clone(),
            packed,
            force,
            Some((state_nonce, state_balance)),
            (sponsored_gas, sponsored_storage),
        );
        if let InsertResult::Failed(info) = result {
            return Err(format!("Failed imported to deferred pool: {}", info));
        }

        self.recalculate_readiness_with_state(
            &transaction.sender(),
            account_cache,
        )
        .map_err(|e| {
            format!("Failed to read account_cache from storage: {}", e)
        })?;

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
    ) -> Result<(U256, u64), String> {
        let mut sponsored_gas = U256::from(0);
        let mut sponsored_storage = 0;
        let sender = transaction.sender();

        // Compute sponsored_gas for `transaction`
        if let Transaction::Native(ref utx) = transaction.unsigned {
            if let Action::Call(ref callee) = utx.action {
                // FIXME: This is a quick fix for performance issue.
                if callee.is_contract_address() {
                    if let Some(sponsor_info) =
                        account_cache.get_sponsor_info(callee).map_err(|e| {
                            format!(
                                "Failed to read account_cache from storage: {}",
                                e
                            )
                        })?
                    {
                        if account_cache
                            .check_commission_privilege(
                                &callee,
                                &sender.address,
                            )
                            .map_err(|e| {
                                format!(
                                    "Failed to read account_cache from storage: {}",
                                    e
                                )
                            })?
                        {
                            let estimated_gas = Self::estimated_gas_fee(transaction.gas().clone(), transaction.gas_price().clone());
                            if estimated_gas <= sponsor_info.sponsor_gas_bound
                                && estimated_gas
                                <= sponsor_info.sponsor_balance_for_gas
                            {
                                sponsored_gas = utx.gas;
                            }
                            let estimated_collateral =
                                U256::from(utx.storage_limit)
                                    * *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
                            if estimated_collateral
                                <= sponsor_info.sponsor_balance_for_collateral + sponsor_info.unused_storage_points()
                            {
                                sponsored_storage = utx.storage_limit;
                            }
                        }
                    }
                }
            }
        }
        Ok((sponsored_gas, sponsored_storage))
    }
}

#[cfg(test)]
mod test_transaction_pool_inner {
    use super::{DeferredPool, InsertResult, TxWithReadyInfo};
    use crate::transaction_pool::transaction_pool_inner::ReadyAccountPool;
    use cfx_types::{Address, AddressSpaceUtil, U256};
    use keylib::{Generator, KeyPair, Random};
    use primitives::{
        Action, NativeTransaction, SignedTransaction, Transaction,
    };
    use std::sync::Arc;

    fn new_test_tx(
        sender: &KeyPair, nonce: usize, gas_price: usize, value: usize,
    ) -> Arc<SignedTransaction> {
        Arc::new(
            Transaction::from(NativeTransaction {
                nonce: U256::from(nonce),
                gas_price: U256::from(gas_price),
                gas: U256::from(50000),
                action: Action::Call(Address::random()),
                value: U256::from(value),
                storage_limit: 0,
                epoch_height: 0,
                chain_id: 1,
                data: Vec::new(),
            })
            .sign(sender.secret()),
        )
    }

    fn new_test_tx_with_read_info(
        sender: &KeyPair, nonce: usize, gas_price: usize, value: usize,
        packed: bool,
    ) -> TxWithReadyInfo
    {
        let transaction = new_test_tx(sender, nonce, gas_price, value);
        TxWithReadyInfo {
            transaction,
            packed,
            sponsored_gas: U256::from(0),
            sponsored_storage: 0,
        }
    }

    #[test]
    fn test_deferred_pool_insert_and_remove() {
        let mut deferred_pool = DeferredPool::new();

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
            InsertResult::Failed(format!("Tx with same nonce already inserted. To replace it, you need to specify a gas price > {}", bob_tx2_new.gas_price()))
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
        let mut deferred_pool = super::DeferredPool::new();

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

    #[test]
    fn test_ready_account_pool() {
        let mut ready_pool = ReadyAccountPool::new(1, 1, 50001.into());
        let account_count = 3;
        let mut senders = Vec::with_capacity(account_count);
        let mut sender_addresses = Vec::with_capacity(account_count);
        for _ in 0..account_count {
            let sender = Random.generate().unwrap();
            sender_addresses.push(sender.address().with_native_space());
            senders.push(sender);
        }
        ready_pool.update(
            &sender_addresses[0],
            Some(new_test_tx(&senders[0], 0, 2, 0)),
        );
        assert_eq!(
            ready_pool.native_pool.top().unwrap().sender(),
            sender_addresses[0]
        );
        assert_eq!(ready_pool.native_pool.waiting_pool.len(), 0);
        assert_eq!(ready_pool.native_pool.packing_pool.len(), 1);
        ready_pool.update(
            &sender_addresses[1],
            Some(new_test_tx(&senders[1], 0, 3, 0)),
        );
        assert_eq!(
            ready_pool.native_pool.top().unwrap().sender(),
            sender_addresses[1]
        );
        assert_eq!(ready_pool.native_pool.waiting_pool.len(), 1);
        assert_eq!(ready_pool.native_pool.packing_pool.len(), 1);
        ready_pool.update(
            &sender_addresses[0],
            Some(new_test_tx(&senders[0], 0, 4, 0)),
        );
        assert_eq!(
            ready_pool.native_pool.top().unwrap().sender(),
            sender_addresses[0]
        );
        assert_eq!(ready_pool.native_pool.waiting_pool.len(), 1);
        assert_eq!(ready_pool.native_pool.packing_pool.len(), 1);
        ready_pool.update(
            &sender_addresses[2],
            Some(new_test_tx(&senders[2], 0, 1, 0)),
        );
        assert_eq!(
            ready_pool.native_pool.top().unwrap().sender(),
            sender_addresses[0]
        );
        assert_eq!(ready_pool.native_pool.waiting_pool.len(), 2);
        assert_eq!(ready_pool.native_pool.packing_pool.len(), 1);
        for i in 0..account_count {
            assert_eq!(
                ready_pool.get(&sender_addresses[i]).unwrap().sender(),
                sender_addresses[i]
            );
        }
        ready_pool.update(&sender_addresses[0], None);
        assert_eq!(
            ready_pool.native_pool.top().unwrap().sender(),
            sender_addresses[1]
        );
        for i in 1..account_count {
            assert_eq!(
                ready_pool.get(&sender_addresses[i]).unwrap().sender(),
                sender_addresses[i]
            );
        }
        assert_eq!(ready_pool.pop().unwrap().sender(), sender_addresses[1]);
        assert_eq!(ready_pool.pop().unwrap().sender(), sender_addresses[2]);
        assert_eq!(ready_pool.native_pool.packing_pool.len(), 0);
        assert_eq!(ready_pool.native_pool.waiting_pool.len(), 0);
    }
}
