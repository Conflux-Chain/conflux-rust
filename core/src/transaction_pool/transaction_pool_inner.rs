use super::{
    account_cache::AccountCache,
    garbage_collector::GarbageCollector,
    impls::TreapMap,
    nonce_pool::{InsertResult, NoncePool, TxWithReadyInfo},
};
use crate::statedb::Result as StateDbResult;
use cfx_types::{address_util::AddressUtil, Address, H256, U256};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use metrics::{
    register_meter_with_group, Counter, CounterUsize, Meter, MeterTimer,
};
use primitives::{
    Account, Action, SignedTransaction, SponsorInfo, TransactionWithSignature,
};
use rlp::*;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
type WeightType = u128;
lazy_static! {
    pub static ref MAX_WEIGHT: U256 = u128::max_value().into();
}

const FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET: u32 = 2000;
// By default, the capacity of tx pool is 500K, so the maximum TPS is
// 500K / 100 = 5K
const TIME_WINDOW: u64 = 100;

lazy_static! {
    static ref TX_POOL_RECALCULATE: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::recalculate");
    static ref TX_POOL_INNER_INSERT_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::inner_insert");
    static ref DEFERRED_POOL_INNER_INSERT: Arc<dyn Meter> =
        register_meter_with_group("timer", "deferred_pool::inner_insert");
    static ref TX_POOL_GET_STATE_TIMER: Arc<dyn Meter> =
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
    buckets: HashMap<Address, NoncePool>,
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
        let bucket = self.buckets.entry(tx.sender).or_insert(NoncePool::new());
        bucket.insert(&tx, force)
    }

    fn contain_address(&self, addr: &Address) -> bool {
        self.buckets.contains_key(addr)
    }

    fn check_sender_and_nonce_exists(
        &self, sender: &Address, nonce: &U256,
    ) -> bool {
        if let Some(bucket) = self.buckets.get(sender) {
            bucket.check_nonce_exists(nonce)
        } else {
            false
        }
    }

    fn count_less(&self, sender: &Address, nonce: &U256) -> usize {
        if let Some(bucket) = self.buckets.get(sender) {
            bucket.count_less(nonce)
        } else {
            0
        }
    }

    fn remove_lowest_nonce(
        &mut self, addr: &Address,
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

    fn get_lowest_nonce(&self, addr: &Address) -> Option<&U256> {
        self.buckets
            .get(addr)
            .and_then(|bucket| bucket.get_lowest_nonce())
    }

    fn recalculate_readiness_with_local_info(
        &mut self, addr: &Address, nonce: U256, balance: U256,
    ) -> Option<Arc<SignedTransaction>> {
        if let Some(bucket) = self.buckets.get(addr) {
            bucket.recalculate_readiness_with_local_info(nonce, balance)
        } else {
            None
        }
    }

    fn check_tx_packed(&self, addr: Address, nonce: U256) -> bool {
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
}

#[derive(DeriveMallocSizeOf)]
struct ReadyAccountPool {
    treap: TreapMap<Address, Arc<SignedTransaction>, WeightType>,
    tx_weight_scaling: u64,
    tx_weight_exp: u8,
}

impl ReadyAccountPool {
    fn new(tx_weight_scaling: u64, tx_weight_exp: u8) -> Self {
        ReadyAccountPool {
            treap: TreapMap::new(),
            tx_weight_scaling,
            tx_weight_exp,
        }
    }

    fn clear(&mut self) {
        while self.len() != 0 {
            self.pop();
        }
    }

    fn len(&self) -> usize { self.treap.len() }

    fn get(&self, address: &Address) -> Option<Arc<SignedTransaction>> {
        self.treap.get(address).map(|tx| tx.clone())
    }

    fn remove(&mut self, address: &Address) -> Option<Arc<SignedTransaction>> {
        self.treap.remove(address)
    }

    fn update(
        &mut self, address: &Address, tx: Option<Arc<SignedTransaction>>,
    ) -> Option<Arc<SignedTransaction>> {
        let replaced = if let Some(tx) = tx {
            if tx.hash[0] & 254 == 0 {
                debug!("Sampled transaction {:?} in ready pool", tx.hash);
            }
            self.insert(tx)
        } else {
            self.remove(address)
        };
        replaced
    }

    fn insert(
        &mut self, tx: Arc<SignedTransaction>,
    ) -> Option<Arc<SignedTransaction>> {
        let scaled_weight = tx.gas_price / self.tx_weight_scaling;
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

        self.treap.insert(tx.sender(), tx.clone(), weight)
    }

    fn pop(&mut self) -> Option<Arc<SignedTransaction>> {
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

        self.remove(&tx.sender())
    }
}

#[derive(DeriveMallocSizeOf)]
pub struct TransactionPoolInner {
    capacity: usize,
    total_received_count: usize,
    unpacked_transaction_count: usize,
    deferred_pool: DeferredPool,
    ready_account_pool: ReadyAccountPool,
    ready_nonces_and_balances: HashMap<Address, (U256, U256)>,
    garbage_collector: GarbageCollector,
    txs: HashMap<H256, Arc<SignedTransaction>>,
    tx_sponsored_gas_map: HashMap<H256, U256>,
}

impl TransactionPoolInner {
    pub fn new(
        capacity: usize, tx_weight_scaling: u64, tx_weight_exp: u8,
    ) -> Self {
        TransactionPoolInner {
            capacity,
            total_received_count: 0,
            unpacked_transaction_count: 0,
            deferred_pool: DeferredPool::new(),
            ready_account_pool: ReadyAccountPool::new(
                tx_weight_scaling,
                tx_weight_exp,
            ),
            ready_nonces_and_balances: HashMap::new(),
            garbage_collector: GarbageCollector::default(),
            txs: HashMap::new(),
            tx_sponsored_gas_map: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.deferred_pool.clear();
        self.ready_account_pool.clear();
        self.ready_nonces_and_balances.clear();
        self.garbage_collector.clear();
        self.txs.clear();
        self.total_received_count = 0;
        self.unpacked_transaction_count = 0;
    }

    pub fn total_deferred(&self) -> usize { self.txs.len() }

    pub fn total_ready_accounts(&self) -> usize {
        self.ready_account_pool.len()
    }

    pub fn total_received(&self) -> usize { self.total_received_count }

    pub fn total_unpacked(&self) -> usize { self.unpacked_transaction_count }

    pub fn get(&self, tx_hash: &H256) -> Option<Arc<SignedTransaction>> {
        self.txs.get(tx_hash).map(|x| x.clone())
    }

    pub fn is_full(&self) -> bool {
        return self.total_deferred() >= self.capacity;
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
    fn collect_garbage(&mut self) {
        let count_before_gc = self.total_deferred();
        while self.is_full() && !self.garbage_collector.is_empty() {
            let victim = self.garbage_collector.top().unwrap().clone();
            let current_timestamp = self.get_current_timestamp();
            let addr = victim.sender;

            // All transactions are not garbage collectable.
            if victim.count == 0
                && victim.timestamp + TIME_WINDOW >= current_timestamp
            {
                break;
            }

            // Accounts which are not in `deferred_pool` may be inserted into
            // `garbage_collector`, we can just ignore them.
            if !self.deferred_pool.contain_address(&addr) {
                self.garbage_collector.pop();
                continue;
            }

            let (ready_nonce, _) = self
                .get_local_nonce_and_balance(&addr)
                .unwrap_or((0.into(), 0.into()));

            let lowest_nonce =
                *self.deferred_pool.get_lowest_nonce(&addr).unwrap();

            // We have to garbage collect an unexecuted transaction.
            // TODO: Implement more heuristic strategies
            if lowest_nonce >= ready_nonce {
                assert_eq!(victim.count, 0);
                GC_UNEXECUTED_COUNTER.inc(1);
                warn!("an unexecuted tx is garbage-collected.");
            }

            if !self
                .deferred_pool
                .check_tx_packed(addr.clone(), lowest_nonce)
            {
                self.unpacked_transaction_count -= 1;
            }

            let removed_tx = self
                .deferred_pool
                .remove_lowest_nonce(&addr)
                .unwrap()
                .get_arc_tx()
                .clone();

            // maintain ready account pool
            if let Some(ready_tx) = self.ready_account_pool.get(&addr) {
                if ready_tx.hash() == removed_tx.hash() {
                    warn!("a ready tx is garbage-collected");
                    GC_READY_COUNTER.inc(1);
                    self.ready_account_pool.remove(&addr);
                }
            }

            // maintain ready info
            if !self.deferred_pool.contain_address(&addr) {
                self.ready_nonces_and_balances.remove(&addr);
                // The picked sender has no transactions now, we pop it from
                // `garbage_collector`.
                self.garbage_collector.pop();
            } else {
                if victim.count > 0 {
                    self.garbage_collector.insert(
                        &addr,
                        victim.count - 1,
                        current_timestamp,
                    );
                } else {
                    self.garbage_collector.insert(&addr, 0, current_timestamp);
                }
            }

            // maintain txs
            self.txs.remove(&removed_tx.hash());
            self.tx_sponsored_gas_map.remove(&removed_tx.hash());
        }

        GC_METER.mark(count_before_gc - self.total_deferred());
    }

    /// Collect garbage and return the remaining quota of the pool to insert new
    /// transactions.
    pub fn remaining_quota(&mut self) -> usize {
        let len = self.total_deferred();
        self.capacity - len + self.garbage_collector.gc_size()
    }

    // the new inserting will fail if tx_pool is full (even if `force` is true)
    fn insert_transaction_without_readiness_check(
        &mut self, transaction: Arc<SignedTransaction>, packed: bool,
        force: bool, state_nonce_and_balance: Option<(U256, U256)>,
        sponsored_gas: U256,
    ) -> InsertResult
    {
        let _timer = MeterTimer::time_func(
            TX_POOL_INNER_WITHOUTCHECK_INSERT_TIMER.as_ref(),
        );
        if !self.deferred_pool.check_sender_and_nonce_exists(
            &transaction.sender(),
            &transaction.nonce(),
        ) {
            self.collect_garbage();
            if self.is_full() {
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
                let count = self
                    .deferred_pool
                    .count_less(&transaction.sender(), &state_nonce);
                let timestamp = self
                    .garbage_collector
                    .get_timestamp(&transaction.sender())
                    .unwrap_or(self.get_current_timestamp());
                self.garbage_collector.insert(
                    &transaction.sender(),
                    count,
                    timestamp,
                );
                self.txs.insert(transaction.hash(), transaction.clone());
                self.tx_sponsored_gas_map
                    .insert(transaction.hash(), sponsored_gas);
                if !packed {
                    self.unpacked_transaction_count += 1;
                }
            }
            InsertResult::Failed(_) => {}
            InsertResult::Updated(replaced_tx) => {
                if !replaced_tx.is_already_packed() {
                    self.unpacked_transaction_count -= 1;
                }
                self.txs.remove(&replaced_tx.hash());
                self.txs.insert(transaction.hash(), transaction.clone());
                self.tx_sponsored_gas_map.remove(&replaced_tx.hash());
                self.tx_sponsored_gas_map
                    .insert(transaction.hash(), sponsored_gas);
                if !packed {
                    self.unpacked_transaction_count += 1;
                }
            }
        }

        result
    }

    pub fn get_local_nonce_and_balance(
        &self, address: &Address,
    ) -> Option<(U256, U256)> {
        self.ready_nonces_and_balances.get(address).map(|x| *x)
    }

    fn update_nonce_and_balance(
        &mut self, address: &Address, nonce: U256, balance: U256,
    ) {
        let count = self.deferred_pool.count_less(address, &nonce);
        let timestamp = self
            .garbage_collector
            .get_timestamp(address)
            .unwrap_or(self.get_current_timestamp());
        self.garbage_collector.insert(address, count, timestamp);
        self.ready_nonces_and_balances
            .insert((*address).clone(), (nonce, balance));
    }

    pub fn get_nonce_and_balance_from_storage(
        &self, address: &Address, account_cache: &mut AccountCache,
    ) -> StateDbResult<(U256, U256)> {
        let _timer = MeterTimer::time_func(TX_POOL_GET_STATE_TIMER.as_ref());
        match account_cache.get_account_mut(address)? {
            Some(account) => {
                Ok((account.nonce.clone(), account.balance.clone()))
            }
            None => Ok((0.into(), 0.into())),
        }
    }

    pub fn get_sponsor_info_from_storage(
        &self, address: &Address, account_cache: &mut AccountCache,
    ) -> StateDbResult<Option<SponsorInfo>> {
        Ok(account_cache
            .get_account_mut(address)?
            .map(|x| x.sponsor_info.clone()))
    }

    fn get_and_update_nonce_and_balance_from_storage(
        &mut self, address: &Address, account_cache: &mut AccountCache,
    ) -> StateDbResult<(U256, U256)> {
        let ret = match account_cache.get_account_mut(address)? {
            Some(account) => (account.nonce.clone(), account.balance.clone()),
            None => (0.into(), 0.into()),
        };
        let count = self.deferred_pool.count_less(address, &ret.0);
        let timestamp = self
            .garbage_collector
            .get_timestamp(address)
            .unwrap_or(self.get_current_timestamp());
        self.garbage_collector.insert(address, count, timestamp);
        self.ready_nonces_and_balances
            .insert((*address).clone(), ret);

        Ok(ret)
    }

    pub fn get_lowest_nonce(&self, addr: &Address) -> U256 {
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

    fn recalculate_readiness_with_local_info(&mut self, addr: &Address) {
        let (nonce, balance) = self
            .get_local_nonce_and_balance(addr)
            .unwrap_or((0.into(), 0.into()));
        let ret = self
            .deferred_pool
            .recalculate_readiness_with_local_info(addr, nonce, balance);
        self.ready_account_pool.update(addr, ret);
    }

    fn recalculate_readiness_with_fixed_info(
        &mut self, addr: &Address, nonce: U256, balance: U256,
    ) {
        self.update_nonce_and_balance(addr, nonce, balance);
        let ret = self
            .deferred_pool
            .recalculate_readiness_with_local_info(addr, nonce, balance);
        self.ready_account_pool.update(addr, ret);
    }

    fn recalculate_readiness_with_state(
        &mut self, addr: &Address, account_cache: &mut AccountCache,
    ) -> StateDbResult<()> {
        let _timer = MeterTimer::time_func(TX_POOL_RECALCULATE.as_ref());
        let (nonce, balance) = self
            .get_and_update_nonce_and_balance_from_storage(
                addr,
                account_cache,
            )?;
        let ret = self
            .deferred_pool
            .recalculate_readiness_with_local_info(addr, nonce, balance);
        self.ready_account_pool.update(addr, ret);

        Ok(())
    }

    pub fn check_tx_packed_in_deferred_pool(&self, tx_hash: &H256) -> bool {
        match self.txs.get(tx_hash) {
            Some(tx) => {
                self.deferred_pool.check_tx_packed(tx.sender(), tx.nonce())
            }
            None => false,
        }
    }

    /// pack at most num_txs transactions randomly
    pub fn pack_transactions<'a>(
        &mut self, num_txs: usize, block_gas_limit: U256,
        block_size_limit: usize, epoch_height_lower_bound: u64,
        epoch_height_upper_bound: u64,
    ) -> Vec<Arc<SignedTransaction>>
    {
        let mut packed_transactions: Vec<Arc<SignedTransaction>> = Vec::new();
        if num_txs == 0 {
            return packed_transactions;
        }

        let mut total_tx_gas_limit: U256 = 0.into();
        let mut total_tx_size: usize = 0;

        let mut big_tx_resample_times_limit = 10;
        let mut recycle_txs = Vec::new();

        'out: while let Some(tx) = self.ready_account_pool.pop() {
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

            // If in rare case we popped up something that is currently outside
            // the bound, we will skip the transaction.
            if tx.epoch_height < epoch_height_lower_bound {
                continue 'out;
            } else if tx.epoch_height > epoch_height_upper_bound {
                recycle_txs.push(tx.clone());
                continue 'out;
            }

            total_tx_gas_limit += *tx.gas_limit();
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
                    .unwrap_or(U256::from(0)),
            );
            self.recalculate_readiness_with_local_info(&tx.sender());

            if packed_transactions.len() >= num_txs {
                break 'out;
            }
        }

        for tx in recycle_txs {
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
                    .unwrap_or(U256::from(0)),
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
        &self,
    ) -> (Vec<Arc<SignedTransaction>>, Vec<Arc<SignedTransaction>>) {
        let ready_txs = self
            .ready_account_pool
            .treap
            .iter()
            .map(|(_, tx)| tx.clone())
            .collect();

        let deferred_txs = self.txs.values().map(|v| v.clone()).collect();

        (ready_txs, deferred_txs)
    }

    // Add transaction into deferred pool and maintain its readiness
    // the packed tag provided
    // if force tag is true, the replacement in nonce pool must be happened
    pub fn insert_transaction_with_readiness_check(
        &mut self, account_cache: &mut AccountCache,
        transaction: Arc<SignedTransaction>, packed: bool, force: bool,
    ) -> Result<(), String>
    {
        let _timer = MeterTimer::time_func(TX_POOL_INNER_INSERT_TIMER.as_ref());
        let mut sponsored_gas = U256::from(0);

        // Compute sponsored_gas for `transaction`
        if let Action::Call(callee) = transaction.action {
            // FIXME: This is a quick fix for performance issue.
            if callee.is_contract_address() {
                if let Ok(Some(sponsor_info)) =
                    self.get_sponsor_info_from_storage(&callee, account_cache)
                {
                    if account_cache.check_commission_privilege(
                        &callee,
                        &transaction.sender(),
                    ) {
                        let estimated_gas =
                            transaction.gas * transaction.gas_price;
                        if estimated_gas <= sponsor_info.sponsor_gas_bound
                            && estimated_gas
                                <= sponsor_info.sponsor_balance_for_gas
                        {
                            sponsored_gas = transaction.gas;
                        }
                    }
                }
            }
        }

        let (state_nonce, state_balance) = self
            .get_nonce_and_balance_from_storage(
                &transaction.sender,
                account_cache,
            )
            .map_err(|e| {
                format!("Failed to read account_cache from storage: {}", e)
            })?;

        if transaction.hash[0] & 254 == 0 {
            trace!(
                "Transaction {:?} sender: {:?} current nonce: {:?}, state nonce:{:?}",
                transaction.hash, transaction.sender, transaction.nonce, state_nonce
            );
        }
        if transaction.nonce
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
            && transaction.nonce < state_nonce
        {
            trace!(
                "Transaction {:?} is discarded due to a too stale nonce, self.nonce={}, state_nonce={}",
                transaction.hash(), transaction.nonce, state_nonce,
            );
            return Err(format!(
                "Transaction {:?} is discarded due to a too stale nonce",
                transaction.hash()
            ));
        }

        let result = self.insert_transaction_without_readiness_check(
            transaction.clone(),
            packed,
            force,
            Some((state_nonce, state_balance)),
            sponsored_gas,
        );
        if let InsertResult::Failed(info) = result {
            return Err(format!("Failed imported to deferred pool: {}", info));
        }

        self.recalculate_readiness_with_state(
            &transaction.sender,
            account_cache,
        )
        .map_err(|e| {
            format!("Failed to read account_cache from storage: {}", e)
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod test_transaction_pool_inner {
    use super::{DeferredPool, InsertResult, TxWithReadyInfo};
    use cfx_types::{Address, U256};
    use keylib::{Generator, KeyPair, Random};
    use primitives::{Action, SignedTransaction, Transaction};
    use std::sync::Arc;

    fn new_test_tx(
        sender: &KeyPair, nonce: usize, gas_price: usize, value: usize,
    ) -> Arc<SignedTransaction> {
        Arc::new(
            Transaction {
                nonce: U256::from(nonce),
                gas_price: U256::from(gas_price),
                gas: U256::from(50000),
                action: Action::Call(Address::random()),
                value: U256::from(value),
                storage_limit: 0,
                epoch_height: 0,
                chain_id: 0,
                data: Vec::new(),
            }
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
        }
    }

    #[test]
    fn test_deferred_pool_insert_and_remove() {
        let mut deferred_pool = DeferredPool::new();

        // insert txs of same sender
        let alice = Random.generate().unwrap();
        let bob = Random.generate().unwrap();
        let eva = Random.generate().unwrap();

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

        assert_eq!(deferred_pool.contain_address(&alice.address()), true);

        assert_eq!(deferred_pool.contain_address(&eva.address()), false);

        assert_eq!(deferred_pool.remove_lowest_nonce(&eva.address()), None);

        assert_eq!(deferred_pool.contain_address(&bob.address()), false);

        assert_eq!(
            deferred_pool.insert(alice_tx2.clone(), false /* force */),
            InsertResult::NewAdded
        );

        assert_eq!(deferred_pool.remove_lowest_nonce(&bob.address()), None);

        assert_eq!(
            deferred_pool.insert(bob_tx1.clone(), false /* force */),
            InsertResult::NewAdded
        );

        assert_eq!(deferred_pool.contain_address(&bob.address()), true);

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
            InsertResult::Failed(format!("Tx with same nonce already inserted. To replace it, you need to specify a gas price > {}", bob_tx2_new.gas_price))
        );

        assert_eq!(
            deferred_pool.get_lowest_nonce(&bob.address()),
            Some(&(1.into()))
        );

        assert_eq!(
            deferred_pool.remove_lowest_nonce(&bob.address()),
            Some(bob_tx1.clone())
        );

        assert_eq!(
            deferred_pool.get_lowest_nonce(&bob.address()),
            Some(&(2.into()))
        );

        assert_eq!(deferred_pool.contain_address(&bob.address()), true);

        assert_eq!(
            deferred_pool.remove_lowest_nonce(&bob.address()),
            Some(bob_tx2_new.clone())
        );

        assert_eq!(deferred_pool.get_lowest_nonce(&bob.address()), None);

        assert_eq!(deferred_pool.contain_address(&bob.address()), false);
    }

    #[test]
    fn test_deferred_pool_recalculate_readiness() {
        let mut deferred_pool = super::DeferredPool::new();

        let alice = Random.generate().unwrap();

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
                &alice.address(),
                5.into(),
                exact_cost.into()
            ),
            None
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice.address(),
                7.into(),
                exact_cost.into()
            ),
            None
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice.address(),
                8.into(),
                exact_cost.into()
            ),
            Some(tx4.transaction.clone())
        );

        deferred_pool.insert(tx3.clone(), false /* force */);
        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice.address(),
                4.into(),
                exact_cost.into()
            ),
            None
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice.address(),
                5.into(),
                exact_cost.into()
            ),
            Some(tx4.transaction.clone())
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice.address(),
                7.into(),
                exact_cost.into()
            ),
            Some(tx4.transaction.clone())
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice.address(),
                8.into(),
                exact_cost.into()
            ),
            Some(tx4.transaction.clone())
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice.address(),
                9.into(),
                exact_cost.into()
            ),
            Some(tx5.transaction.clone())
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice.address(),
                10.into(),
                exact_cost.into()
            ),
            None
        );

        assert_eq!(
            deferred_pool.recalculate_readiness_with_local_info(
                &alice.address(),
                5.into(),
                (exact_cost - 1).into()
            ),
            None
        );
    }
}
