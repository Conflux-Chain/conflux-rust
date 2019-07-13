// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod impls;

#[cfg(test)]
mod test_treap;

extern crate rand;

pub use self::impls::TreapMap;
use crate::{
    block_data_manager::BlockDataManager, consensus::BestInformation,
    executive, statedb::StateDb, storage::Storage, vm,
};
use cfx_types::{Address, H256, H512, U256, U512};
use metrics::{
    register_meter_with_group, Gauge, GaugeUsize, Meter, MeterTimer,
};
use parking_lot::{Mutex, RwLock};
use primitives::{
    Account, Action, EpochId, SignedTransaction, TransactionWithSignature,
};
use rlp::*;
use std::{
    collections::{hash_map::HashMap, BTreeMap, VecDeque},
    mem,
    ops::{Deref, DerefMut},
    sync::Arc,
};

lazy_static! {
    static ref TX_POOL_GAUGE: Arc<Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "size");
    static ref TX_POOL_READY_GAUGE: Arc<Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "ready_size");
    static ref TX_POOL_INSERT_TIMER: Arc<Meter> =
        register_meter_with_group("timer", "tx_pool::insert_new_tx");
    static ref TX_POOL_RECOVER_TIMER: Arc<Meter> =
        register_meter_with_group("timer", "tx_pool::recover_public");
    static ref TX_POOL_RECALCULATE: Arc<Meter> =
        register_meter_with_group("timer", "tx_pool::recalculate");
    static ref TX_POOL_INNER_INSERT_TIMER: Arc<Meter> =
        register_meter_with_group("timer", "tx_pool::inner_insert");
}

pub const DEFAULT_MIN_TRANSACTION_GAS_PRICE: u64 = 1;
pub const DEFAULT_MAX_TRANSACTION_GAS_LIMIT: u64 = 100_000_000;
pub const DEFAULT_MAX_BLOCK_GAS_LIMIT: u64 = 30_000 * 100_000;

pub const FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET: u32 = 2000;

pub struct AccountCache<'storage> {
    pub accounts: HashMap<Address, Account>,
    pub storage: StateDb<'storage>,
}

impl<'storage> AccountCache<'storage> {
    pub fn new(storage: Storage<'storage>) -> Self {
        AccountCache {
            accounts: HashMap::new(),
            storage: StateDb::new(storage),
        }
    }

    pub fn get_ready_account(&mut self, address: &Address) -> Option<&Account> {
        self.accounts.get(address)
    }

    pub fn get_account_mut(
        &mut self, address: &Address,
    ) -> Option<&mut Account> {
        if !self.accounts.contains_key(&address) {
            let account =
                self.storage.get_account(&address).ok().and_then(|x| x);
            if let Some(account) = account {
                self.accounts.insert((*address).clone(), account);
            }
        }
        self.accounts.get_mut(&address)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct TxWithReadyInfo {
    transaction: Arc<SignedTransaction>,
    packed: bool,
}

impl TxWithReadyInfo {
    pub fn is_already_packed(&self) -> bool { self.packed }

    pub fn get_arc_tx(&self) -> &Arc<SignedTransaction> { &self.transaction }

    pub fn should_replace(&self, x: &Self, force: bool) -> bool {
        if force {
            return true;
        }
        if x.is_already_packed() {
            return false;
        }
        if self.is_already_packed() {
            return true;
        }
        self.gas_price > x.gas_price
    }
}

impl Deref for TxWithReadyInfo {
    type Target = SignedTransaction;

    fn deref(&self) -> &Self::Target { &self.transaction }
}

#[derive(Debug, PartialEq)]
enum InsertResult {
    /// new item added
    NewAdded,
    /// failed to update with lower gas price tx
    Failed(String),
    /// succeeded to update with higher gas price tx
    Updated(TxWithReadyInfo),
}

struct NoncePool {
    inner: BTreeMap<U256, TxWithReadyInfo>,
}

impl NoncePool {
    fn new() -> Self {
        NoncePool {
            inner: Default::default(),
        }
    }

    // FIXME: later we should limit the number of txs from one sender.
    //  the FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET roughly doing this job
    fn insert(&mut self, tx: &TxWithReadyInfo, force: bool) -> InsertResult {
        let mut ret = if self.inner.contains_key(&tx.nonce) {
            InsertResult::Failed(format!("Tx with same nonce already inserted, try to replace it with a higher gas price"))
        } else {
            InsertResult::NewAdded
        };

        let tx_in_pool = self.inner.entry(tx.nonce).or_insert(tx.clone());
        if tx.should_replace(tx_in_pool, force) {
            // replace with higher gas price transaction
            ret = InsertResult::Updated(tx_in_pool.clone());
            *tx_in_pool = tx.clone();
        }
        ret
    }

    fn get_tx_by_nonce(&self, nonce: U256) -> Option<TxWithReadyInfo> {
        self.inner.get(&nonce).map(|x| x.clone())
    }

    fn get_lowest_nonce(&self) -> Option<&U256> {
        self.inner.iter().next().map(|(k, _)| k)
    }

    fn remove(&mut self, nonce: &U256) -> Option<TxWithReadyInfo> {
        self.inner.remove(nonce)
    }

    fn remove_lowest_nonce(&mut self) -> Option<TxWithReadyInfo> {
        let lowest_nonce = self.get_lowest_nonce().map(|x| x.clone());
        lowest_nonce.and_then(|nonce| self.remove(&nonce))
    }

    fn recalculate_readiness_with_local_info(
        &self, nonce: U256, balance: U256,
    ) -> Option<Arc<SignedTransaction>> {
        let mut next_nonce = nonce;
        let mut balance_left = balance;
        while let Some(tx) = self.inner.get(&next_nonce) {
            let cost = tx.value + tx.gas_price * tx.gas;
            if balance_left < cost {
                return None;
            }

            if !tx.packed {
                return Some(tx.transaction.clone());
            }
            balance_left -= cost;
            next_nonce += 1.into();
        }
        None
    }

    fn is_empty(&self) -> bool { self.inner.is_empty() }
}

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

struct ReadyAccountPool {
    treap: TreapMap<Address, Arc<SignedTransaction>, U512>,
}

impl ReadyAccountPool {
    fn new() -> Self {
        ReadyAccountPool {
            treap: TreapMap::new(),
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
            self.insert(tx)
        } else {
            self.remove(address)
        };
        replaced
    }

    fn insert(
        &mut self, tx: Arc<SignedTransaction>,
    ) -> Option<Arc<SignedTransaction>> {
        self.treap
            .insert(tx.sender(), tx.clone(), U512::from(tx.gas_price))
    }

    fn pop(&mut self) -> Option<Arc<SignedTransaction>> {
        if self.treap.len() == 0 {
            return None;
        }

        let sum_gas_price = self.treap.sum_weight();
        let mut rand_value = U512::from(H512::random());
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

pub struct TransactionPoolInner {
    capacity: usize,
    deferred_pool: DeferredPool,
    ready_account_pool: ReadyAccountPool,
    ready_nonces_and_balances: HashMap<Address, (U256, U256)>,
    garbage_collection_queue: VecDeque<Address>,
    txs: HashMap<H256, Arc<SignedTransaction>>,
}

impl TransactionPoolInner {
    pub fn with_capacity(capacity: usize) -> Self {
        TransactionPoolInner {
            capacity,
            deferred_pool: DeferredPool::new(),
            ready_account_pool: ReadyAccountPool::new(),
            ready_nonces_and_balances: HashMap::new(),
            garbage_collection_queue: VecDeque::new(),
            txs: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.deferred_pool.clear();
        self.ready_account_pool.clear();
        self.ready_nonces_and_balances.clear();
        self.garbage_collection_queue.clear();
        self.txs.clear();
    }

    pub fn len(&self) -> usize { self.txs.len() }

    fn get(&self, tx_hash: &H256) -> Option<Arc<SignedTransaction>> {
        self.txs.get(tx_hash).map(|x| x.clone())
    }

    fn collect_garbage(&mut self) {
        while self.garbage_collection_queue.len() > self.capacity {
            let addr = self.garbage_collection_queue.pop_front().unwrap();
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
                    self.ready_account_pool.remove(&addr);
                }
            }

            // alert if a tx after ready nonce is collected
            let (nonce, _) = self
                .get_local_nonce_and_balance(&addr)
                .unwrap_or((0.into(), 0.into()));
            if removed_tx.nonce() >= nonce {
                warn!("a tx after execution is garbage-collected");
            }

            // maintain ready info
            if !self.deferred_pool.contain_address(&addr) {
                self.ready_nonces_and_balances.remove(&addr);
            }

            // maintain txs
            self.txs.remove(&removed_tx.hash());
        }
    }

    fn insert(
        &mut self, transaction: Arc<SignedTransaction>, packed: bool,
        force: bool,
    ) -> InsertResult
    {
        let result = self.deferred_pool.insert(
            TxWithReadyInfo {
                transaction: transaction.clone(),
                packed,
            },
            force,
        );

        match &result {
            InsertResult::NewAdded => {
                self.garbage_collection_queue
                    .push_back(transaction.sender());
                self.txs.insert(transaction.hash(), transaction);
                self.collect_garbage();
            }
            InsertResult::Failed(_) => {}
            InsertResult::Updated(replaced_tx) => {
                self.txs.remove(&replaced_tx.hash());
                self.txs.insert(transaction.hash(), transaction);
            }
        }

        result
    }

    fn get_local_nonce_and_balance(
        &self, address: &Address,
    ) -> Option<(U256, U256)> {
        self.ready_nonces_and_balances.get(address).map(|x| *x)
    }

    fn update_nonce_and_balance(
        &mut self, address: &Address, nonce: U256, balance: U256,
    ) {
        self.ready_nonces_and_balances
            .insert((*address).clone(), (nonce, balance));
    }

    fn get_nonce_and_balance_from_storage(
        &self, address: &Address, account_cache: &mut AccountCache,
    ) -> (U256, U256) {
        match account_cache.get_account_mut(address) {
            Some(account) => (account.nonce.clone(), account.balance.clone()),
            None => (0.into(), 0.into()),
        }
    }

    fn get_and_update_nonce_and_balance_from_storage(
        &mut self, address: &Address, account_cache: &mut AccountCache,
    ) -> (U256, U256) {
        let ret = match account_cache.get_account_mut(address) {
            Some(account) => (account.nonce.clone(), account.balance.clone()),
            None => (0.into(), 0.into()),
        };
        self.ready_nonces_and_balances
            .insert((*address).clone(), ret);
        ret
    }

    fn get_lowest_nonce(&self, addr: &Address) -> U256 {
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
    ) {
        let (nonce, balance) = self
            .get_and_update_nonce_and_balance_from_storage(addr, account_cache);
        let _timer = MeterTimer::time_func(TX_POOL_RECALCULATE.as_ref());
        let ret = self
            .deferred_pool
            .recalculate_readiness_with_local_info(addr, nonce, balance);
        self.ready_account_pool.update(addr, ret);
    }

    fn check_tx_packed_in_deferred_pool(&self, tx_hash: &H256) -> bool {
        match self.txs.get(tx_hash) {
            Some(tx) => {
                self.deferred_pool.check_tx_packed(tx.sender(), tx.nonce())
            }
            None => false,
        }
    }
}

pub struct TransactionPool {
    inner: RwLock<TransactionPoolInner>,
    to_propagate_trans: Arc<RwLock<HashMap<H256, Arc<SignedTransaction>>>>,
    pub data_man: Arc<BlockDataManager>,
    spec: vm::Spec,
    best_executed_epoch: Mutex<EpochId>,
    consensus_best_info: Mutex<Arc<BestInformation>>,
    set_tx_requests: Mutex<Vec<Arc<SignedTransaction>>>,
    recycle_tx_requests: Mutex<Vec<Arc<SignedTransaction>>>,
}

pub type SharedTransactionPool = Arc<TransactionPool>;

impl TransactionPool {
    pub fn with_capacity(
        capacity: usize, data_man: Arc<BlockDataManager>,
    ) -> Self {
        let genesis_hash = data_man.genesis_block.hash();
        TransactionPool {
            inner: RwLock::new(TransactionPoolInner::with_capacity(capacity)),
            to_propagate_trans: Arc::new(RwLock::new(HashMap::new())),
            data_man,
            spec: vm::Spec::new_spec(),
            best_executed_epoch: Mutex::new(genesis_hash),
            consensus_best_info: Mutex::new(Arc::new(Default::default())),
            set_tx_requests: Mutex::new(Default::default()),
            recycle_tx_requests: Mutex::new(Default::default()),
        }
    }

    pub fn len(&self) -> usize { self.inner.read().len() }

    pub fn get_transaction(
        &self, tx_hash: &H256,
    ) -> Option<Arc<SignedTransaction>> {
        self.inner.read().get(tx_hash)
    }

    pub fn check_tx_packed_in_deferred_pool(&self, tx_hash: &H256) -> bool {
        self.inner.read().check_tx_packed_in_deferred_pool(tx_hash)
    }

    pub fn get_local_account_info(&self, address: &Address) -> (U256, U256) {
        self.inner
            .read()
            .get_local_nonce_and_balance(address)
            .unwrap_or((0.into(), 0.into()))
    }

    pub fn get_state_account_info(&self, address: &Address) -> (U256, U256) {
        let mut account_cache = self.get_best_state_account_cache();
        self.inner
            .read()
            .get_nonce_and_balance_from_storage(address, &mut account_cache)
    }

    /// Try to insert `transactions` into transaction pool.
    ///
    /// If some tx is already in our tx_cache, it will be ignored and will not
    /// be added to returned `passed_transactions`. If some tx invalid or
    /// cannot be inserted to the tx pool, it will be included in the returned
    /// `failure` and will not be propagated.
    pub fn insert_new_transactions(
        &self, transactions: &Vec<TransactionWithSignature>,
    ) -> (Vec<Arc<SignedTransaction>>, HashMap<H256, String>) {
        let _timer = MeterTimer::time_func(TX_POOL_INSERT_TIMER.as_ref());
        let mut passed_transactions = Vec::new();
        let mut failure = HashMap::new();
        match self.data_man.recover_unsigned_tx(transactions) {
            Ok(signed_trans) => {
                let mut account_cache = self.get_best_state_account_cache();
                let mut inner = self.inner.write();
                let mut to_prop = self.to_propagate_trans.write();
                for tx in signed_trans {
                    if let Err(e) = self.verify_transaction(tx.as_ref()) {
                        debug!(
                            "tx {:?} fails to pass verification, err={:?}",
                            &tx.hash, e
                        );
                        failure.insert(tx.hash(), e);
                        continue;
                    }
                    if let Err(e) = self
                        .add_transaction_and_check_readiness_without_lock(
                            &mut *inner,
                            &mut account_cache,
                            tx.clone(),
                            false,
                            false,
                        )
                    {
                        debug!(
                            "tx {:?} fails to be inserted to pool, err={:?}",
                            &tx.hash, e
                        );
                        failure.insert(tx.hash(), e);
                        continue;
                    }
                    passed_transactions.push(tx.clone());
                    if !to_prop.contains_key(&tx.hash) {
                        to_prop.insert(tx.hash, tx);
                    }
                }
            }
            Err(e) => {
                for tx in transactions {
                    failure.insert(tx.hash(), format!("{:?}", e).into());
                }
            }
        }
        TX_POOL_GAUGE.update(self.len());
        TX_POOL_READY_GAUGE.update(self.inner.read().ready_account_pool.len());

        (passed_transactions, failure)
    }

    /// verify transactions based on the rules that have nothing to do with
    /// readiness
    pub fn verify_transaction(
        &self, transaction: &SignedTransaction,
    ) -> Result<(), String> {
        // check transaction gas limit
        if transaction.gas > DEFAULT_MAX_TRANSACTION_GAS_LIMIT.into() {
            warn!(
                "Transaction discarded due to above gas limit: {} > {}",
                transaction.gas(),
                DEFAULT_MAX_TRANSACTION_GAS_LIMIT
            );
            return Err(format!(
                "transaction gas {} exceeds the maximum value {}",
                transaction.gas(),
                DEFAULT_MAX_TRANSACTION_GAS_LIMIT
            ));
        }

        // check transaction intrinsic gas
        let tx_intrinsic_gas = executive::Executive::gas_required_for(
            transaction.action == Action::Create,
            &transaction.data,
            &self.spec,
        );
        if transaction.gas < (tx_intrinsic_gas as usize).into() {
            debug!(
                "Transaction discarded due to gas less than required: {} < {}",
                transaction.gas, tx_intrinsic_gas
            );
            return Err(format!(
                "transaction gas {} less than intrinsic gas {}",
                transaction.gas, tx_intrinsic_gas
            ));
        }

        // check transaction gas price
        if transaction.gas_price < DEFAULT_MIN_TRANSACTION_GAS_PRICE.into() {
            warn!("Transaction {} discarded due to below minimal gas price: price {}", transaction.hash(), transaction.gas_price);
            return Err(format!(
                "transaction gas price {} less than the minimum value {}",
                transaction.gas_price, DEFAULT_MIN_TRANSACTION_GAS_PRICE
            ));
        }

        if let Err(e) = transaction.transaction.verify_basic() {
            warn!("Transaction {:?} discarded due to not pass basic verification.", transaction.hash());
            return Err(format!("{:?}", e));
        }

        Ok(())
    }

    // Add transaction into deferred pool and maintain its readiness
    // the packed tag provided
    // if force tag is true, the replacement in nonce pool must be happened
    pub fn add_transaction_and_check_readiness_without_lock(
        &self, inner: &mut TransactionPoolInner,
        account_cache: &mut AccountCache, transaction: Arc<SignedTransaction>,
        packed: bool, force: bool,
    ) -> Result<(), String>
    {
        /*
        if self.capacity <= inner.len() {
            warn!("Transaction discarded due to insufficient txpool capacity: {:?}", transaction.hash());
            return Err(format!("Transaction discarded due to insufficient txpool capacity: {:?}", transaction.hash()));
        }
        */
        let (state_nonce, _) = inner.get_nonce_and_balance_from_storage(
            &transaction.sender,
            account_cache,
        );

        if transaction.nonce
            >= state_nonce
                + U256::from(FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET)
        {
            debug!(
                "Transaction {:?} is discarded due to in too distant future",
                transaction.hash()
            );
            return Err(format!(
                "Transaction {:?} is discarded due to in too distant future",
                transaction.hash()
            ));
        } else if transaction.nonce
            < inner.get_lowest_nonce(&transaction.sender)
        {
            debug!(
                "Transaction {:?} is discarded due to a too stale nonce",
                transaction.hash()
            );
            return Err(format!(
                "Transaction {:?} is discarded due to a too stale nonce",
                transaction.hash()
            ));
        }

        let result = self.add_to_deferred_pool_without_lock(
            inner,
            transaction.clone(),
            packed,
            force,
        );
        if let InsertResult::Failed(info) = result {
            return Err(format!("Failed imported to deferred pool: {}", info));
        }

        inner.recalculate_readiness_with_state(
            &transaction.sender,
            account_cache,
        );

        Ok(())
    }

    pub fn get_to_propagate_trans(
        &self,
    ) -> HashMap<H256, Arc<SignedTransaction>> {
        let mut to_prop = self.to_propagate_trans.write();
        let mut res = HashMap::new();
        mem::swap(&mut *to_prop, &mut res);
        res
    }

    pub fn set_to_propagate_trans(
        &self, transactions: HashMap<H256, Arc<SignedTransaction>>,
    ) {
        let mut to_prop = self.to_propagate_trans.write();
        to_prop.extend(transactions);
    }

    // If a tx is failed executed due to invalid nonce or if its enclosing block
    // becomes orphan due to era transition. This function should be invoked
    // to recycle it
    pub fn recycle_transactions(
        &self, transactions: Vec<Arc<SignedTransaction>>,
    ) {
        if transactions.is_empty() {
            // Fast return. Also used to for bench mode.
            return;
        }

        let mut recycle_req_buffer = self.recycle_tx_requests.lock();
        for tx in transactions {
            recycle_req_buffer.push(tx);
        }
    }

    fn add_to_deferred_pool_without_lock(
        &self, inner: &mut TransactionPoolInner,
        transaction: Arc<SignedTransaction>, packed: bool, force: bool,
    ) -> InsertResult
    {
        let _timer = MeterTimer::time_func(TX_POOL_INNER_INSERT_TIMER.as_ref());
        trace!(
            "Insert tx into deferred pool, hash={:?} sender={:?}",
            transaction.hash(),
            transaction.sender
        );
        inner.insert(transaction, packed, force)
    }

    pub fn set_tx_packed(&self, transactions: Vec<Arc<SignedTransaction>>) {
        if transactions.is_empty() {
            // Fast return. Also used to for bench mode.
            return;
        }
        let mut tx_req_buffer = self.set_tx_requests.lock();
        for tx in transactions {
            tx_req_buffer.push(tx);
        }
    }

    /// pack at most num_txs transactions randomly
    pub fn pack_transactions<'a>(
        &self, num_txs: usize, block_gas_limit: U256, block_size_limit: usize,
    ) -> Vec<Arc<SignedTransaction>> {
        let mut packed_transactions: Vec<Arc<SignedTransaction>> = Vec::new();
        if num_txs == 0 {
            return packed_transactions;
        }
        let mut inner = self.inner.write();

        let mut total_tx_gas_limit: U256 = 0.into();
        let mut total_tx_size: usize = 0;

        let mut big_tx_resample_times_limit = 10;
        let mut too_big_txs = Vec::new();

        'out: while let Some(tx) = inner.ready_account_pool.pop() {
            let tx_size = tx.rlp_size();
            if block_gas_limit - total_tx_gas_limit < *tx.gas_limit()
                || block_size_limit - total_tx_size < tx_size
            {
                too_big_txs.push(tx.clone());
                if big_tx_resample_times_limit > 0 {
                    big_tx_resample_times_limit -= 1;
                    continue 'out;
                } else {
                    break 'out;
                }
            }

            total_tx_gas_limit += *tx.gas_limit();
            total_tx_size += tx_size;

            packed_transactions.push(tx.clone());
            inner.insert(tx.clone(), true, true);
            inner.recalculate_readiness_with_local_info(&tx.sender());

            if packed_transactions.len() >= num_txs {
                break 'out;
            }
        }

        for tx in too_big_txs {
            inner.ready_account_pool.insert(tx);
        }

        // FIXME: to be optimized by only recalculating readiness once for one
        //  sender
        for tx in packed_transactions.iter().rev() {
            inner.insert(tx.clone(), false, true);
            inner.recalculate_readiness_with_local_info(&tx.sender());
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

    pub fn notify_state_start(&self, accounts_from_execution: Vec<Account>) {
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();

        for account in &accounts_from_execution {
            inner.recalculate_readiness_with_fixed_info(
                &account.address,
                account.nonce,
                account.balance,
            );
        }
    }

    pub fn clear_tx_pool(&self) {
        let mut inner = self.inner.write();
        inner.clear()
    }

    /// stats retrieves the length of ready and deferred pool.
    pub fn stats(&self) -> (usize, usize) {
        let inner = self.inner.read();
        (inner.ready_account_pool.len(), inner.len())
    }

    /// content retrieves the ready and deferred transactions.
    pub fn content(
        &self,
    ) -> (Vec<Arc<SignedTransaction>>, Vec<Arc<SignedTransaction>>) {
        let inner = self.inner.read();

        let ready_txs = inner
            .ready_account_pool
            .treap
            .iter()
            .map(|(_, tx)| tx.clone())
            .collect();

        let deferred_txs = inner.txs.values().map(|v| v.clone()).collect();

        (ready_txs, deferred_txs)
    }

    pub fn notify_new_best_info(&self, best_info: Arc<BestInformation>) {
        let mut set_tx_buffer = self.set_tx_requests.lock();
        let mut recycle_tx_buffer = self.recycle_tx_requests.lock();
        let mut consensus_best_info = self.consensus_best_info.lock();
        *consensus_best_info = best_info;

        let mut account_cache = self.get_best_state_account_cache();
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();

        while let Some(tx) = set_tx_buffer.pop() {
            self.add_transaction_and_check_readiness_without_lock(
                inner,
                &mut account_cache,
                tx,
                true,
                false,
            )
            .ok();
        }

        while let Some(tx) = recycle_tx_buffer.pop() {
            debug!(
                "should not trigger recycle transaction, nonce = {}, sender = {:?}, \
                account nonce = {}, hash = {:?} .",
                &tx.nonce, &tx.sender,
                &account_cache.get_account_mut(&tx.sender).map_or(0.into(), |x| x.nonce), tx.hash);
            self.add_transaction_and_check_readiness_without_lock(
                inner,
                &mut account_cache,
                tx,
                false,
                true,
            )
            .ok();
        }
    }

    pub fn get_best_info_with_packed_transactions(
        &self, num_txs: usize, block_size_limit: usize, block_gas_limit: U256,
        additional_transactions: Vec<Arc<SignedTransaction>>,
    ) -> (Arc<BestInformation>, Vec<Arc<SignedTransaction>>)
    {
        let consensus_best_info = self.consensus_best_info.lock();

        let transactions_from_pool =
            self.pack_transactions(num_txs, block_gas_limit, block_size_limit);

        let transactions = [
            additional_transactions.as_slice(),
            transactions_from_pool.as_slice(),
        ]
        .concat();

        (consensus_best_info.clone(), transactions)
    }

    pub fn set_best_executed_epoch(&self, best_executed_epoch: &EpochId) {
        *self.best_executed_epoch.lock() = best_executed_epoch.clone();
    }

    fn get_best_state_account_cache(&self) -> AccountCache {
        AccountCache::new(unsafe {
            self.data_man
                .storage_manager
                .get_state_readonly_assumed_existence(
                    *self.best_executed_epoch.lock(),
                )
                .unwrap()
        })
    }
}

#[cfg(test)]
mod test_transaction_pool {
    use super::{InsertResult, TxWithReadyInfo};
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
        }
    }

    #[test]
    fn test_deferred_pool_insert_and_remove() {
        let mut deferred_pool = super::DeferredPool::new();

        // insert txs of same sender
        let alice = Random.generate().unwrap();
        let bob = Random.generate().unwrap();
        let eva = Random.generate().unwrap();

        let alice_tx1 = new_test_tx_with_read_info(&alice, 5, 10, 100, false);
        let alice_tx2 = new_test_tx_with_read_info(&alice, 6, 10, 100, false);
        let bob_tx1 = new_test_tx_with_read_info(&bob, 1, 10, 100, false);
        let bob_tx2 = new_test_tx_with_read_info(&bob, 2, 10, 100, false);
        let bob_tx2_new = new_test_tx_with_read_info(&bob, 2, 11, 100, false);

        assert_eq!(
            deferred_pool.insert(alice_tx1.clone(), false),
            InsertResult::NewAdded
        );

        assert_eq!(deferred_pool.contain_address(&alice.address()), true);

        assert_eq!(deferred_pool.contain_address(&eva.address()), false);

        assert_eq!(deferred_pool.remove_lowest_nonce(&eva.address()), None);

        assert_eq!(deferred_pool.contain_address(&bob.address()), false);

        assert_eq!(
            deferred_pool.insert(alice_tx2.clone(), false),
            InsertResult::NewAdded
        );

        assert_eq!(deferred_pool.remove_lowest_nonce(&bob.address()), None);

        assert_eq!(
            deferred_pool.insert(bob_tx1.clone(), false),
            InsertResult::NewAdded
        );

        assert_eq!(deferred_pool.contain_address(&bob.address()), true);

        assert_eq!(
            deferred_pool.insert(bob_tx2.clone(), false),
            InsertResult::NewAdded
        );

        assert_eq!(
            deferred_pool.insert(bob_tx2_new.clone(), false),
            InsertResult::Updated(bob_tx2.clone())
        );

        assert_eq!(
            deferred_pool.insert(bob_tx2.clone(), false),
            InsertResult::Failed(format!("Tx with same nonce already inserted, try to replace it with a higher gas price"))
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
        let tx1 = new_test_tx_with_read_info(&alice, 5, 10, 10000, true);
        let tx2 = new_test_tx_with_read_info(&alice, 6, 10, 10000, true);
        let tx3 = new_test_tx_with_read_info(&alice, 7, 10, 10000, true);
        let tx4 = new_test_tx_with_read_info(&alice, 8, 10, 10000, false);
        let tx5 = new_test_tx_with_read_info(&alice, 9, 10, 10000, false);
        let exact_cost = 4 * (gas * 10 + 10000);

        deferred_pool.insert(tx1.clone(), false);
        deferred_pool.insert(tx2.clone(), false);
        deferred_pool.insert(tx4.clone(), false);
        deferred_pool.insert(tx5.clone(), false);

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

        deferred_pool.insert(tx3.clone(), false);
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
