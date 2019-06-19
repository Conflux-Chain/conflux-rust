// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod impls;
//mod ready;

#[cfg(test)]
mod tests;

extern crate rand;

pub use self::impls::TreapMap;
//use self::ready::Readiness;
use crate::{
    cache_manager::{CacheId, CacheManager},
    executive,
    pow::WORKER_COMPUTATION_PARALLELISM,
    statedb::StateDb,
    storage::{Storage, StorageManager, StorageManagerTrait},
    vm,
};
use cfx_types::{Address, H256, H512, U256, U512};
use metrics::Gauge;
use parking_lot::{Mutex, RwLock};
use primitives::{
    Account, Action, EpochId, SignedTransaction, TransactionWithSignature,
};
use rlp::*;
use std::{
    collections::{hash_map::HashMap, BTreeMap, VecDeque},
    ops::{Deref, DerefMut},
    sync::{mpsc::channel, Arc},
};
use threadpool::ThreadPool;

lazy_static! {
    static ref TX_POOL_GAUGE: Gauge = Gauge::register("tx_pool_size");
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
            let account = self
                .storage
                .get_account(&address, false)
                .ok()
                .and_then(|x| x);
            if let Some(account) = account {
                self.accounts.insert((*address).clone(), account);
            }
        }
        self.accounts.get_mut(&address)
    }
}

#[derive(Clone, Debug)]
struct TxWithReadyInfo {
    transaction: Arc<SignedTransaction>,
    packed: bool,
}

impl TxWithReadyInfo {
    pub fn is_already_packed(&self) -> bool { self.packed }

    pub fn get_arc_tx(&self) -> &Arc<SignedTransaction> { &self.transaction }

    pub fn replace(&self, x: &Self, force: bool) -> bool {
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

#[derive(Debug)]
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
        if tx.replace(tx_in_pool, force) {
            // replace with higher gas price transaction
            ret = InsertResult::Updated(tx_in_pool.clone());
            *tx_in_pool = tx.clone();
        }
        ret
    }

    #[allow(dead_code)]
    fn get(&self, nonce: &U256) -> Option<TxWithReadyInfo> {
        self.inner.get(nonce).map(|tx| tx.clone())
    }

    #[allow(dead_code)]
    fn get_mut(&mut self, nonce: &U256) -> Option<&mut TxWithReadyInfo> {
        self.inner.get_mut(nonce)
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

    #[allow(dead_code)]
    fn remove(
        &mut self, addr: &Address, nonce: &U256,
    ) -> Option<TxWithReadyInfo> {
        match self.buckets.get_mut(addr) {
            None => None,
            Some(bucket) => {
                let ret = bucket.remove(nonce);
                if bucket.is_empty() {
                    self.buckets.remove(addr);
                }
                ret
            }
        }
    }

    #[allow(dead_code)]
    fn get(&self, addr: &Address, nonce: &U256) -> Option<TxWithReadyInfo> {
        self.buckets.get(addr).and_then(|bucket| bucket.get(nonce))
    }

    #[allow(dead_code)]
    fn get_mut(
        &mut self, addr: &Address, nonce: &U256,
    ) -> Option<&mut TxWithReadyInfo> {
        self.buckets
            .get_mut(addr)
            .and_then(|bucket| bucket.get_mut(nonce))
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
        if let Some(tx) = tx {
            self.insert(tx)
        } else {
            self.remove(address)
        }
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

    fn get_nonce_from_storage(
        &self, address: &Address, account_cache: &mut AccountCache,
    ) -> U256 {
        match account_cache.get_account_mut(address) {
            Some(account) => account.nonce.clone(),
            None => 0.into(),
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
        let ret = self
            .deferred_pool
            .recalculate_readiness_with_local_info(addr, nonce, balance);
        self.ready_account_pool.update(addr, ret);
    }
}

pub struct TransactionPool {
    inner: RwLock<TransactionPoolInner>,
    storage_manager: Arc<StorageManager>,
    pub transaction_pubkey_cache: RwLock<HashMap<H256, Arc<SignedTransaction>>>,
    pub worker_pool: Arc<Mutex<ThreadPool>>,
    cache_man: Arc<Mutex<CacheManager<CacheId>>>,
    spec: vm::Spec,
}

pub type SharedTransactionPool = Arc<TransactionPool>;

impl TransactionPool {
    pub fn with_capacity(
        capacity: usize, storage_manager: Arc<StorageManager>,
        worker_pool: Arc<Mutex<ThreadPool>>,
        cache_man: Arc<Mutex<CacheManager<CacheId>>>,
    ) -> Self
    {
        TransactionPool {
            inner: RwLock::new(TransactionPoolInner::with_capacity(capacity)),
            storage_manager,
            transaction_pubkey_cache: RwLock::new(HashMap::with_capacity(
                capacity,
            )),
            worker_pool,
            cache_man,
            spec: vm::Spec::new_spec(),
        }
    }

    pub fn len(&self) -> usize { self.inner.read().len() }

    pub fn get_transaction(
        &self, tx_hash: &H256,
    ) -> Option<Arc<SignedTransaction>> {
        self.inner.read().get(tx_hash)
    }

    pub fn insert_new_transactions(
        &self, latest_epoch: EpochId,
        transactions: &Vec<TransactionWithSignature>,
    ) -> Vec<Result<H256, String>>
    {
        let mut failures = HashMap::new();

        let uncached_trans: Vec<TransactionWithSignature>;
        {
            let tx_cache = self.transaction_pubkey_cache.read();
            uncached_trans = transactions
                .iter()
                .map(|tx| tx.clone())
                .filter(|tx| {
                    let tx_hash = tx.hash();
                    let inserted = tx_cache.contains_key(&tx_hash);

                    if inserted {
                        failures.insert(
                            tx_hash,
                            "transaction already exists".into(),
                        );
                    }

                    !inserted
                })
                .collect();
        }

        let mut signed_trans = Vec::new();
        if uncached_trans.len() < WORKER_COMPUTATION_PARALLELISM * 8 {
            let mut signed_txes = Vec::new();
            for tx in uncached_trans {
                match tx.recover_public() {
                    Ok(public) => {
                        let signed_tx =
                            Arc::new(SignedTransaction::new(public, tx));
                        signed_txes.push(signed_tx);
                    }
                    Err(e) => {
                        debug!(
                            "Unable to recover the public key of transaction {:?}: {:?}",
                            tx.hash(), e
                        );
                        failures.insert(
                            tx.hash(),
                            format!(
                                "failed to recover the public key: {:?}",
                                e
                            ),
                        );
                    }
                }
            }
            signed_trans.push(signed_txes);
        } else {
            let tx_num = uncached_trans.len();
            let tx_num_per_worker = tx_num / WORKER_COMPUTATION_PARALLELISM;
            let mut remainder =
                tx_num - (tx_num_per_worker * WORKER_COMPUTATION_PARALLELISM);
            let mut start_idx = 0;
            let mut end_idx = 0;
            let mut unsigned_trans = Vec::new();

            for tx in uncached_trans {
                if start_idx == end_idx {
                    // a new segment of transactions
                    end_idx = start_idx + tx_num_per_worker;
                    if remainder > 0 {
                        end_idx += 1;
                        remainder -= 1;
                    }
                    let unsigned_txes = Vec::new();
                    unsigned_trans.push(unsigned_txes);
                }

                unsigned_trans.last_mut().unwrap().push(tx);

                start_idx += 1;
            }

            signed_trans.resize(unsigned_trans.len(), Vec::new());
            let (sender, receiver) = channel();
            let worker_pool = self.worker_pool.lock().clone();
            let mut idx = 0;
            for unsigned_txes in unsigned_trans {
                let sender = sender.clone();
                worker_pool.execute(move || {
                    let mut signed_txes = Vec::new();
                    let mut failed_txes = HashMap::new();
                    for tx in unsigned_txes {
                        match tx.recover_public() {
                            Ok(public) => {
                                let signed_tx = Arc::new(SignedTransaction::new(public, tx));
                                signed_txes.push(signed_tx);
                            }
                            Err(e) => {
                                debug!(
                                    "Unable to recover the public key of transaction {:?}: {:?}",
                                    tx.hash(), e
                                );
                                failed_txes.insert(tx.hash(), format!("failed to recover the public key: {:?}", e));
                            }
                        }
                    }
                    sender.send((idx, (signed_txes, failed_txes))).unwrap();
                });
                idx += 1;
            }
            worker_pool.join();

            for (idx, signed_failed_txes) in
                receiver.iter().take(signed_trans.len())
            {
                signed_trans[idx] = signed_failed_txes.0;

                for (tx_hash, error) in signed_failed_txes.1 {
                    failures.insert(tx_hash, error);
                }
            }
        }

        let mut account_cache = AccountCache::new(
            self.storage_manager.get_state_at(latest_epoch).unwrap(),
        );
        {
            let mut tx_cache = self.transaction_pubkey_cache.write();
            let mut cache_man = self.cache_man.lock();

            let mut inner = self.inner.write();
            let inner = &mut *inner;

            for txes in signed_trans {
                for tx in txes {
                    tx_cache.insert(tx.hash(), tx.clone());
                    cache_man.note_used(CacheId::TransactionPubkey(tx.hash()));
                    if let Err(e) = self.verify_transaction(tx.as_ref()) {
                        warn!("Transaction discarded due to failure of passing verification {:?}: {}", tx.hash(), e);
                        failures.insert(tx.hash(), e);
                        continue;
                    }
                    let hash = tx.hash();
                    match self.add_transaction_and_check_readiness_without_lock(
                        inner,
                        &mut account_cache,
                        tx,
                        false,
                        false,
                    ) {
                        Ok(_) => {}
                        Err(e) => {
                            failures.insert(hash, e);
                        }
                    }
                }
            }
        }
        TX_POOL_GAUGE.update(self.len() as i64);

        transactions
            .iter()
            .map(|tx| {
                let tx_hash = tx.hash();
                match failures.get(&tx_hash) {
                    Some(e) => Err(e.clone()),
                    None => Ok(tx_hash),
                }
            })
            .collect()
    }

    // verify transactions based on the rules that
    // have nothing to do with readiness
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
        let state_nonce =
            inner.get_nonce_from_storage(&transaction.sender, account_cache);

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

        if let InsertResult::Failed(info) = self
            .add_to_deferred_pool_without_lock(
                inner,
                transaction.clone(),
                packed,
                force,
            )
        {
            return Err(format!("Failed imported to deferred pool: {}", info));
        }

        inner.recalculate_readiness_with_state(
            &transaction.sender,
            account_cache,
        );

        Ok(())
    }

    // If a tx is failed executed due to invalid nonce
    // This function should be invoked to recycle it
    pub fn recycle_failed_executed_transactions(
        &self, transactions: Vec<Arc<SignedTransaction>>, state: Storage,
    ) {
        let mut account_cache = AccountCache::new(state);
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();
        for tx in transactions {
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

    fn add_to_deferred_pool_without_lock(
        &self, inner: &mut TransactionPoolInner,
        transaction: Arc<SignedTransaction>, packed: bool, force: bool,
    ) -> InsertResult
    {
        trace!(
            "Insert tx into deferred pool, hash={:?} sender={:?}",
            transaction.hash(),
            transaction.sender
        );
        inner.insert(transaction, packed, force)
    }

    pub fn set_tx_packed(
        &self, transactions: Vec<Arc<SignedTransaction>>, epoch_id: EpochId,
    ) {
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();
        let mut account_cache = AccountCache::new(
            self.storage_manager.get_state_at(epoch_id).unwrap(),
        );
        for tx in transactions {
            self.add_transaction_and_check_readiness_without_lock(
                inner,
                &mut account_cache,
                tx,
                true,
                false,
            )
            .ok();
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
            inner.recalculate_readiness_with_local_info(&tx.sender());

            if packed_transactions.len() >= num_txs {
                break 'out;
            }
        }

        for tx in too_big_txs {
            inner.ready_account_pool.insert(tx);
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

    pub fn transactions_to_propagate(&self) -> Vec<Arc<SignedTransaction>> {
        let _inner = self.inner.read();
        unimplemented!()
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
}

#[cfg(test)]
mod tests2 {
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

    #[test]
    fn test_nonce_pool_new_added() {
        let mut nonce_pool = super::NoncePool::new();

        // insert txs of same sender
        let sender1 = Random.generate().unwrap();
        let tx11 = new_test_tx(&sender1, 5, 10, 100);
        assert_eq!(
            nonce_pool.insert(tx11.clone()),
            super::InsertResult::NewAdded
        );
        let tx12 = new_test_tx(&sender1, 6, 10, 100);
        assert_eq!(
            nonce_pool.insert(tx12.clone()),
            super::InsertResult::NewAdded
        );

        // insert txs of different sender
        let sender2 = Random.generate().unwrap();
        let tx21 = new_test_tx(&sender2, 5, 10, 100);
        assert_eq!(
            nonce_pool.insert(tx21.clone()),
            super::InsertResult::NewAdded
        );

        // could get all txs with valid sender address and nonce
        assert_eq!(
            nonce_pool.get(&tx11.sender, &tx11.nonce),
            Some(tx11.clone())
        );
        assert_eq!(
            nonce_pool.get(&tx12.sender, &tx12.nonce),
            Some(tx12.clone())
        );
        assert_eq!(
            nonce_pool.get(&tx21.sender, &tx21.nonce),
            Some(tx21.clone())
        );

        // could remove txs with valid sender address and nonce
        assert_eq!(
            nonce_pool.remove(&tx21.sender, &tx21.nonce),
            Some(tx21.clone())
        );
        assert_eq!(
            nonce_pool.remove(&tx12.sender, &tx12.nonce),
            Some(tx12.clone())
        );

        // could not remove or get txs with invalid sender address and nonce
        assert_eq!(nonce_pool.remove(&tx21.sender, &tx21.nonce), None);
        assert_eq!(nonce_pool.remove(&tx12.sender, &tx12.nonce), None);
        assert_eq!(nonce_pool.get(&tx12.sender, &tx12.nonce), None);
        assert_eq!(nonce_pool.get(&tx21.sender, &tx21.nonce), None);
    }

    #[test]
    fn test_nonce_pool_update() {
        let mut pool = super::NoncePool::new();

        let sender = Random.generate().unwrap();
        let tx = new_test_tx(&sender, 5, 10, 100);
        assert_eq!(pool.insert(tx.clone()), super::InsertResult::NewAdded);
        assert_eq!(pool.get(&tx.sender, &tx.nonce), Some(tx.clone()));

        // insert duplicated tx
        assert_eq!(pool.insert(tx.clone()), super::InsertResult::Failed);

        // update with lower gas price tx
        let tx2 = new_test_tx(&sender, 5, 9, 100);
        assert_eq!(pool.insert(tx2.clone()), super::InsertResult::Failed);
        assert_eq!(pool.get(&tx2.sender, &tx2.nonce), Some(tx.clone()));

        // update with higher gas price tx
        let tx3 = new_test_tx(&sender, 5, 11, 100);
        assert_eq!(
            pool.insert(tx3.clone()),
            super::InsertResult::Updated(tx.clone())
        );
        assert_eq!(pool.get(&tx3.sender, &tx3.nonce), Some(tx3.clone()));
        assert_eq!(pool.get(&tx.sender, &tx.nonce), Some(tx3.clone()));
    }
    /*
        #[test]
        fn test_pending_pool() {
            let mut pool = super::UnconfirmedTransactions::new();
            assert_eq!(pool.pending_pool_size(), 0);

            // new added tx
            let sender = Random.generate().unwrap();
            let tx = new_test_tx(&sender, 5, 10, 100);
            assert!(pool.insert(tx.clone()));
            assert_eq!(pool.pending_pool_size(), 1);
            assert_eq!(pool.get_mut(&tx.sender, &tx.nonce), Some(tx.clone()));
            assert_eq!(pool.get_by_hash(&tx.hash()), Some(tx.clone()));

            // new added tx of different nonce
            let tx2 = new_test_tx(&sender, 6, 10, 100);
            assert!(pool.insert(tx2.clone()));
            assert_eq!(pool.pending_pool_size(), 2);
            assert_eq!(pool.remove(&tx2.sender, &tx2.nonce), Some(tx2.clone()));
            assert_eq!(pool.pending_pool_size(), 1);

            // update tx with lower gas price
            let tx3 = new_test_tx(&sender, 5, 9, 100);
            assert!(!pool.insert(tx3.clone()));
            assert_eq!(pool.pending_pool_size(), 1);

            // update tx with higher gas price
            let tx4 = new_test_tx(&sender, 5, 11, 100);
            assert!(pool.insert(tx4.clone()));
            assert_eq!(pool.pending_pool_size(), 1);
            assert_eq!(pool.get_mut(&tx.sender, &tx.nonce), Some(tx4.clone()));
            assert_eq!(pool.get_by_hash(&tx.hash()), None);
            assert_eq!(pool.get_by_hash(&tx4.hash()), Some(tx4.clone()));
        }
    */
    #[test]
    fn test_ready_pool() {
        let mut pool = super::ReadyTransactionPool::new();
        assert_eq!(pool.len(), 0);

        // new added tx
        let sender = Random.generate().unwrap();
        let tx = new_test_tx(&sender, 5, 10, 100);
        assert!(pool.insert(tx.clone()));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.get(&tx.hash()), Some(tx.clone()));
        assert_eq!(pool.get_by_nonce(&tx.sender, &tx.nonce), Some(tx.clone()));

        // update tx with lower gas price
        let tx2 = new_test_tx(&sender, 5, 9, 100);
        assert!(!pool.insert(tx2.clone()));
        assert_eq!(pool.len(), 1);

        // update tx with higher gas price
        let tx3 = new_test_tx(&sender, 5, 11, 100);
        assert!(pool.insert(tx3.clone()));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.get_by_nonce(&tx.sender, &tx.nonce), Some(tx3.clone()));
        assert_eq!(pool.get(&tx.hash()), None);
        assert_eq!(pool.get(&tx3.hash()), Some(tx3.clone()));
    }
}
