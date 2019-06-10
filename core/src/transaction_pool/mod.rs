// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod impls;
mod ready;

#[cfg(test)]
mod tests;

extern crate rand;

pub use self::impls::TreapMap;
use self::ready::Readiness;
use crate::{
    cache_manager::{CacheId, CacheManager},
    executive,
    pow::WORKER_COMPUTATION_PARALLELISM,
    state::State,
    statedb::StateDb,
    storage::{Storage, StorageManager, StorageManagerTrait},
    vm,
};
use cfx_types::{Address, H256, H512, U256, U512};
use metrics::Gauge;
use parking_lot::{Mutex, RwLock};
use primitives::{
    Account, Action, EpochId, SignedTransaction, TransactionAddress,
    TransactionWithSignature,
};
use rlp::*;
use std::{
    cmp::{min, Ordering},
    collections::{hash_map::HashMap, BTreeMap, HashSet, VecDeque},
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
                self.accounts.insert(address.clone(), account);
            }
        }
        self.accounts.get_mut(&address)
    }

    fn is_ready(&mut self, tx: &SignedTransaction) -> Readiness {
        let sender = tx.sender();
        let account = self.get_account_mut(&sender);
        if let Some(account) = account {
            match tx.nonce().cmp(&account.nonce) {
                Ordering::Greater => {
                    if (tx.nonce() - account.nonce)
                        > FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET.into()
                    {
                        Readiness::TooDistantFuture
                    } else {
                        Readiness::Future
                    }
                }
                Ordering::Less => Readiness::Stale,
                Ordering::Equal => Readiness::Ready,
            }
        } else {
            if tx.nonce() > FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET.into() {
                Readiness::TooDistantFuture
            } else {
                // TODO: when tx.nonce == 0, we should check if the transaction
                // is receiver paid.
                if tx.nonce == 0.into() {
                    debug!("Transaction from empty account: {:?}.", tx);
                }
                Readiness::Future
            }
        }
    }
}

trait TxTypeTrait : Clone /*+ Debug */+ Send + Sync + Deref<Target = SignedTransaction> {
    fn replaces(&self, x: &Self) -> bool;
}

impl TxTypeTrait for Arc<SignedTransaction> {
    fn replaces(&self, x: &Self) -> bool { self.gas_price > x.gas_price }
}

#[derive(Clone, Debug)]
struct TxWithPackedMarkAndCachedBalance(Arc<SignedTransaction>, bool, U256);

impl TxWithPackedMarkAndCachedBalance {
    pub fn is_already_packed(&self) -> bool { self.1 }

    pub fn get_arc_tx(&self) -> &Arc<SignedTransaction> { &self.0 }

    pub fn get_cached_account_balance_before_tx(&self) -> &U256 { &self.2 }

    pub fn get_cached_account_balance_before_tx_mut(&mut self) -> &mut U256 {
        &mut self.2
    }
}

impl Deref for TxWithPackedMarkAndCachedBalance {
    type Target = SignedTransaction;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl TxTypeTrait for TxWithPackedMarkAndCachedBalance {
    fn replaces(&self, x: &Self) -> bool {
        !x.is_already_packed()
            && (self.is_already_packed()
                || self.get_arc_tx().replaces(x.get_arc_tx()))
    }
}

#[derive(Debug, PartialEq)]
enum InsertResult<TxType: TxTypeTrait> {
    /// new item added
    NewAdded,
    /// failed to update with lower gas price tx
    Failed,
    /// succeeded to update with higher gas price tx
    Updated(TxType),
}

struct NoncePool<TxType: TxTypeTrait> {
    buckets: HashMap<Address, BTreeMap<U256, TxType>>,
}

impl<TxType: TxTypeTrait> NoncePool<TxType> {
    fn new() -> Self {
        NoncePool {
            buckets: Default::default(),
        }
    }

    fn insert(&mut self, tx: TxType) -> InsertResult<TxType> {
        let bucket =
            self.buckets.entry(tx.sender).or_insert(Default::default());

        let mut ret = if bucket.contains_key(&tx.nonce) {
            InsertResult::Failed
        } else {
            InsertResult::NewAdded
        };

        let tx_in_pool = bucket.entry(tx.nonce).or_insert(tx.clone());
        if tx.replaces(tx_in_pool) {
            // replace with higher gas price transaction
            ret = InsertResult::Updated(tx_in_pool.clone());
            *tx_in_pool = tx.clone();
        }

        ret
    }

    fn remove_below(
        &mut self, addr: &Address, nonce: &U256,
    ) -> (Vec<H256>, bool) {
        let mut result = (vec![], false);

        match self.buckets.get_mut(addr) {
            None => {}
            Some(bucket) => {
                let nonces_to_delete = bucket
                    .range(&0.into()..nonce)
                    .map(|(key, _)| *key)
                    .collect::<Vec<_>>();

                for nonce in nonces_to_delete {
                    match bucket.remove(&nonce) {
                        Some(tx) => {
                            result.0.push(tx.hash);
                        }
                        None => {}
                    }
                }

                if bucket.is_empty() {
                    self.buckets.remove(addr);
                    result.1 = true;
                }
            }
        }

        result
    }

    fn remove(&mut self, addr: &Address, nonce: &U256) -> Option<TxType> {
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

    fn get(&self, addr: &Address, nonce: &U256) -> Option<TxType> {
        self.buckets
            .get(addr)
            .and_then(|bucket| bucket.get(nonce))
            .map(|tx| tx.clone())
    }

    fn get_mut(&mut self, addr: &Address, nonce: &U256) -> Option<&mut TxType> {
        self.buckets
            .get_mut(addr)
            .and_then(|bucket| bucket.get_mut(nonce))
    }

    fn get_lowest_nonce_transaction(
        &self, addr: &Address,
    ) -> Option<(&U256, &TxType)> {
        self.buckets
            .get(addr)
            .and_then(|bucket| bucket.iter().next())
    }
}

struct UnexecutedTransactions {
    nonce_pool: NoncePool<TxWithPackedMarkAndCachedBalance>,
    ready_nonces_and_balances: HashMap<Address, (U256, U256)>,
    txs: HashMap<H256, Arc<SignedTransaction>>,
    recent_states_accounts: VecDeque<HashMap<Address, U256>>,
    recent_states_accounts_nonces: HashMap<Address, VecDeque<U256>>,
    number_packed_txs: usize,
}

impl UnexecutedTransactions {
    const KEEP_NONCE_AT_OLD_STATE: usize = 100;

    fn new() -> Self {
        UnexecutedTransactions {
            nonce_pool: NoncePool::new(),
            ready_nonces_and_balances: Default::default(),
            txs: HashMap::new(),
            recent_states_accounts: Default::default(),
            recent_states_accounts_nonces: Default::default(),
            number_packed_txs: 0,
        }
    }

    pub fn number_packed_txs(&self) -> usize { self.number_packed_txs }

    fn pending_pool_size(&self) -> usize {
        self.txs.len() - self.number_packed_txs
    }

    pub fn notify_state_start(&mut self) {
        let mut removed_txs = 0;
        // FIXME: Use a better way than this Self::KEEP_NONCE_AT_OLD_STATE.
        // FIXME: maybe maintain a difference of known transactions and transactions that
        // FIXME: already packed in pivot-chain (with deferred state). When deferred pivot
        // FIXME: changes maintain transaction pool.
        if self.recent_states_accounts.len() > Self::KEEP_NONCE_AT_OLD_STATE {
            match self.recent_states_accounts.pop_front() {
                None => {}
                Some(old_state_accounts) => {
                    for (address, _nonce) in old_state_accounts {
                        // FIXME: Maintenance of self.recent_states_accounts_nonces is forgotten.
                        // FIXME: this is why the code below doesn't run.
                        // FIXME: Note that we should fix the counting of
                        // FIXME: total transactions packed by chain as well.
                        match self
                            .recent_states_accounts_nonces
                            .get_mut(&address)
                        {
                            None => {}
                            Some(nonces) => {
                                // Unwrap is safe here because it's guaranteed
                                // to exist.
                                let oldest_nonce = nonces
                                    .iter()
                                    .min_by_key(|x| *x)
                                    .unwrap()
                                    .clone();
                                let (removed_tx_hashes, address_cleared) = self
                                    .nonce_pool
                                    .remove_below(&address, &oldest_nonce);
                                if address_cleared {
                                    self.ready_nonces_and_balances
                                        .remove(&address);
                                }
                                removed_txs += removed_tx_hashes.len();
                                for hash in removed_tx_hashes {
                                    self.txs.remove(&hash);
                                }

                                // Remove old account nonce data.
                                nonces.pop_front();
                            }
                        }
                    }
                }
            }
        }

        debug!("Removed {} old txs from transaction pool.", removed_txs);
        self.recent_states_accounts.push_back(Default::default());
    }

    pub fn notify_state_account(&mut self, address: Address, nonce: U256) {
        match self.recent_states_accounts.back_mut() {
            None => {
                unreachable!();
            }
            Some(ref mut last_state) => match last_state.get(&address) {
                Some(largest_nonce) => {
                    if nonce.gt(largest_nonce) {
                        last_state.insert(address, nonce);
                    }
                }
                None => {
                    last_state.insert(address, nonce);
                }
            },
        }
    }

    fn insert(&mut self, tx: Arc<SignedTransaction>, packed: bool) -> bool {
        let balance = match self.nonce_pool.get_mut(&tx.sender, &tx.nonce) {
            Some(tx) => tx.get_cached_account_balance_before_tx().clone(),
            None => 0.into(),
        };

        let result = match self.nonce_pool.insert(
            TxWithPackedMarkAndCachedBalance(tx.clone(), packed, balance),
        ) {
            InsertResult::NewAdded => {
                self.txs.entry(tx.hash()).or_insert(tx.clone());
                true
            }
            InsertResult::Failed => false,
            InsertResult::Updated(old_tx) => {
                self.txs.remove(&old_tx.hash());
                self.txs.insert(tx.hash(), tx.clone());
                true
            }
        };

        if packed && result {
            self.number_packed_txs += 1;
        }

        result
    }

    pub fn get_mut(
        &mut self, address: &Address, nonce: &U256,
    ) -> Option<&mut TxWithPackedMarkAndCachedBalance> {
        self.nonce_pool.get_mut(address, nonce)
    }

    fn get_by_hash(&self, tx_hash: &H256) -> Option<Arc<SignedTransaction>> {
        self.txs.get(tx_hash).map(|tx| tx.clone())
    }

    fn get_balance_and_nonce_info(
        &self, address: &Address,
    ) -> Option<&(U256, U256)> {
        self.ready_nonces_and_balances.get(address)
    }

    fn get_cached_balance_and_nonce_info(
        &self, address: &Address, account_cache: &mut AccountCache,
    ) -> (U256, U256) {
        match self.get_balance_and_nonce_info(address) {
            Some(info) => info.clone(),
            None => match account_cache.get_account_mut(address) {
                Some(account) => {
                    (account.nonce.clone(), account.balance.clone())
                }
                None => (0.into(), 0.into()),
            },
        }
    }
}

struct ReadyTransactionPool {
    nonce_pool: NoncePool<Arc<SignedTransaction>>,
    treap: TreapMap<H256, Arc<SignedTransaction>, U512>,
}

impl ReadyTransactionPool {
    fn new() -> Self {
        ReadyTransactionPool {
            nonce_pool: NoncePool::new(),
            treap: TreapMap::new(),
        }
    }

    fn len(&self) -> usize { self.treap.len() }

    fn get(&self, tx_hash: &H256) -> Option<Arc<SignedTransaction>> {
        self.treap.get(tx_hash).map(|tx| tx.clone())
    }

    pub fn get_by_nonce(
        &self, address: &Address, nonce: &U256,
    ) -> Option<Arc<SignedTransaction>> {
        self.nonce_pool.get(address, nonce)
    }

    fn remove(
        &mut self, address: &Address, nonce: &U256,
    ) -> Option<Arc<SignedTransaction>> {
        let result = self.nonce_pool.remove(address, nonce);
        match result {
            Some(ref tx) => {
                self.treap.remove(&tx.hash);
            }
            None => {}
        }

        result
    }

    fn remove_below(&mut self, address: &Address, nonce: &U256) {
        let (tx_hashes, _empty_after_removal) =
            self.nonce_pool.remove_below(address, nonce);
        for hash in tx_hashes {
            self.treap.remove(&hash);
        }
    }

    fn remove_by_hash(
        &mut self, tx_hash: &H256,
    ) -> Option<Arc<SignedTransaction>> {
        self.treap
            .remove(tx_hash)
            .and_then(|tx| self.nonce_pool.remove(&tx.sender, &tx.nonce))
    }

    fn insert(&mut self, tx: Arc<SignedTransaction>) -> bool {
        match self.nonce_pool.insert(tx.clone()) {
            InsertResult::NewAdded => {
                self.treap.insert(
                    tx.hash(),
                    tx.clone(),
                    U512::from(tx.gas_price),
                );
                true
            }
            InsertResult::Failed => false,
            InsertResult::Updated(old_tx) => {
                self.treap.remove(&old_tx.hash());
                self.treap.insert(
                    tx.hash(),
                    tx.clone(),
                    U512::from(tx.gas_price),
                );
                true
            }
        }
    }

    // FIXME: remove debug method.
    fn _assert_nonce_consecutive(&self, address: &Address) {
        match self.nonce_pool.buckets.get(address) {
            Some(bucket) => {
                let mut iter = bucket.iter();
                match iter.next() {
                    Some((start_nonce, _)) => {
                        let mut prev_nonce = start_nonce;
                        while let Some((nonce, _)) = iter.next() {
                            let expected = *prev_nonce + U256::from(1);
                            assert_eq!(
                                *nonce, expected,
                                "assert nonce failed for {:?}, start_nonce = {}, missing = {}, next = {}",
                                address, start_nonce, expected, nonce
                            );
                            prev_nonce = nonce;
                        }
                    }
                    None => {}
                }
            }
            None => {}
        }
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

        self.remove_by_hash(&tx.hash())
    }
}

pub struct TransactionPoolInner {
    unexecuted_txs: UnexecutedTransactions,
    ready_transactions: ReadyTransactionPool,
}

impl TransactionPoolInner {
    pub fn new() -> Self {
        TransactionPoolInner {
            unexecuted_txs: UnexecutedTransactions::new(),
            ready_transactions: ReadyTransactionPool::new(),
        }
    }

    // The size of unconfirmed txs. Not exact same as pending pool size.
    pub fn len(&self) -> usize { self.unexecuted_txs.txs.len() }

    fn get(&self, tx_hash: &H256) -> Option<Arc<SignedTransaction>> {
        self.ready_transactions
            .get(tx_hash)
            .or_else(|| self.unexecuted_txs.get_by_hash(tx_hash))
    }
}

pub struct TransactionPool {
    capacity: usize,
    inner: RwLock<TransactionPoolInner>,
    storage_manager: Arc<StorageManager>,
    pub transaction_pubkey_cache: RwLock<HashMap<H256, Arc<SignedTransaction>>>,
    pub unexecuted_transaction_addresses:
        Mutex<HashMap<H256, HashSet<TransactionAddress>>>,
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
            capacity,
            inner: RwLock::new(TransactionPoolInner::new()),
            storage_manager,
            // TODO Cache capacity should be set seperately
            transaction_pubkey_cache: RwLock::new(HashMap::with_capacity(
                capacity,
            )),
            unexecuted_transaction_addresses: Mutex::new(HashMap::new()),
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
        // FIXME: do not unwrap.
        let mut failures = HashMap::new();

        let uncached_trans: Vec<TransactionWithSignature>;
        {
            let tx_cache = self.transaction_pubkey_cache.read();
            let unexecuted_transaction_addresses =
                self.unexecuted_transaction_addresses.lock();
            uncached_trans = transactions
                .iter()
                .map(|tx| tx.clone())
                .filter(|tx| {
                    let tx_hash = tx.hash();
                    // Sample 1/128 transactions
                    if tx_hash[0] & 254 == 0 {
                        debug!("Sampled transaction {:?}", tx_hash);
                    }
                    let inserted = tx_cache.contains_key(&tx_hash)
                        || unexecuted_transaction_addresses
                            .contains_key(&tx_hash);

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

    // Only call this method when nonce matches.
    // The second step verification for ready transactions
    fn verify_ready_transaction(
        &self, next_nonce: &mut U256, account_balance: &mut U256,
        transaction: &SignedTransaction,
    ) -> bool
    {
        // check balance
        let cost = transaction.value + transaction.gas_price * transaction.gas;
        if account_balance.deref().lt(&cost) {
            // FIXME: change back to trace,
            trace!(
                "Transaction {:?} not ready due to not enough balance: {} < {}",
                transaction,
                //transaction.hash(),
                account_balance,
                cost
            );
            return false;
        }
        *account_balance -= cost;
        *next_nonce += 1.into();
        true
    }

    pub fn add_transaction_and_check_readiness_without_lock(
        &self, inner: &mut TransactionPoolInner,
        account_cache: &mut AccountCache, transaction: Arc<SignedTransaction>,
    ) -> Result<(), String>
    {
        // FIXME: remove the cap check in experiment.
        /*
        if self.capacity <= inner.len() {
            warn!("Transaction discarded due to insufficient txpool capacity: {:?}", transaction.hash());
            return Err(format!("Transaction discarded due to insufficient txpool capacity: {:?}", transaction.hash()));
        }
        */

        // Now the balance is updated. For the new transaction we check if: it's
        // new; its nonce is ready to be packed, the balance at the
        // transaction; when the pending pool can not tell if the nonce
        // is ready to be packed, e.g. the pending pool doesn't contain
        // any packed transaction, account_cached's nonce and balance is
        // used.
        let (mut next_nonce, mut balance) =
            inner.unexecuted_txs.get_cached_balance_and_nonce_info(
                &transaction.sender,
                account_cache,
            );

        if transaction.nonce
            >= next_nonce + U256::from(FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET)
        {
            debug!(
                "Transaction {:?} is discarded due to in too distant future",
                transaction.hash()
            );
            return Err(format!(
                "Transaction {:?} is discarded due to in too distant future",
                transaction.hash()
            ));
        }

        /*
            else if transaction.nonce <= inner.unconfirmed_txs.nonce_pool.get_lowest_nonce_transaction(&transaction.sender) {
            // FIXME: this log is unnecessary.
            debug!(
                "Transaction {:?} is discarded due to stale nonce",
                transaction.hash()
            );
            return Err(format!(
                "Transaction {:?} is discarded due to stale nonce",
                transaction.hash()
            ))
        }
        */

        if !self.add_pending_without_lock(inner, transaction.clone(), false) {
            return Err(format!("Failed imported to pending queue"));
        }

        if transaction.nonce == next_nonce {
            self.recalculate_ready_without_lock(
                inner,
                &transaction.sender,
                &mut next_nonce,
                &mut balance,
                false,
            );

            if next_nonce == transaction.nonce {
                debug!(
                    "new transaction is not ready because of insufficient \
                     balance. See previous log. {:?}",
                    transaction.hash()
                );
                return Err(format!(
                    "Transaction is not ready because of insufficient balance."
                ));
            }
        } else if next_nonce < transaction.nonce {
            trace!("new transaction is not ready because nonce {} > ready nonce {}, sender {:?}. tx_hash {:?}",
                   transaction.nonce, next_nonce, transaction.sender, transaction.hash());
            return Err(format!("Transaction is not ready because of nonce."));
        } else {
            next_nonce = transaction.nonce.clone();
            balance = inner
                .unexecuted_txs
                .get_mut(&transaction.sender, &transaction.nonce)
                .unwrap()
                .get_cached_account_balance_before_tx()
                .clone();

            // Replace the old transaction from ready pool first,
            inner.ready_transactions.insert(transaction.clone());

            // Replacing a pending transaction with higher gas price.
            // May need to take out some transactions from ready pool!
            self.recalculate_ready_without_lock(
                inner,
                &transaction.sender,
                &mut next_nonce,
                &mut balance,
                false,
            )
        }

        Ok(())
    }

    // FIXME: remove unused methods.
    pub fn _add_ready(&self, transaction: Arc<SignedTransaction>) -> bool {
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();
        self._add_ready_without_lock(inner, transaction)
    }

    pub fn _add_ready_without_lock(
        &self, inner: &mut TransactionPoolInner,
        transaction: Arc<SignedTransaction>,
    ) -> bool
    {
        trace!(
            "Insert tx into ready hash={:?} sender={:?}",
            transaction.hash(),
            transaction.sender
        );
        let result = inner.ready_transactions.insert(transaction.clone());
        if !result {
            match inner
                .ready_transactions
                .get_by_nonce(&transaction.sender, &transaction.nonce)
            {
                Some(existing_transaction) => {
                    if existing_transaction.hash() != transaction.hash() {
                        debug!(
                            "can not insert transaction {:?} because of existing transaction {:?}",
                            existing_transaction.deref(), transaction.deref()
                        );
                    }
                }
                None => {
                    debug!("can not happen.");
                }
            }
        }

        result
    }

    // TODO: unused.
    pub fn _add_pending(&self, transaction: Arc<SignedTransaction>) -> bool {
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();
        self.add_pending_without_lock(inner, transaction, false)
    }

    // TODO: maybe use a better name? The transactions here are transactions
    // TODO: with invalid nonce found by block execution.
    pub fn recycle_future_transactions(
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
            )
            .ok();
        }
    }

    pub fn add_pending_without_lock(
        &self, inner: &mut TransactionPoolInner,
        transaction: Arc<SignedTransaction>, packed: bool,
    ) -> bool
    {
        trace!(
            "Insert tx into pending hash={:?} sender={:?}",
            transaction.hash(),
            transaction.sender
        );
        inner.unexecuted_txs.insert(transaction, packed)
    }

    // FIXME: I noticed that the order of ready transaction removal may be
    // FIXME: behind the state execution, which is weird. Moving the caller
    // FIXME: to the end of on_new_block may crash _assert_nonce_consecutive
    // easier.
    pub fn set_tx_stale_for_ready(&self, transaction: Arc<SignedTransaction>) {
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();
        self.add_pending_without_lock(inner, transaction.clone(), true);
        // FIXME: this is a temporary workaround for the issue explained above.
        // FIXME: similar workaround can be found in notify_ready.
        self.remove_lower_nonces_from_ready_pool_without_lock(
            inner,
            &transaction.sender,
            &(transaction.nonce + U256::from(1)),
        );

        match inner
            .unexecuted_txs
            .get_balance_and_nonce_info(&transaction.sender)
            .cloned()
        {
            Some(mut nonce_info) => {
                if transaction.nonce.eq(&nonce_info.0) {
                    self.recalculate_ready_without_lock(
                        inner,
                        &transaction.sender,
                        &mut nonce_info.0,
                        &mut nonce_info.1,
                        false,
                    );
                }
            }
            None => {}
        }
    }

    pub fn remove_lower_nonces_from_ready_pool_without_lock(
        &self, inner: &mut TransactionPoolInner, address: &Address,
        nonce: &U256,
    )
    {
        inner.ready_transactions.remove_below(address, nonce);
    }

    // TODO: Unused. think about when/how to use this method.
    pub fn _remove_confirmed_tx(
        &self, transaction: &SignedTransaction,
    ) -> bool {
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();
        if self
            .remove_pending_without_lock(inner, transaction)
            .is_some()
        {
            true
        } else {
            false
        }
    }

    pub fn remove_pending_without_lock(
        &self, _inner: &mut TransactionPoolInner,
        _transaction: &SignedTransaction,
    ) -> Option<Arc<SignedTransaction>>
    {
        None
    }

    /// pack at most num_txs transactions randomly
    pub fn pack_transactions<'a>(
        &self, num_txs: usize, block_gas_limit: U256, block_size_limit: usize,
        _state: State<'a>,
    ) -> Vec<Arc<SignedTransaction>>
    {
        let mut _inner = self.inner.write();
        let mut packed_transactions: Vec<Arc<SignedTransaction>> = Vec::new();
        if num_txs == 0 {
            return packed_transactions;
        }
        let mut inner = self.inner.write();
        let num_txs = min(num_txs, inner.ready_transactions.len());
        let mut nonce_map = HashMap::new();
        let mut future_txs = HashMap::new();
        debug!(
            "Before packing ready pool size:{}, pending pool size:{}",
            inner.ready_transactions.len(),
            inner.unexecuted_txs.pending_pool_size()
        );

        let mut total_tx_gas_limit: U256 = 0.into();
        let mut total_tx_size: usize = 0;

        let mut big_tx_resample_times_limit = 10;

        // FIXME: the sampling should be per account.
        'out: while let Some(tx) = inner.ready_transactions.pop() {
            let sender = tx.sender;
            // Get the nonce to pack from ready pool.
            // FIXME: should use state balance to determine the end nonce range.
            let rest_lowest_nonce_tx_from_same_sender = inner
                .ready_transactions
                .nonce_pool
                .get_lowest_nonce_transaction(&sender);
            let lowest_nonce_in_ready_pool =
                match rest_lowest_nonce_tx_from_same_sender {
                    Some((nonce, _tx)) => {
                        if nonce.lt(&tx.nonce) {
                            nonce.clone()
                        } else {
                            tx.nonce.clone()
                        }
                    }
                    None => tx.nonce.clone(),
                };
            let nonce_entry = nonce_map.entry(tx.sender);
            let nonce = nonce_entry.or_insert(lowest_nonce_in_ready_pool);
            if tx.nonce > *nonce {
                future_txs
                    .entry(sender)
                    .or_insert(HashMap::new())
                    .insert(tx.nonce, tx);
            } else if tx.nonce == *nonce {
                let tx_size = tx.rlp_size();
                if block_gas_limit - total_tx_gas_limit < *tx.gas_limit()
                    || block_size_limit - total_tx_size < tx_size
                {
                    future_txs
                        .entry(sender)
                        .or_insert(HashMap::new())
                        .insert(tx.nonce, tx);
                    if big_tx_resample_times_limit > 0 {
                        big_tx_resample_times_limit -= 1;
                        continue 'out;
                    } else {
                        break 'out;
                    }
                }

                total_tx_gas_limit += *tx.gas_limit();
                total_tx_size += tx_size;

                *nonce += 1.into();
                packed_transactions.push(tx);

                if packed_transactions.len() >= num_txs {
                    break 'out;
                }

                if let Some(tx_map) = future_txs.get_mut(&sender) {
                    while let Some(tx) = tx_map.remove(nonce) {
                        let tx_size = tx.rlp_size();
                        if block_gas_limit - total_tx_gas_limit
                            < *tx.gas_limit()
                            || block_size_limit - total_tx_size < tx_size
                        {
                            tx_map.insert(tx.nonce, tx);
                            if big_tx_resample_times_limit > 0 {
                                big_tx_resample_times_limit -= 1;
                                continue 'out;
                            } else {
                                break 'out;
                            }
                        }

                        total_tx_gas_limit += *tx.gas_limit();
                        total_tx_size += tx_size;

                        packed_transactions.push(tx);
                        *nonce += 1.into();

                        if packed_transactions.len() >= num_txs {
                            break 'out;
                        }
                    }
                }
            } else {
                debug!(
                    "Ready tx nonce below state nonce, drop transaction {:?} \
                     from ready_transactions",
                    tx.clone(),
                )
            }
        }

        for tx in packed_transactions.iter() {
            inner.ready_transactions.insert(tx.clone());
        }

        for (_, txs) in future_txs.into_iter() {
            for (_, tx) in txs.into_iter() {
                inner.ready_transactions.insert(tx.clone());
            }
        }

        if log::max_level() >= log::Level::Debug {
            let mut rlp_s = RlpStream::new();
            for tx in &packed_transactions {
                rlp_s.append::<TransactionWithSignature>(&**tx);
            }
            debug!(
                "After packing ready pool size:{}, pending pool size:{}, packed_transactions: {}, \
                rlp size: {}, total txs received {}, total txs packed by chain {}",
                inner.ready_transactions.len(),
                inner.unexecuted_txs.pending_pool_size(),
                packed_transactions.len(),
                rlp_s.out().len(),
                // FIXME: use correct counter to get total number of txs received.
                inner.len(),
                inner.unexecuted_txs.number_packed_txs(),
            );
        }

        packed_transactions
    }

    pub fn transactions_to_propagate(&self) -> Vec<Arc<SignedTransaction>> {
        let inner = self.inner.read();

        inner
            .unexecuted_txs
            .nonce_pool
            .buckets
            .values()
            .flat_map(|nonce_map| nonce_map.values())
            .filter_map(|x| {
                if x.is_already_packed() {
                    None
                } else {
                    Some(x.get_arc_tx().clone())
                }
            })
            .collect()
    }

    pub fn notify_state_start(&self, accounts_from_execution: Vec<Account>) {
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();
        inner.unexecuted_txs.notify_state_start();

        for account in &accounts_from_execution {
            self.notify_ready(inner, &account.address, account);
        }
    }

    // TODO: In the final version we must check for all block if their nonce
    // TODO: sequence is correct before issuing any notify_ready call.
    pub fn notify_ready(
        &self, inner: &mut TransactionPoolInner, address: &Address,
        account: &Account,
    )
    {
        // FIXME: this is wrong. we can only remove what being packed.

        // FIXME: to overcome the deliver order issue,
        // FIXME: we remove all lower nonces in ready_pool, to prevent gap from
        // FIXME: being introduced into ready pool.
        match inner
            .ready_transactions
            .nonce_pool
            .get_lowest_nonce_transaction(address)
        {
            Some((nonce, _)) => {
                if nonce.lt(&account.nonce) {
                    debug!(
                        "remove lower nonce for address {:?} nonce {:?} from ready pool by\
                        block execution result, which should not happen.",
                        address, account.nonce,
                    );
                    self.remove_lower_nonces_from_ready_pool_without_lock(
                        inner,
                        address,
                        &account.nonce,
                    );
                }
            }
            None => {}
        }
        // In this case we check if there are unpacked transaction that are
        // waiting to be packed, and if the balance really need
        // to be updated.
        //
        // We check for the highest consecutive nonce for the account and
        // see if there is any unpacked transaction. But for
        // balance update we should still process from the nonce
        // of the state.
        //
        // Conclusion: Do checking the balance at the nonce first, if
        // performance isn't good, check for unpacked
        // transaction to avoid useless account balance update?
        match inner.unexecuted_txs.get_mut(address, &account.nonce) {
            Some(tx) => {
                if tx
                    .get_cached_account_balance_before_tx()
                    .gt(&account.balance)
                {
                    // No need to update the ready pool when the pool is still
                    // recent.
                    return;
                }
            }
            None => {
                // No transaction to pack immediately, nothing to do.
                return;
            }
        }

        self.recalculate_ready_without_lock(
            inner,
            address,
            &mut account.nonce.clone(),
            &mut account.balance.clone(),
            true,
        );
    }

    fn recalculate_ready_without_lock(
        &self, inner: &mut TransactionPoolInner, address: &Address,
        next_nonce: &mut U256, account_balance: &mut U256,
        from_block_execution: bool,
    )
    {
        let mut start_nonce = next_nonce.clone();

        if from_block_execution {
            inner
                .unexecuted_txs
                .notify_state_account(address.clone(), next_nonce.clone());
        }

        trace!("Notify ready {:?} with nonce {:?}", address, next_nonce);

        loop {
            if let Some(tx) = inner.unexecuted_txs.get_mut(address, next_nonce)
            {
                trace!(
                    "We got the tx from pending_pool with hash {:?}",
                    tx.hash()
                );
                // Set the correct account balance before this transaction.
                *tx.get_cached_account_balance_before_tx_mut() =
                    *account_balance;

                // The unpacked transaction should be ready but we need to
                // process it to calculate the balance.
                if self.verify_ready_transaction(
                    next_nonce,
                    account_balance,
                    tx.deref(),
                ) {
                    // FIXME: change back to trace
                    trace!(
                        "Successfully verified tx with hash {:?}",
                        tx.hash()
                    );
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // Update the next ready nonce.
        match inner
            .unexecuted_txs
            .ready_nonces_and_balances
            .get_mut(address)
        {
            Some(ready_nonce_info) => {
                let old_ready_nonce = ready_nonce_info.0;
                *ready_nonce_info =
                    (next_nonce.clone(), account_balance.clone());
                if next_nonce.deref().lt(&old_ready_nonce) {
                    // Remove transactions from ready.
                    let mut nonce = next_nonce.clone();
                    while nonce < old_ready_nonce {
                        inner.ready_transactions.remove(address, &nonce);
                        nonce += 1.into();
                    }
                }

                if old_ready_nonce > start_nonce {
                    start_nonce = old_ready_nonce;
                }
            }
            None => {
                // There is a new transaction added before calling.
                if !from_block_execution {
                    inner.unexecuted_txs.ready_nonces_and_balances.insert(
                        address.clone(),
                        (next_nonce.clone(), account_balance.clone()),
                    );
                }
            }
        }

        while start_nonce.lt(next_nonce) {
            match inner
                .unexecuted_txs
                .get_mut(address, &start_nonce)
                .cloned()
            {
                Some(tx) => {
                    if !tx.is_already_packed() {
                        inner
                            .ready_transactions
                            .insert(tx.get_arc_tx().clone());
                    }
                }
                None => {
                    debug!(
                        "unreachable: start_nonce = {}, next_nonce = {}",
                        start_nonce, next_nonce
                    );
                    unreachable!()
                }
            }

            start_nonce += 1.into();
        }
    }

    /// stats retrieves the length of ready and pending queue.
    pub fn stats(&self) -> (usize, usize, usize) {
        let inner = self.inner.read();
        (
            inner.ready_transactions.len(),
            inner.unexecuted_txs.pending_pool_size(),
            // FIXME: change it to the number of total tx received, and check why there is no tx removal (or why the len() == total received).
            inner.len(),
        )
    }

    /// content retrieves the ready and pending transactions.
    pub fn content(
        &self,
    ) -> (Vec<Arc<SignedTransaction>>, Vec<Arc<SignedTransaction>>) {
        let inner = self.inner.read();

        let ready_txs = inner
            .ready_transactions
            .treap
            .iter()
            .map(|(_, tx)| tx.clone())
            .collect();

        let pending_txs = inner
            .unexecuted_txs
            .txs
            .values()
            .map(|v| v.clone())
            .collect();

        (ready_txs, pending_txs)
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
