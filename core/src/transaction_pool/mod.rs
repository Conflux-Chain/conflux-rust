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
use parking_lot::{Mutex, RwLock};
use primitives::{
    Account, Action, EpochId, SignedTransaction, TransactionAddress,
    TransactionWithSignature,
};
use std::{
    cmp::{min, Ordering},
    collections::{hash_map::HashMap, HashSet},
    ops::DerefMut,
    sync::{mpsc::channel, Arc},
};
use threadpool::ThreadPool;

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

    fn is_ready(&mut self, tx: &SignedTransaction) -> Readiness {
        let sender = tx.sender();
        if !self.accounts.contains_key(&sender) {
            let account = self
                .storage
                .get_account(&sender, false)
                .ok()
                .and_then(|x| x);
            if let Some(account) = account {
                self.accounts.insert(sender.clone(), account);
            }
        }
        let account = self.accounts.get_mut(&sender);
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
                Readiness::Future
            }
        }
    }
}

#[derive(Debug, PartialEq)]
enum InsertResult {
    /// new item added
    NewAdded,
    /// failed to update with lower gas price tx
    Failed,
    /// succeeded to update with higher gas price tx
    Updated(Arc<SignedTransaction>),
}

struct NoncePool {
    buckets: HashMap<Address, HashMap<U256, Arc<SignedTransaction>>>,
}

impl NoncePool {
    fn new() -> Self {
        NoncePool {
            buckets: HashMap::new(),
        }
    }

    fn insert(&mut self, tx: Arc<SignedTransaction>) -> InsertResult {
        let bucket = self.buckets.entry(tx.sender).or_insert(HashMap::new());

        let mut ret = if bucket.contains_key(&tx.nonce) {
            InsertResult::Failed
        } else {
            InsertResult::NewAdded
        };

        let tx_in_pool = bucket.entry(tx.nonce).or_insert(tx.clone());
        if tx_in_pool.gas_price < tx.gas_price {
            // replace with higher gas price transaction
            ret = InsertResult::Updated(tx_in_pool.clone());
            *tx_in_pool = tx.clone();
        }

        ret
    }

    fn remove(
        &mut self, addr: &Address, nonce: &U256,
    ) -> Option<Arc<SignedTransaction>> {
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

    fn get(
        &self, addr: &Address, nonce: &U256,
    ) -> Option<Arc<SignedTransaction>> {
        self.buckets
            .get(addr)
            .and_then(|bucket| bucket.get(nonce))
            .map(|tx| tx.clone())
    }
}

struct PendingTransactionPool {
    nonce_pool: NoncePool,
    txs: HashMap<H256, Arc<SignedTransaction>>,
}

impl PendingTransactionPool {
    fn new() -> Self {
        PendingTransactionPool {
            nonce_pool: NoncePool::new(),
            txs: HashMap::new(),
        }
    }

    fn len(&self) -> usize { self.txs.len() }

    fn insert(&mut self, tx: Arc<SignedTransaction>) -> bool {
        match self.nonce_pool.insert(tx.clone()) {
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
        }
    }

    pub fn remove(
        &mut self, address: &Address, nonce: &U256,
    ) -> Option<Arc<SignedTransaction>> {
        self.nonce_pool
            .remove(address, nonce)
            .and_then(|tx| self.txs.remove(&tx.hash()))
    }

    pub fn get(
        &self, address: &Address, nonce: &U256,
    ) -> Option<Arc<SignedTransaction>> {
        self.nonce_pool.get(address, nonce)
    }

    fn get_by_hash(&self, tx_hash: &H256) -> Option<Arc<SignedTransaction>> {
        self.txs.get(tx_hash).map(|tx| tx.clone())
    }
}

struct ReadyTransactionPool {
    nonce_pool: NoncePool,
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

    fn remove(&mut self, tx_hash: &H256) -> Option<Arc<SignedTransaction>> {
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

        self.remove(&tx.hash())
    }
}

pub struct TransactionPoolInner {
    pending_transactions: PendingTransactionPool,
    ready_transactions: ReadyTransactionPool,
}

impl TransactionPoolInner {
    pub fn new() -> Self {
        TransactionPoolInner {
            pending_transactions: PendingTransactionPool::new(),
            ready_transactions: ReadyTransactionPool::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.pending_transactions.len() + self.ready_transactions.len()
    }

    fn get(&self, tx_hash: &H256) -> Option<Arc<SignedTransaction>> {
        self.ready_transactions
            .get(tx_hash)
            .or_else(|| self.pending_transactions.get_by_hash(tx_hash))
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
        transactions: Vec<TransactionWithSignature>,
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
        let mut passed_transaction = Vec::new();
        {
            let mut tx_cache = self.transaction_pubkey_cache.write();
            let mut cache_man = self.cache_man.lock();
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
                    match self.add_with_readiness(&mut account_cache, tx) {
                        Ok(_) => {
                            passed_transaction.push(hash);
                        }
                        Err(e) => {
                            failures.insert(hash, e);
                        }
                    }
                }
            }
        }

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
            &vm::Spec::new_spec(),
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

    // The second step verification for ready transactions
    pub fn verify_ready_transaction(
        &self, account: &Account, transaction: &SignedTransaction,
    ) -> bool {
        // check balance
        let cost = transaction.value + transaction.gas_price * transaction.gas;
        if account.balance < cost {
            trace!(
                "Transaction {} not ready due to not enough balance: {} < {}",
                transaction.hash(),
                account.balance,
                cost
            );
            return false;
        }
        true
    }

    pub fn add_with_readiness(
        &self, account_cache: &mut AccountCache,
        transaction: Arc<SignedTransaction>,
    ) -> Result<(), String>
    {
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();

        if self.capacity <= inner.len() {
            warn!("Transaction discarded due to insufficient txpool capacity: {:?}", transaction.hash());
            return Err(format!("Transaction discarded due to insufficient txpool capacity: {:?}", transaction.hash()));
        }

        match account_cache.is_ready(&transaction) {
            Readiness::Ready => {
                let account =
                    account_cache.accounts.get_mut(&transaction.sender);
                if let Some(mut account) = account {
                    if self
                        .verify_ready_transaction(account, transaction.as_ref())
                    {
                        if self
                            .add_ready_without_lock(inner, transaction.clone())
                        {
                            account.nonce = account.nonce + 1;
                            self.notify_ready_without_lock(
                                inner,
                                &transaction.sender,
                                account,
                            );
                            Ok(())
                        } else {
                            Err(format!("Already imported"))
                        }
                    } else {
                        if self.add_pending_without_lock(
                            inner,
                            transaction.clone(),
                        ) {
                            Ok(())
                        } else {
                            Err(format!("Failed imported to panding queue"))
                        }
                    }
                } else {
                    warn!("Ready transaction {} discarded due to sender not exist (should not happen!)", transaction.hash());
                    Err(format!("Ready transaction {} discarded due to sender not exist (should not happen!)", transaction.hash()))
                }
            }
            Readiness::Future => {
                if !self.add_pending_without_lock(inner, transaction.clone()) {
                    return Err(format!("Already imported"));
                }

                if transaction.nonce > 0.into() {
                    if inner
                        .ready_transactions
                        .get_by_nonce(
                            &transaction.sender,
                            &(transaction.nonce - 1),
                        )
                        .is_some()
                    {
                        if let Some(account) =
                            account_cache.accounts.get_mut(&transaction.sender)
                        {
                            account.nonce = transaction.nonce.clone();
                            self.notify_ready_without_lock(
                                inner,
                                &transaction.sender,
                                account,
                            );
                        }
                    }
                }

                Ok(())
            }
            Readiness::TooDistantFuture => {
                debug!("Transaction {:?} is discarded due to in too distant future", transaction.hash());
                Err(format!("Transaction {:?} is discarded due to in too distant future", transaction.hash()))
            }
            Readiness::Stale => {
                debug!(
                    "Transaction {:?} is discarded due to stale nonce",
                    transaction.hash()
                );
                Err(format!(
                    "Transaction {:?} is discarded due to stale nonce",
                    transaction.hash()
                ))
            }
        }
    }

    pub fn add_ready(&self, transaction: Arc<SignedTransaction>) -> bool {
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();
        self.add_ready_without_lock(inner, transaction)
    }

    pub fn add_ready_without_lock(
        &self, inner: &mut TransactionPoolInner,
        transaction: Arc<SignedTransaction>,
    ) -> bool
    {
        trace!(
            "Insert tx into ready hash={:?} sender={:?}",
            transaction.hash(),
            transaction.sender
        );
        inner.ready_transactions.insert(transaction)
    }

    pub fn add_pending(&self, transaction: Arc<SignedTransaction>) -> bool {
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();
        self.add_pending_without_lock(inner, transaction)
    }

    pub fn recycle_future_transactions(
        &self, transactions: Vec<Arc<SignedTransaction>>, state: Storage,
    ) {
        let mut account_cache = AccountCache::new(state);
        for tx in transactions {
            self.add_with_readiness(&mut account_cache, tx).ok();
        }
    }

    pub fn add_pending_without_lock(
        &self, inner: &mut TransactionPoolInner,
        transaction: Arc<SignedTransaction>,
    ) -> bool
    {
        trace!(
            "Insert tx into pending hash={:?} sender={:?}",
            transaction.hash(),
            transaction.sender
        );
        inner.pending_transactions.insert(transaction)
    }

    pub fn remove_ready(&self, transaction: Arc<SignedTransaction>) -> bool {
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();
        if self.remove_ready_without_lock(inner, transaction).is_some() {
            true
        } else {
            false
        }
    }

    pub fn remove_ready_without_lock(
        &self, inner: &mut TransactionPoolInner,
        transaction: Arc<SignedTransaction>,
    ) -> Option<Arc<SignedTransaction>>
    {
        let hash = transaction.hash();
        inner.ready_transactions.remove(&hash)
    }

    pub fn remove_pending(&self, transaction: &SignedTransaction) -> bool {
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
        &self, inner: &mut TransactionPoolInner,
        transaction: &SignedTransaction,
    ) -> Option<Arc<SignedTransaction>>
    {
        inner
            .pending_transactions
            .remove(&transaction.sender, &transaction.nonce)
    }

    /// pack at most num_txs transactions randomly
    pub fn pack_transactions<'a>(
        &self, num_txs: usize, state: State<'a>,
    ) -> Vec<Arc<SignedTransaction>> {
        let mut inner = self.inner.write();
        let mut packed_transactions: Vec<Arc<SignedTransaction>> = Vec::new();
        let num_txs = min(num_txs, inner.ready_transactions.len());
        let mut nonce_map = HashMap::new();
        let mut future_txs = HashMap::new();
        debug!(
            "Before packing ready pool size:{}, pending pool size:{}",
            inner.ready_transactions.len(),
            inner.pending_transactions.len()
        );

        loop {
            if packed_transactions.len() >= num_txs {
                break;
            }

            let tx = match inner.ready_transactions.pop() {
                None => break,
                Some(tx) => tx,
            };

            let sender = tx.sender;
            let nonce_entry = nonce_map.entry(sender);
            let state_nonce = state.nonce(&sender);
            if state_nonce.is_err() {
                debug!(
                    "state nonce error: {:?}, tx: {:?}",
                    state_nonce,
                    tx.clone()
                );
                inner.pending_transactions.insert(tx);
                continue;
            }
            let nonce =
                nonce_entry.or_insert(state_nonce.expect("Not err here"));
            if tx.nonce > *nonce {
                future_txs
                    .entry(sender)
                    .or_insert(HashMap::new())
                    .insert(tx.nonce, tx);
            } else if tx.nonce == *nonce {
                *nonce += 1.into();
                packed_transactions.push(tx);
                if let Some(tx_map) = future_txs.get_mut(&sender) {
                    loop {
                        if tx_map.is_empty() {
                            break;
                        }
                        if let Some(tx) = tx_map.remove(nonce) {
                            packed_transactions.push(tx);
                            *nonce += 1.into();
                        } else {
                            break;
                        }
                    }
                }
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
        debug!(
            "After packing ready pool size:{}, pending pool size:{}",
            inner.ready_transactions.len(),
            inner.pending_transactions.len()
        );

        packed_transactions
    }

    pub fn transactions_to_propagate(&self) -> Vec<Arc<SignedTransaction>> {
        let inner = self.inner.read();

        inner
            .pending_transactions
            .txs
            .values()
            .map(|v| v.clone())
            .chain(
                inner
                    .ready_transactions
                    .treap
                    .iter()
                    .map(|(_, x)| x.clone()),
            )
            .collect()
    }

    pub fn notify_ready(&self, address: &Address, account: &Account) {
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();
        self.notify_ready_without_lock(inner, address, account);
    }

    fn notify_ready_without_lock(
        &self, inner: &mut TransactionPoolInner, address: &Address,
        account: &Account,
    )
    {
        let mut nonce = account.nonce.clone();

        trace!("Notify ready {:?} with nonce {:?}", address, nonce);

        loop {
            let mut success = false;

            if let Some(tx) = inner.pending_transactions.get(address, &nonce) {
                trace!(
                    "We got the tx from pending_pool with hash {:?}",
                    tx.hash()
                );
                if self.verify_ready_transaction(account, tx.as_ref()) {
                    success = true;
                    trace!(
                        "Successfully verified tx with hash {:?}",
                        tx.hash()
                    );
                }
            }

            if success {
                if let Some(tx) =
                    inner.pending_transactions.remove(address, &nonce)
                {
                    if !self.add_ready_without_lock(inner, tx) {
                        trace!(
                            "Check passed but fail to insert ready transaction"
                        );
                    }
                    nonce += 1.into();
                    continue;
                }
            }
            break;
        }
    }

    /// stats retrieves the length of ready and pending queue.
    pub fn stats(&self) -> (usize, usize) {
        let inner = self.inner.read();
        (
            inner.ready_transactions.len(),
            inner.pending_transactions.len(),
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
            .pending_transactions
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

    #[test]
    fn test_pending_pool() {
        let mut pool = super::PendingTransactionPool::new();
        assert_eq!(pool.len(), 0);

        // new added tx
        let sender = Random.generate().unwrap();
        let tx = new_test_tx(&sender, 5, 10, 100);
        assert!(pool.insert(tx.clone()));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.get(&tx.sender, &tx.nonce), Some(tx.clone()));
        assert_eq!(pool.get_by_hash(&tx.hash()), Some(tx.clone()));

        // new added tx of different nonce
        let tx2 = new_test_tx(&sender, 6, 10, 100);
        assert!(pool.insert(tx2.clone()));
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.remove(&tx2.sender, &tx2.nonce), Some(tx2.clone()));
        assert_eq!(pool.len(), 1);

        // update tx with lower gas price
        let tx3 = new_test_tx(&sender, 5, 9, 100);
        assert!(!pool.insert(tx3.clone()));
        assert_eq!(pool.len(), 1);

        // update tx with higher gas price
        let tx4 = new_test_tx(&sender, 5, 11, 100);
        assert!(pool.insert(tx4.clone()));
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.get(&tx.sender, &tx.nonce), Some(tx4.clone()));
        assert_eq!(pool.get_by_hash(&tx.hash()), None);
        assert_eq!(pool.get_by_hash(&tx4.hash()), Some(tx4.clone()));
    }

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
