// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod impls;

#[cfg(test)]
mod test_treap;

mod account_cache;
mod garbage_collector;
mod nonce_pool;
mod transaction_pool_inner;

extern crate rand;

pub use self::impls::TreapMap;
use crate::{
    block_data_manager::BlockDataManager,
    consensus::BestInformation,
    executive,
    statedb::Result as StateDbResult,
    storage::{StateIndex, StateReadonlyIndex, StorageManagerTrait},
    vm,
};
use account_cache::AccountCache;
use cfx_types::{Address, H256, U256};
use metrics::{
    register_meter_with_group, Gauge, GaugeUsize, Lock, Meter, MeterTimer,
    RwLockExtensions,
};
use parking_lot::{Mutex, RwLock};
use primitives::{
    Account, Action, SignedTransaction, TransactionWithSignature,
};
use std::{collections::hash_map::HashMap, mem, ops::DerefMut, sync::Arc};
use transaction_pool_inner::TransactionPoolInner;

lazy_static! {
    static ref TX_POOL_DEFERRED_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "stat_deferred_txs");
    static ref TX_POOL_UNPACKED_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "stat_unpacked_txs");
    static ref TX_POOL_READY_GAUGE: Arc<dyn Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "stat_ready_accounts");
    static ref INSERT_TPS: Arc<dyn Meter> =
        register_meter_with_group("txpool", "insert_tps");
    static ref INSERT_TXS_TPS: Arc<dyn Meter> =
        register_meter_with_group("txpool", "insert_txs_tps");
    static ref INSERT_TXS_SUCCESS_TPS: Arc<dyn Meter> =
        register_meter_with_group("txpool", "insert_txs_success_tps");
    static ref INSERT_TXS_FAILURE_TPS: Arc<dyn Meter> =
        register_meter_with_group("txpool", "insert_txs_failure_tps");
    static ref TX_POOL_INSERT_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::insert_new_tx");
    static ref INSERT_TXS_QUOTA_LOCK: Lock =
        Lock::register("txpool_insert_txs_quota_lock");
    static ref INSERT_TXS_ENQUEUE_LOCK: Lock =
        Lock::register("txpool_insert_txs_enqueue_lock");
}

pub const DEFAULT_MAX_TRANSACTION_GAS_LIMIT: u64 = 100_000_000;
pub const DEFAULT_MAX_BLOCK_GAS_LIMIT: u64 = 30_000 * 100_000;

pub struct TxPoolConfig {
    pub capacity: usize,
    pub min_tx_price: u64,
    pub max_tx_gas: u64,
    pub max_block_gas: u64,
}

impl Default for TxPoolConfig {
    fn default() -> Self {
        TxPoolConfig {
            capacity: 500_000,
            min_tx_price: 1,
            max_tx_gas: DEFAULT_MAX_TRANSACTION_GAS_LIMIT,
            max_block_gas: DEFAULT_MAX_BLOCK_GAS_LIMIT,
        }
    }
}

pub struct TransactionPool {
    config: TxPoolConfig,
    inner: RwLock<TransactionPoolInner>,
    to_propagate_trans: Arc<RwLock<HashMap<H256, Arc<SignedTransaction>>>>,
    pub data_man: Arc<BlockDataManager>,
    spec: vm::Spec,
    best_executed_epoch: Mutex<StateReadonlyIndex>,
    consensus_best_info: Mutex<Arc<BestInformation>>,
    set_tx_requests: Mutex<Vec<Arc<SignedTransaction>>>,
    recycle_tx_requests: Mutex<Vec<Arc<SignedTransaction>>>,
}

pub type SharedTransactionPool = Arc<TransactionPool>;

impl TransactionPool {
    pub fn new(config: TxPoolConfig, data_man: Arc<BlockDataManager>) -> Self {
        let genesis_hash = data_man.true_genesis.hash();
        let inner = TransactionPoolInner::with_capacity(config.capacity);
        TransactionPool {
            config,
            inner: RwLock::new(inner),
            to_propagate_trans: Arc::new(RwLock::new(HashMap::new())),
            data_man: data_man.clone(),
            spec: vm::Spec::new_spec(),
            best_executed_epoch: Mutex::new(StateReadonlyIndex::from_ref(
                StateIndex::new_for_readonly(
                    &genesis_hash,
                    &data_man.true_genesis_state_root(),
                ),
            )),
            consensus_best_info: Mutex::new(Arc::new(Default::default())),
            set_tx_requests: Mutex::new(Default::default()),
            recycle_tx_requests: Mutex::new(Default::default()),
        }
    }

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

    pub fn get_state_account_info(
        &self, address: &Address,
    ) -> StateDbResult<(U256, U256)> {
        let mut account_cache = self.get_best_state_account_cache()?;
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
        &self, mut transactions: Vec<TransactionWithSignature>,
    ) -> (Vec<Arc<SignedTransaction>>, HashMap<H256, String>) {
        INSERT_TPS.mark(1);
        INSERT_TXS_TPS.mark(transactions.len());
        let _timer = MeterTimer::time_func(TX_POOL_INSERT_TIMER.as_ref());

        let mut passed_transactions = Vec::new();
        let mut failure = HashMap::new();

        // filter out invalid transactions.
        let mut index = 0;
        while let Some(tx) = transactions.get(index) {
            match self.verify_transaction(tx) {
                Ok(_) => index += 1,
                Err(e) => {
                    let removed = transactions.swap_remove(index);
                    debug!("failed to insert tx into pool (validation failed), hash = {:?}, error = {:?}", removed.hash, e);
                    failure.insert(removed.hash, e);
                }
            }
        }

        // ensure the pool has enough quota to insert new transactions.
        let quota = self
            .inner
            .write_with_metric(&INSERT_TXS_QUOTA_LOCK)
            .remaining_quota();
        if quota < transactions.len() {
            for tx in transactions.split_off(quota) {
                trace!("failed to insert tx into pool (quota not enough), hash = {:?}", tx.hash);
                failure.insert(tx.hash, "txpool is full".into());
            }
        }

        if transactions.is_empty() {
            INSERT_TXS_SUCCESS_TPS.mark(passed_transactions.len());
            INSERT_TXS_FAILURE_TPS.mark(failure.len());
            return (passed_transactions, failure);
        }

        // Recover public key and insert into pool with readiness check.
        // Note, the workload of recovering public key is very heavy, especially
        // in case of high TPS (e.g. > 8000). So, it's better to recover public
        // key after basic verification.
        match self.data_man.recover_unsigned_tx(&transactions) {
            Ok(signed_trans) => {
                // FIXME: shouldn't unwrap, but pop-up the error.
                let mut account_cache =
                    self.get_best_state_account_cache().unwrap();
                let mut inner =
                    self.inner.write_with_metric(&INSERT_TXS_ENQUEUE_LOCK);
                let mut to_prop = self.to_propagate_trans.write();

                for tx in signed_trans {
                    if let Err(e) = self.add_transaction_with_readiness_check(
                        &mut *inner,
                        &mut account_cache,
                        tx.clone(),
                        false,
                        false,
                    ) {
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

        TX_POOL_DEFERRED_GAUGE.update(self.total_deferred());
        TX_POOL_UNPACKED_GAUGE.update(self.total_unpacked());
        TX_POOL_READY_GAUGE.update(self.total_ready_accounts());

        INSERT_TXS_SUCCESS_TPS.mark(passed_transactions.len());
        INSERT_TXS_FAILURE_TPS.mark(failure.len());

        (passed_transactions, failure)
    }

    /// verify transactions based on the rules that have nothing to do with
    /// readiness
    fn verify_transaction(
        &self, transaction: &TransactionWithSignature,
    ) -> Result<(), String> {
        // check transaction gas limit
        if transaction.gas > DEFAULT_MAX_TRANSACTION_GAS_LIMIT.into() {
            warn!(
                "Transaction discarded due to above gas limit: {} > {}",
                transaction.gas, DEFAULT_MAX_TRANSACTION_GAS_LIMIT
            );
            return Err(format!(
                "transaction gas {} exceeds the maximum value {}",
                transaction.gas, DEFAULT_MAX_TRANSACTION_GAS_LIMIT
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
        if transaction.gas_price < self.config.min_tx_price.into() {
            trace!("Transaction {} discarded due to below minimal gas price: price {}", transaction.hash(), transaction.gas_price);
            return Err(format!(
                "transaction gas price {} less than the minimum value {}",
                transaction.gas_price, self.config.min_tx_price
            ));
        }

        if let Err(e) = transaction.verify_basic() {
            warn!("Transaction {:?} discarded due to not pass basic verification.", transaction.hash());
            return Err(format!("{:?}", e));
        }

        Ok(())
    }

    // Add transaction into deferred pool and maintain its readiness
    // the packed tag provided
    // if force tag is true, the replacement in nonce pool must be happened
    pub fn add_transaction_with_readiness_check(
        &self, inner: &mut TransactionPoolInner,
        account_cache: &mut AccountCache, transaction: Arc<SignedTransaction>,
        packed: bool, force: bool,
    ) -> Result<(), String>
    {
        inner.insert_transaction_with_readiness_check(
            account_cache,
            transaction,
            packed,
            force,
        )
    }

    pub fn get_to_be_propagated_transactions(
        &self,
    ) -> HashMap<H256, Arc<SignedTransaction>> {
        let mut to_prop = self.to_propagate_trans.write();
        let mut res = HashMap::new();
        mem::swap(&mut *to_prop, &mut res);
        res
    }

    pub fn set_to_be_propagated_transactions(
        &self, transactions: HashMap<H256, Arc<SignedTransaction>>,
    ) {
        let mut to_prop = self.to_propagate_trans.write();
        to_prop.extend(transactions);
    }

    pub fn remove_to_be_propagated_transactions(&self, tx_hash: &H256) {
        self.to_propagate_trans.write().remove(tx_hash);
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

    pub fn set_tx_packed(&self, transactions: &Vec<Arc<SignedTransaction>>) {
        if transactions.is_empty() {
            // Fast return. Also used to for bench mode.
            return;
        }
        let mut tx_req_buffer = self.set_tx_requests.lock();
        for tx in transactions {
            tx_req_buffer.push(tx.clone());
        }
    }

    pub fn pack_transactions<'a>(
        &self, num_txs: usize, block_gas_limit: U256, block_size_limit: usize,
    ) -> Vec<Arc<SignedTransaction>> {
        let mut inner = self.inner.write();
        inner.pack_transactions(num_txs, block_gas_limit, block_size_limit)
    }

    pub fn notify_modified_accounts(
        &self, accounts_from_execution: Vec<Account>,
    ) {
        let mut inner = self.inner.write();
        inner.notify_modified_accounts(accounts_from_execution)
    }

    pub fn clear_tx_pool(&self) {
        let mut inner = self.inner.write();
        inner.clear()
    }

    pub fn total_deferred(&self) -> usize {
        let inner = self.inner.read();
        inner.total_deferred()
    }

    pub fn total_ready_accounts(&self) -> usize {
        let inner = self.inner.read();
        inner.total_ready_accounts()
    }

    pub fn total_received(&self) -> usize {
        let inner = self.inner.read();
        inner.total_received()
    }

    pub fn total_unpacked(&self) -> usize {
        let inner = self.inner.read();
        inner.total_unpacked()
    }

    /// stats retrieves the length of ready and deferred pool.
    pub fn stats(&self) -> (usize, usize, usize, usize) {
        let inner = self.inner.read();
        (
            inner.total_ready_accounts(),
            inner.total_deferred(),
            inner.total_received(),
            inner.total_unpacked(),
        )
    }

    /// content retrieves the ready and deferred transactions.
    pub fn content(
        &self,
    ) -> (Vec<Arc<SignedTransaction>>, Vec<Arc<SignedTransaction>>) {
        let inner = self.inner.read();
        inner.content()
    }

    pub fn notify_new_best_info(&self, best_info: Arc<BestInformation>) {
        let mut set_tx_buffer = self.set_tx_requests.lock();
        let mut recycle_tx_buffer = self.recycle_tx_requests.lock();
        let mut consensus_best_info = self.consensus_best_info.lock();
        *consensus_best_info = best_info;

        // FIXME: don't unwrap, propogate the error.
        let mut account_cache = self.get_best_state_account_cache().unwrap();
        let mut inner = self.inner.write();
        let inner = inner.deref_mut();

        while let Some(tx) = set_tx_buffer.pop() {
            self.add_transaction_with_readiness_check(
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
                &account_cache.get_account_mut(&tx.sender)
                    // FIXME: don't unwrap, propogate the error.
                    .unwrap().map_or(0.into(), |x| x.nonce), tx.hash);
            self.add_transaction_with_readiness_check(
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

    pub fn set_best_executed_epoch(&self, best_executed_epoch: StateIndex) {
        *self.best_executed_epoch.lock() =
            StateReadonlyIndex::from_ref(best_executed_epoch);
    }

    fn get_best_state_account_cache(&self) -> StateDbResult<AccountCache> {
        Ok(AccountCache::new(
            self.data_man
                .storage_manager
                .get_state_no_commit(self.best_executed_epoch.lock().as_ref())?
                // Unwrap is safe here because the state exists.
                .unwrap(),
        ))
    }
}
