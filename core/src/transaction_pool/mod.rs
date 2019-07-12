// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod impls;

#[cfg(test)]
mod test_treap;

mod account_cache;
mod transaction_pool_inner;

extern crate rand;

pub use self::impls::TreapMap;
use crate::{
    block_data_manager::BlockDataManager, consensus::BestInformation,
    executive, pow::WORKER_COMPUTATION_PARALLELISM, vm,
};
use account_cache::AccountCache;
use cfx_types::{Address, H256, U256};
use metrics::{
    register_meter_with_group, Gauge, GaugeUsize, Meter, MeterTimer,
};
use parking_lot::{Mutex, RwLock};
use primitives::{
    Account, Action, EpochId, SignedTransaction, TransactionWithSignature,
};
use std::{
    collections::hash_map::HashMap,
    mem,
    ops::DerefMut,
    sync::{mpsc::channel, Arc},
};
use threadpool::ThreadPool;
use transaction_pool_inner::TransactionPoolInner;

lazy_static! {
    static ref TX_POOL_GAUGE: Arc<Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "unexecuted_size");
    static ref TX_POOL_READY_GAUGE: Arc<Gauge<usize>> =
        GaugeUsize::register_with_group("txpool", "ready_size");
    static ref TX_POOL_INSERT_TIMER: Arc<Meter> =
        register_meter_with_group("timer", "tx_pool::insert_new_tx");
    static ref TX_POOL_RECOVER_TIMER: Arc<Meter> =
        register_meter_with_group("timer", "tx_pool::recover_public");
}

pub const DEFAULT_MIN_TRANSACTION_GAS_PRICE: u64 = 1;
pub const DEFAULT_MAX_TRANSACTION_GAS_LIMIT: u64 = 100_000_000;
pub const DEFAULT_MAX_BLOCK_GAS_LIMIT: u64 = 30_000 * 100_000;

pub struct TransactionPool {
    inner: RwLock<TransactionPoolInner>,
    pub worker_pool: Arc<Mutex<ThreadPool>>,
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
        capacity: usize, worker_pool: Arc<Mutex<ThreadPool>>,
        data_man: Arc<BlockDataManager>,
    ) -> Self
    {
        let genesis_hash = data_man.genesis_block.hash();
        TransactionPool {
            inner: RwLock::new(TransactionPoolInner::with_capacity(capacity)),
            worker_pool,
            to_propagate_trans: Arc::new(RwLock::new(HashMap::new())),
            data_man,
            spec: vm::Spec::new_spec(),
            best_executed_epoch: Mutex::new(genesis_hash),
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

    pub fn get_state_account_info(&self, address: &Address) -> (U256, U256) {
        let mut account_cache = self.get_best_state_account_cache();
        self.inner
            .read()
            .get_nonce_and_balance_from_storage(address, &mut account_cache)
    }

    pub fn insert_new_transactions(
        &self, transactions: &Vec<TransactionWithSignature>,
    ) -> (Vec<Arc<SignedTransaction>>, HashMap<H256, String>) {
        let _timer = MeterTimer::time_func(TX_POOL_INSERT_TIMER.as_ref());
        let mut failures = HashMap::new();
        let uncached_trans =
            self.data_man.get_uncached_transactions(transactions);

        let mut signed_trans = Vec::new();
        if uncached_trans.len() < WORKER_COMPUTATION_PARALLELISM * 8 {
            let _timer = MeterTimer::time_func(TX_POOL_RECOVER_TIMER.as_ref());
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
            let _timer = MeterTimer::time_func(TX_POOL_RECOVER_TIMER.as_ref());
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

        let mut account_cache = self.get_best_state_account_cache();
        let mut passed_transactions = Vec::new();
        {
            let mut inner = self.inner.write();
            let inner = &mut *inner;

            for txes in signed_trans {
                for tx in txes {
                    self.data_man.cache_transaction(&tx.hash(), tx.clone());
                    if let Err(e) = self.verify_transaction(tx.as_ref()) {
                        warn!("Transaction discarded due to failure of passing verification {:?}: {}", tx.hash(), e);
                        failures.insert(tx.hash(), e);
                        continue;
                    }
                    let hash = tx.hash();
                    match self.add_transaction_with_readiness_check(
                        inner,
                        &mut account_cache,
                        tx.clone(),
                        false,
                        false,
                    ) {
                        Ok(_) => {
                            let mut to_prop = self.to_propagate_trans.write();
                            if !to_prop.contains_key(&tx.hash) {
                                to_prop.insert(tx.hash, tx.clone());
                            }
                            passed_transactions.push(tx);
                        }
                        Err(e) => {
                            failures.insert(hash, e);
                        }
                    }
                }
            }
        }
        TX_POOL_GAUGE.update(self.total_unexecuted());
        TX_POOL_READY_GAUGE.update(self.inner.read().total_ready_accounts());

        (passed_transactions, failures)
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

    pub fn total_unexecuted(&self) -> usize {
        let inner = self.inner.read();
        inner.total_unexecuted()
    }

    /// stats retrieves the length of ready and deferred pool.
    pub fn stats(&self) -> (usize, usize, usize, usize) {
        let inner = self.inner.read();
        (
            inner.total_ready_accounts(),
            inner.total_deferred(),
            inner.total_received(),
            inner.total_unexecuted(),
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

        let mut account_cache = self.get_best_state_account_cache();
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
                &account_cache.get_account_mut(&tx.sender).map_or(0.into(), |x| x.nonce), tx.hash);
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
