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
    block_data_manager::BlockDataManager, consensus::BestInformation,
    machine::Machine, state::State, verification::VerificationConfig, vm::Spec,
};
use account_cache::AccountCache;
use cfx_parameters::block::DEFAULT_TARGET_BLOCK_GAS_LIMIT;
use cfx_statedb::{Result as StateDbResult, StateDb};
use cfx_storage::{Result as StorageResult, StateIndex, StorageManagerTrait};
use cfx_types::{Address, H256, U256};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use metrics::{
    register_meter_with_group, Gauge, GaugeUsize, Lock, Meter, MeterTimer,
    RwLockExtensions,
};
use parking_lot::{Mutex, RwLock};
use primitives::{Account, SignedTransaction, TransactionWithSignature};
use std::{
    cmp::{max, min},
    collections::hash_map::HashMap,
    mem,
    ops::DerefMut,
    sync::Arc,
};
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
    static ref TX_POOL_VERIFY_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::verify");
    static ref TX_POOL_GET_STATE_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::get_state");
    static ref INSERT_TXS_QUOTA_LOCK: Lock =
        Lock::register("txpool_insert_txs_quota_lock");
    static ref INSERT_TXS_ENQUEUE_LOCK: Lock =
        Lock::register("txpool_insert_txs_enqueue_lock");
    static ref PACK_TRANSACTION_LOCK: Lock =
        Lock::register("txpool_pack_transactions");
    static ref NOTIFY_BEST_INFO_LOCK: Lock =
        Lock::register("txpool_notify_best_info");
    static ref NOTIFY_MODIFIED_LOCK: Lock =
        Lock::register("txpool_notify_modified_info");
}

// FIXME: obviously the max tx gas limit follows the max block gas limit.
// FIXME: and we can scale it by some factor which matches the expiry condition
// FIXME: (according to the formular).
pub const DEFAULT_MAX_TRANSACTION_GAS_LIMIT: u64 = 100_000_000;

pub struct TxPoolConfig {
    pub capacity: usize,
    pub min_tx_price: u64,
    pub max_tx_gas: u64,
    pub tx_weight_scaling: u64,
    pub tx_weight_exp: u8,
    pub target_block_gas_limit: u64,
}

impl MallocSizeOf for TxPoolConfig {
    fn size_of(&self, _ops: &mut MallocSizeOfOps) -> usize { 0 }
}

impl Default for TxPoolConfig {
    fn default() -> Self {
        TxPoolConfig {
            capacity: 500_000,
            min_tx_price: 1,
            max_tx_gas: DEFAULT_MAX_TRANSACTION_GAS_LIMIT,
            // TODO: Set a proper default scaling since tx pool uses u128 as
            // weight.
            tx_weight_scaling: 1,
            tx_weight_exp: 1,
            target_block_gas_limit: DEFAULT_TARGET_BLOCK_GAS_LIMIT,
        }
    }
}

pub struct TransactionPool {
    config: TxPoolConfig,
    verification_config: VerificationConfig,
    inner: RwLock<TransactionPoolInner>,
    to_propagate_trans: Arc<RwLock<HashMap<H256, Arc<SignedTransaction>>>>,
    pub data_man: Arc<BlockDataManager>,
    best_executed_state: Mutex<Arc<State>>,
    consensus_best_info: Mutex<Arc<BestInformation>>,
    set_tx_requests: Mutex<Vec<Arc<SignedTransaction>>>,
    recycle_tx_requests: Mutex<Vec<Arc<SignedTransaction>>>,
    machine: Arc<Machine>,
}

impl MallocSizeOf for TransactionPool {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        let inner_size = self.inner.read().size_of(ops);
        let to_propagate_trans_size =
            self.to_propagate_trans.read().size_of(ops);
        let consensus_best_info_size =
            self.consensus_best_info.lock().size_of(ops);
        let set_tx_requests_size = self.set_tx_requests.lock().size_of(ops);
        let recycle_tx_requests_size =
            self.recycle_tx_requests.lock().size_of(ops);
        self.config.size_of(ops)
            + inner_size
            + to_propagate_trans_size
            + self.data_man.size_of(ops)
            + consensus_best_info_size
            + set_tx_requests_size
            + recycle_tx_requests_size
        // Does not count size_of machine
    }
}

pub type SharedTransactionPool = Arc<TransactionPool>;

impl TransactionPool {
    pub fn new(
        config: TxPoolConfig, verification_config: VerificationConfig,
        data_man: Arc<BlockDataManager>, machine: Arc<Machine>,
    ) -> Self
    {
        let genesis_hash = data_man.true_genesis.hash();
        let inner = TransactionPoolInner::new(
            config.capacity,
            config.tx_weight_scaling,
            config.tx_weight_exp,
        );
        let best_executed_state = Mutex::new(
            Self::best_executed_state(
                &data_man,
                StateIndex::new_for_readonly(
                    &genesis_hash,
                    &data_man.true_genesis_state_root(),
                ),
            )
            .expect("The genesis state is guaranteed to exist."),
        );
        TransactionPool {
            config,
            verification_config,
            inner: RwLock::new(inner),
            to_propagate_trans: Arc::new(RwLock::new(HashMap::new())),
            data_man: data_man.clone(),
            best_executed_state,
            consensus_best_info: Mutex::new(Arc::new(Default::default())),
            set_tx_requests: Mutex::new(Default::default()),
            recycle_tx_requests: Mutex::new(Default::default()),
            machine,
        }
    }

    pub fn machine(&self) -> Arc<Machine> { self.machine.clone() }

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
        let account_cache = self.get_best_state_account_cache();
        account_cache.get_nonce_and_balance(address)
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
        let current_best_info = self.consensus_best_info.lock().clone();

        // filter out invalid transactions.
        let mut index = 0;

        let (chain_id, best_height) = {
            (
                current_best_info.best_chain_id(),
                current_best_info.best_epoch_number,
            )
        };

        while let Some(tx) = transactions.get(index) {
            match self.verify_transaction_tx_pool(
                tx,
                /* basic_check = */ true,
                chain_id,
                best_height,
            ) {
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
                let account_cache = self.get_best_state_account_cache();
                let mut inner =
                    self.inner.write_with_metric(&INSERT_TXS_ENQUEUE_LOCK);
                let mut to_prop = self.to_propagate_trans.write();

                for tx in signed_trans {
                    if let Err(e) = self.add_transaction_with_readiness_check(
                        &mut *inner,
                        &account_cache,
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

    /// Try to insert `signed_transaction` into transaction pool.
    ///
    /// If some tx is already in our tx_cache, it will be ignored and will not
    /// be added to returned `passed_transactions`. If some tx invalid or
    /// cannot be inserted to the tx pool, it will be included in the returned
    /// `failure` and will not be propagated.
    pub fn insert_new_signed_transactions(
        &self, mut signed_transactions: Vec<Arc<SignedTransaction>>,
    ) -> (Vec<Arc<SignedTransaction>>, HashMap<H256, String>) {
        INSERT_TPS.mark(1);
        INSERT_TXS_TPS.mark(signed_transactions.len());
        let _timer = MeterTimer::time_func(TX_POOL_INSERT_TIMER.as_ref());

        let mut passed_transactions = Vec::new();
        let mut failure = HashMap::new();
        let current_best_info = { self.consensus_best_info.lock().clone() };

        // filter out invalid transactions.
        let mut index = 0;

        let (chain_id, best_height) = {
            (
                current_best_info.best_chain_id(),
                current_best_info.best_epoch_number,
            )
        };

        while let Some(tx) = signed_transactions.get(index) {
            match self.verify_transaction_tx_pool(
                &tx.transaction,
                true, /* basic_check = */
                chain_id,
                best_height,
            ) {
                Ok(_) => index += 1,
                Err(e) => {
                    let removed = signed_transactions.swap_remove(index);
                    debug!("failed to insert tx into pool (validation failed), hash = {:?}, error = {:?}", removed.hash, e);
                    failure.insert(removed.hash, e);
                }
            }
        }

        // ensure the pool has enough quota to insert new signed transactions.
        let quota = self
            .inner
            .write_with_metric(&INSERT_TXS_QUOTA_LOCK)
            .remaining_quota();
        if quota < signed_transactions.len() {
            for tx in signed_transactions.split_off(quota) {
                trace!("failed to insert tx into pool (quota not enough), hash = {:?}", tx.hash);
                failure.insert(tx.hash, "txpool is full".into());
            }
        }

        if signed_transactions.is_empty() {
            INSERT_TXS_SUCCESS_TPS.mark(passed_transactions.len());
            INSERT_TXS_FAILURE_TPS.mark(failure.len());
            return (passed_transactions, failure);
        }

        // Insert into pool with readiness check.
        // Notice it does not recover the public as the input transactions are
        // already signed.

        {
            let account_cache = self.get_best_state_account_cache();
            let mut inner =
                self.inner.write_with_metric(&INSERT_TXS_ENQUEUE_LOCK);
            let mut to_prop = self.to_propagate_trans.write();

            for tx in signed_transactions {
                if let Err(e) = self.add_transaction_with_readiness_check(
                    &mut *inner,
                    &account_cache,
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
            //RwLock is dropped here
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
    fn verify_transaction_tx_pool(
        &self, transaction: &TransactionWithSignature, basic_check: bool,
        chain_id: u32, best_height: u64,
    ) -> Result<(), String>
    {
        let _timer = MeterTimer::time_func(TX_POOL_VERIFY_TIMER.as_ref());

        if basic_check {
            if let Err(e) = self
                .verification_config
                .verify_transaction_common(transaction, chain_id)
            {
                warn!("Transaction {:?} discarded due to not passing basic verification.", transaction.hash());
                return Err(format!("{:?}", e));
            }
        }

        // If it is zero, it might be possible that it is not initialized
        // TODO: figure out when we should active txpool.
        // TODO: Ideally txpool should only be initialized after Normal phase.
        if best_height == 0 {
            warn!("verify transaction while best info isn't initialized");
        } else {
            if VerificationConfig::check_transaction_epoch_bound(
                transaction,
                best_height,
                self.verification_config.transaction_epoch_bound,
            ) < 0
            {
                // Check the epoch height is in bound. Because this is such a
                // loose bound, we can check it here as if it
                // will not change at all during its life time.
                warn!(
                    "Transaction discarded due to epoch height out of the bound: \
                    best height {} tx epoch height {}",
                    best_height, transaction.epoch_height);
                return Err(format!(
                    "transaction epoch height {} is out side the range of the current \
                    pivot height ({}) bound, only {} drift allowed!",
                    transaction.epoch_height, best_height,
                    self.verification_config.transaction_epoch_bound));
            }
        }

        // check transaction gas limit
        if transaction.gas > self.config.max_tx_gas.into() {
            warn!(
                "Transaction discarded due to above gas limit: {} > {}",
                transaction.gas, self.config.max_tx_gas
            );
            return Err(format!(
                "transaction gas {} exceeds the maximum value {}",
                transaction.gas, self.config.max_tx_gas
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

        Ok(())
    }

    // Add transaction into deferred pool and maintain its readiness
    // the packed tag provided
    // if force tag is true, the replacement in nonce pool must be happened
    pub fn add_transaction_with_readiness_check(
        &self, inner: &mut TransactionPoolInner, account_cache: &AccountCache,
        transaction: Arc<SignedTransaction>, packed: bool, force: bool,
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
        mut best_epoch_height: u64,
    ) -> Vec<Arc<SignedTransaction>>
    {
        let mut inner = self.inner.write_with_metric(&PACK_TRANSACTION_LOCK);
        best_epoch_height += 1;
        let transaction_epoch_bound =
            self.verification_config.transaction_epoch_bound;
        let height_lower_bound = if best_epoch_height > transaction_epoch_bound
        {
            best_epoch_height - transaction_epoch_bound
        } else {
            0
        };
        let height_upper_bound = best_epoch_height + transaction_epoch_bound;
        inner.pack_transactions(
            num_txs,
            block_gas_limit,
            block_size_limit,
            height_lower_bound,
            height_upper_bound,
        )
    }

    pub fn notify_modified_accounts(
        &self, accounts_from_execution: Vec<Account>,
    ) {
        let mut inner = self.inner.write_with_metric(&NOTIFY_MODIFIED_LOCK);
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
        &self, address: Option<Address>,
    ) -> (Vec<Arc<SignedTransaction>>, Vec<Arc<SignedTransaction>>) {
        let inner = self.inner.read();
        inner.content(address)
    }

    pub fn notify_new_best_info(
        &self, best_info: Arc<BestInformation>,
    ) -> StateDbResult<()> {
        let mut set_tx_buffer = self.set_tx_requests.lock();
        let mut recycle_tx_buffer = self.recycle_tx_requests.lock();
        {
            let mut consensus_best_info = self.consensus_best_info.lock();
            *consensus_best_info = best_info.clone();
        }

        let account_cache = self.get_best_state_account_cache();
        let mut inner = self.inner.write_with_metric(&NOTIFY_BEST_INFO_LOCK);
        let inner = inner.deref_mut();

        while let Some(tx) = set_tx_buffer.pop() {
            self.add_transaction_with_readiness_check(
                inner,
                &account_cache,
                tx,
                true,
                false,
            )
            .ok();
        }

        let (chain_id, best_height) =
            { (best_info.best_chain_id(), best_info.best_epoch_number) };

        while let Some(tx) = recycle_tx_buffer.pop() {
            debug!(
                "should not trigger recycle transaction, nonce = {}, sender = {:?}, \
                account nonce = {}, hash = {:?} .",
                &tx.nonce, &tx.sender,
                account_cache.get_nonce(&tx.sender)?, tx.hash);

            if let Err(e) = self.verify_transaction_tx_pool(
                &tx,
                /* basic_check = */ false,
                chain_id,
                best_height,
            ) {
                warn!(
                    "Recycled transaction {:?} discarded due to not passing verification {}.",
                    tx.hash(), e
                );
            }
            self.add_transaction_with_readiness_check(
                inner,
                &account_cache,
                tx,
                false,
                true,
            )
            .ok();
        }

        Ok(())
    }

    pub fn get_best_info_with_packed_transactions(
        &self, num_txs: usize, block_size_limit: usize,
        additional_transactions: Vec<Arc<SignedTransaction>>,
    ) -> (Arc<BestInformation>, U256, Vec<Arc<SignedTransaction>>)
    {
        // We do not need to hold the lock because it is fine for us to generate
        // blocks that are slightly behind the best state.
        // We do not want to stall the consensus thread.
        let consensus_best_info_clone = self.consensus_best_info.lock().clone();

        let parent_block_gas_limit = self
            .data_man
            .block_by_hash(
                &consensus_best_info_clone.best_block_hash,
                /* update_cache = */ true,
            )
            // The parent block must exists.
            .expect(&concat!(file!(), ":", line!(), ":", column!()))
            .block_header
            .gas_limit()
            .clone();

        let gas_limit_divisor = self.machine.params().gas_limit_bound_divisor;
        let min_gas_limit = self.machine.params().min_gas_limit;
        assert!(parent_block_gas_limit >= min_gas_limit);
        let gas_lower = max(
            parent_block_gas_limit - parent_block_gas_limit / gas_limit_divisor
                + 1,
            min_gas_limit,
        );
        let gas_upper = parent_block_gas_limit
            + parent_block_gas_limit / gas_limit_divisor
            - 1;

        let target_gas_limit = self.config.target_block_gas_limit.into();
        let self_gas_limit = min(max(target_gas_limit, gas_lower), gas_upper);

        let transactions_from_pool = self.pack_transactions(
            num_txs,
            self_gas_limit.clone(),
            block_size_limit,
            consensus_best_info_clone.best_epoch_number,
        );

        let transactions = [
            additional_transactions.as_slice(),
            transactions_from_pool.as_slice(),
        ]
        .concat();

        (consensus_best_info_clone, self_gas_limit, transactions)
    }

    fn best_executed_state(
        data_man: &BlockDataManager, best_executed_epoch: StateIndex,
    ) -> StorageResult<Arc<State>> {
        Ok(Arc::new(State::new(
            StateDb::new(
                data_man
                    .storage_manager
                    .get_state_no_commit(
                        best_executed_epoch,
                        /* try_open = */ false,
                    )?
                    // Safe because the state is guaranteed to be available
                    .unwrap(),
            ),
            Default::default(),
            &Spec::new_spec(),
            // So far block_number is unused in txpool's state, it's fine to
            // specify a fake number. block_number 1 corresponds to the state
            // of genesis block.
            1, /* block_number */
        )))
    }

    pub fn set_best_executed_epoch(
        &self, best_executed_epoch: StateIndex,
    ) -> StorageResult<()> {
        *self.best_executed_state.lock() =
            Self::best_executed_state(&self.data_man, best_executed_epoch)?;

        Ok(())
    }

    fn get_best_state_account_cache(&self) -> AccountCache {
        let _timer = MeterTimer::time_func(TX_POOL_GET_STATE_TIMER.as_ref());
        AccountCache::new((&*self.best_executed_state.lock()).clone())
    }
}
