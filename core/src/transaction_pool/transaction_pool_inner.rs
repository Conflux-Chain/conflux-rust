use super::{
    account_cache::AccountCache,
    impls::TreapMap,
    nonce_pool::{InsertResult, NoncePool, TxWithReadyInfo},
};
use cfx_types::{Address, H256, H512, U256, U512};
use metrics::{register_meter_with_group, Meter, MeterTimer};
use primitives::{Account, SignedTransaction, TransactionWithSignature};
use rlp::*;
use std::{
    collections::{hash_map::HashMap, VecDeque},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

pub const FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET: u32 = 2000;
pub const TIME_WINDOW: u64 = 100;

lazy_static! {
    static ref TX_POOL_RECALCULATE: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::recalculate");
    static ref TX_POOL_INNER_INSERT_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "tx_pool::inner_insert");
    static ref TX_POOL_INNER_FAILED_GARBAGE_COLLECTED: Arc<dyn Meter> =
        register_meter_with_group("txpool", "failed_garbage_collected");
    static ref DEFERRED_POOL_INNER_INSERT: Arc<dyn Meter> =
        register_meter_with_group("timer", "deferred_pool::inner_insert");
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

    fn check_sender_and_nonce_exists(
        &self, sender: &Address, nonce: &U256,
    ) -> bool {
        if let Some(bucket) = self.buckets.get(sender) {
            bucket.check_nonce_exists(nonce)
        } else {
            false
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
    total_received_count: usize,
    unpacked_transaction_count: usize,
    deferred_pool: DeferredPool,
    ready_account_pool: ReadyAccountPool,
    ready_nonces_and_balances: HashMap<Address, (U256, U256)>,
    garbage_collection_queue: VecDeque<(Address, u64)>,
    txs: HashMap<H256, Arc<SignedTransaction>>,
}

impl TransactionPoolInner {
    pub fn with_capacity(capacity: usize) -> Self {
        TransactionPoolInner {
            capacity,
            total_received_count: 0,
            unpacked_transaction_count: 0,
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
        return self.garbage_collection_queue.len() >= self.capacity;
    }

    pub fn get_current_timestamp(&self) -> u64 {
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
        since_the_epoch.as_secs()
    }

    fn collect_garbage(&mut self) {
        while self.is_full() {
            let (addr, timestamp) =
                self.garbage_collection_queue.front().unwrap().clone();

            if timestamp + TIME_WINDOW >= self.get_current_timestamp() {
                break;
            }

            self.garbage_collection_queue.pop_front();

            // abort if a tx'nonce >= ready nonce
            let (ready_nonce, _) = self
                .get_local_nonce_and_balance(&addr)
                .unwrap_or((0.into(), 0.into()));

            let lowest_nonce =
                *self.deferred_pool.get_lowest_nonce(&addr).unwrap();

            if lowest_nonce >= ready_nonce {
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
                    self.ready_account_pool.remove(&addr);
                }
            }

            // maintain ready info
            if !self.deferred_pool.contain_address(&addr) {
                self.ready_nonces_and_balances.remove(&addr);
            }

            // maintain txs
            self.txs.remove(&removed_tx.hash());
        }
    }

    // the new inserting will fail if tx_pool is full (even if `force` is true)
    pub fn insert_transaction_without_readiness_check(
        &mut self, transaction: Arc<SignedTransaction>, packed: bool,
        force: bool,
    ) -> InsertResult
    {
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
                },
                force,
            )
        };

        match &result {
            InsertResult::NewAdded => {
                self.garbage_collection_queue.push_back((
                    transaction.sender(),
                    self.get_current_timestamp(),
                ));
                self.txs.insert(transaction.hash(), transaction.clone());
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
                if !packed {
                    self.unpacked_transaction_count += 1;
                }
            }
        }

        result
    }

    #[allow(dead_code)]
    fn get_local_nonce(&self, address: &Address) -> Option<&U256> {
        self.ready_nonces_and_balances.get(address).map(|(x, _)| x)
    }

    pub fn get_local_nonce_and_balance(
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

    pub fn get_nonce_and_balance_from_storage(
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
    ) {
        let (nonce, balance) = self
            .get_and_update_nonce_and_balance_from_storage(addr, account_cache);
        let _timer = MeterTimer::time_func(TX_POOL_RECALCULATE.as_ref());
        let ret = self
            .deferred_pool
            .recalculate_readiness_with_local_info(addr, nonce, balance);
        self.ready_account_pool.update(addr, ret);
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
        block_size_limit: usize,
    ) -> Vec<Arc<SignedTransaction>>
    {
        let mut packed_transactions: Vec<Arc<SignedTransaction>> = Vec::new();
        if num_txs == 0 {
            return packed_transactions;
        }

        let mut total_tx_gas_limit: U256 = 0.into();
        let mut total_tx_size: usize = 0;

        let mut big_tx_resample_times_limit = 10;
        let mut too_big_txs = Vec::new();

        'out: while let Some(tx) = self.ready_account_pool.pop() {
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
            self.insert_transaction_without_readiness_check(
                tx.clone(),
                true,
                true,
            );
            self.recalculate_readiness_with_local_info(&tx.sender());

            if packed_transactions.len() >= num_txs {
                break 'out;
            }
        }

        for tx in too_big_txs {
            self.ready_account_pool.insert(tx);
        }

        // FIXME: to be optimized by only recalculating readiness once for one
        //  sender
        for tx in packed_transactions.iter().rev() {
            self.insert_transaction_without_readiness_check(
                tx.clone(),
                false,
                true,
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
                &account.address,
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
        /*
        if self.capacity <= inner.len() {
            warn!("Transaction discarded due to insufficient txpool capacity: {:?}", transaction.hash());
            return Err(format!("Transaction discarded due to insufficient txpool capacity: {:?}", transaction.hash()));
        }
        */
        let (state_nonce, _) = self.get_nonce_and_balance_from_storage(
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
        } else if transaction.nonce < self.get_lowest_nonce(&transaction.sender)
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

        let _timer = MeterTimer::time_func(TX_POOL_INNER_INSERT_TIMER.as_ref());
        let result = self.insert_transaction_without_readiness_check(
            transaction.clone(),
            packed,
            force,
        );
        if let InsertResult::Failed(info) = result {
            return Err(format!("Failed imported to deferred pool: {}", info));
        }

        self.recalculate_readiness_with_state(
            &transaction.sender,
            account_cache,
        );

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
        let mut deferred_pool = DeferredPool::new();

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
