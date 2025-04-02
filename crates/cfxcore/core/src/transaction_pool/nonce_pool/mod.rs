#![allow(dead_code)]

mod nonce_pool_map;
mod weight;

use crate::transaction_pool::TransactionPoolError;
use cfx_packing_pool::{PackingBatch, PackingPoolConfig};
use cfx_parameters::{
    consensus::TRANSACTION_DEFAULT_EPOCH_BOUND,
    staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT,
};
use cfx_rpc_cfx_types::PendingReason;
use cfx_types::{U128, U256, U512};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use primitives::{SignedTransaction, Transaction};
use std::{ops::Deref, sync::Arc};

use self::{nonce_pool_map::NoncePoolMap, weight::NoncePoolWeight};

#[derive(Clone, Debug, DeriveMallocSizeOf)]
pub struct TxWithReadyInfo {
    pub transaction: Arc<SignedTransaction>,
    pub packed: bool,
    pub sponsored_gas: U256,
    pub sponsored_storage: u64,
    tx_cost: U256,
}

impl TxWithReadyInfo {
    pub fn new(
        transaction: Arc<SignedTransaction>, packed: bool, sponsored_gas: U256,
        sponsored_storage: u64,
    ) -> Self {
        let tx_cost =
            Self::cal_tx_cost(&*transaction, sponsored_gas, sponsored_storage);
        Self {
            transaction,
            packed,
            sponsored_gas,
            sponsored_storage,
            tx_cost,
        }
    }
}

#[cfg(test)]
impl PartialEq for TxWithReadyInfo {
    fn eq(&self, other: &Self) -> bool {
        // We don't compare `in_sample_pool` in test
        self.transaction == other.transaction
            && self.packed == other.packed
            && self.sponsored_gas == other.sponsored_gas
            && self.sponsored_storage == other.sponsored_storage
    }
}

impl TxWithReadyInfo {
    pub fn is_already_packed(&self) -> bool { self.packed }

    pub fn get_arc_tx(&self) -> &Arc<SignedTransaction> { &self.transaction }

    pub fn get_tx_cost(&self) -> U256 { self.tx_cost }

    pub fn should_replace(
        &self, x: &Self, force: bool,
    ) -> Result<&'static str, TransactionPoolError> {
        if force {
            return Ok("force tx replace");
        }

        if x.is_already_packed() {
            return Err(TransactionPoolError::NonceTooStale {
                hash: self.hash,
                nonce: self.nonce().saturating_add(1.into()),
            });
        }

        if self.is_already_packed() {
            // Note: currently, the `packed` is marked only if tx has been
            // executed locally
            return Ok("tx has been executed");
        }
        if let (Transaction::Native(ref tx), Transaction::Native(ref other)) =
            (&self.unsigned, &x.unsigned)
        {
            if *tx.epoch_height()
                > other
                    .epoch_height()
                    .saturating_add(TRANSACTION_DEFAULT_EPOCH_BOUND)
            {
                return Ok("too old epoch height");
            }
        }

        let next_gas_price = Self::compute_next_price(*x.gas_price());
        if self.gas_price() >= &next_gas_price {
            Ok("higher gas price")
        } else {
            Err(TransactionPoolError::HigherGasPriceNeeded {
                expected: next_gas_price,
            })
        }
    }

    #[inline]
    fn compute_next_price(price: U256) -> U256 {
        if price < 100.into() {
            price + 1
        } else {
            price + (price / 100) * 2
        }
    }

    pub fn cal_tx_cost(
        transaction: &SignedTransaction, sponsored_gas: U256,
        sponsored_storage: u64,
    ) -> U256 {
        let estimate_gas_u512 = (transaction.gas() - sponsored_gas)
            .full_mul(*transaction.gas_price());
        // normally, the value <= 2^128
        let estimate_gas = if estimate_gas_u512 > U512::from(U128::max_value())
        {
            U256::from(U128::max_value())
        } else {
            (transaction.gas() - sponsored_gas) * transaction.gas_price()
        };
        let storage_collateral_requirement =
            if let Transaction::Native(ref tx) = transaction.unsigned {
                U256::from(*tx.storage_limit() - sponsored_storage)
                    * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
            } else {
                U256::zero()
            };
        // normally, the value <= 2^192
        if *transaction.value()
            > U256::from(u64::MAX) * U256::from(U128::max_value())
        {
            U256::from(u64::MAX) * U256::from(U128::max_value())
                + estimate_gas
                + storage_collateral_requirement
        } else {
            transaction.value() + estimate_gas + storage_collateral_requirement
        }
    }
}

impl Deref for TxWithReadyInfo {
    type Target = SignedTransaction;

    fn deref(&self) -> &Self::Target { &self.transaction }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum InsertResult {
    /// new item added
    NewAdded,
    /// failed to update with lower gas price tx
    Failed(TransactionPoolError),
    /// succeeded to update with higher gas price tx
    Updated(TxWithReadyInfo),
}

pub struct NoncePool {
    map: NoncePoolMap,
}

impl MallocSizeOf for NoncePool {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.map.size_of(ops)
    }
}

impl NoncePool {
    #[inline]
    pub fn new() -> Self {
        Self {
            map: NoncePoolMap::new(),
        }
    }

    #[inline]
    // FIXME: later we should limit the number of txs from one sender.
    //  the FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET roughly doing this job
    pub fn insert(
        &mut self, tx: &TxWithReadyInfo, force: bool,
    ) -> InsertResult {
        self.map.insert(tx, force)
    }

    pub fn mark_packed(&mut self, nonce: &U256, packed: bool) -> bool {
        self.map.mark_packed(nonce, packed)
    }

    #[inline]
    pub fn get_tx_by_nonce(&self, nonce: U256) -> Option<TxWithReadyInfo> {
        self.map.get(&nonce).cloned()
    }

    /// Iter transactions with nonce >= the start nonce. The start nonce may not
    /// exist and the transaction nonces may not continous.
    #[inline]
    pub fn iter_tx_by_nonce(
        &self, nonce: &U256,
    ) -> impl Iterator<Item = &TxWithReadyInfo> {
        self.map.iter_range(nonce)
    }

    #[inline]
    pub fn get_lowest_nonce_tx(&self) -> Option<&SignedTransaction> {
        self.map.leftmost().map(|x| &*x.transaction)
    }

    #[inline]
    pub fn remove(&mut self, nonce: &U256) -> Option<TxWithReadyInfo> {
        self.map.remove(nonce)
    }

    #[inline]
    pub fn remove_lowest_nonce(&mut self) -> Option<TxWithReadyInfo> {
        let nonce = *self.get_lowest_nonce_tx()?.nonce();
        self.remove(&nonce)
    }

    // return the number of transactions whose nonce >= `nonce`
    // and the first transaction with nonce >= `nonce`
    pub fn get_pending_info(
        &self, nonce: &U256,
    ) -> Option<(usize, Arc<SignedTransaction>)> {
        let tx = self.map.succ(nonce).cloned();
        if let Some(tx) = tx {
            let pending_count = self.count_from(&(nonce));
            Some((pending_count, tx.transaction))
        } else {
            None
        }
    }

    /// Return unpacked transactions from `nonce`.
    pub fn get_pending_transactions<'a>(
        &'a self, nonce: &U256,
    ) -> Vec<&'a TxWithReadyInfo> {
        let mut pending_txs = Vec::new();
        for tx_info in self.map.iter_range(&nonce) {
            if !tx_info.packed {
                pending_txs.push(tx_info);
            } else {
                debug!("packed pending tx: tx_info={:?}", tx_info);
            }
        }
        pending_txs
    }

    /// First, find a transaction `tx` such that
    ///   1. all nonce in `[nonce, tx.nonce()]` exists
    ///   2. tx.packed is false and tx.nonce() is minimum
    /// Then, find a sequential of transactions started at the first transaction
    /// such that   
    ///   1. the nonce is continous and all transactions are not packed
    ///   2. the balance is enough.
    ///
    /// The first return value is the transaction in the first step.
    /// i.e., the first unpacked transaction from a sequential of transactions
    /// starting from `nonce`, may be `nonce` itself.
    /// The second return value is the last nonce in the sequential transaction
    /// series from the tx.nonce()
    pub fn recalculate_readiness_with_local_info(
        &self, nonce: U256, balance: U256,
    ) -> Option<(&TxWithReadyInfo, U256)> {
        let tx = self.map.query(&nonce)?;

        let a = if nonce == U256::from(0) {
            NoncePoolWeight::default()
        } else {
            self.map.weight(&(nonce - 1))
        };
        let b = self.map.weight(&tx.nonce());
        // 1. b.cost - a.cost means the sum of cost of
        // transactions in `[nonce, tx.nonce()]`
        // 2. b.size - a.size means number of transactions in
        // `[nonce, tx.nonce()]`
        // 3. tx.nonce() - nonce + 1 means expected
        // number of transactions in `[nonce, tx.nonce()]`
        let size_elapsed = b.size - a.size;
        let cost_elapsed = b.cost - a.cost;
        if U256::from(size_elapsed - 1) != tx.nonce() - nonce
            || cost_elapsed > balance
        {
            return None;
        }

        let end_nonce = self.map.continous_ready_nonce(
            tx.nonce(),
            b,
            balance - cost_elapsed,
        );
        Some((tx, end_nonce))
    }

    /// Make packing batch with readiness info (`first_tx` and
    /// `last_valid_nonce`). Input without readiness check may cause unexpected
    /// behaviour.
    pub fn make_packing_batch(
        &self, first_tx: &TxWithReadyInfo, config: &PackingPoolConfig,
        last_valid_nonce: U256,
    ) -> PackingBatch<Arc<SignedTransaction>> {
        let start_nonce = *first_tx.transaction.nonce();
        let mut batch = PackingBatch::new(first_tx.transaction.clone());

        let mut next_nonce = start_nonce + 1;

        for tx in self.iter_tx_by_nonce(&(start_nonce + 1)) {
            if tx.nonce() != &next_nonce {
                break;
            }
            next_nonce += 1.into();
            let res = batch.insert(tx.transaction.clone(), config);
            if res.1.is_err() {
                break;
            }
            if next_nonce > last_valid_nonce {
                break;
            }
        }
        batch
    }

    #[cfg(test)]
    pub fn recalculate_readiness_with_local_info_test(
        &self, nonce: U256, balance: U256,
    ) -> Option<Arc<SignedTransaction>> {
        self.recalculate_readiness_with_local_info(nonce, balance)
            .map(|x| x.0.transaction.clone())
    }

    pub fn check_pending_reason_with_local_info(
        &self, nonce: U256, balance: U256, pending_tx: &SignedTransaction,
    ) -> Option<PendingReason> {
        let a = if nonce == U256::from(0) {
            NoncePoolWeight::default()
        } else {
            self.map.weight(&(nonce - 1))
        };
        let b = self.map.weight(&pending_tx.nonce());
        // 1. b.cost - a.cost means the sum of cost of transactions in `[nonce,
        // tx.nonce()]`
        // 2. b.size - a.size means number of transactions in `[nonce,
        // tx.nonce()]`

        // The expected nonce is just an estimation by assuming all packed
        // transactions will be executed successfully.
        let expected_nonce = nonce + U256::from(b.size - a.size - 1);
        if expected_nonce != *pending_tx.nonce() {
            return Some(PendingReason::FutureNonce);
        }
        let expected_balance = b.cost - a.cost;
        if expected_balance > balance {
            return Some(PendingReason::NotEnoughCash);
        }
        None
    }

    #[inline]
    pub fn is_empty(&self) -> bool { self.map.len() == 0 }

    /// return the number of transactions whose nonce < `nonce`
    pub fn count_less(&self, nonce: &U256) -> usize {
        if *nonce == U256::from(0) {
            0
        } else {
            self.map.weight(&(nonce - 1)).size as usize
        }
    }

    /// return the number of transactions whose nonce >= `nonce`
    #[inline]
    pub fn count_from(&self, nonce: &U256) -> usize {
        self.map.len() - self.count_less(nonce)
    }

    pub fn check_nonce_exists(&self, nonce: &U256) -> bool {
        self.map.get(nonce).is_some()
    }

    pub fn succ_nonce(&self, nonce: &U256) -> Option<U256> {
        Some(*(self.map.succ(nonce)?.transaction.nonce()))
    }
}

#[cfg(test)]
mod nonce_pool_test {
    use super::{InsertResult, NoncePool, TxWithReadyInfo};
    use crate::{
        keylib::{Generator, KeyPair, Random},
        transaction_pool::TransactionPoolError,
    };
    use cfx_parameters::staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT;
    use cfx_types::{Address, U128, U256};
    use primitives::{
        transaction::native_transaction::NativeTransaction, Action,
        SignedTransaction, Transaction,
    };
    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::{collections::BTreeMap, sync::Arc};

    fn new_test_tx(
        sender: &KeyPair, nonce: U256, gas: U256, gas_price: U256, value: U256,
        storage_limit: u64,
    ) -> Arc<SignedTransaction> {
        Arc::new(
            Transaction::from(NativeTransaction {
                nonce,
                gas_price,
                gas,
                action: Action::Call(Address::random()),
                value,
                storage_limit,
                epoch_height: 0,
                chain_id: 1,
                data: Vec::new(),
            })
            .sign(sender.secret()),
        )
    }

    fn new_test_tx_with_ready_info(
        sender: &KeyPair, nonce: U256, gas: U256, gas_price: U256, value: U256,
        storage_limit: u64, packed: bool,
    ) -> TxWithReadyInfo {
        let transaction =
            new_test_tx(sender, nonce, gas, gas_price, value, storage_limit);
        TxWithReadyInfo::new(
            transaction,
            packed,
            gas / U256::from(2),
            storage_limit / 2,
        )
    }

    #[test]
    fn test_tx_cost() {
        let me = Random.generate().unwrap();
        let value_max = U256::from(u64::MAX) * U256::from(U128::max_value());
        let gas_fee_max = U256::from(U128::max_value());
        // normal case without storage limit
        let tx = new_test_tx_with_ready_info(
            &me,
            0.into(),
            50000.into(),
            10.into(),
            10000.into(),
            0,
            false,
        );
        assert_eq!(tx.get_tx_cost(), U256::from(10 * 50000 / 2 + 10000));
        // normal case with storage limit
        let tx = new_test_tx_with_ready_info(
            &me,
            0.into(),
            50000.into(),
            10.into(),
            10000.into(),
            5000,
            false,
        );
        assert_eq!(
            tx.get_tx_cost(),
            U256::from(10 * 50000 / 2 + 10000)
                + U256::from(5000 / 2) * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
        );
        // very large tx value, not fit the range
        let tx = new_test_tx_with_ready_info(
            &me,
            0.into(),
            50000.into(),
            10.into(),
            value_max + U256::from(1),
            0,
            false,
        );
        assert_eq!(tx.get_tx_cost(), U256::from(10 * 50000 / 2) + value_max);
        // very large tx value, fit the range, #1
        let tx = new_test_tx_with_ready_info(
            &me,
            0.into(),
            50000.into(),
            10.into(),
            value_max,
            0,
            false,
        );
        assert_eq!(tx.get_tx_cost(), U256::from(10 * 50000 / 2) + value_max);
        // very large tx value, fit the range, #1
        let tx = new_test_tx_with_ready_info(
            &me,
            0.into(),
            50000.into(),
            10.into(),
            value_max - U256::from(1),
            0,
            false,
        );
        assert_eq!(
            tx.get_tx_cost(),
            U256::from(10 * 50000 / 2) + value_max - U256::from(1)
        );
        // very large gas fee, not fit the range, #1
        let tx = new_test_tx_with_ready_info(
            &me,
            0.into(),
            U256::from(U128::max_value()),
            U256::max_value(),
            10000.into(),
            5000,
            false,
        );
        assert_eq!(
            tx.get_tx_cost(),
            gas_fee_max
                + U256::from(10000)
                + U256::from(5000 / 2) * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
        );
        // very large gas fee, not fit the range, #2
        let tx = new_test_tx_with_ready_info(
            &me,
            0.into(),
            U256::from(2) * (gas_fee_max + U256::from(1)),
            U256::from(1),
            10000.into(),
            5000,
            false,
        );
        assert_eq!(
            tx.get_tx_cost(),
            gas_fee_max
                + U256::from(10000)
                + U256::from(5000 / 2) * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
        );
        // very large gas fee, fit the range, #1
        let tx = new_test_tx_with_ready_info(
            &me,
            0.into(),
            U256::from(2) * gas_fee_max,
            U256::from(1),
            10000.into(),
            5000,
            false,
        );
        assert_eq!(
            tx.get_tx_cost(),
            gas_fee_max
                + U256::from(10000)
                + U256::from(5000 / 2) * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
        );
        // very large gas fee, fit the range, #2
        let tx = new_test_tx_with_ready_info(
            &me,
            0.into(),
            U256::from(2) * (gas_fee_max - U256::from(1)),
            U256::from(1),
            10000.into(),
            5000,
            false,
        );
        assert_eq!(
            tx.get_tx_cost(),
            gas_fee_max - U256::from(1)
                + U256::from(10000)
                + U256::from(5000 / 2) * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
        );
    }

    #[test]
    fn test_basic_operation() {
        let me = Random.generate().unwrap();
        let mut tx1 = Vec::new();
        let mut tx2 = Vec::new();
        for i in 0..10 {
            tx1.push(new_test_tx_with_ready_info(
                &me,
                i.into(),
                50000.into(),
                10.into(),
                10000.into(),
                5000,
                false,
            ));
        }
        for i in 0..10 {
            tx2.push(new_test_tx_with_ready_info(
                &me,
                i.into(),
                50000.into(),
                10.into(),
                10000.into(),
                50000,
                false,
            ));
        }
        let mut nonce_pool = NoncePool::new();
        assert_eq!(nonce_pool.is_empty(), true);
        for i in 0..10 {
            assert_eq!(
                nonce_pool.insert(&tx1[i as usize], false /* force */),
                InsertResult::NewAdded
            );
            assert_eq!(
                nonce_pool.get_tx_by_nonce(U256::from(i)),
                Some(tx1[i].clone())
            );
            assert_eq!(
                nonce_pool.insert(&tx2[i as usize], false /* force */),
                InsertResult::Failed(
                    TransactionPoolError::HigherGasPriceNeeded {
                        expected: tx1[i as usize].gas_price() + 1
                    }
                )
            );
            assert_eq!(
                nonce_pool.insert(&tx2[i as usize], true /* force */),
                InsertResult::Updated(tx1[i as usize].clone())
            );
            assert_eq!(nonce_pool.is_empty(), false);
        }
        for i in 0..10 {
            assert_eq!(nonce_pool.count_from(&U256::from(i)), 10 - i);
        }
        for i in 0..10 {
            assert_eq!(nonce_pool.count_from(&U256::from(i)), 10 - i);
            assert_eq!(
                *nonce_pool.get_lowest_nonce_tx().unwrap().nonce(),
                U256::from(i)
            );
            assert_eq!(nonce_pool.remove_lowest_nonce(), Some(tx2[i].clone()));
            assert_eq!(nonce_pool.remove(&U256::from(i)), None);
            assert_eq!(nonce_pool.check_nonce_exists(&U256::from(i)), false);
            assert_eq!(nonce_pool.count_from(&U256::from(i)), 9 - i);
        }
        assert_eq!(nonce_pool.is_empty(), true);
    }

    #[test]
    fn test_readiness() {
        let me = Random.generate().unwrap();
        let mut tx = Vec::new();
        let value = U256::from(10000);
        let gas_price = U256::from(10);
        let storage_limit = 5000;
        let gas = U256::from(50000);
        let storage_per_tx =
            U256::from(storage_limit / 2) * *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
        for i in 5..10 {
            if i <= 7 {
                tx.push(new_test_tx_with_ready_info(
                    &me,
                    i.into(),
                    gas * U256::from(2),
                    gas_price,
                    value,
                    storage_limit,
                    true,
                ));
            } else {
                tx.push(new_test_tx_with_ready_info(
                    &me,
                    i.into(),
                    gas * U256::from(2),
                    gas_price,
                    value,
                    storage_limit,
                    false,
                ));
            }
        }
        let exact_cost = U256::from(4)
            * (gas * gas_price + U256::from(value) + storage_per_tx);
        let mut nonce_pool = NoncePool::new();

        for i in vec![0, 1, 3, 4] {
            assert_eq!(
                nonce_pool.insert(&tx[i], false /* force */),
                InsertResult::NewAdded
            );
            assert_eq!(
                nonce_pool.get_tx_by_nonce((i + 5).into()),
                Some(tx[i].clone())
            );
        }

        assert_eq!(nonce_pool.get_tx_by_nonce(7.into()), None);
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info_test(
                4.into(),
                exact_cost
            ),
            None
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info_test(
                5.into(),
                exact_cost
            ),
            None
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info_test(
                7.into(),
                exact_cost
            ),
            None
        );
        assert_eq!(
            nonce_pool.insert(&tx[2], false /* force */),
            InsertResult::NewAdded
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info_test(
                4.into(),
                exact_cost
            ),
            None
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info_test(
                5.into(),
                exact_cost
            ),
            Some(tx[3].transaction.clone())
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info_test(
                7.into(),
                exact_cost
            ),
            Some(tx[3].transaction.clone())
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info_test(
                8.into(),
                exact_cost
            ),
            Some(tx[3].transaction.clone())
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info_test(
                9.into(),
                exact_cost
            ),
            Some(tx[4].transaction.clone())
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info_test(
                10.into(),
                exact_cost
            ),
            None
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info_test(
                5.into(),
                exact_cost - U256::from(1),
            ),
            None
        );
    }

    fn recalculate_readiness_with_local_info(
        nonce_pool: &BTreeMap<U256, TxWithReadyInfo>, nonce: U256,
        balance: U256,
    ) -> Option<(Arc<SignedTransaction>, U256)> {
        let mut next_nonce = nonce;
        let mut balance_left = balance;

        let first_tx = loop {
            let tx = nonce_pool.get(&next_nonce)?;
            let cost = tx.get_tx_cost();
            if balance_left < cost {
                return None;
            }

            if !tx.is_already_packed() {
                balance_left -= cost;
                next_nonce += 1.into();

                break tx.transaction.clone();
            }
            balance_left -= cost;
            next_nonce += 1.into();
        };

        loop {
            let tx = if let Some(tx) = nonce_pool.get(&next_nonce) {
                tx
            } else {
                return Some((first_tx, next_nonce - 1));
            };
            let cost = tx.get_tx_cost();

            if balance_left < cost || tx.is_already_packed() {
                return Some((first_tx, next_nonce - 1));
            }

            balance_left -= cost;
            next_nonce += 1.into();
        }
    }

    #[test]
    fn test_correctness() {
        let me = Random.generate().unwrap();
        let mut rng = XorShiftRng::from_entropy();
        let mut tx = Vec::new();
        let storage_limit = 5000;
        let gas_price = U256::from(10);
        let gas = U256::from(50000);
        let value = U256::from(10000);
        let count = 100000;
        let storage_per_tx =
            U256::from(storage_limit / 2) * *DRIPS_PER_STORAGE_COLLATERAL_UNIT;
        for i in 0..count {
            tx.push(new_test_tx_with_ready_info(
                &me,
                i.into(),
                gas * U256::from(2),
                gas_price,
                value,
                storage_limit,
                rng.next_u64() % 2 == 1,
            ));
        }
        let mut nonce_pool = NoncePool::new();
        let mut mock_nonce_pool = BTreeMap::new();

        // random insert
        for _ in 0..count {
            let nonce: usize = rng.next_u64() as usize % count;
            if mock_nonce_pool.contains_key(&nonce.into()) {
                assert_eq!(
                    nonce_pool.insert(&tx[nonce], true /* force */),
                    InsertResult::Updated(tx[nonce].clone())
                );
            } else {
                assert_eq!(
                    nonce_pool.insert(&tx[nonce], false /* force */),
                    InsertResult::NewAdded
                );
                mock_nonce_pool.insert(nonce.into(), tx[nonce].clone());
            }
        }

        // random change packed
        for _ in 0..count {
            let nonce: usize = rng.next_u64() as usize % count;
            let packed = rng.next_u64() % 2 == 1;
            let current_packed =
                if let Some(x) = mock_nonce_pool.get_mut(&nonce.into()) {
                    let current_packed = x.packed;
                    x.packed = packed;
                    Some(current_packed)
                } else {
                    None
                };
            let should_change = current_packed.map_or(false, |p| p != packed);
            let changed = nonce_pool.mark_packed(&nonce.into(), packed);
            assert_eq!(should_change, changed);
            tx[nonce].packed = packed;
        }

        for i in 0..count * 2 {
            let balance = U256::from(rng.next_u64() % 100)
                * (gas * gas_price + U256::from(value) + storage_per_tx);
            let mut nonce: usize = rng.next_u64() as usize % count;
            if i < count {
                nonce = i;
            }
            let expected = recalculate_readiness_with_local_info(
                &mock_nonce_pool,
                nonce.into(),
                balance.into(),
            );
            assert_eq!(
                expected,
                nonce_pool
                    .recalculate_readiness_with_local_info(
                        nonce.into(),
                        balance.into(),
                    )
                    .map(|(tx, nonce)| (tx.transaction.clone(), nonce))
            );
        }

        // random delete
        for _ in 0..1000 {
            let nonce: usize = rng.next_u64() as usize % count;
            assert_eq!(
                nonce_pool.remove(&nonce.into()),
                mock_nonce_pool.remove(&nonce.into())
            );
        }

        // random insert
        for _ in 0..1000 {
            let nonce: usize = rng.next_u64() as usize % count;
            if mock_nonce_pool.contains_key(&nonce.into()) {
                assert_eq!(
                    nonce_pool.insert(&tx[nonce], true /* force */),
                    InsertResult::Updated(tx[nonce].clone())
                );
            } else {
                assert_eq!(
                    nonce_pool.insert(&tx[nonce], false /* force */),
                    InsertResult::NewAdded
                );
                mock_nonce_pool.insert(nonce.into(), tx[nonce].clone());
            }
        }

        for i in 0..count * 2 {
            let balance = U256::from(rng.next_u64() % 100)
                * (gas * gas_price + U256::from(value) + storage_per_tx);
            let mut nonce: usize = rng.next_u64() as usize % count;
            if i < count {
                nonce = i;
            }
            let expected = recalculate_readiness_with_local_info(
                &mock_nonce_pool,
                nonce.into(),
                balance,
            );
            assert_eq!(
                expected,
                nonce_pool
                    .recalculate_readiness_with_local_info(
                        nonce.into(),
                        balance,
                    )
                    .map(|(tx, nonce)| (tx.transaction.clone(), nonce))
            );
        }
    }
}
