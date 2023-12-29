mod nonce_pool_map;
mod weight;

use crate::transaction_pool::transaction_pool_inner::PendingReason;
use cfx_parameters::{
    consensus::TRANSACTION_DEFAULT_EPOCH_BOUND,
    staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT,
};
use cfx_types::{U128, U256, U512};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use primitives::{SignedTransaction, Transaction};
use std::{ops::Deref, sync::Arc};

use self::nonce_pool_map::NoncePoolMap;

#[derive(Clone, Debug, PartialEq, DeriveMallocSizeOf)]
pub struct TxWithReadyInfo {
    pub transaction: Arc<SignedTransaction>,
    pub packed: bool,
    pub sponsored_gas: U256,
    pub sponsored_storage: u64,
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
        let higher_epoch_height =
            if let Transaction::Native(ref tx) = self.unsigned {
                if let Transaction::Native(ref other) = x.unsigned {
                    // FIXME: Use epoch_bound in spec. It's still a part of
                    // normal config.
                    if tx.epoch_height
                        > other.epoch_height.saturating_add(
                            TRANSACTION_DEFAULT_EPOCH_BOUND.saturating_mul(2),
                        )
                    {
                        // the epoch_height between `self` and `other` has been
                        // more than
                        // twice `TRANSACTION_DEFAULT_EPOCH_BOUND`. Since `self`
                        // has passed epoch height
                        // verification, it's sure that `other` cannot pass this
                        // verification anymore and should be dropped.
                        return true;
                    }
                    tx.epoch_height > other.epoch_height
                } else {
                    // Should be unreachable. But I'm not very sure about this.
                    // Return false is safe.
                    false
                }
            } else {
                false
            };
        self.gas_price() > x.gas_price()
            || self.gas_price() == x.gas_price() && higher_epoch_height
    }

    pub fn calc_tx_cost(&self) -> U256 {
        let estimate_gas_u512 =
            (self.gas() - self.sponsored_gas).full_mul(*self.gas_price());
        // normally, the value <= 2^128
        let estimate_gas = if estimate_gas_u512 > U512::from(U128::max_value())
        {
            U256::from(U128::max_value())
        } else {
            (self.gas() - self.sponsored_gas) * self.gas_price()
        };
        let sponsored_storage = self.sponsored_storage;
        let storage_collateral_requirement =
            if let Transaction::Native(ref tx) = self.unsigned {
                U256::from(tx.storage_limit - sponsored_storage)
                    * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
            } else {
                U256::zero()
            };
        // normally, the value <= 2^192
        if *self.value() > U256::from(u64::MAX) * U256::from(U128::max_value())
        {
            U256::from(u64::MAX) * U256::from(U128::max_value())
                + estimate_gas
                + storage_collateral_requirement
        } else {
            self.value() + estimate_gas + storage_collateral_requirement
        }
    }
}

impl Deref for TxWithReadyInfo {
    type Target = SignedTransaction;

    fn deref(&self) -> &Self::Target { &self.transaction }
}

#[derive(Debug, PartialEq)]
pub enum InsertResult {
    /// new item added
    NewAdded,
    /// failed to update with lower gas price tx
    Failed(String),
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
    pub fn get_pending_transactions(
        &self, nonce: &U256,
    ) -> Vec<Arc<SignedTransaction>> {
        let mut pending_txs = Vec::new();
        let mut maybe_tx_info = self.map.succ(nonce).cloned();
        // TODO: More efficient traversal of Treap.
        while let Some(tx_info) = maybe_tx_info {
            if !tx_info.packed {
                pending_txs.push(tx_info.transaction.clone());
            } else {
                debug!("packed pending tx: tx_info={:?}", tx_info);
            }
            maybe_tx_info =
                self.map.succ(&(tx_info.transaction.nonce() + 1)).cloned();
        }
        pending_txs
    }

    /// find a transaction `tx` such that
    ///   1. all nonce in `[nonce, tx.nonce()]` exists
    ///   2. tx.packed is false and tx.nonce() is minimum
    pub fn recalculate_readiness_with_local_info(
        &self, nonce: U256, balance: U256,
    ) -> Option<Arc<SignedTransaction>> {
        let tx = self.map.query(&nonce)?;

        let a = if nonce == U256::from(0) {
            (0, U256::from(0))
        } else {
            self.map.rank(&(nonce - 1))
        };
        let b = self.map.rank(&tx.nonce());
        // 1. b.1 - a.1 means the sum of cost of transactions in `[nonce,
        // tx.nonce()]`
        // 2. b.0 - a.0 means number of transactions in `[nonce,
        // tx.nonce()]` 3. x.nonce() - nonce + 1 means expected
        // number of transactions in `[nonce, tx.nonce()]`
        (U256::from(b.0 - a.0 - 1) == tx.nonce() - nonce
            && b.1 - a.1 <= balance)
            .then_some(tx)
    }

    pub fn check_pending_reason_with_local_info(
        &self, nonce: U256, balance: U256, pending_tx: &SignedTransaction,
    ) -> Option<PendingReason> {
        let a = if nonce == U256::from(0) {
            (0, U256::from(0))
        } else {
            self.map.rank(&(nonce - 1))
        };
        let b = self.map.rank(&pending_tx.nonce());
        // 1. b.1 - a.1 means the sum of cost of transactions in `[nonce,
        // tx.nonce()]`
        // 2. b.0 - a.0 means number of transactions in `[nonce, tx.nonce()]`

        // The expected nonce is just an estimation by assuming all packed
        // transactions will be executed successfully.
        let expected_nonce = nonce + U256::from(b.0 - a.0 - 1);
        if expected_nonce != *pending_tx.nonce() {
            return Some(PendingReason::FutureNonce);
        }
        let expected_balance = b.1 - a.1;
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
            self.map.rank(&(nonce - 1)).0 as usize
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
    use cfx_parameters::staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT;
    use cfx_types::{Address, U128, U256};
    use keylib::{Generator, KeyPair, Random};
    use primitives::{
        Action, NativeTransaction, SignedTransaction, Transaction,
    };
    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::{collections::BTreeMap, sync::Arc};

    fn new_test_tx(
        sender: &KeyPair, nonce: U256, gas: U256, gas_price: U256, value: U256,
        storage_limit: u64,
    ) -> Arc<SignedTransaction>
    {
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
    ) -> TxWithReadyInfo
    {
        let transaction =
            new_test_tx(sender, nonce, gas, gas_price, value, storage_limit);
        TxWithReadyInfo {
            transaction,
            packed,
            sponsored_gas: gas / U256::from(2),
            sponsored_storage: storage_limit / 2,
        }
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
        assert_eq!(tx.calc_tx_cost(), U256::from(10 * 50000 / 2 + 10000));
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
            tx.calc_tx_cost(),
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
        assert_eq!(tx.calc_tx_cost(), U256::from(10 * 50000 / 2) + value_max);
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
        assert_eq!(tx.calc_tx_cost(), U256::from(10 * 50000 / 2) + value_max);
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
            tx.calc_tx_cost(),
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
            tx.calc_tx_cost(),
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
            tx.calc_tx_cost(),
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
            tx.calc_tx_cost(),
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
            tx.calc_tx_cost(),
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
            assert_eq!(nonce_pool.insert(&tx2[i as usize], false /* force */),
                       InsertResult::Failed(format!("Tx with same nonce already inserted. To replace it, you need to specify a gas price > {}", &tx1[i as usize].gas_price())));
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
            nonce_pool
                .recalculate_readiness_with_local_info(4.into(), exact_cost),
            None
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(5.into(), exact_cost),
            None
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(7.into(), exact_cost),
            None
        );
        assert_eq!(
            nonce_pool.insert(&tx[2], false /* force */),
            InsertResult::NewAdded
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(4.into(), exact_cost),
            None
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(5.into(), exact_cost),
            Some(tx[3].transaction.clone())
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(7.into(), exact_cost),
            Some(tx[3].transaction.clone())
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(8.into(), exact_cost),
            Some(tx[3].transaction.clone())
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(9.into(), exact_cost),
            Some(tx[4].transaction.clone())
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(10.into(), exact_cost),
            None
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info(
                5.into(),
                exact_cost - U256::from(1),
            ),
            None
        );
    }

    fn recalculate_readiness_with_local_info(
        nonce_pool: &BTreeMap<U256, TxWithReadyInfo>, nonce: U256,
        balance: U256,
    ) -> Option<Arc<SignedTransaction>>
    {
        let mut next_nonce = nonce;
        let mut balance_left = balance;
        while let Some(tx) = nonce_pool.get(&next_nonce) {
            let cost = tx.calc_tx_cost();
            if balance_left < cost {
                return None;
            }

            if !tx.is_already_packed() {
                return Some(tx.transaction.clone());
            }
            balance_left -= cost;
            next_nonce += 1.into();
        }
        None
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
                nonce_pool.recalculate_readiness_with_local_info(
                    nonce.into(),
                    balance.into(),
                )
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
                nonce_pool.recalculate_readiness_with_local_info(
                    nonce.into(),
                    balance,
                )
            );
        }
    }
}
