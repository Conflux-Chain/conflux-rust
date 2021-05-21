use crate::transaction_pool::transaction_pool_inner::PendingReason;
use cfx_parameters::staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT;
use cfx_types::{U128, U256, U512};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use primitives::SignedTransaction;
use rand::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use std::{cmp::Ordering, mem, ops::Deref, sync::Arc};

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
        self.gas_price > x.gas_price
            || self.gas_price == x.gas_price
                && self.epoch_height > x.epoch_height
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

#[derive(Debug, DeriveMallocSizeOf)]
struct NoncePoolNode {
    /// transaction in current node
    tx: TxWithReadyInfo,
    /// number of unpacked transactions in subtree
    subtree_unpacked: u32,
    /// sum of cost of transaction in subtree
    subtree_cost: U256,
    // number of transaction in subtree
    subtree_size: u32,
    /// priority of this node following the max binary heap invariant
    priority: u64,
    /// left/right child of this node
    child: [Option<Box<NoncePoolNode>>; 2],
}

impl NoncePoolNode {
    fn calc_tx_cost(tx: &TxWithReadyInfo) -> U256 {
        let estimate_gas_u512 =
            (tx.gas - tx.sponsored_gas).full_mul(tx.gas_price);
        // normally, the value <= 2^128
        let estimate_gas = if estimate_gas_u512 > U512::from(U128::max_value())
        {
            U256::from(U128::max_value())
        } else {
            (tx.gas - tx.sponsored_gas) * tx.gas_price
        };
        // normally, the value <= 2^192
        if tx.value > U256::from(u64::MAX) * U256::from(U128::max_value()) {
            U256::from(u64::MAX) * U256::from(U128::max_value())
                + estimate_gas
                + U256::from(tx.storage_limit - tx.sponsored_storage)
                    * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
        } else {
            tx.value
                + estimate_gas
                + U256::from(tx.storage_limit - tx.sponsored_storage)
                    * *DRIPS_PER_STORAGE_COLLATERAL_UNIT
        }
    }

    pub fn new(tx: &TxWithReadyInfo, priority: u64) -> Self {
        NoncePoolNode {
            tx: tx.clone(),
            subtree_unpacked: 1 - tx.packed as u32,
            subtree_cost: Self::calc_tx_cost(tx),
            subtree_size: 1,
            priority,
            child: [None, None],
        }
    }

    /// return the leftmost node
    pub fn leftmost(&self) -> Option<&TxWithReadyInfo> {
        if self.child[0].as_ref().is_some() {
            self.child[0].as_ref().unwrap().leftmost()
        } else {
            Some(&self.tx)
        }
    }

    pub fn get(&self, nonce: &U256) -> Option<&TxWithReadyInfo> {
        match nonce.cmp(&self.tx.nonce) {
            Ordering::Less => self.child[0].as_ref().and_then(|x| x.get(nonce)),
            Ordering::Equal => Some(&self.tx),
            Ordering::Greater => {
                self.child[1].as_ref().and_then(|x| x.get(nonce))
            }
        }
    }

    // return the next item with nonce >= given nonce
    pub fn succ(&self, nonce: &U256) -> Option<&TxWithReadyInfo> {
        match nonce.cmp(&self.tx.nonce) {
            Ordering::Less | Ordering::Equal => {
                let ret = if self.child[0].as_ref().is_some() {
                    self.child[0].as_ref().unwrap().succ(nonce)
                } else {
                    None
                };
                if ret.is_none() {
                    Some(&self.tx)
                } else {
                    ret
                }
            }
            Ordering::Greater => {
                if self.child[1].as_ref().is_some() {
                    self.child[1].as_ref().unwrap().succ(nonce)
                } else {
                    None
                }
            }
        }
    }

    /// insert a new TxWithReadyInfo. if the corresponding nonce already exists,
    /// will replace with higher gas price transaction
    pub fn insert(
        node: &mut Option<Box<NoncePoolNode>>, tx: &TxWithReadyInfo,
        priority: u64, force: bool,
    ) -> InsertResult
    {
        if node.is_none() {
            *node = Some(Box::new(NoncePoolNode::new(tx, priority)));
            return InsertResult::NewAdded;
        }
        let cmp = tx.nonce().cmp(&node.as_ref().unwrap().tx.nonce);
        if cmp == Ordering::Equal {
            let result = {
                if tx.should_replace(&node.as_ref().unwrap().tx, force) {
                    InsertResult::Updated(mem::replace(
                        &mut node.as_mut().unwrap().tx,
                        tx.clone(),
                    ))
                } else {
                    InsertResult::Failed(format!("Tx with same nonce already inserted. To replace it, you need to specify a gas price > {}", &node.as_ref().unwrap().tx.gas_price))
                }
            };
            node.as_mut().unwrap().update();
            result
        } else {
            let d = (cmp == Ordering::Greater) as usize;
            let result = NoncePoolNode::insert(
                &mut node.as_mut().unwrap().child[d],
                tx,
                priority,
                force,
            );
            if node.as_ref().unwrap().priority
                < node.as_ref().unwrap().child[d].as_ref().unwrap().priority
            {
                NoncePoolNode::rotate(node, d);
            }
            node.as_mut().unwrap().update();
            result
        }
    }

    pub fn remove(
        node: &mut Option<Box<NoncePoolNode>>, nonce: &U256,
    ) -> Option<TxWithReadyInfo> {
        if node.is_none() {
            return None;
        }
        let result = match nonce.cmp(&node.as_ref().unwrap().tx.nonce) {
            Ordering::Less => NoncePoolNode::remove(
                &mut node.as_mut().unwrap().child[0],
                nonce,
            ),
            Ordering::Equal => {
                // leaf node, remove directly
                if node.as_ref().unwrap().child[0].is_none()
                    && node.as_ref().unwrap().child[1].is_none()
                {
                    return Some(mem::replace(node, None).unwrap().tx);
                }
                // rotate the node the a leaf node according to child's priority
                // rotate left if left.priority < right.priority, or rotate
                // right otherwise
                if node.as_ref().unwrap().child[0].is_none()
                    || node.as_ref().unwrap().child[1].is_some()
                        && node.as_ref().unwrap().child[0]
                            .as_ref()
                            .unwrap()
                            .priority
                            < node.as_ref().unwrap().child[1]
                                .as_ref()
                                .unwrap()
                                .priority
                {
                    NoncePoolNode::rotate(node, 1);
                    NoncePoolNode::remove(
                        &mut node.as_mut().unwrap().child[0],
                        nonce,
                    )
                } else {
                    NoncePoolNode::rotate(node, 0);
                    NoncePoolNode::remove(
                        &mut node.as_mut().unwrap().child[1],
                        nonce,
                    )
                }
            }
            Ordering::Greater => NoncePoolNode::remove(
                &mut node.as_mut().unwrap().child[1],
                nonce,
            ),
        };
        node.as_mut().unwrap().update();
        result
    }

    /// find number of transactions and sum of cost whose nonce <= `nonce`
    pub fn rank(
        node: &Option<Box<NoncePoolNode>>, nonce: &U256,
    ) -> (u32, U256) {
        match node.as_ref() {
            Some(node) => {
                let cmp = nonce.cmp(&node.tx.nonce);
                if cmp == Ordering::Less {
                    NoncePoolNode::rank(&node.child[0], nonce)
                } else {
                    let mut ret = NoncePoolNode::size(&node.child[0]);
                    ret.0 += 1;
                    ret.1 += Self::calc_tx_cost(&node.tx);
                    if cmp == Ordering::Greater {
                        let tmp = NoncePoolNode::rank(&node.child[1], nonce);
                        ret.0 += tmp.0;
                        ret.1 += tmp.1;
                    }
                    ret
                }
            }
            None => (0, 0.into()),
        }
    }

    /// find an unpacked transaction `tx` where `tx.nonce >= nonce`
    /// and `tx.nonce` is minimum
    pub fn query(
        node: &Option<Box<NoncePoolNode>>, nonce: &U256,
    ) -> Option<Arc<SignedTransaction>> {
        node.as_ref().and_then(|node| {
            if node.subtree_unpacked == 0 {
                return None;
            }
            match nonce.cmp(&node.tx.nonce) {
                Ordering::Less => NoncePoolNode::query(&node.child[0], nonce)
                    .or_else(|| {
                        if !node.tx.packed {
                            Some(node.tx.transaction.clone())
                        } else {
                            NoncePoolNode::query(&node.child[1], nonce)
                        }
                    }),
                Ordering::Equal => {
                    if !node.tx.packed {
                        Some(node.tx.transaction.clone())
                    } else {
                        NoncePoolNode::query(&node.child[1], nonce)
                    }
                }
                Ordering::Greater => {
                    NoncePoolNode::query(&node.child[1], nonce)
                }
            }
        })
    }

    /// rotate to maintain max binary heap invariant
    /// ch = 0 means rotate right; ch = 1 means rotate left
    fn rotate(node: &mut Option<Box<NoncePoolNode>>, ch: usize) {
        let mut c = mem::replace(&mut node.as_mut().unwrap().child[ch], None);
        if c.is_some() {
            mem::swap(node, &mut c);
            mem::swap(
                &mut c.as_mut().unwrap().child[ch],
                &mut node.as_mut().unwrap().child[ch ^ 1],
            );
            c.as_mut().unwrap().update();
            node.as_mut().unwrap().child[ch ^ 1] = c;
            node.as_mut().unwrap().update();
        }
    }

    /// update subtree info: cost_sum, size, unpacked
    fn update(&mut self) {
        self.subtree_unpacked = 1 - self.tx.packed as u32;
        self.subtree_cost = Self::calc_tx_cost(&self.tx);
        self.subtree_size = 1;
        for i in 0..2 {
            if self.child[i as usize].is_some() {
                let child = self.child[i as usize].as_ref().unwrap();
                self.subtree_unpacked += child.subtree_unpacked;
                self.subtree_cost += child.subtree_cost;
                self.subtree_size += child.subtree_size;
            }
        }
    }

    /// return the size and the sum of balance of current subtree
    fn size(node: &Option<Box<NoncePoolNode>>) -> (u32, U256) {
        if node.is_none() {
            (0, 0.into())
        } else {
            (
                node.as_ref().unwrap().subtree_size,
                node.as_ref().unwrap().subtree_cost,
            )
        }
    }
}

pub struct NoncePool {
    root: Option<Box<NoncePoolNode>>,
    rng: XorShiftRng,
}

impl MallocSizeOf for NoncePool {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.root.size_of(ops)
    }
}

impl NoncePool {
    pub fn new() -> Self {
        NoncePool {
            root: None,
            rng: XorShiftRng::from_entropy(),
        }
    }

    // FIXME: later we should limit the number of txs from one sender.
    //  the FURTHEST_FUTURE_TRANSACTION_NONCE_OFFSET roughly doing this job
    pub fn insert(
        &mut self, tx: &TxWithReadyInfo, force: bool,
    ) -> InsertResult {
        NoncePoolNode::insert(&mut self.root, tx, self.rng.next_u64(), force)
    }

    pub fn get_tx_by_nonce(&self, nonce: U256) -> Option<TxWithReadyInfo> {
        self.root
            .as_ref()
            .and_then(|node| node.get(&nonce).map(|x| x.clone()))
    }

    pub fn get_lowest_nonce(&self) -> Option<&U256> {
        self.root
            .as_ref()
            .and_then(|node| node.leftmost().map(|x| &x.transaction.nonce))
    }

    pub fn remove(&mut self, nonce: &U256) -> Option<TxWithReadyInfo> {
        NoncePoolNode::remove(&mut self.root, nonce)
    }

    pub fn remove_lowest_nonce(&mut self) -> Option<TxWithReadyInfo> {
        let lowest_nonce = self.get_lowest_nonce().map(|x| x.clone());
        lowest_nonce.and_then(|nonce| self.remove(&nonce))
    }

    pub fn get_pending_info(
        &self, nonce: &U256,
    ) -> Option<(usize, Arc<SignedTransaction>)> {
        let tx = self
            .root
            .as_ref()
            .and_then(|node| node.succ(&nonce).map(|x| x.clone()));
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
        let mut maybe_tx_info = self
            .root
            .as_ref()
            .and_then(|node| node.succ(&nonce).map(|x| x.clone()));
        // TODO: More efficient traversal of Treap.
        while let Some(tx_info) = maybe_tx_info {
            if !tx_info.packed {
                pending_txs.push(tx_info.transaction.clone());
            }
            maybe_tx_info = self.root.as_ref().and_then(|node| {
                node.succ(&(tx_info.transaction.nonce + U256::from(1)))
                    .map(|x| x.clone())
            });
        }
        pending_txs
    }

    /// find a transaction `tx` such that
    ///   1. all nonce in `[nonce, tx.nonce]` exists
    ///   2. tx.packed is false and tx.nonce is minimum
    pub fn recalculate_readiness_with_local_info(
        &self, nonce: U256, balance: U256,
    ) -> Option<Arc<SignedTransaction>> {
        NoncePoolNode::query(&self.root, &nonce).filter(|x| {
            let a = if nonce == U256::from(0) {
                (0, U256::from(0))
            } else {
                NoncePoolNode::rank(&self.root, &(nonce - 1))
            };
            let b = NoncePoolNode::rank(&self.root, &x.nonce);
            // 1. b.1 - a.1 means the sum of cost of transactions in `[nonce,
            // tx.nonce]`
            // 2. b.0 - a.0 means number of transactions in `[nonce, tx.nonce]`
            // 3. x.nonce - nonce + 1 means expected number of transactions in
            // `[nonce, tx.nonce]`
            U256::from(b.0 - a.0 - 1) == x.nonce - nonce && b.1 - a.1 <= balance
        })
    }

    pub fn check_pending_reason_with_local_info(
        &self, nonce: U256, balance: U256, pending_tx: &SignedTransaction,
    ) -> Option<PendingReason> {
        let a = if nonce == U256::from(0) {
            (0, U256::from(0))
        } else {
            NoncePoolNode::rank(&self.root, &(nonce - 1))
        };
        let b = NoncePoolNode::rank(&self.root, &pending_tx.nonce);
        // 1. b.1 - a.1 means the sum of cost of transactions in `[nonce,
        // tx.nonce]`
        // 2. b.0 - a.0 means number of transactions in `[nonce, tx.nonce]`

        // The expected nonce is just an estimation by assuming all packed
        // transactions will be executed successfully.
        let expected_nonce = nonce + U256::from(b.0 - a.0 - 1);
        if expected_nonce != pending_tx.nonce {
            return Some(PendingReason::FutureNonce);
        }
        let expected_balance = b.1 - a.1;
        if expected_balance > balance {
            return Some(PendingReason::NotEnoughCash);
        }
        None
    }

    pub fn is_empty(&self) -> bool { self.root.is_none() }

    /// return the number of transactions whose nonce < `nonce`
    pub fn count_less(&self, nonce: &U256) -> usize {
        if *nonce == U256::from(0) {
            0
        } else {
            NoncePoolNode::rank(&self.root, &(nonce - 1)).0 as usize
        }
    }

    /// return the number of transactions whose nonce >= `nonce`
    pub fn count_from(&self, nonce: &U256) -> usize {
        NoncePoolNode::size(&self.root).0 as usize - self.count_less(nonce)
    }

    pub fn check_nonce_exists(&self, nonce: &U256) -> bool {
        self.root
            .as_ref()
            .and_then(|node| node.get(&nonce))
            .is_some()
    }
}

#[cfg(test)]
mod nonce_pool_test {
    use super::{InsertResult, NoncePool, TxWithReadyInfo};
    use crate::transaction_pool::nonce_pool::NoncePoolNode;
    use cfx_parameters::staking::DRIPS_PER_STORAGE_COLLATERAL_UNIT;
    use cfx_types::{Address, U128, U256};
    use keylib::{Generator, KeyPair, Random};
    use primitives::{Action, SignedTransaction, Transaction};
    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use std::{collections::BTreeMap, sync::Arc};

    fn new_test_tx(
        sender: &KeyPair, nonce: U256, gas: U256, gas_price: U256, value: U256,
        storage_limit: u64,
    ) -> Arc<SignedTransaction>
    {
        Arc::new(
            Transaction {
                nonce,
                gas_price,
                gas,
                action: Action::Call(Address::random()),
                value,
                storage_limit,
                epoch_height: 0,
                chain_id: 0,
                data: Vec::new(),
            }
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
        assert_eq!(
            NoncePoolNode::calc_tx_cost(&tx),
            U256::from(10 * 50000 / 2 + 10000)
        );
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
            NoncePoolNode::calc_tx_cost(&tx),
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
        assert_eq!(
            NoncePoolNode::calc_tx_cost(&tx),
            U256::from(10 * 50000 / 2) + value_max
        );
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
        assert_eq!(
            NoncePoolNode::calc_tx_cost(&tx),
            U256::from(10 * 50000 / 2) + value_max
        );
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
            NoncePoolNode::calc_tx_cost(&tx),
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
            NoncePoolNode::calc_tx_cost(&tx),
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
            NoncePoolNode::calc_tx_cost(&tx),
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
            NoncePoolNode::calc_tx_cost(&tx),
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
            NoncePoolNode::calc_tx_cost(&tx),
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
                       InsertResult::Failed(format!("Tx with same nonce already inserted. To replace it, you need to specify a gas price > {}", &tx1[i as usize].gas_price)));
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
            assert_eq!(*nonce_pool.get_lowest_nonce().unwrap(), U256::from(i));
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
                .recalculate_readiness_with_local_info(4.into(), exact_cost,),
            None
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(5.into(), exact_cost,),
            None
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(7.into(), exact_cost,),
            None
        );
        assert_eq!(
            nonce_pool.insert(&tx[2], false /* force */),
            InsertResult::NewAdded
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(4.into(), exact_cost,),
            None
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(5.into(), exact_cost,),
            Some(tx[3].transaction.clone())
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(7.into(), exact_cost,),
            Some(tx[3].transaction.clone())
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(8.into(), exact_cost,),
            Some(tx[3].transaction.clone())
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(9.into(), exact_cost,),
            Some(tx[4].transaction.clone())
        );
        assert_eq!(
            nonce_pool
                .recalculate_readiness_with_local_info(10.into(), exact_cost,),
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
            let cost = NoncePoolNode::calc_tx_cost(tx);
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
