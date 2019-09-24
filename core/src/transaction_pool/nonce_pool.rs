use cfx_types::U256;
use primitives::SignedTransaction;
use rand::{prng::XorShiftRng, FromEntropy, RngCore};
use std::{cmp::Ordering, mem, ops::Deref, sync::Arc};

#[derive(Clone, Debug, PartialEq)]
pub struct TxWithReadyInfo {
    pub transaction: Arc<SignedTransaction>,
    pub packed: bool,
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

#[derive(Debug)]
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
    pub fn new(tx: &TxWithReadyInfo, priority: u64) -> Self {
        NoncePoolNode {
            tx: tx.clone(),
            subtree_unpacked: 1 - tx.packed as u32,
            subtree_cost: tx.value + tx.gas * tx.gas_price,
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

    /// insert a new TxWithReadyInfo. if the corresponding nonce already exists,
    /// will replace with higher gas price transaction
    pub fn insert(
        node: &mut Option<Box<NoncePoolNode>>, tx: &TxWithReadyInfo,
        priority: u64, force: bool,
    ) -> InsertResult
    {
        if node.is_none() {
            mem::replace(
                node,
                Some(Box::new(NoncePoolNode::new(tx, priority))),
            );
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
                    InsertResult::Failed(format!("Tx with same nonce already inserted, try to replace it with a higher gas price"))
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
                    ret.1 += node.tx.value + node.tx.gas * node.tx.gas_price;
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

    /// find a transaction `tx` where `tx.nonce >= nonce` and `tx.last_packed_ts
    /// <= ts` and `tx.nonce` is minimum
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
            mem::replace(&mut node.as_mut().unwrap().child[ch ^ 1], c);
            node.as_mut().unwrap().update();
        }
    }

    /// update subtree info: last_packed_ts and cost_sum
    fn update(&mut self) {
        self.subtree_unpacked = 1 - self.tx.packed as u32;
        self.subtree_cost = self.tx.value + self.tx.gas * self.tx.gas_price;
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

    /// find a transaction `tx` such that
    ///   1. all nonce in `[nouce, tx.nouce]` exists
    ///   2. tx.packed is false and tx.nouce is minimum
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
            // 1. b.1 - a.1 means the sum of cost of transactions in `[nouce,
            // tx.nouce]`
            // 2, b.0 - a.0 means number of transactions in `[nouce, tx.nouce]`
            // 3. x.nonce - nonce + 1 means expected number of transactions in
            // `[nouce, tx.nouce]`
            U256::from(b.0 - a.0 - 1) == x.nonce - nonce && b.1 - a.1 <= balance
        })
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
    #[allow(dead_code)]
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
    use cfx_types::{Address, U256};
    use keylib::{Generator, KeyPair, Random};
    use primitives::{Action, SignedTransaction, Transaction};
    use rand::{prng::XorShiftRng, FromEntropy, RngCore};
    use std::{collections::BTreeMap, sync::Arc};

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

    fn new_test_tx_with_ready_info(
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
    fn test_basic_operation() {
        let me = Random.generate().unwrap();
        let mut tx1 = Vec::new();
        let mut tx2 = Vec::new();
        for i in 0..10 {
            tx1.push(new_test_tx_with_ready_info(
                &me, i as usize, 10, 10000, false,
            ));
        }
        for i in 0..10 {
            tx2.push(new_test_tx_with_ready_info(
                &me, i as usize, 10, 10000, false,
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
            assert_eq!(nonce_pool.insert(&tx2[i as usize], false /* force */), InsertResult::Failed(format!("Tx with same nonce already inserted, try to replace it with a higher gas price")));
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
        for i in 5..10 {
            if i <= 7 {
                tx.push(new_test_tx_with_ready_info(
                    &me, i as usize, 10, 10000, true,
                ));
            } else {
                tx.push(new_test_tx_with_ready_info(
                    &me, i as usize, 10, 10000, false,
                ));
            }
        }
        let gas = 50000;
        let exact_cost = 4 * (gas * 10 + 10000);
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
            nonce_pool.recalculate_readiness_with_local_info(
                4.into(),
                exact_cost.into(),
            ),
            None
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info(
                5.into(),
                exact_cost.into(),
            ),
            None
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info(
                7.into(),
                exact_cost.into(),
            ),
            None
        );
        assert_eq!(
            nonce_pool.insert(&tx[2], false /* force */),
            InsertResult::NewAdded
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info(
                4.into(),
                exact_cost.into(),
            ),
            None
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info(
                5.into(),
                exact_cost.into(),
            ),
            Some(tx[3].transaction.clone())
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info(
                7.into(),
                exact_cost.into(),
            ),
            Some(tx[3].transaction.clone())
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info(
                8.into(),
                exact_cost.into(),
            ),
            Some(tx[3].transaction.clone())
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info(
                9.into(),
                exact_cost.into(),
            ),
            Some(tx[4].transaction.clone())
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info(
                10.into(),
                exact_cost.into(),
            ),
            None
        );
        assert_eq!(
            nonce_pool.recalculate_readiness_with_local_info(
                5.into(),
                (exact_cost - 1).into(),
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
            let cost = tx.value + tx.gas_price * tx.gas;
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
        let count = 100000;
        for i in 0..count {
            tx.push(new_test_tx_with_ready_info(
                &me,
                i as usize,
                10,
                10000,
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

        let gas = 50000;
        for i in 0..count * 2 {
            let balance = rng.next_u64() % 100 * (gas * 10 + 10000);
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
            let balance = rng.next_u64() % 100 * (gas * 10 + 10000);
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
    }
}
