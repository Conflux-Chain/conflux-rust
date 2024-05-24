// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{node::Node, update::ApplyOpOutcome, KeyMngTrait, TreapMapConfig};

use super::{SharedKeyTreapMapConfig, TreapMap};
use cfx_types::{Address, Public, H256, U256, U512};
use cfxkey::Signature;
use primitives::{
    transaction::native_transaction::NativeTransaction, Action,
    SignedTransaction, Transaction,
};
use rand::{seq::SliceRandom, thread_rng, Rng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use rand_xorshift::XorShiftRng;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    ops::{Add, Sub},
};

struct TestTreapMapConfig;
impl SharedKeyTreapMapConfig for TestTreapMapConfig {
    type Key = H256;
    type Value = SignedTransaction;
    type Weight = U512;
}

struct SimpleTreapMapConfig;
impl SharedKeyTreapMapConfig for SimpleTreapMapConfig {
    type Key = u32;
    type Value = u32;
    type Weight = u32;
}

struct ComplexTreapMapConfig;
impl TreapMapConfig for ComplexTreapMapConfig {
    type ExtMap = BTreeSet<u32>;
    type SearchKey = u32;
    type SortKey = u32;
    type Value = u32;
    type Weight = u32;

    fn next_node_dir(
        me: (&Self::SortKey, &Self::SearchKey),
        other: (&Self::SortKey, &Self::SearchKey),
    ) -> Option<crate::Direction> {
        match me.0.cmp(other.0) {
            Ordering::Less => Some(crate::Direction::Left),
            Ordering::Equal => None,
            Ordering::Greater => Some(crate::Direction::Right),
        }
    }
}

impl KeyMngTrait<ComplexTreapMapConfig> for BTreeSet<u32> {
    fn view_update(
        &mut self, key: &u32, value: Option<&u32>, _old_value: Option<&u32>,
    ) {
        if value.is_some() {
            self.insert(*key);
        } else {
            self.remove(key);
        }
    }

    fn len(&self) -> usize { self.len() }

    fn get_sort_key(&self, key: &u32) -> Option<u32> {
        self.contains(key).then_some(*key)
    }

    fn make_sort_key(&self, key: &u32, _value: &u32) -> u32 { *key }
}

fn get_rng_for_test() -> ChaChaRng { ChaChaRng::from_seed([123; 32]) }

struct MockTreapMap<K, V, W> {
    inner: BTreeMap<K, (W, V)>,
}

impl<
        K: Ord,
        V,
        W: Add<Output = W> + Sub<Output = W> + Ord + Clone + From<u32>,
    > MockTreapMap<K, V, W>
{
    pub fn new() -> MockTreapMap<K, V, W> {
        MockTreapMap {
            inner: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize { self.inner.len() }

    pub fn _is_empty(&self) -> bool { self.inner.is_empty() }

    pub fn contains_key(&self, key: &K) -> bool { self.inner.contains_key(key) }

    pub fn insert(&mut self, key: K, value: V, weight: W) -> Option<V> {
        self.inner
            .insert(key, (weight, value))
            .and_then(|x| Some(x.1))
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.remove(key).and_then(|x| Some(x.1))
    }

    pub fn sum_weight(&self) -> W {
        let mut sum = W::from(0);
        for (_, (weight, _)) in self.inner.iter() {
            sum = sum + weight.clone();
        }
        sum
    }

    pub fn _get(&self, key: &K) -> Option<&V> {
        self.inner.get(key).and_then(|x| Some(&(x.1)))
    }

    pub fn get_by_weight(&self, query_weight: W) -> Option<&V> {
        let mut sum = W::from(0);
        for (_, (weight, value)) in self.inner.iter() {
            sum = sum + weight.clone();
            if sum > query_weight.clone() {
                return Some(value);
            }
        }
        None
    }
}

enum Operation {
    Len,
    ContainsKey,
    Insert,
    Remove,
    _SumWeight,
    GetByWeight,
    ConsistencyCheck,
}

fn next_u512(rng: &mut ChaChaRng) -> U512 {
    let mut result = U512::from(0);
    for _ in 0..8 {
        result = (result << 64) + (U512::from(rng.next_u64()));
    }
    result
}

fn next_u256(rng: &mut ChaChaRng) -> U256 {
    let mut result = U256::from(0);
    for _ in 0..4 {
        result = (result << 64) + (U256::from(rng.next_u64()));
    }
    result
}

fn next_signed_transaction(rng: &mut ChaChaRng) -> SignedTransaction {
    SignedTransaction::new(
        Public::from_low_u64_be(0),
        Transaction::from(NativeTransaction {
            nonce: 0.into(),
            gas_price: next_u256(rng),
            gas: next_u256(rng),
            value: next_u256(rng),
            action: Action::Call(Address::from_low_u64_be(0)),
            storage_limit: 0,
            epoch_height: 0,
            chain_id: 1,
            data: vec![],
        })
        .with_signature(Signature::default()),
    )
}

#[test]
fn test_randomly_generated_signed_transaction() {
    let mut operation_rng = get_rng_for_test();
    let tx1 = next_signed_transaction(&mut operation_rng);
    let tx2 = next_signed_transaction(&mut operation_rng);
    assert_ne!(tx1.hash(), tx2.hash());
}

#[test]
fn test_insert_query_random() {
    let mut treap_map: TreapMap<TestTreapMapConfig> =
        TreapMap::new_with_rng(XorShiftRng::from_seed([123; 16]));
    let mut mock_treap_map: MockTreapMap<H256, SignedTransaction, U512> =
        MockTreapMap::new();

    let mut operation_rng = get_rng_for_test();

    let operation_num = 10000;

    let mut tx_vec: Vec<SignedTransaction> = vec![];

    for _ in 0..operation_num {
        let operation = match operation_rng.gen::<u32>() % 4 {
            0 => Operation::Len,
            1 => Operation::ContainsKey,
            2 => Operation::Insert,
            3 => Operation::GetByWeight,
            4 => Operation::ConsistencyCheck,
            _ => panic!(),
        };

        match operation {
            Operation::Len => assert_eq!(treap_map.len(), mock_treap_map.len()),
            Operation::ContainsKey => {
                let tx = if tx_vec.is_empty() {
                    next_signed_transaction(&mut operation_rng)
                } else {
                    tx_vec[operation_rng.next_u64() as usize % tx_vec.len()]
                        .clone()
                };
                assert_eq!(
                    treap_map.contains_key(&tx.hash()),
                    mock_treap_map.contains_key(&tx.hash())
                );
            }
            Operation::Insert => {
                let tx = next_signed_transaction(&mut operation_rng);
                tx_vec.push(tx.clone());
                assert_eq!(
                    treap_map.insert(
                        tx.hash(),
                        tx.clone(),
                        U512::from(tx.gas_price().clone())
                    ),
                    mock_treap_map.insert(
                        tx.hash(),
                        tx.clone(),
                        U512::from(tx.gas_price().clone())
                    )
                );
            }
            Operation::GetByWeight => {
                assert_eq!(treap_map.sum_weight(), mock_treap_map.sum_weight());
                let sum_weight = treap_map.sum_weight();
                if sum_weight != 0.into() {
                    let rand_value = next_u512(&mut operation_rng) % sum_weight;
                    assert_eq!(
                        treap_map.get_by_weight(rand_value.clone()),
                        mock_treap_map.get_by_weight(rand_value.clone())
                    );
                }
            }
            _ => {}
        }
    }
}

#[test]
fn test_insert_remove_query_random() {
    let mut treap_map: TreapMap<TestTreapMapConfig> =
        TreapMap::new_with_rng(XorShiftRng::from_seed([123; 16]));
    let mut mock_treap_map: MockTreapMap<H256, SignedTransaction, U512> =
        MockTreapMap::new();

    let mut operation_rng = get_rng_for_test();

    let operation_num = 10000;

    let mut tx_vec: Vec<SignedTransaction> = vec![];

    for _ in 0..operation_num {
        let operation = match operation_rng.gen::<u32>() % 7 {
            0 => Operation::Len,
            1 => Operation::ContainsKey,
            2..=3 => Operation::Insert,
            4 => Operation::GetByWeight,
            5 => Operation::Remove,
            6 => Operation::ConsistencyCheck,
            _ => panic!(),
        };

        match operation {
            Operation::Len => assert_eq!(treap_map.len(), mock_treap_map.len()),
            Operation::ContainsKey => {
                let tx = if tx_vec.is_empty() {
                    next_signed_transaction(&mut operation_rng)
                } else {
                    tx_vec[operation_rng.next_u64() as usize % tx_vec.len()]
                        .clone()
                };
                assert_eq!(
                    treap_map.contains_key(&tx.hash()),
                    mock_treap_map.contains_key(&tx.hash())
                );
            }
            Operation::Insert => {
                let tx = next_signed_transaction(&mut operation_rng);
                tx_vec.push(tx.clone());
                assert_eq!(
                    treap_map.insert(
                        tx.hash(),
                        tx.clone(),
                        U512::from(tx.gas_price().clone())
                    ),
                    mock_treap_map.insert(
                        tx.hash(),
                        tx.clone(),
                        U512::from(tx.gas_price().clone())
                    )
                );
            }
            Operation::GetByWeight => {
                assert_eq!(treap_map.sum_weight(), mock_treap_map.sum_weight());
                let sum_weight = treap_map.sum_weight();
                if sum_weight != 0.into() {
                    let rand_value = next_u512(&mut operation_rng) % sum_weight;
                    assert_eq!(
                        treap_map.get_by_weight(rand_value.clone()),
                        mock_treap_map.get_by_weight(rand_value.clone())
                    );
                }
            }
            Operation::Remove => {
                let tx = if tx_vec.is_empty() {
                    next_signed_transaction(&mut operation_rng)
                } else {
                    tx_vec[operation_rng.next_u64() as usize % tx_vec.len()]
                        .clone()
                };
                assert_eq!(
                    treap_map.remove(&tx.hash()),
                    mock_treap_map.remove(&tx.hash())
                );
            }
            Operation::ConsistencyCheck => {
                treap_map.assert_consistency();
            }
            _ => {}
        }
    }
}

#[test]
fn test_iterator() {
    let mut treap_map: TreapMap<SimpleTreapMapConfig> = TreapMap::new();
    assert_eq!(treap_map.insert(5, 0, 1), None);
    assert_eq!(treap_map.insert(4, 0, 1), None);
    assert_eq!(treap_map.insert(1, 0, 1), None);
    assert_eq!(treap_map.insert(3, 0, 1), None);
    assert_eq!(treap_map.insert(2, 0, 1), None);

    let vec: Vec<(&u32, &u32)> = treap_map.key_values().collect();
    assert_eq!(vec, vec![(&1, &0), (&2, &0), (&3, &0), (&4, &0), (&5, &0)]);
}

#[test]
fn test_set_same_key() {
    let mut treap_map: TreapMap<SimpleTreapMapConfig> = TreapMap::new();
    assert_eq!(treap_map.insert(1, 1, 1), None);
    assert_eq!(treap_map.insert(2, 2, 1), None);
    assert_eq!(treap_map.insert(1, 3, 1), Some(1));
    assert_eq!(treap_map.insert(2, 4, 1), Some(2));
    assert_eq!(treap_map.remove(&1), Some(3));
    assert_eq!(treap_map.remove(&2), Some(4));
}

#[test]
fn test_change_weight() {
    let mut treap_map: TreapMap<SimpleTreapMapConfig> = TreapMap::new();
    for i in 0..5 {
        treap_map.insert(i, i, i);
        treap_map.assert_consistency();
    }
    // Reset weight again
    for i in 0..5 {
        treap_map.insert(i, i, i);
        treap_map.assert_consistency();
    }
    // Change weight
    for i in 0..5 {
        treap_map.insert(i, i, 10 - i);
        treap_map.assert_consistency();
    }
    assert_eq!(treap_map.root.unwrap().sum_weight(), 40);
}

#[test]
fn test_apply_op_change_value() {
    let mut treap_map: TreapMap<ComplexTreapMapConfig> = TreapMap::new();
    for i in 0..100 {
        treap_map.insert(i * 2, i * 2, i * 2);
        treap_map.assert_consistency();
    }
    // Test update value
    let mut indicies: Vec<_> = (0u32..200).collect();
    indicies.shuffle(&mut thread_rng());
    for i in indicies {
        let should_fail = i % 3 == 0;
        let update = |node: &mut Node<_>| {
            if should_fail {
                Err(())
            } else {
                node.value = 1000 + i;
                Ok(ApplyOpOutcome {
                    out: (),
                    update_weight: false,
                    update_key: false,
                    delete_item: false,
                })
            }
        };
        let insert = |rng: &mut dyn RngCore| {
            if should_fail {
                Err(())
            } else {
                Ok((Node::new(i, 1000 + i, i, 1000 + i, rng.next_u64()), ()))
            }
        };
        let res = treap_map.update(&i, update, insert);
        assert_eq!(res.is_ok(), !should_fail);
        assert_eq!(
            treap_map.get(&i).cloned(),
            if !should_fail {
                Some(1000 + i)
            } else if i % 2 == 0 {
                Some(i)
            } else {
                None
            }
        );
        treap_map.assert_consistency();
    }
}

#[test]
fn test_apply_op_change_weight() {
    let mut treap_map: TreapMap<ComplexTreapMapConfig> = TreapMap::new();
    for i in 0..100 {
        treap_map.insert(i * 2, i * 2, i * 2);
        treap_map.assert_consistency();
    }
    // Test update value
    let mut indicies: Vec<_> = (0u32..200).collect();
    indicies.shuffle(&mut thread_rng());
    for i in indicies {
        let should_fail = i % 3 == 0;
        let update = |node: &mut Node<_>| {
            if should_fail {
                Err(())
            } else {
                node.weight = 1000 + i;
                Ok(ApplyOpOutcome {
                    out: (),
                    update_weight: true,
                    update_key: false,
                    delete_item: false,
                })
            }
        };
        let insert = |rng: &mut dyn RngCore| {
            if should_fail {
                Err(())
            } else {
                Ok((Node::new(i, 1000 + i, i, 1000 + i, rng.next_u64()), ()))
            }
        };
        let res = treap_map.update(&i, update, insert);
        assert_eq!(res.is_ok(), !should_fail);
        treap_map.assert_consistency();
    }
    let target_weight: usize = (0..200)
        .map(|i| {
            if i % 3 != 0 {
                i + 1000
            } else if i % 2 == 0 {
                i
            } else {
                0
            }
        })
        .sum();
    assert_eq!(treap_map.root.unwrap().sum_weight(), target_weight as u32);
}

#[test]
fn test_apply_op_change_key() {
    let mut treap_map: TreapMap<ComplexTreapMapConfig> = TreapMap::new();
    for i in 0..100 {
        treap_map.insert(i * 2, i * 2, i * 2);
        treap_map.assert_consistency();
    }
    // Test update value
    let mut indicies: Vec<_> = (0u32..200).collect();
    indicies.shuffle(&mut thread_rng());
    for i in indicies {
        let should_fail = i % 3 == 0;
        let delete_item = i % 5 == 0;
        let has_initial = i % 2 == 0;
        let update = |node: &mut Node<_>| {
            if should_fail {
                Err(())
            } else {
                node.key = 1000 + i;
                node.sort_key = 1000 + i;
                node.weight = 1000 + i;
                node.value = 1000 + i;
                Ok(ApplyOpOutcome {
                    out: (),
                    update_weight: true,
                    update_key: true,
                    delete_item,
                })
            }
        };
        let insert = |rng: &mut dyn RngCore| {
            if should_fail || delete_item {
                Err(())
            } else {
                Ok((
                    Node::new(i, 1000 + i, 1000 + i, 1000 + i, rng.next_u64()),
                    (),
                ))
            }
        };
        let res = treap_map.update(&i, update, insert);
        assert_eq!(res.is_err(), should_fail || (!has_initial && delete_item));
        treap_map.assert_consistency();

        let no_erasure = !(delete_item && !should_fail);

        match (should_fail, has_initial) {
            (true, true) => {
                assert_eq!(treap_map.get(&i).cloned(), Some(i));
                assert_eq!(treap_map.get(&(i + 1000)).cloned(), None);
            }
            (true, false) => {
                assert_eq!(treap_map.get(&i).cloned(), None);
                assert_eq!(treap_map.get(&(i + 1000)).cloned(), None);
            }
            (false, true) => {
                assert_eq!(treap_map.get(&i).cloned(), None);
                assert_eq!(
                    treap_map.get(&(1000 + i)).cloned(),
                    no_erasure.then_some(1000 + i)
                );
            }
            (false, false) => {
                assert_eq!(
                    treap_map.get(&i).cloned(),
                    no_erasure.then_some(i + 1000)
                );
                assert_eq!(treap_map.get(&(i + 1000)).cloned(), None);
            }
        }
    }
    let target_weight: usize = (0..200)
        .map(|i| {
            if i % 3 != 0 {
                if i % 5 != 0 {
                    i + 1000
                } else {
                    0
                }
            } else if i % 2 == 0 {
                i
            } else {
                0
            }
        })
        .sum();
    assert_eq!(treap_map.root.unwrap().sum_weight(), target_weight as u32);
}

#[test]
fn test_apply_op_change_key_for_shared_key() {
    let mut treap_map: TreapMap<SimpleTreapMapConfig> = TreapMap::new();
    for i in 0..100 {
        treap_map.insert(i * 2, i * 2, i * 2);
        treap_map.assert_consistency();
    }
    // Test update value
    let mut indicies: Vec<_> = (0u32..200).collect();
    indicies.shuffle(&mut thread_rng());
    for i in indicies {
        let should_fail = i % 3 == 0;
        let delete_item = i % 5 == 0;
        let has_initial = i % 2 == 0;
        let update = |node: &mut Node<_>| {
            if should_fail {
                Err(())
            } else {
                node.key = 1000 + i;
                node.weight = 1000 + i;
                node.value = 1000 + i;
                Ok(ApplyOpOutcome {
                    out: (),
                    update_weight: true,
                    update_key: true,
                    delete_item,
                })
            }
        };
        let insert = |rng: &mut dyn RngCore| {
            if should_fail || delete_item {
                Err(())
            } else {
                Ok((Node::new(i, 1000 + i, (), 1000 + i, rng.next_u64()), ()))
            }
        };
        let res = treap_map.update(&i, update, insert);
        assert_eq!(res.is_err(), should_fail || (!has_initial && delete_item));
        treap_map.assert_consistency();

        let no_erasure = !(delete_item && !should_fail);

        match (should_fail, has_initial) {
            (true, true) => {
                assert_eq!(treap_map.get(&i).cloned(), Some(i));
                assert_eq!(treap_map.get(&(i + 1000)).cloned(), None);
            }
            (true, false) => {
                assert_eq!(treap_map.get(&i).cloned(), None);
                assert_eq!(treap_map.get(&(i + 1000)).cloned(), None);
            }
            (false, true) => {
                assert_eq!(treap_map.get(&i).cloned(), None);
                assert_eq!(
                    treap_map.get(&(1000 + i)).cloned(),
                    no_erasure.then_some(1000 + i)
                );
            }
            (false, false) => {
                assert_eq!(
                    treap_map.get(&i).cloned(),
                    no_erasure.then_some(1000 + i)
                );
                assert_eq!(treap_map.get(&(i + 1000)).cloned(), None);
            }
        }
    }
    let target_weight: usize = (0..200)
        .map(|i| {
            if i % 3 != 0 {
                if i % 5 != 0 {
                    i + 1000
                } else {
                    0
                }
            } else if i % 2 == 0 {
                i
            } else {
                0
            }
        })
        .sum();
    assert_eq!(treap_map.root.unwrap().sum_weight(), target_weight as u32);
}
