// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::TreapMap;
use cfx_types::{Address, Public, H256, U256, U512};
use keylib::Signature;
use primitives::{Action, SignedTransaction, Transaction};
use rand::{prng::XorShiftRng, ChaChaRng, Rng, RngCore, SeedableRng};
use std::{
    collections::BTreeMap,
    ops::{Add, Sub},
};

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
        Transaction {
            nonce: 0.into(),
            gas_price: next_u256(rng),
            gas: next_u256(rng),
            value: next_u256(rng),
            action: Action::Call(Address::from_low_u64_be(0)),
            data: vec![],
        }
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
    let mut treap_map: TreapMap<H256, SignedTransaction, U512> =
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
    let mut treap_map: TreapMap<H256, SignedTransaction, U512> =
        TreapMap::new_with_rng(XorShiftRng::from_seed([123; 16]));
    let mut mock_treap_map: MockTreapMap<H256, SignedTransaction, U512> =
        MockTreapMap::new();

    let mut operation_rng = get_rng_for_test();

    let operation_num = 10000;

    let mut tx_vec: Vec<SignedTransaction> = vec![];

    for _ in 0..operation_num {
        let operation = match operation_rng.gen::<u32>() % 6 {
            0 => Operation::Len,
            1 => Operation::ContainsKey,
            2..=3 => Operation::Insert,
            4 => Operation::GetByWeight,
            5 => Operation::Remove,
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
            _ => {}
        }
    }
}

#[test]
fn test_iterator() {
    let mut treap_map: TreapMap<u32, u32, u32> = TreapMap::new();
    assert_eq!(treap_map.insert(5, 0, 1), None);
    assert_eq!(treap_map.insert(4, 0, 1), None);
    assert_eq!(treap_map.insert(1, 0, 1), None);
    assert_eq!(treap_map.insert(3, 0, 1), None);
    assert_eq!(treap_map.insert(2, 0, 1), None);

    let vec: Vec<(&u32, &u32)> = treap_map.iter().collect();
    assert_eq!(vec, vec![(&1, &0), (&2, &0), (&3, &0), (&4, &0), (&5, &0)]);
}
