use std::{convert::Infallible, sync::Arc};

use cfx_types::U256;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use primitives::SignedTransaction;
use treap_map::{
    ApplyOpOutcome, Node, SearchDirection, SearchResult,
    SharedKeyTreapMapConfig, TreapMap, WeightConsolidate,
};

use super::{weight::NoncePoolWeight, InsertResult, TxWithReadyInfo};

struct NoncePoolConfig;

impl SharedKeyTreapMapConfig for NoncePoolConfig {
    type Key = U256;
    type Value = TxWithReadyInfo;
    type Weight = NoncePoolWeight;
}

pub(super) struct NoncePoolMap(TreapMap<NoncePoolConfig>);

impl NoncePoolMap {
    #[inline]
    pub fn new() -> Self { Self(TreapMap::new()) }

    #[inline]
    pub fn len(&self) -> usize { self.0.len() }

    #[inline]
    pub fn get(&self, nonce: &U256) -> Option<&TxWithReadyInfo> {
        self.0.get(nonce)
    }

    #[inline]
    pub fn remove(&mut self, nonce: &U256) -> Option<TxWithReadyInfo> {
        self.0.remove(nonce)
    }

    /// insert a new TxWithReadyInfo. if the corresponding nonce already exists,
    /// will replace with higher gas price transaction
    pub fn insert(
        &mut self, tx: &TxWithReadyInfo, force: bool,
    ) -> InsertResult {
        self.0.update(tx.transaction.nonce(), |node|-> Result<_, Infallible> {
            if tx.should_replace(&node.value, force) {
                let old_value =std::mem::replace(
                    &mut node.value,
                    tx.clone(),
                );
                node.weight = NoncePoolWeight::from_tx_info(&node.value);
                Ok(ApplyOpOutcome {
                    out: InsertResult::Updated(old_value),
                    update_weight: true,
                    update_key:false
                })
            } else {
                let err_msg = format!("Tx with same nonce already inserted. To replace it, you need to specify a gas price > {}", &node.value.transaction.gas_price());
                Ok(ApplyOpOutcome {
                    out: InsertResult::Failed(err_msg),
                    update_weight: false,
                    update_key: false,
                })
            }
        }, |rng| {
            let weight = NoncePoolWeight::from_tx_info(&tx);
            let key = tx.transaction.nonce();
            Ok((Node::new(*key, tx.clone(), (), weight, rng.next_u64()), InsertResult::NewAdded))
        }).unwrap()
    }

    /// mark packed of given nonce, return false if nothing changes
    pub fn mark_packed(&mut self, nonce: &U256, packed: bool) -> bool {
        self.0
            .update(
                nonce,
                |node| {
                    if node.value.packed == packed {
                        return Err(());
                    }
                    node.value.packed = packed;
                    node.weight = NoncePoolWeight::from_tx_info(&node.value);
                    Ok(ApplyOpOutcome {
                        out: (),
                        update_weight: true,
                        update_key: false,
                    })
                },
                |_| Err(()),
            )
            .is_ok()
    }

    /// find an unpacked transaction `tx` where `tx.nonce() >= nonce`
    /// and `tx.nonce()` is minimum
    pub fn query(&self, nonce: &U256) -> Option<Arc<SignedTransaction>> {
        let ret = self.0.search(|left_weight, node| {
            if left_weight.max_unpackd_nonce.map_or(false, |x| x >= *nonce) {
                SearchDirection::Left
            } else if node
                .weight
                .max_unpackd_nonce
                .map_or(false, |x| x >= *nonce)
            {
                SearchDirection::Stop
            } else {
                SearchDirection::Right(NoncePoolWeight::consolidate(
                    left_weight,
                    &node.weight,
                ))
            }
        });
        if let Some(SearchResult::Found { node, .. }) = ret {
            Some(node.value.transaction.clone())
        } else {
            None
        }
    }

    /// find number of transactions and sum of cost whose nonce <= `nonce`
    pub fn rank(&self, nonce: &U256) -> (u32, U256) {
        let ret = self.0.search(|left_weight, node| {
            if nonce < &node.key {
                SearchDirection::Left
            } else if nonce == &node.key {
                SearchDirection::Stop
            } else {
                SearchDirection::RightOrStop(NoncePoolWeight::consolidate(
                    left_weight,
                    &node.weight,
                ))
            }
        });
        if let Some(SearchResult::Found { node, base_weight }) = ret {
            let weight =
                NoncePoolWeight::consolidate(&base_weight, &node.weight);
            (weight.subtree_size, weight.subtree_cost)
        } else {
            (0, 0.into())
        }
    }

    // return the next item with nonce >= given nonce
    pub fn succ(&self, nonce: &U256) -> Option<&TxWithReadyInfo> {
        let ret = self.0.search(|_, node| {
            if nonce <= &node.key {
                SearchDirection::LeftOrStop
            } else {
                // This search don't read weight, so we can return arbitrary
                // here.
                SearchDirection::Right(NoncePoolWeight::empty())
            }
        });
        if let Some(SearchResult::Found { node, .. }) = ret {
            Some(&node.value)
        } else {
            None
        }
    }

    /// return the leftmost node
    pub fn leftmost(&self) -> Option<&TxWithReadyInfo> {
        let ret = self.0.search(|_, _| SearchDirection::LeftOrStop);
        if let Some(SearchResult::Found { node, .. }) = ret {
            Some(&node.value)
        } else {
            None
        }
    }
}

impl MallocSizeOf for NoncePoolMap {
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.0.size_of(ops)
    }
}
