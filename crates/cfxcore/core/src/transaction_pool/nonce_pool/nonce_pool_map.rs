use std::convert::Infallible;

use cfx_types::U256;
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use treap_map::{
    ApplyOpOutcome, ConsoliableWeight, Node, SearchDirection, SearchResult,
    SharedKeyTreapMapConfig, TreapMap,
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

    /// Iter transactions with nonce >= the start nonce. The start nonce may not
    /// exist and the transaction nonces may not continous.
    #[inline]
    pub fn iter_range(
        &self, nonce: &U256,
    ) -> impl Iterator<Item = &TxWithReadyInfo> {
        self.0.iter_range(nonce).map(|x| &x.value)
    }

    /// Insert a new TxWithReadyInfo. if the corresponding nonce already exists,
    /// will replace with higher gas price transaction
    pub fn insert(
        &mut self, tx: &TxWithReadyInfo, force: bool,
    ) -> InsertResult {
        self.0
            .update(
                tx.transaction.nonce(),
                |node| -> Result<_, Infallible> {
                    let insert_result;
                    let update_weight;
                    match tx.should_replace(&node.value, force) {
                        Ok(_reason) => {
                            let old_value =
                                std::mem::replace(&mut node.value, tx.clone());
                            node.weight =
                                NoncePoolWeight::from_tx_info(&node.value);
                            insert_result = InsertResult::Updated(old_value);
                            update_weight = true;
                        }
                        Err(e) => {
                            insert_result = InsertResult::Failed(e);
                            update_weight = false;
                        }
                    };

                    Ok(ApplyOpOutcome {
                        out: insert_result,
                        update_weight,
                        update_key: false,
                        delete_item: false,
                    })
                },
                |rng| {
                    let weight = NoncePoolWeight::from_tx_info(&tx);
                    let key = tx.transaction.nonce();
                    Ok((
                        Node::new(*key, tx.clone(), (), weight, rng.next_u64()),
                        InsertResult::NewAdded,
                    ))
                },
            )
            .unwrap()
    }

    /// mark packed of given nonce, return false if nothing changes
    pub fn mark_packed(&mut self, nonce: &U256, packed: bool) -> bool {
        let update = |node: &mut Node<NoncePoolConfig>| {
            let no_change = packed == node.value.packed;
            if no_change {
                return Err(());
            }
            node.value.packed = packed;
            node.weight = NoncePoolWeight::from_tx_info(&node.value);
            Ok(ApplyOpOutcome {
                out: (),
                update_weight: true,
                update_key: false,
                delete_item: false,
            })
        };
        self.0.update(nonce, update, |_| Err(())).is_ok()
    }

    /// find an unpacked transaction `tx` where `tx.nonce() >= nonce`
    /// and `tx.nonce()` is minimum
    /// i.e. the first unpacked transaction with nonce >= `nonce`
    pub fn query(&self, nonce: &U256) -> Option<&TxWithReadyInfo> {
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
            Some(&node.value)
        } else {
            None
        }
    }

    /// Find the accumulated weight for the transactions whose nonce <= `nonce`
    pub fn weight(&self, nonce: &U256) -> NoncePoolWeight {
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
            NoncePoolWeight::consolidate(&base_weight, &node.weight)
        } else {
            NoncePoolWeight::empty()
        }
    }

    /// Find last valid nonce passing the readiness check. The `start_weight`
    /// must equal to `self.weight(start_nonce)`, otherwise it may cause
    /// unexpected behaviour.
    #[inline]
    pub fn continous_ready_nonce(
        &self, start_nonce: &U256, start_weight: NoncePoolWeight,
        rest_balance: U256,
    ) -> U256 {
        let ret = self.0.search(|left_weight, node| {
            let weight =
                NoncePoolWeight::consolidate(left_weight, &node.weight);
            if start_nonce > &node.key {
                return SearchDirection::Right(weight);
            }
            if start_nonce == &node.key {
                return SearchDirection::RightOrStop(weight);
            }

            let nonce_elapsed = node.value.nonce() - start_nonce;
            if nonce_elapsed > U256::from(u32::MAX) {
                return SearchDirection::Left;
            }
            let nonce_elapsed = nonce_elapsed.as_u32();

            let item_elapsed = weight.size - start_weight.size;
            let unpacked_elapsed =
                weight.unpacked_size - start_weight.unpacked_size;
            let cost_elapsed = weight.cost - start_weight.cost;

            if item_elapsed != unpacked_elapsed
                || nonce_elapsed != unpacked_elapsed
            {
                // There should be packed transaction or missed nonce in middle
                return SearchDirection::Left;
            }

            if cost_elapsed > rest_balance {
                return SearchDirection::Left;
            }

            SearchDirection::RightOrStop(weight)
        });
        if let Some(SearchResult::Found { node, .. }) = ret {
            *node.value.nonce()
        } else {
            *start_nonce
        }
    }

    /// return the next item with nonce >= given nonce
    pub fn succ(&self, nonce: &U256) -> Option<&TxWithReadyInfo> {
        let ret = self.0.search_no_weight(|node| {
            if nonce <= &node.key {
                SearchDirection::LeftOrStop
            } else {
                SearchDirection::Right(())
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
        let ret = self.0.search_no_weight(|_| SearchDirection::LeftOrStop);
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
