// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    config::{KeyMngTrait, WeightConsolidate},
    search::{prefix_sum_search, SearchDirection},
    update::{ApplyOp, ApplyOpOutcome, InsertOp, RemoveOp},
    SearchResult,
};

use super::{config::TreapMapConfig, node::Node};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use rand::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;

pub struct TreapMap<C: TreapMapConfig> {
    #[cfg(test)]
    pub(crate) root: Option<Box<Node<C>>>,
    #[cfg(not(test))]
    root: Option<Box<Node<C>>>,
    ext_map: C::ExtMap,
    rng: XorShiftRng,
}

impl<C: TreapMapConfig> MallocSizeOf for TreapMap<C>
where
    Node<C>: MallocSizeOf,
    C::ExtMap: MallocSizeOf,
{
    fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
        self.root.size_of(ops) + self.ext_map.size_of(ops)
    }
}

impl<C: TreapMapConfig> TreapMap<C> {
    pub fn new() -> TreapMap<C> {
        TreapMap {
            root: None,
            rng: XorShiftRng::from_entropy(),
            ext_map: Default::default(),
        }
    }

    pub fn new_with_rng(rng: XorShiftRng) -> TreapMap<C> {
        TreapMap {
            root: None,
            rng,
            ext_map: Default::default(),
        }
    }

    pub fn len(&self) -> usize { self.ext_map.len() }

    pub fn is_empty(&self) -> bool { self.ext_map.len() == 0 }

    pub fn contains_key(&self, key: &C::SearchKey) -> bool {
        self.get(key).is_some()
    }

    pub fn insert(
        &mut self, key: C::SearchKey, value: C::Value, weight: C::Weight,
    ) -> Option<C::Value> {
        let sort_key = self.ext_map.make_sort_key(&key, &value);

        let node = Node::new(key, value, sort_key, weight, self.rng.next_u64());

        let (result, _, _) = Node::update_inner(
            &mut self.root,
            InsertOp {
                node: Box::new(node),
                ext_map: &mut self.ext_map,
            },
        );

        result
    }

    pub fn remove(&mut self, key: &C::SearchKey) -> Option<C::Value> {
        let sort_key = self.ext_map.get_sort_key(&key)?;

        let (result, _, _) = Node::update_inner(
            &mut self.root,
            RemoveOp {
                key: (&sort_key, key),
                ext_map: &mut self.ext_map,
            },
        );

        result
    }

    pub fn update<U, I, T, E>(
        &mut self, key: &C::SearchKey, update: U, insert: I,
    ) -> Result<T, E>
    where
        U: FnOnce(&mut Node<C>) -> Result<ApplyOpOutcome<T>, E>,
        I: FnOnce(&mut dyn RngCore) -> Result<(Node<C>, T), E>,
    {
        let sort_key = if let Some(sort_key) = self.ext_map.get_sort_key(key) {
            sort_key
        } else {
            return match insert(&mut self.rng) {
                Ok((node, ret)) => {
                    self.insert(node.key, node.value, node.weight);
                    Ok(ret)
                }
                Err(err) => Err(err),
            };
        };
        let rng = &mut self.rng;
        let (res, _, _) = Node::update_inner(
            &mut self.root,
            ApplyOp {
                key: (&sort_key, key),
                update,
                insert: || insert(rng),
                ext_map: &mut self.ext_map,
            },
        );
        let (ret, maybe_node) = res?;
        if let Some(node) = maybe_node {
            self.insert(node.key, node.value, node.weight);
        }
        Ok(ret)
    }

    pub fn sum_weight(&self) -> C::Weight {
        match &self.root {
            Some(node) => node.sum_weight(),
            None => C::Weight::empty(),
        }
    }

    pub fn get(&self, key: &C::SearchKey) -> Option<&C::Value> {
        let sort_key = self.ext_map.get_sort_key(key)?;
        self.root.as_ref().and_then(|x| x.get(&sort_key, key))
    }

    pub fn get_by_weight(&self, weight: C::Weight) -> Option<&C::Value>
    where C::Weight: Ord {
        use SearchDirection::*;
        prefix_sum_search(
            self.root.as_ref()?,
            C::Weight::empty(),
            |base, mid| {
                if &weight < base {
                    Left
                } else {
                    let right_base = C::Weight::consolidate(base, &mid.weight);
                    if weight < right_base {
                        Stop
                    } else {
                        Right(right_base)
                    }
                }
            },
        )
        .maybe_value()
    }

    pub fn search<F>(&self, f: F) -> Option<SearchResult<C>>
    where F: FnMut(&C::Weight, &Node<C>) -> SearchDirection<C::Weight> {
        Some(prefix_sum_search(
            self.root.as_ref()?,
            C::Weight::empty(),
            f,
        ))
    }

    pub fn iter(&self) -> Iter<C> {
        let mut iter = Iter { nodes: vec![] };
        if let Some(ref n) = self.root {
            iter.nodes.push(&**n);
            iter.extend_path();
        }
        iter
    }

    pub fn values(&self) -> impl Iterator<Item = &C::Value> {
        self.iter().map(|node| &node.value)
    }

    pub fn key_values(
        &self,
    ) -> impl Iterator<Item = (&C::SearchKey, &C::Value)> {
        self.iter().map(|node| (&node.key, &node.value))
    }

    #[cfg(test)]
    pub fn assert_consistency(&self)
    where C::Weight: std::fmt::Debug {
        if let Some(node) = self.root.as_ref() {
            node.assert_consistency()
        }
    }
}

pub struct Iter<'a, C: TreapMapConfig> {
    nodes: Vec<&'a Node<C>>,
}

impl<'a, C: TreapMapConfig> Clone for Iter<'a, C> {
    fn clone(&self) -> Self {
        Self {
            nodes: self.nodes.clone(),
        }
    }
}

impl<'a, C: TreapMapConfig> Iter<'a, C> {
    fn extend_path(&mut self) {
        loop {
            let node = *self.nodes.last().unwrap();
            match node.left {
                None => return,
                Some(ref n) => self.nodes.push(&**n),
            }
        }
    }
}

impl<'a, C: TreapMapConfig> Iterator for Iter<'a, C> {
    type Item = &'a Node<C>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.nodes.pop() {
            None => None,
            Some(node) => {
                if let Some(ref n) = node.right {
                    self.nodes.push(&**n);
                    self.extend_path();
                }
                Some(&node)
            }
        }
    }
}
