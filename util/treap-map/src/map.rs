// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::{
    config::{ConsoliableWeight, KeyMngTrait},
    search::{accumulate_weight_search, SearchDirection},
    update::{ApplyOp, ApplyOpOutcome, InsertOp, RemoveOp},
    Direction, NoWeight, SearchResult,
};

use super::{config::TreapMapConfig, node::Node};
use malloc_size_of::{MallocSizeOf, MallocSizeOfOps};
use rand::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;

/// A treap map data structure.
///
/// See [`TreapMapConfig`][crate::TreapMapConfig] for more details.
pub struct TreapMap<C: TreapMapConfig> {
    /// The root node of the treap.
    #[cfg(test)]
    pub(crate) root: Option<Box<Node<C>>>,
    #[cfg(not(test))]
    root: Option<Box<Node<C>>>,

    /// A map for recovering the `sort_key` from the `search_key`.
    /// This is useful when the `sort_key` is derived from `search_key` and
    /// `value`.
    ext_map: C::ExtMap,

    /// A random number generator used for generating priority values for new
    /// nodes.
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

    /// Updates the value of a node with the given key in the treap map.
    ///
    /// # Parameters
    /// - `key`: The search key of the node to be updated.
    /// - `update`: A function that is called if a node with the given key
    ///   already exists. It takes a mutable reference to the node and returns
    ///   an `ApplyOpOutcome<T>` or a custom error `E`. See
    ///   [`ApplyOpOutcome`][crate::ApplyOpOutcome] for more details.
    /// - `insert`: A function that is called if a node with the given key does
    ///   not exist. It takes a mutable reference to a random number generator
    ///   (for computing priority for a [`Node`][crate::Node]) and should return
    ///   a tuple containing a new `Node<C>` and a value of type `T`, or an
    ///   error of type `E`.
    ///   - WARNING: The key of the new node must match the key provided to the
    ///     function.
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

    #[inline]
    pub fn get_by_weight(&self, weight: C::Weight) -> Option<&C::Value>
    where C::Weight: Ord {
        use SearchDirection::*;
        self.search(|base, mid| {
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
        })?
        .maybe_value()
    }

    /// See details in [`crate::accumulate_weight_search`]
    pub fn search<F>(&self, f: F) -> Option<SearchResult<C, C::Weight>>
    where F: FnMut(&C::Weight, &Node<C>) -> SearchDirection<C::Weight> {
        Some(accumulate_weight_search(self.root.as_ref()?, f, |weight| {
            weight
        }))
    }

    /// See details in [`crate::accumulate_weight_search`]
    /// If the search process does not require accessing 'weight', this function
    /// can outperform `search` by eliminating the maintenance of the 'weight'
    /// dimension.
    pub fn search_no_weight<F>(
        &self, mut f: F,
    ) -> Option<SearchResult<C, NoWeight>>
    where F: FnMut(&Node<C>) -> SearchDirection<()> {
        static NW: NoWeight = NoWeight;
        Some(accumulate_weight_search(
            self.root.as_ref()?,
            |_, node| f(node).map_into(|_| NoWeight),
            |_| &NW,
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

    pub fn iter_range(&self, key: &C::SearchKey) -> Iter<C>
    where C: TreapMapConfig<SortKey = ()> {
        let mut iter = Iter { nodes: vec![] };
        if let Some(ref n) = self.root {
            iter.nodes.push(&**n);
            iter.extend_path_with_key((&(), key));
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

    #[cfg(any(test, feature = "testonly_code"))]
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

    fn extend_path_with_key(&mut self, key: (&C::SortKey, &C::SearchKey)) {
        loop {
            let node = *self.nodes.last().unwrap();
            match C::next_node_dir(key, (&node.sort_key, &node.key)) {
                Some(Direction::Left) => {
                    if let Some(left) = &node.left {
                        self.nodes.push(left);
                    } else {
                        return;
                    }
                }
                None => {
                    return;
                }
                Some(Direction::Right) => {
                    let node = self.nodes.pop().unwrap();
                    if let Some(right) = &node.right {
                        self.nodes.push(right);
                    } else {
                        return;
                    }
                }
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
