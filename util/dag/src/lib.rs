use hibitset::BitSet;
use std::{
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    hash::Hash,
};

/// Topologically sort `index_set` and return a sorted `Vec`.
/// For the nodes without order-before relationship, the ones with smaller
/// `order_indicator` output will be ordered first.
pub fn topological_sort<'a, NodeIndex, F, OrderIndicator, FOrd, Set>(
    index_set: &'a Set, prev_edges: F, order_indicator: FOrd,
) -> Vec<NodeIndex>
where
    NodeIndex: 'a + Copy + Hash + Eq + PartialEq + Ord,
    F: Fn(NodeIndex) -> Vec<NodeIndex>,
    OrderIndicator: Ord,
    FOrd: Fn(NodeIndex) -> OrderIndicator,
    Set: 'a + SetLike<NodeIndex> + Default,
    &'a Set: IntoIterator<Item = &'a NodeIndex>,
{
    let mut num_next_edges = HashMap::new();

    for me in index_set.into_iter() {
        num_next_edges.entry(*me).or_insert(0);
        for prev in &prev_edges(*me) {
            if index_set.contains(prev) {
                *num_next_edges.entry(*prev).or_insert(0) += 1;
            }
        }
    }

    let mut candidates = BinaryHeap::new();
    let mut reversed_indices = Vec::new();

    for me in index_set.into_iter() {
        if num_next_edges[me] == 0 {
            candidates.push((order_indicator(*me), *me));
        }
    }
    while let Some((_, me)) = candidates.pop() {
        reversed_indices.push(me);

        for prev in &prev_edges(me) {
            if index_set.contains(prev) {
                num_next_edges.entry(*prev).and_modify(|e| *e -= 1);
                if num_next_edges[prev] == 0 {
                    candidates.push((order_indicator(*prev), *prev));
                }
            }
        }
    }
    reversed_indices.reverse();
    reversed_indices
}

// TODO: Ideally I want to allow `Iter: for<'a> Iterator<Item = &'a NodeIndex>`,
// but this is not allowed for associated types because of https://github.com/rust-lang/rust/issues/49601.
fn get_future<NodeIndex, F, FStop, Set, Iter>(
    index_set: Iter, next_edges: F, stop_condition: FStop,
) -> Set
where
    NodeIndex: Copy + Hash + Eq + PartialEq + Ord,
    F: Fn(NodeIndex) -> Vec<NodeIndex>,
    FStop: Fn(NodeIndex) -> bool,
    Set: SetLike<NodeIndex> + Default,
    Iter: Iterator<Item = NodeIndex>,
{
    let mut queue = VecDeque::new();
    let mut visited = Set::default();
    for i in index_set {
        visited.insert(i);
        queue.push_back(i);
    }
    // TODO: Implement future.
    while let Some(x) = queue.pop_front() {
        for succ in next_edges(x) {
            if stop_condition(succ) {
                continue;
            }
            if !visited.contains(&succ) {
                queue.push_back(succ);
                visited.insert(succ);
            }
        }
    }
    visited
}

pub trait Graph {
    type NodeIndex: 'static + Copy + Hash + Eq + PartialEq + Ord;
}

// TODO: Decide if returning Iterator is better than returning `Vec`?
pub trait DAG: Graph {
    fn prev_edges(&self, node_index: Self::NodeIndex) -> Vec<Self::NodeIndex>;

    fn topological_sort_with_order_indicator<'a, OrderIndicator, FOrd, Set>(
        &self, index_set: &'a Set, order_indicator: FOrd,
    ) -> Vec<Self::NodeIndex>
    where
        OrderIndicator: Ord,
        FOrd: Fn(Self::NodeIndex) -> OrderIndicator,
        Set: 'a + SetLike<Self::NodeIndex> + Default,
        &'a Set: IntoIterator<Item = &'a Self::NodeIndex>,
    {
        topological_sort(&index_set, |i| self.prev_edges(i), order_indicator)
    }

    fn topological_sort<'a, Set>(
        &self, index_set: &'a Set,
    ) -> Vec<Self::NodeIndex>
    where
        Set: 'a + SetLike<Self::NodeIndex> + Default,
        &'a Set: IntoIterator<Item = &'a Self::NodeIndex>,
    {
        // Any topological order will work, so just return a constant for
        // `order_indicator`.
        self.topological_sort_with_order_indicator(index_set, |_| true)
    }
}

pub trait RichDAG: DAG {
    fn next_edges(&self, node_index: Self::NodeIndex) -> Vec<Self::NodeIndex>;

    fn get_future_with_stop_condition<FStop, Set, Iter>(
        &self, index_set: Iter, stop_condition: FStop,
    ) -> Set
    where
        FStop: Fn(Self::NodeIndex) -> bool,
        Set: SetLike<Self::NodeIndex> + Default,
        Iter: Iterator<Item = Self::NodeIndex>,
    {
        get_future(index_set, |i| self.next_edges(i), stop_condition)
    }

    fn get_future<Set, Iter>(&self, index_set: Iter) -> Set
    where
        Set: SetLike<Self::NodeIndex> + Default,
        Iter: Iterator<Item = Self::NodeIndex>,
    {
        self.get_future_with_stop_condition(index_set, |_| false)
    }
}

pub trait TreeGraph: Graph {
    fn parent(&self, node_index: Self::NodeIndex) -> Option<Self::NodeIndex>;
    fn referees(&self, node_index: Self::NodeIndex) -> Vec<Self::NodeIndex>;
}

pub trait RichTreeGraph: TreeGraph {
    fn children(&self, node_index: Self::NodeIndex) -> Vec<Self::NodeIndex>;
    fn referrers(&self, node_index: Self::NodeIndex) -> Vec<Self::NodeIndex>;
}

impl<T: TreeGraph> DAG for T {
    fn prev_edges(&self, node_index: Self::NodeIndex) -> Vec<Self::NodeIndex> {
        let mut prev_edges = self.referees(node_index);
        if let Some(p) = self.parent(node_index) {
            prev_edges.push(p);
        }
        prev_edges
    }
}

impl<T: RichTreeGraph + DAG> RichDAG for T {
    fn next_edges(&self, node_index: Self::NodeIndex) -> Vec<Self::NodeIndex> {
        let mut next_edges = self.children(node_index);
        next_edges.append(&mut self.referrers(node_index));
        next_edges
    }
}

pub trait SetLike<T> {
    fn insert(&mut self, i: T) -> bool;
    fn contains(&self, i: &T) -> bool;
}

impl<T: Eq + Hash> SetLike<T> for HashSet<T> {
    fn insert(&mut self, i: T) -> bool { self.insert(i) }

    fn contains(&self, i: &T) -> bool { self.contains(i) }
}

impl SetLike<usize> for BitSet {
    fn insert(&mut self, i: usize) -> bool { self.add(i as u32) }

    fn contains(&self, i: &usize) -> bool { self.contains(*i as u32) }
}
