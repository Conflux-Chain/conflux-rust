use hibitset::BitSet;
use std::{
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    convert::TryInto,
    fmt::Debug,
    hash::Hash,
};

/// Topologically sort `index_set` and return a sorted `Vec`.
/// For the nodes without order-before relationship, the ones with smaller
/// `order_indicator` output will be ordered first.
pub fn topological_sort<InIndex, OutIndex, F, OrderIndicator, FOrd, Set>(
    index_set: Set, prev_edges: F, order_indicator: FOrd,
) -> Vec<OutIndex>
where
    InIndex: Copy + Hash + Eq + PartialEq + Ord + TryInto<OutIndex>,
    <InIndex as TryInto<OutIndex>>::Error: Debug,
    F: Fn(InIndex) -> Vec<InIndex>,
    OrderIndicator: Ord,
    FOrd: Fn(InIndex) -> OrderIndicator,
    Set: SetLike<InIndex> + Default + Clone + IntoIterator<Item = InIndex>,
{
    let mut num_next_edges = HashMap::new();

    for me in index_set.clone() {
        num_next_edges.entry(me).or_insert(0);
        for prev in prev_edges(me) {
            if index_set.contains(&prev) {
                *num_next_edges.entry(prev).or_insert(0) += 1;
            }
        }
    }

    let mut candidates = BinaryHeap::new();
    let mut reversed_indices = Vec::new();

    for me in index_set.clone() {
        if num_next_edges[&me] == 0 {
            candidates.push((order_indicator(me), me));
        }
    }
    while let Some((_, me)) = candidates.pop() {
        reversed_indices.push(me.try_into().expect("index in range"));

        for prev in prev_edges(me) {
            if index_set.contains(&prev) {
                num_next_edges.entry(prev).and_modify(|e| *e -= 1);
                if num_next_edges[&prev] == 0 {
                    candidates.push((order_indicator(prev), prev));
                }
            }
        }
    }
    reversed_indices.reverse();
    reversed_indices
}

// TODO: Ideally I want to allow `Iter: for<'a> Iterator<Item = &'a NodeIndex>`,
// but this is not allowed for associated types because of https://github.com/rust-lang/rust/issues/49601.
pub fn get_future<'a, InIndex, OutIndex, F, FStop, Set, Iter>(
    index_set: Iter, next_edges: F, stop_condition: FStop,
) -> Set
where
    InIndex: 'a + Copy + TryInto<OutIndex>,
    <InIndex as TryInto<OutIndex>>::Error: Debug,
    OutIndex: 'a + Copy + Hash + Eq + PartialEq + Ord,
    F: Fn(InIndex) -> Vec<InIndex>,
    FStop: Fn(InIndex) -> bool,
    Set: SetLike<OutIndex> + Default,
    Iter: IntoIterator<Item = InIndex>,
{
    let mut queue = VecDeque::new();
    let mut visited = Set::default();
    for i in index_set {
        visited.insert(i.try_into().expect("index in range"));
        queue.push_back(i);
    }
    // TODO: Implement future.
    while let Some(x) = queue.pop_front() {
        for succ in next_edges(x) {
            if stop_condition(succ) {
                continue;
            }
            let out_index = succ.try_into().expect("index in range");
            if !visited.contains(&out_index) {
                queue.push_back(succ);
                visited.insert(out_index);
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

    fn topological_sort_with_order_indicator<OrderIndicator, FOrd, Set>(
        &self, index_set: Set, order_indicator: FOrd,
    ) -> Vec<Self::NodeIndex>
    where
        OrderIndicator: Ord,
        FOrd: Fn(Self::NodeIndex) -> OrderIndicator,
        Set: SetLike<Self::NodeIndex>
            + Default
            + Clone
            + IntoIterator<Item = Self::NodeIndex>,
    {
        topological_sort(index_set, |i| self.prev_edges(i), order_indicator)
    }

    fn topological_sort<Set>(&self, index_set: Set) -> Vec<Self::NodeIndex>
    where Set: SetLike<Self::NodeIndex>
            + Default
            + Clone
            + IntoIterator<Item = Self::NodeIndex> {
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
        Iter: IntoIterator<Item = Self::NodeIndex>,
    {
        get_future(index_set, |i| self.next_edges(i), stop_condition)
    }

    fn get_future<Set, Iter>(&self, index_set: Iter) -> Set
    where
        Set: SetLike<Self::NodeIndex> + Default,
        Iter: IntoIterator<Item = Self::NodeIndex>,
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

impl SetLike<u32> for BitSet {
    fn insert(&mut self, i: u32) -> bool { self.add(i) }

    fn contains(&self, i: &u32) -> bool { self.contains(*i) }
}
