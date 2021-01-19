use std::{
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    hash::Hash,
};

/// Topologically sort `index_set` and return a sorted `Vec`.
/// For the nodes without order-before relationship, the ones with smaller
/// `order_indicator` output will be ordered first.
fn topological_sort<NodeIndex, F, OrderIndicator, FOrd>(
    index_set: &Vec<NodeIndex>, prev_edges: F, order_indicator: FOrd,
) -> Vec<NodeIndex>
where
    NodeIndex: Copy + Hash + Eq + PartialEq + Ord,
    F: Fn(NodeIndex) -> Vec<NodeIndex>,
    OrderIndicator: Ord,
    FOrd: Fn(NodeIndex) -> OrderIndicator,
{
    let mut num_next_edges = HashMap::new();

    for me in index_set {
        num_next_edges.entry(*me).or_insert(0);
        for prev in &prev_edges(*me) {
            if index_set.contains(prev) {
                *num_next_edges.entry(*prev).or_insert(0) += 1;
            }
        }
    }

    let mut candidates = BinaryHeap::new();
    let mut reversed_indices = Vec::new();

    for me in index_set {
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

// TODO: Support BitSet?
fn get_future<NodeIndex, F, FStop>(
    index_set: &Vec<NodeIndex>, next_edges: F, stop_condition: FStop,
) -> HashSet<NodeIndex>
where
    NodeIndex: Copy + Hash + Eq + PartialEq + Ord,
    F: Fn(NodeIndex) -> Vec<NodeIndex>,
    FStop: Fn(NodeIndex) -> bool,
{
    let mut queue = VecDeque::new();
    let mut visited = HashSet::new();
    for i in index_set {
        visited.insert(*i);
        queue.push_back(*i);
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
    type NodeIndex: Copy + Hash + Eq + PartialEq + Ord;
}

// TODO: Decide if returning Iterator is better than returning `Vec`?
pub trait DAG: Graph {
    fn prev_edges(&self, node_index: Self::NodeIndex) -> Vec<Self::NodeIndex>;

    fn topological_sort_with_order_indicator<OrderIndicator, FOrd>(
        &self, index_set: &Vec<Self::NodeIndex>, order_indicator: FOrd,
    ) -> Vec<Self::NodeIndex>
    where
        OrderIndicator: Ord,
        FOrd: Fn(Self::NodeIndex) -> OrderIndicator,
    {
        topological_sort(&index_set, |i| self.prev_edges(i), order_indicator)
    }

    fn topological_sort(
        &self, index_set: &Vec<Self::NodeIndex>,
    ) -> Vec<Self::NodeIndex> {
        // Any topological order will work, so just return a constant for
        // `order_indicator`.
        self.topological_sort_with_order_indicator(index_set, |_| true)
    }
}

pub trait RichDAG: DAG {
    fn next_edges(&self, node_index: Self::NodeIndex) -> Vec<Self::NodeIndex>;

    fn get_future<FStop>(
        &self, index_set: &Vec<Self::NodeIndex>, stop_condition: FStop,
    ) -> HashSet<Self::NodeIndex>
    where FStop: Fn(Self::NodeIndex) -> bool {
        get_future(index_set, |i| self.next_edges(i), stop_condition)
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
