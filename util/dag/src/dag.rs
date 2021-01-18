use std::{
    collections::{BinaryHeap, HashMap, HashSet, VecDeque},
    hash::Hash,
};

fn topological_sort<NodeIndex, F, OrderIndicator, FOrd>(
    index_set: &Vec<NodeIndex>, outgoing_edges: F, order_indicator: FOrd,
) -> Vec<NodeIndex>
where
    NodeIndex: Copy + Hash + Eq + PartialEq + Ord,
    F: Fn(NodeIndex) -> Vec<NodeIndex>,
    OrderIndicator: Ord,
    FOrd: Fn(NodeIndex) -> OrderIndicator,
{
    let mut num_incoming_edges = HashMap::new();

    for me in index_set {
        num_incoming_edges.entry(*me).or_insert(0);
        for d in &outgoing_edges(*me) {
            if index_set.contains(d) {
                *num_incoming_edges.entry(*d).or_insert(0) += 1;
            }
        }
    }

    let mut candidates = BinaryHeap::new();
    let mut reversed_indices = Vec::new();

    for me in index_set {
        if num_incoming_edges[me] == 0 {
            candidates.push((order_indicator(*me), *me));
        }
    }
    while let Some((_, me)) = candidates.pop() {
        reversed_indices.push(me);

        for d in &outgoing_edges(me) {
            if index_set.contains(d) {
                num_incoming_edges.entry(*d).and_modify(|e| *e -= 1);
                if num_incoming_edges[d] == 0 {
                    candidates.push((order_indicator(*d), *d));
                }
            }
        }
    }
    reversed_indices.reverse();
    reversed_indices
}

// TODO: Support BitSet?
fn get_future<NodeIndex, F, FStop>(
    index_set: &Vec<NodeIndex>, incoming_edges: F, stop_condition: FStop,
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
        for succ in incoming_edges(x) {
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
    fn outgoing_edges(
        &self, node_index: Self::NodeIndex,
    ) -> Vec<Self::NodeIndex>;
    fn topological_sort<OrderIndicator, FOrd>(
        &self, index_set: &Vec<Self::NodeIndex>, order_indicator: FOrd,
    ) -> Vec<Self::NodeIndex>
    where
        OrderIndicator: Ord,
        FOrd: Fn(Self::NodeIndex) -> OrderIndicator,
    {
        topological_sort(
            &index_set,
            |i| self.outgoing_edges(i),
            order_indicator,
        )
    }
}

pub trait RichDAG: DAG {
    fn incoming_edges(
        &self, node_index: Self::NodeIndex,
    ) -> Vec<Self::NodeIndex>;

    fn get_future<FStop>(
        &self, index_set: &Vec<Self::NodeIndex>, stop_condition: FStop,
    ) -> HashSet<Self::NodeIndex>
    where FStop: Fn(Self::NodeIndex) -> bool {
        get_future(index_set, |i| self.incoming_edges(i), stop_condition)
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
    fn outgoing_edges(
        &self, node_index: Self::NodeIndex,
    ) -> Vec<Self::NodeIndex> {
        let mut outgoing_edges = self.referees(node_index);
        if let Some(p) = self.parent(node_index) {
            outgoing_edges.push(p);
        }
        outgoing_edges
    }
}

impl<T: RichTreeGraph + DAG> RichDAG for T {
    fn incoming_edges(
        &self, node_index: Self::NodeIndex,
    ) -> Vec<Self::NodeIndex> {
        let mut incoming_edges = self.children(node_index);
        incoming_edges.append(&mut self.referrers(node_index));
        incoming_edges
    }
}
