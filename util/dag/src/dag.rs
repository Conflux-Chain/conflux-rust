use std::{
    collections::{BinaryHeap, HashMap},
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
}

pub trait TreeGraph: Graph {
    fn parent(&self, node_index: Self::NodeIndex) -> Self::NodeIndex;
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
        outgoing_edges.push(self.parent(node_index));
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
