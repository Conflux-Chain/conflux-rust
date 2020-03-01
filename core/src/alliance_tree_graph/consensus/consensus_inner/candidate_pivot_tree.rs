// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::parameters::consensus::NULL;

use slab::Slab;
use std::collections::{HashMap, VecDeque};

struct TreeNode {
    /// This is the parent index of current tree node.
    parent: usize,
    /// This is the corresponding consensus graph index
    consensus_index: usize,
    /// This are the indices of children of current tree node.
    children: Vec<usize>,
}

pub struct CandidatePivotTree {
    arena: Slab<TreeNode>,
    consensus_indices_mapping: HashMap<usize, usize>,
    root_index: usize,
}

impl CandidatePivotTree {
    pub fn new(root: usize) -> Self {
        let mut pivot_tree = Self {
            arena: Slab::new(),
            consensus_indices_mapping: HashMap::new(),
            root_index: NULL,
        };

        let me = pivot_tree.arena.insert(TreeNode {
            parent: NULL,
            consensus_index: root,
            children: Vec::new(),
        });
        pivot_tree.consensus_indices_mapping.insert(root, me);
        pivot_tree.root_index = me;

        pivot_tree
    }

    pub fn contains(&self, consensus_index: usize) -> bool {
        self.consensus_indices_mapping
            .contains_key(&consensus_index)
    }

    pub fn add_leaf(&mut self, parent: usize, leaf: usize) -> bool {
        if !self.consensus_indices_mapping.contains_key(&parent) {
            debug!("Invalid pivot proposal: parent not in tree mapping");
            return false;
        }

        let parent_index = self.consensus_indices_mapping[&parent];

        if let Some(leaf_index) = self.consensus_indices_mapping.get(&leaf) {
            if self.arena[*leaf_index].parent == parent_index
                && self.arena[parent_index].children.contains(leaf_index)
            {
                return true;
            } else {
                warn!("Should not change parent-child relation.");
                return false;
            }
        }

        let me = self.arena.insert(TreeNode {
            parent: parent_index,
            consensus_index: leaf,
            children: Vec::new(),
        });
        self.arena[parent_index].children.push(me);
        self.consensus_indices_mapping.insert(leaf, me);
        true
    }

    /// Make `consensus_index` the new root of the tree, and discard all other
    /// siblings.
    pub fn make_root(&mut self, consensus_index: usize) {
        let me = *self
            .consensus_indices_mapping
            .get(&consensus_index)
            .expect("consensus_index must exist");

        assert!(self.arena[me].parent == self.root_index);

        let mut queue = VecDeque::new();
        let mut exclude = Vec::new();
        queue.push_back(self.root_index);
        while let Some(index) = queue.pop_front() {
            exclude.push(index);
            for child in &self.arena[index].children {
                if *child != me {
                    queue.push_back(*child);
                }
            }
        }
        for index in exclude {
            self.consensus_indices_mapping
                .remove(&self.arena[index].consensus_index);
            self.arena.remove(index);
        }
        self.arena[me].parent = NULL;
        self.root_index = me;
    }
}

#[cfg(test)]
mod tests {
    use super::CandidatePivotTree;

    #[test]
    fn test_add_leaf() {
        let mut pivot_tree = CandidatePivotTree::new(0);

        assert_eq!(pivot_tree.root_index, 0);
        assert_eq!(pivot_tree.arena.len(), 1);
        assert_eq!(pivot_tree.consensus_indices_mapping.len(), 1);

        // invalid parent
        assert!(!pivot_tree.add_leaf(2, 1));
        assert_eq!(pivot_tree.root_index, 0);
        assert_eq!(pivot_tree.arena.len(), 1);
        assert_eq!(pivot_tree.consensus_indices_mapping.len(), 1);

        // add valid leaf
        assert!(pivot_tree.add_leaf(0, 2));
        assert_eq!(pivot_tree.root_index, 0);
        assert_eq!(pivot_tree.arena.len(), 2);
        assert_eq!(pivot_tree.consensus_indices_mapping.len(), 2);

        // add valid leaf
        assert!(pivot_tree.add_leaf(0, 1));
        assert_eq!(pivot_tree.root_index, 0);
        assert_eq!(pivot_tree.arena.len(), 3);
        assert_eq!(pivot_tree.consensus_indices_mapping.len(), 3);

        // add existing node
        assert!(pivot_tree.add_leaf(0, 1));
        assert_eq!(pivot_tree.root_index, 0);
        assert_eq!(pivot_tree.arena.len(), 3);
        assert_eq!(pivot_tree.consensus_indices_mapping.len(), 3);

        // add existing node and change parent
        assert!(!pivot_tree.add_leaf(2, 1));
        assert_eq!(pivot_tree.root_index, 0);
        assert_eq!(pivot_tree.arena.len(), 3);
        assert_eq!(pivot_tree.consensus_indices_mapping.len(), 3);

        assert!(pivot_tree.contains(0));
        assert!(pivot_tree.contains(1));
        assert!(pivot_tree.contains(2));
        assert!(!pivot_tree.contains(3));
    }

    #[test]
    fn test_make_root() {
        let mut pivot_tree = CandidatePivotTree::new(0);

        assert_eq!(pivot_tree.root_index, 0);
        assert!(pivot_tree.add_leaf(0, 1));
        assert!(pivot_tree.add_leaf(0, 2));
        assert!(pivot_tree.add_leaf(0, 3));
        assert!(pivot_tree.add_leaf(1, 4));
        assert!(pivot_tree.add_leaf(1, 5));
        assert!(pivot_tree.add_leaf(1, 6));
        assert!(pivot_tree.add_leaf(2, 7));

        assert_eq!(pivot_tree.arena.len(), 8);
        assert_eq!(pivot_tree.consensus_indices_mapping.len(), 8);

        for index in vec![0, 1, 2, 3, 4, 5, 6, 7] {
            assert!(pivot_tree.contains(index));
        }

        pivot_tree.make_root(1);
        for index in vec![1, 4, 5, 6] {
            assert!(pivot_tree.contains(index));
        }
        for index in vec![0, 2, 3, 7] {
            assert!(!pivot_tree.contains(index));
        }
        assert_eq!(pivot_tree.root_index, 1);
        assert_eq!(pivot_tree.arena.len(), 4);
        assert_eq!(pivot_tree.consensus_indices_mapping.len(), 4);

        pivot_tree.make_root(6);
        for index in vec![6] {
            assert!(pivot_tree.contains(index));
        }
        for index in vec![0, 1, 2, 3, 4, 5, 7] {
            assert!(!pivot_tree.contains(index));
        }
        assert_eq!(pivot_tree.root_index, 6);
        assert_eq!(pivot_tree.arena.len(), 1);
        assert_eq!(pivot_tree.consensus_indices_mapping.len(), 1);
    }
}
