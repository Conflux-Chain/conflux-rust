// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::parameters::consensus::{NULL, NULLU64};

use slab::Slab;
use std::collections::{HashMap, VecDeque};

struct TreeNode {
    /// This is the parent index of current tree node.
    #[allow(dead_code)]
    parent: usize,
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
        debug!("add_leaf parent={:?} leaf={:?}", parent, leaf);
        if !self.consensus_indices_mapping.contains_key(&parent) {
            return false;
        }
        if self.consensus_indices_mapping.contains_key(&leaf) {
            return false;
        }
        let parent_index = self.consensus_indices_mapping[&parent];
        debug!("parent_index={:?}", parent_index);
        let me = self.arena.insert(TreeNode {
            parent: parent_index,
            children: Vec::new(),
        });
        self.arena[parent_index].children.push(me);
        self.consensus_indices_mapping.insert(leaf, me);
        debug!("add success");
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
            self.arena.remove(index);
        }
        self.arena[me].parent = NULL;
        self.root_index = me;
    }
}
