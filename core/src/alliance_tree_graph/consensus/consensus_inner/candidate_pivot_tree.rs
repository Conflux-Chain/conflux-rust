// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::parameters::consensus::{NULL, NULLU64};

use slab::Slab;
use std::collections::HashMap;

struct TreeNode {
    /// This is the parent index of current tree node.
    #[allow(dead_code)]
    parent: usize,
    /// This is the height of current tree node.  
    height: u64,
}

pub struct CandidatePivotTree {
    arena: Slab<TreeNode>,
    consensus_indices_mapping: HashMap<usize, usize>,
}

impl CandidatePivotTree {
    pub fn new(root: usize, height: u64) -> Self {
        let mut pivot_tree = Self {
            arena: Slab::new(),
            consensus_indices_mapping: HashMap::new(),
        };

        let me = pivot_tree.arena.insert(TreeNode {
            parent: NULL,
            height,
        });
        pivot_tree.consensus_indices_mapping.insert(root, me);

        pivot_tree
    }

    pub fn height(&self, consensus_index: usize) -> u64 {
        self.consensus_indices_mapping
            .get(&consensus_index)
            .map(|arena_index| self.arena[*arena_index].height)
            .unwrap_or(NULLU64)
    }

    pub fn add_leaf(&mut self, parent: usize, leaf: usize) -> bool {
        if !self.consensus_indices_mapping.contains_key(&parent) {
            return false;
        }
        if self.consensus_indices_mapping.contains_key(&leaf) {
            return false;
        }
        let parent_index = self.consensus_indices_mapping[&parent];
        let parent_height = self.arena[parent_index].height;
        let me = self.arena.insert(TreeNode {
            parent: parent_index,
            height: parent_height + 1,
        });
        self.consensus_indices_mapping.insert(leaf, me);
        true
    }
}
