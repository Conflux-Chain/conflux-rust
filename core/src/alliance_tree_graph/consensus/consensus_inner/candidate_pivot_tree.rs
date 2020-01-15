// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use slab::Slab;
use std::collections::HashMap;

pub struct CandidatePivotTree {
    pub parent: Slab<usize>,
    pub consensus_indices_mapping: HashMap<usize, usize>,
}

impl CandidatePivotTree {
    pub fn new(root: usize) -> Self {
        let mut pivot_tree = Self {
            parent: Slab::new(),
            consensus_indices_mapping: HashMap::new(),
        };

        let root_index = pivot_tree.parent.insert(root);
        pivot_tree
            .consensus_indices_mapping
            .insert(root, root_index);

        pivot_tree
    }
}
