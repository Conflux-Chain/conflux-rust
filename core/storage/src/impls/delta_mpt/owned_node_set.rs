// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// A container to store information about owned nodes.
#[derive(Default, Debug)]
pub struct OwnedNodeSet {
    dirty: BTreeMap<ActualSlabIndex, Option<DeltaMptDbKey>>,
    committed: BTreeSet<DeltaMptDbKey>,
}

impl OwnedNodeSet {
    /// Insertion takes an extra argument `original_db_key` to
    /// indicate where a dirty node comes from.  If it's a new node,
    /// pass None.  If it's a committed node, the argument is ignored.
    pub fn insert(
        &mut self, val: NodeRefDeltaMpt, original_db_key: Option<DeltaMptDbKey>,
    ) -> bool {
        match val {
            NodeRefDeltaMpt::Committed { db_key } => {
                self.committed.insert(db_key)
            }
            NodeRefDeltaMpt::Dirty { index } => {
                self.dirty.insert(index, original_db_key).is_none()
            }
        }
    }

    pub fn remove(&mut self, val: &NodeRefDeltaMpt) -> bool {
        match val {
            NodeRefDeltaMpt::Committed { db_key } => {
                self.committed.remove(db_key)
            }
            NodeRefDeltaMpt::Dirty { index, .. } => {
                self.dirty.remove(index).is_some()
            }
        }
    }

    pub fn contains(&self, val: &NodeRefDeltaMpt) -> bool {
        match val {
            NodeRefDeltaMpt::Committed { db_key } => {
                self.committed.contains(db_key)
            }
            NodeRefDeltaMpt::Dirty { index, .. } => {
                self.dirty.contains_key(index)
            }
        }
    }

    pub fn iter(&self) -> Iter<'_> {
        Iter {
            dirty_iter: self.dirty.iter().fuse(),
            committed_iter: self.committed.iter().fuse(),
        }
    }

    pub fn get_original_db_key(
        &self, index: ActualSlabIndex,
    ) -> Option<DeltaMptDbKey> {
        match self.dirty.get(&index).cloned() {
            Some(Some(index)) => Some(index),
            _ => None,
        }
    }
}

pub struct Iter<'a> {
    committed_iter:
        std::iter::Fuse<std::collections::btree_set::Iter<'a, DeltaMptDbKey>>,
    dirty_iter: std::iter::Fuse<
        std::collections::btree_map::Iter<
            'a,
            ActualSlabIndex,
            Option<DeltaMptDbKey>,
        >,
    >,
}

impl<'a> Iterator for Iter<'a> {
    type Item = NodeRefDeltaMpt;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(dirty) = self.dirty_iter.next() {
            return Some(NodeRefDeltaMpt::Dirty { index: *dirty.0 });
        }

        if let Some(committed) = self.committed_iter.next() {
            return Some(NodeRefDeltaMpt::Committed { db_key: *committed });
        }

        return None;
    }
}

impl<'a> IntoIterator for &'a OwnedNodeSet {
    type IntoIter = Iter<'a>;
    type Item = NodeRefDeltaMpt;

    fn into_iter(self) -> Iter<'a> { self.iter() }
}

use super::{
    node_memory_manager::ActualSlabIndex, node_ref_map::DeltaMptDbKey,
    NodeRefDeltaMpt,
};
use std::collections::{BTreeMap, BTreeSet};
