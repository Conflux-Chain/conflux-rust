// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Clone)]
pub struct DeltaMptIterator {
    pub mpt: Arc<DeltaMpt>,
    pub maybe_root_node: Option<NodeRefDeltaMpt>,
}

impl DeltaMptIterator {
    pub fn iterate<'a, DeltaMptDumper: KVInserter<MptKeyValue>>(
        &self, dumper: &mut DeltaMptDumper,
    ) -> Result<()> {
        match &self.maybe_root_node {
            None => {}
            Some(root_node) => {
                let db = &mut *self.mpt.db_owned_read()?;
                let owned_node_set = Default::default();
                let mut cow_root_node = CowNodeRef::new(
                    root_node.clone(),
                    &owned_node_set,
                    self.mpt.get_mpt_id(),
                );
                let guarded_trie_node =
                    GuardedValue::take(cow_root_node.get_trie_node(
                        self.mpt.get_node_memory_manager(),
                        &self.mpt.get_node_memory_manager().get_allocator(),
                        db,
                    )?);
                cow_root_node.iterate_internal(
                    &owned_node_set,
                    &self.mpt,
                    guarded_trie_node,
                    CompressedPathRaw::new_zeroed(0, 0),
                    dumper,
                    db,
                )?;
            }
        }

        Ok(())
    }
}

use crate::storage::{
    impls::{
        delta_mpt::{CowNodeRef, DeltaMpt, NodeRefDeltaMpt},
        errors::Result,
        merkle_patricia_trie::{CompressedPathRaw, KVInserter, MptKeyValue},
    },
    utils::guarded_value::GuardedValue,
};
use std::sync::Arc;
