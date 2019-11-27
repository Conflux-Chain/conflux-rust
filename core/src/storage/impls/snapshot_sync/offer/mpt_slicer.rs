// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[allow(unused)]
pub struct MptSlicer<'a> {
    cursor: MptCursor<
        &'a mut dyn SnapshotMptTraitReadOnly,
        BasicPathNode<&'a mut dyn SnapshotMptTraitReadOnly>,
    >,
}

impl<'a> MptSlicer<'a> {
    pub fn new(mpt: &'a mut dyn SnapshotMptTraitReadOnly) -> Result<Self> {
        let mut cursor = MptCursor::new(mpt);
        cursor.load_root()?;
        Ok(Self { cursor })
    }

    pub fn new_from_key(
        mpt: &'a mut dyn SnapshotMptTraitReadOnly, key: &[u8],
    ) -> Result<Self> {
        let mut slicer = Self::new(mpt)?;
        slicer.cursor.open_path_for_key::<access_mode::Read>(key)?;
        Ok(slicer)
    }

    pub fn to_proof(&self) -> TrieProof { self.cursor.to_proof() }

    pub fn get_range_end_key(&self) -> Option<&[u8]> {
        // The cursor stops at the key which just exceed,the rlp_size_limit,
        // or at the root node.
        let key = self
            .cursor
            .get_path_nodes()
            .last()
            .unwrap()
            .get_path_to_node()
            .path_slice();
        if key.len() == 0 {
            None
        } else {
            Some(key)
        }
    }

    pub fn advance(&mut self, mut rlp_size_limit: u64) -> Result<()> {
        let current_node = self.cursor.current_node_mut();
        // First, check the value of this node, if we are the first time
        // visiting this node.
        if current_node.next_child_index == 0 {
            let maybe_value = current_node.value_as_slice();
            match maybe_value {
                MptValue::Some(value) => {
                    let key_value_size = rlp_key_value_len(
                        current_node.get_path_to_node().path_size(),
                        value.len(),
                    );
                    if rlp_size_limit <= key_value_size {
                        return Ok(());
                    } else {
                        rlp_size_limit -= key_value_size;
                    }
                }
                _ => {}
            }
        }

        for (
            this_child_index,
            &SubtreeMerkleWithSize {
                ref subtree_size, ..
            },
        ) in current_node
            .trie_node
            .get_children_table_ref()
            .iter()
            .set_start_index(current_node.next_child_index)
        {
            if *subtree_size <= rlp_size_limit {
                rlp_size_limit -= *subtree_size;
            } else {
                let child_node = unsafe {
                    // Mute Rust borrow checker because there is no way
                    // around. It's actually safe to open_child_index while
                    // we immutably borrows the trie_node, because
                    // open_child_index won't modify
                    // trie_node.
                    &mut *(current_node
                        as *const BasicPathNode<
                            &'a mut dyn SnapshotMptTraitReadOnly,
                        >
                        as *mut BasicPathNode<
                            &'a mut dyn SnapshotMptTraitReadOnly,
                        >)
                }
                .open_child_index(this_child_index)?
                // Unwrap is fine because the child is guaranteed to exist.
                .unwrap();

                drop(current_node);

                self.cursor.push_node(child_node);
                return self.advance(rlp_size_limit);
            }
        }

        // Pop-up because subtree isn't large enough.
        if rlp_size_limit > 0 && self.cursor.get_path_nodes().len() > 1 {
            self.cursor.pop_one_node()?;
            return self.advance(rlp_size_limit);
        }

        Ok(())
    }
}

use super::super::super::{
    super::storage_db::snapshot_mpt::{
        SnapshotMptTraitReadOnly, SubtreeMerkleWithSize,
    },
    errors::*,
    merkle_patricia_trie::{mpt_cursor::*, *},
};
