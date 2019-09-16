// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Merge an MPT with sorted deletion and insertion stream.
/// The merge can be in-place or writing to a new MPT (save-as mode).
///
/// In the merging process, the merger keeps a path from root to a node. When
/// the next key to process from insertion or deletion stream lies outside the
/// subtree of the last node in the path, the last node is closed. New nodes are
/// open if the key goes further down extending the path. In in-place mode, node
/// deletions are executed and node writes happen when a modified node is
/// closed. In save-as mode, node deletion is no-op, and node writes happen
/// when a node is closed, and when opening the new node. All modified
/// node and skipped subtree are saved into the new MPT.
///
/// In a save-as copy, the base_mpt could be implemented as an iterator of the
/// original MPT because the original MPT is exactly visited in string order
/// by the path_db_key. (See definition of path_db_key below.)
// TODO(yz): In future merge can be made into multiple threads easily by merging
// different children in parallel then combine the root node.
pub struct MptMerger<'a> {
    rw_cursor: MptCursorRw<MergeMptsInRequest<'a>>,
}

impl<'a> MptMerger<'a> {
    pub fn new(
        maybe_readonly_mpt: Option<&'a mut dyn SnapshotMptTraitReadOnly>,
        out_mpt: &'a mut dyn SnapshotMptTraitSingleWriter,
    ) -> Self
    {
        Self {
            rw_cursor: MptCursorRw::new(MergeMptsInRequest {
                maybe_readonly_mpt,
                out_mpt,
            }),
        }
    }

    // TODO(yz): Invent a trait for inserter to generalize.
    pub fn merge(&mut self, inserter: &DeltaMptInserter) -> Result<MerkleHash> {
        self.rw_cursor.load_root()?;

        struct Merger<'x, 'a: 'x> {
            merger: &'x mut MptMerger<'a>,
        };

        impl<'x, 'a: 'x> Merger<'x, 'a> {
            fn merger_mut(&mut self) -> &mut MptMerger<'a> { self.merger }
        }

        impl<'x, 'a: 'x> KVInserter<(Vec<u8>, Box<[u8]>)> for Merger<'x, 'a> {
            fn push(&mut self, v: (Vec<u8>, Box<[u8]>)) -> Result<()> {
                let (key, value) = v;
                if value.len() > 0 {
                    self.merger_mut().rw_cursor.insert(&key, value)?;
                } else {
                    self.merger_mut().rw_cursor.delete(&key)?;
                }
                Ok(())
            }
        }

        inserter.iterate(Merger { merger: self })?;

        self.rw_cursor.finish()
    }

    // Will be modified and used when syncing snapshot.
    #[allow(unused)]
    /// The iterators operate on key, value store.
    pub fn merge_insertion_deletion_separated<'k>(
        &mut self, mut delete_keys_iter: impl Iterator<Item = &'k [u8]>,
        mut insert_keys_iter: impl Iterator<Item = (&'k [u8], Box<[u8]>)>,
    ) -> Result<MerkleHash>
    {
        self.rw_cursor.load_root()?;

        let mut key_to_delete = delete_keys_iter.next();
        let mut key_value_to_insert = insert_keys_iter.next();

        loop {
            if key_to_delete.is_none() {
                if key_value_to_insert.is_some() {
                    let (key, value) = key_value_to_insert.unwrap();
                    self.rw_cursor.insert(key, value)?;
                    while let Some((key, value)) = insert_keys_iter.next() {
                        self.rw_cursor.insert(key, value)?;
                    }
                    break;
                }
            };

            if key_value_to_insert.is_none() {
                if key_to_delete.is_some() {
                    self.rw_cursor.delete(key_to_delete.as_ref().unwrap())?;
                    while let Some(key) = delete_keys_iter.next() {
                        self.rw_cursor.delete(key)?;
                    }
                    break;
                }
            }

            // In a diff, if there is a deletion of the same key of a insertion,
            // delete only happens before the insertion because the inserted key
            // value must present in the final merged result for it to be in the
            // diff.
            let key_delete = key_to_delete.as_ref().unwrap();
            let key_insert = &key_value_to_insert.as_ref().unwrap().0;
            if key_delete <= key_insert {
                self.rw_cursor.delete(key_delete)?;
                key_to_delete = delete_keys_iter.next();
            } else {
                self.rw_cursor
                    .insert(key_insert, key_value_to_insert.unwrap().1)?;
                key_value_to_insert = insert_keys_iter.next();
            }
        }

        self.rw_cursor.finish()
    }
}

struct MergeMptsInRequest<'a> {
    maybe_readonly_mpt: Option<&'a mut dyn SnapshotMptTraitReadOnly>,
    out_mpt: &'a mut dyn SnapshotMptTraitSingleWriter,
}

impl GetReadMpt for MergeMptsInRequest<'_> {
    fn get_merkle_root(&self) -> &MerkleHash {
        if self.maybe_readonly_mpt.is_some() {
            self.maybe_readonly_mpt.as_ref().unwrap().get_merkle_root()
        } else {
            self.out_mpt.get_merkle_root()
        }
    }

    fn get_read_mpt(&mut self) -> &mut dyn SnapshotMptTraitReadOnly {
        if self.maybe_readonly_mpt.is_some() {
            *self.maybe_readonly_mpt.as_mut().unwrap()
        } else {
            self.out_mpt.as_readonly()
        }
    }
}

impl GetRwMpt for MergeMptsInRequest<'_> {
    fn get_write_mpt(&mut self) -> &mut dyn SnapshotMptTraitSingleWriter {
        self.out_mpt
    }

    fn get_write_and_read_mpt(
        &mut self,
    ) -> (
        &mut dyn SnapshotMptTraitSingleWriter,
        Option<&mut dyn SnapshotMptTraitReadOnly>,
    ) {
        (
            self.out_mpt,
            // Can't use map() here because it would be a compilation error.
            match &mut self.maybe_readonly_mpt {
                None => None,
                Some(x) => Some(*x),
            },
        )
    }

    fn is_save_as_write(&self) -> bool { self.maybe_readonly_mpt.is_some() }

    fn is_in_place_update(&self) -> bool { self.maybe_readonly_mpt.is_none() }
}

use super::{
    super::super::{
        super::storage_db::snapshot_mpt::*, errors::*,
        storage_manager::DeltaMptInserter,
    },
    cow_node_ref::KVInserter,
    mpt_cursor::*,
};
use primitives::MerkleHash;
