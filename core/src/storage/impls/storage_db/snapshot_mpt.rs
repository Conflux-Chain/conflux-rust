// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotMpt<
    DbType: KeyValueDbTraitOwnedRead<ValueType = SnapshotMptDbValue> + ?Sized,
    BorrowType: BorrowMut<DbType>,
> {
    pub db: BorrowType,
    pub _marker_db_type: std::marker::PhantomData<DbType>,
}

fn mpt_node_path_to_db_key(path: &dyn CompressedPathTrait) -> Vec<u8> {
    let path_slice = path.path_slice();
    let end_mask = path.end_mask();

    let full_slice = if end_mask == 0 {
        path_slice
    } else {
        &path_slice[0..path_slice.len() - 1]
    };

    let mut result = Vec::with_capacity(1 + path.path_steps() as usize);
    // Root node has empty compressed_path, so we always prefix the compressed
    // path with letter p.
    result.push('p' as u8);

    for full_byte in full_slice {
        result.push(CompressedPathRaw::first_nibble(*full_byte));
        result.push(CompressedPathRaw::second_nibble(*full_byte));
    }
    if end_mask != 0 {
        result
            .push(CompressedPathRaw::first_nibble(*path_slice.last().unwrap()));
    }

    result
}

fn mpt_node_path_from_db_key(db_key: &[u8]) -> Result<CompressedPathRaw> {
    // The 'p' letter.
    let mut offset = 1;

    let last_offset = db_key.len() - 1;
    let mut path = CompressedPathRaw::new_zeroed(
        (db_key.len() / 2).try_into()?,
        // When last_offset is odd, 0xff is passed to first_nibble, otherwise
        // 0.
        CompressedPathRaw::first_nibble(0xff * ((last_offset & 1) as u8)),
    );
    let path_mut = path.path_slice_mut();

    let mut path_index = 0;
    while offset < last_offset {
        path_mut[path_index] = CompressedPathRaw::set_second_nibble(
            CompressedPathRaw::from_first_nibble(db_key[offset]),
            db_key[offset + 1],
        );
        offset += 2;
        path_index += 1;
    }

    // A half-byte at the end.
    if offset == last_offset {
        path_mut[path_index] =
            CompressedPathRaw::from_first_nibble(db_key[offset]);
    }

    Ok(path)
}

impl<
        DbType: KeyValueDbTraitOwnedRead<ValueType = SnapshotMptDbValue> + ?Sized,
        BorrowType: BorrowMut<DbType>,
    > SnapshotMptTraitReadOnly for SnapshotMpt<DbType, BorrowType>
where DbType:
        for<'db> KeyValueDbIterableTrait<'db, SnapshotMptValue, Error, [u8]>
{
    fn get_merkle_root(&self) -> &MerkleHash { unimplemented!() }

    fn load_node(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Option<SnapshotMptNode>> {
        let key = mpt_node_path_to_db_key(path);
        match self.db.borrow_mut().get_mut(&key)? {
            None => Ok(None),
            Some(SnapshotMptDbValue(rlp, subtree_size)) => {
                Ok(Some(SnapshotMptNode(
                    VanillaTrieNode::<MerkleHash>::decode(&Rlp::new(&rlp))?,
                    subtree_size,
                )))
            }
        }
    }

    fn iterate_subtree_trie_nodes_without_root(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Box<dyn SnapshotMptIteraterTrait + '_>> {
        let begin_key_excl = mpt_node_path_to_db_key(path);

        let mut end_key_excl = begin_key_excl.clone();
        // The key is non empty. See also comment for compressed_path_to_db_key.
        *end_key_excl.last_mut().unwrap() += 1;

        Ok(Box::new(
            self.db
                .borrow_mut()
                .iter_range_excl(&begin_key_excl, &end_key_excl)?
                .map(|(key, value, subtree_size)| {
                    Ok((
                        mpt_node_path_from_db_key(&key)?,
                        VanillaTrieNode::<MerkleHash>::decode(&Rlp::new(
                            &value,
                        ))?,
                        subtree_size,
                    ))
                }),
        ))
    }
}

impl<
        DbType: KeyValueDbTraitSingleWriter<ValueType = SnapshotMptDbValue> + ?Sized,
        BorrowType: BorrowMut<DbType>,
    > SnapshotMptTraitSingleWriter for SnapshotMpt<DbType, BorrowType>
where DbType:
        for<'db> KeyValueDbIterableTrait<'db, SnapshotMptValue, Error, [u8]>
{
    fn as_readonly(&mut self) -> &mut dyn SnapshotMptTraitReadOnly { self }

    fn delete_node(&mut self, path: &dyn CompressedPathTrait) -> Result<()> {
        let key = mpt_node_path_to_db_key(path);
        self.db.borrow_mut().delete(&key)?;
        Ok(())
    }

    fn write_node(
        &mut self, path: &dyn CompressedPathTrait, trie_node: &SnapshotMptNode,
    ) -> Result<()> {
        let key = mpt_node_path_to_db_key(path);
        self.db.borrow_mut().put(
            &key,
            &SnapshotMptDbValue(
                trie_node.0.rlp_bytes().into_boxed_slice(),
                trie_node.1,
            ),
        )?;
        Ok(())
    }
}

use super::super::{
    super::storage_db::{
        key_value_db::{
            KeyValueDbIterableTrait, KeyValueDbTraitOwnedRead,
            KeyValueDbTraitSingleWriter,
        },
        snapshot_mpt::*,
    },
    errors::*,
    multi_version_merkle_patricia_trie::merkle_patricia_trie::{
        trie_node::VanillaTrieNode, CompressedPathRaw, CompressedPathTrait,
    },
};
use fallible_iterator::FallibleIterator;
use primitives::MerkleHash;
use rlp::*;
use std::{borrow::BorrowMut, convert::TryInto};
