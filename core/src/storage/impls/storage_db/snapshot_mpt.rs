// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotMpt<DbType: ?Sized, BorrowType: BorrowMut<DbType>> {
    pub db: BorrowType,
    pub merkle_root: MerkleHash,
    pub _marker_db_type: std::marker::PhantomData<DbType>,
}

pub trait SnapshotMptLoadNode {
    fn load_node_rlp(
        &mut self, key: &[u8],
    ) -> Result<Option<SnapshotMptDbValue>>;
}

pub fn mpt_node_path_to_db_key(path: &dyn CompressedPathTrait) -> Vec<u8> {
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

pub fn mpt_node_path_from_db_key(db_key: &[u8]) -> Result<CompressedPathRaw> {
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

impl<DbType: SnapshotMptLoadNode + ?Sized, BorrowType: BorrowMut<DbType>>
    SnapshotMpt<DbType, BorrowType>
{
    pub fn new(db: BorrowType) -> Result<Self> {
        let mut mpt = Self {
            db,
            merkle_root: MERKLE_NULL_NODE,
            _marker_db_type: Default::default(),
        };
        if let Some(rlp) = mpt.db.borrow_mut().load_node_rlp(
            &mpt_node_path_to_db_key(&CompressedPathRaw::default()),
        )? {
            mpt.merkle_root =
                *SnapshotMptNode(Rlp::new(&rlp).as_val()?).get_merkle();
        }
        Ok(mpt)
    }

    pub fn get_merkle_root_impl(&self) -> MerkleHash { self.merkle_root }
}

impl<DbType: SnapshotMptLoadNode + ?Sized, BorrowType: BorrowMut<DbType>>
    SnapshotMptTraitRead for SnapshotMpt<DbType, BorrowType>
{
    fn get_merkle_root(&self) -> MerkleHash { self.get_merkle_root_impl() }

    fn load_node(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Option<SnapshotMptNode>> {
        let key = mpt_node_path_to_db_key(path);
        match self.db.borrow_mut().load_node_rlp(&key)? {
            None => Ok(None),
            Some(rlp) => Ok(Some(SnapshotMptNode(Rlp::new(&rlp).as_val()?))),
        }
    }
}

impl<
        DbType: SnapshotMptLoadNode
            + for<'db> KeyValueDbIterableTrait<'db, SnapshotMptValue, Error, [u8]>
            + ?Sized,
        BorrowType: BorrowMut<DbType>,
    > SnapshotMptTraitReadAndIterate for SnapshotMpt<DbType, BorrowType>
{
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
                .map(|(key, value)| {
                    Ok((
                        mpt_node_path_from_db_key(&key)?,
                        SnapshotMptNode::decode(&Rlp::new(&value))?,
                    ))
                }),
        ))
    }
}

impl<
        DbType: SnapshotMptLoadNode
            + KeyValueDbTraitSingleWriter<ValueType = SnapshotMptDbValue>
            + for<'db> KeyValueDbIterableTrait<'db, SnapshotMptValue, Error, [u8]>
            + ?Sized,
        BorrowType: BorrowMut<DbType>,
    > SnapshotMptTraitRw for SnapshotMpt<DbType, BorrowType>
{
    fn delete_node(&mut self, path: &dyn CompressedPathTrait) -> Result<()> {
        let key = mpt_node_path_to_db_key(path);
        self.db.borrow_mut().delete(&key)?;
        Ok(())
    }

    fn write_node(
        &mut self, path: &dyn CompressedPathTrait, trie_node: &SnapshotMptNode,
    ) -> Result<()> {
        let key = mpt_node_path_to_db_key(path);
        self.db
            .borrow_mut()
            .put(&key, &trie_node.rlp_bytes().into_boxed_slice())?;
        Ok(())
    }
}

use crate::storage::{
    impls::{
        errors::*,
        merkle_patricia_trie::{CompressedPathRaw, CompressedPathTrait},
    },
    storage_db::{
        key_value_db::{KeyValueDbIterableTrait, KeyValueDbTraitSingleWriter},
        snapshot_mpt::*,
        SnapshotMptTraitRead,
    },
};
use fallible_iterator::FallibleIterator;
use primitives::{MerkleHash, MERKLE_NULL_NODE};
use rlp::*;
use std::{borrow::BorrowMut, convert::TryInto};
