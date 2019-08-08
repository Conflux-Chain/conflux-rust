// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SnapshotMpt<DbType: KeyValueDbTraitRead, BorrowType: Borrow<DbType>>
{
    pub db: BorrowType,
    pub _marker_db_type: std::marker::PhantomData<DbType>,
}

fn compressed_path_to_db_key(_path: &CompressedPathTrait) -> Vec<u8> {
    // FIXME: implement.
    // FIXME: The trick to make path in increasing order correspond to a tree
    // FIXME: structure is to expand each byte into two nibbles, with the
    // FIXME: second nibble = 0 for byte without second nibble, and second
    // FIXME: nibble |= 16 for byte with second nibble.
    // FIXME: We may find some other solution. The problem is that each byte
    // FIXME: with end_mask correspond to 17 * 16 total states.
    unimplemented!()
}

impl<DbType: KeyValueDbTraitRead, BorrowType: Borrow<DbType>>
    SnapshotMptTraitReadOnly for SnapshotMpt<DbType, BorrowType>
{
    fn get_merkle_root(&self) -> &MerkleHash { unimplemented!() }

    fn load_node(
        &self, path: &CompressedPathTrait,
    ) -> Result<Option<VanillaTrieNode<MerkleHash>>> {
        let _key = compressed_path_to_db_key(path);
        unimplemented!()
    }

    fn iterate_subtree_trie_nodes_without_root(
        &self, path: &CompressedPathTrait,
    ) -> Box<SnapshotMptIteraterTrait> {
        let _key = compressed_path_to_db_key(path);
        unimplemented!()
    }
}

impl<DbType: KeyValueDbTraitSingleWriter, BorrowType: BorrowMut<DbType>>
    SnapshotMptTraitSingleWriter for SnapshotMpt<DbType, BorrowType>
{
    fn delete_node(&mut self, path: &CompressedPathTrait) -> Result<()> {
        let _key = compressed_path_to_db_key(path);
        unimplemented!()
    }

    fn write_node(
        &mut self, path: &CompressedPathTrait,
        _trie_node: &VanillaTrieNode<MerkleHash>,
    ) -> Result<()>
    {
        let _key = compressed_path_to_db_key(path);
        unimplemented!()
    }
}

use super::super::{
    super::storage_db::{
        key_value_db::{KeyValueDbTraitRead, KeyValueDbTraitSingleWriter},
        snapshot_mpt::{
            SnapshotMptIteraterTrait, SnapshotMptTraitReadOnly,
            SnapshotMptTraitSingleWriter,
        },
    },
    errors::*,
    multi_version_merkle_patricia_trie::merkle_patricia_trie::{
        trie_node::VanillaTrieNode, CompressedPathTrait,
    },
};
use primitives::MerkleHash;
use std::borrow::{Borrow, BorrowMut};
