// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SliceVerifyReadWritePathNode<Mpt>(Option<ReadWritePathNode<Mpt>>);

impl<Mpt> SliceVerifyReadWritePathNode<Mpt> {
    fn take(mut self) -> ReadWritePathNode<Mpt> { self.0.take().unwrap() }

    fn as_ref(&self) -> &ReadWritePathNode<Mpt> { self.0.as_ref().unwrap() }

    fn as_mut(&mut self) -> &mut ReadWritePathNode<Mpt> {
        self.0.as_mut().unwrap()
    }
}

impl<Mpt> Drop for SliceVerifyReadWritePathNode<Mpt> {
    fn drop(&mut self) {}
}

impl<Mpt> TakeMpt<Mpt> for SliceVerifyReadWritePathNode<Mpt> {
    fn take_mpt(&mut self) -> Option<Mpt> { self.as_mut().take_mpt() }
}

impl<Mpt: GetReadMpt> CursorLoadNodeWrapper<Mpt>
    for SliceVerifyReadWritePathNode<Mpt>
{
    fn load_node_wrapper<'a>(
        &self, mpt: &mut Mpt, path: &CompressedPathRaw,
    ) -> Result<SnapshotMptNode> {
        self.as_ref().load_node_wrapper(mpt, path)
    }
}

impl<Mpt: GetRwMpt> PathNodeTrait<Mpt> for SliceVerifyReadWritePathNode<Mpt> {
    fn new_loaded(basic_node: BasicPathNode<Mpt>, parent_node: &Self) -> Self {
        let mut rw_path_node = ReadWritePathNode::<Mpt>::new_loaded(
            basic_node,
            parent_node.as_ref(),
        );
        // Disable path compression for boundary nodes of MptSliceVerifier.
        rw_path_node.maybe_first_realized_child_index = 0;
        SliceVerifyReadWritePathNode(Some(rw_path_node))
    }

    fn commit(self, parent_node: &mut Self) -> Result<Option<Mpt>> {
        self.take().commit(parent_node.as_mut())
    }

    fn commit_root(self, mpt_taken: &mut Option<Mpt>) -> Result<MerkleHash> {
        self.take().commit_root(mpt_taken)
    }

    fn get_basic_path_node(&self) -> &BasicPathNode<Mpt> {
        self.as_ref().get_basic_path_node()
    }

    fn get_basic_path_node_mut(&mut self) -> &mut BasicPathNode<Mpt> {
        self.as_mut().get_basic_path_node_mut()
    }

    fn open_child_index(&mut self, child_index: u8) -> Result<Option<Self>> {
        self.as_mut().next_child_index = child_index;
        let mut mpt_taken = self.as_mut().mpt.take();

        match self
            .as_ref()
            .trie_node
            .get_children_table_ref()
            .get_child(child_index)
        {
            None => {
                self.as_mut().mpt = mpt_taken;

                Ok(None)
            }
            Some(&SubtreeMerkleWithSize {
                merkle: ref supposed_merkle_hash,
                ..
            }) => {
                match Self::load_into(
                    self,
                    &mut mpt_taken,
                    child_index,
                    supposed_merkle_hash,
                ) {
                    Err(e) => match e.kind() {
                        ErrorKind::SnapshotMPTTrieNodeNotFound => {
                            self.as_mut().mpt = mpt_taken;

                            Ok(None)
                        }
                        _ => Err(e),
                    },
                    Ok(node) => Ok(Some(node)),
                }
            }
        }
    }
}

impl<Mpt: GetRwMpt> RwPathNodeTrait<Mpt> for SliceVerifyReadWritePathNode<Mpt> {
    fn get_read_write_path_node(&mut self) -> &mut ReadWritePathNode<Mpt> {
        self.as_mut()
    }

    fn get_read_only_path_node(&self) -> &ReadWritePathNode<Mpt> {
        self.as_ref()
    }

    fn unmatched_child_node_for_path_diversion(
        self, new_path_db_key: CompressedPathRaw,
        new_compressed_path: CompressedPathRaw,
    ) -> Result<ReadWritePathNode<Mpt>>
    {
        self.take().unmatched_child_node_for_path_diversion(
            new_path_db_key,
            new_compressed_path,
        )
    }

    fn replace_value_valid(&mut self, value: Box<[u8]>) {
        self.as_mut().replace_value_valid(value)
    }

    fn delete_value_assumed_existence(&mut self) {
        self.as_mut().delete_value_assumed_existence()
    }
}

impl<Mpt: GetRwMpt, Cursor: CursorLoadNodeWrapper<Mpt> + CursorSetIoError>
    CursorToRootNode<Mpt, SliceVerifyReadWritePathNode<Mpt>> for Cursor
{
    fn new_root(
        &self, basic_node: BasicPathNode<Mpt>, mpt_is_empty: bool,
    ) -> SliceVerifyReadWritePathNode<Mpt> {
        SliceVerifyReadWritePathNode(Some(ReadWritePathNode {
            basic_node,
            is_loaded: !mpt_is_empty,
            maybe_first_realized_child_index:
                ReadWritePathNode::<Mpt>::NULL_CHILD_INDEX,
            the_first_child_if_pending: None,
            maybe_compressed_path_split_child_index:
                ReadWritePathNode::<Mpt>::NULL_CHILD_INDEX,
            maybe_compressed_path_split_child_node: None,
            subtree_size_delta: 0,
            delta_subtree_size: 0,
            has_io_error: self.io_error(),
            db_committed: false,
        }))
    }
}

use crate::storage::{
    impls::{
        errors::*,
        merkle_patricia_trie::{
            mpt_cursor::{
                BasicPathNode, CursorLoadNodeWrapper, CursorSetIoError,
                CursorToRootNode, GetReadMpt, GetRwMpt, PathNodeTrait,
                ReadWritePathNode, RwPathNodeTrait, TakeMpt,
            },
            CompressedPathRaw, TrieNodeTrait,
        },
    },
    storage_db::{SnapshotMptNode, SubtreeMerkleWithSize},
};
use primitives::MerkleHash;
