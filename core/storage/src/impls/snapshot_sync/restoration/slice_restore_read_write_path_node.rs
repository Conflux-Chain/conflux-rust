// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

pub struct SliceVerifyReadWritePathNode(Option<ReadWritePathNode>);

impl SliceVerifyReadWritePathNode {
    fn take(mut self) -> ReadWritePathNode { self.0.take().unwrap() }

    pub fn as_ref(&self) -> &ReadWritePathNode { self.0.as_ref().unwrap() }

    fn as_mut(&mut self) -> &mut ReadWritePathNode { self.0.as_mut().unwrap() }
}

impl Drop for SliceVerifyReadWritePathNode {
    fn drop(&mut self) {}
}

impl LoadNodeWrapper for SliceVerifyReadWritePathNode {
    fn load_node_wrapper<Mpt: GetReadMpt>(
        &self, mpt: &mut Mpt, path: &CompressedPathRaw,
    ) -> Result<SnapshotMptNode> {
        self.as_ref().load_node_wrapper(mpt, path)
    }
}

impl PathNodeTrait for SliceVerifyReadWritePathNode {
    fn new_loaded(basic_node: BasicPathNode, parent_node: &Self) -> Self {
        let mut rw_path_node =
            ReadWritePathNode::new_loaded(basic_node, parent_node.as_ref());
        // Disable path compression for boundary nodes of MptSliceVerifier.
        rw_path_node.disable_path_compression();
        SliceVerifyReadWritePathNode(Some(rw_path_node))
    }

    fn get_basic_path_node(&self) -> &BasicPathNode {
        self.as_ref().get_basic_path_node()
    }

    fn get_basic_path_node_mut(&mut self) -> &mut BasicPathNode {
        self.as_mut().get_basic_path_node_mut()
    }

    fn open_child_index_ro<Mpt: GetReadMpt>(
        &mut self, _mpt: &mut Mpt, _child_index: u8,
    ) -> Result<Option<Self>> {
        unreachable!();
    }
}

impl RwPathNodeTrait for SliceVerifyReadWritePathNode {
    fn new(
        basic_node: BasicPathNode, parent_node: &Self, value_size: usize,
    ) -> Self {
        // Do not disable path compression for non-boundary nodes.
        SliceVerifyReadWritePathNode(Some(ReadWritePathNode::new(
            basic_node,
            parent_node.as_ref(),
            value_size,
        )))
    }

    fn get_read_write_path_node(&mut self) -> &mut ReadWritePathNode {
        self.as_mut()
    }

    fn get_read_only_path_node(&self) -> &ReadWritePathNode { self.as_ref() }

    fn commit<Mpt: GetRwMpt>(
        self, mpt: &mut Mpt, parent_node: &mut Self,
    ) -> Result<()> {
        self.take().commit(mpt, parent_node.as_mut())
    }

    fn commit_root<Mpt: GetRwMpt>(self, mpt: &mut Mpt) -> Result<MerkleHash> {
        self.take().commit_root(mpt)
    }

    fn open_child_index<Mpt: GetRwMpt>(
        &mut self, mpt: &mut Mpt, child_index: u8,
    ) -> Result<Option<Self>> {
        match self.as_mut().open_child_index(mpt, child_index) {
            Err(e) => Err(e),
            Ok(Some(mut node)) => {
                // Disable path compression for boundary nodes of
                // MptSliceVerifier.
                node.disable_path_compression();

                Ok(Some(SliceVerifyReadWritePathNode(Some(node))))
            }
            Ok(None) => Ok(None),
        }
    }

    fn unmatched_child_node_for_path_diversion<Mpt: GetRwMpt>(
        self, mpt: &mut Mpt, new_path_db_key: CompressedPathRaw,
        new_compressed_path: CompressedPathRaw,
    ) -> Result<ReadWritePathNode>
    {
        self.take().unmatched_child_node_for_path_diversion(
            mpt,
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
    CursorToRootNode<Mpt, SliceVerifyReadWritePathNode> for Cursor
{
    fn new_root(
        &self, basic_node: BasicPathNode, mpt_is_empty: bool,
    ) -> SliceVerifyReadWritePathNode {
        let mut root_node = <Self as CursorToRootNode<
            Mpt,
            ReadWritePathNode,
        >>::new_root(self, basic_node, mpt_is_empty);
        root_node.disable_path_compression();
        SliceVerifyReadWritePathNode(Some(root_node))
    }
}

use crate::{
    impls::{
        errors::*,
        merkle_patricia_trie::{
            mpt_cursor::{
                BasicPathNode, CursorLoadNodeWrapper, CursorSetIoError,
                CursorToRootNode, GetReadMpt, GetRwMpt, LoadNodeWrapper,
                PathNodeTrait, ReadWritePathNode, RwPathNodeTrait,
            },
            CompressedPathRaw,
        },
    },
    storage_db::SnapshotMptNode,
};
use primitives::MerkleHash;
