// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// The MptSliceVerifier can be used in restoration of Snapshot MPT and
// Delta MPT. For OneStepSync of Snapshot MPT, the verified slice can be applied
// to MptMerger to create the updated snapshot MPT.
#[allow(unused)]
pub struct MptSliceVerifier {
    key_value_inserter:
        MptCursorRw<SliceMptRebuilder, ReadWritePathNode<SliceMptRebuilder>>,
    key_range_left: Vec<u8>,
    key_range_right_excl: Vec<u8>,
}

struct SliceMptRebuilder {
    merkle_root: MerkleHash,
    boundary_nodes: HashMap<CompressedPathRaw, VanillaTrieNode<MerkleHash>>,
    new_nodes: Vec<(CompressedPathRaw, SnapshotMptDbValue)>,
    boundary_subtree_total_size: HashMap<BoundarySubtreeIndex, u64>,

    is_valid: bool,
}

#[derive(PartialEq, Eq, Hash)]
struct BoundarySubtreeIndex {
    node: MerkleHash,
    child_index: u8,
}

impl MptSliceVerifier {
    #[allow(dead_code)]
    /// Validity of the inputs should be already checked.
    pub fn new(
        key_range_left: Vec<u8>, key_range_right_excl: Vec<u8>,
        left_proof: TrieProof, right_proof: TrieProof, merkle_root: MerkleHash,
    ) -> Self
    {
        let mut boundary_nodes = HashMap::default();

        let left_node_paths = left_proof.compute_paths_for_all_nodes();
        for (path, trie_proof_node) in left_node_paths
            .into_iter()
            .zip(left_proof.nodes.into_iter())
        {
            boundary_nodes.insert(path, trie_proof_node.into());
        }
        let right_node_paths = right_proof.compute_paths_for_all_nodes();
        for (path, trie_proof_node) in right_node_paths
            .into_iter()
            .zip(right_proof.nodes.into_iter())
        {
            boundary_nodes.insert(path, trie_proof_node.into());
        }
        Self {
            key_range_left,
            key_range_right_excl,
            key_value_inserter: MptCursorRw::new(SliceMptRebuilder {
                merkle_root,
                boundary_nodes,
                new_nodes: Default::default(),
                boundary_subtree_total_size: Default::default(),
                is_valid: true,
            }),
        }
    }
}

impl SnapshotMptTraitReadOnly for SliceMptRebuilder {
    fn get_merkle_root(&self) -> &H256 { &self.merkle_root }

    fn load_node(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Option<SnapshotMptNode>> {
        Ok(self.boundary_nodes.get(path).map(|node| {
            let mut children_table = VanillaChildrenTable::default();
            for (child_index, merkle) in node.get_children_table_ref().iter() {
                unsafe {
                    *children_table.get_child_mut_unchecked(child_index) =
                        SubtreeMerkleWithSize {
                            merkle: *merkle,
                            subtree_size: 0,
                            delta_subtree_size: 0,
                        };
                    *children_table.get_children_count_mut() += 1;
                }
            }
            SnapshotMptNode(VanillaTrieNode::new(
                node.get_merkle().clone(),
                children_table,
                node.value_as_slice()
                    .into_option()
                    .map(|value| value.into()),
                node.compressed_path_ref().into(),
            ))
        }))
    }

    fn iterate_subtree_trie_nodes_without_root(
        &mut self, _path: &dyn CompressedPathTrait,
    ) -> Result<Box<dyn SnapshotMptIteraterTrait>> {
        // The validator runs the MptCursorRW in in-place mode, where subtree
        // iteration is unnecessary.
        unsafe { unreachable_unchecked() }
    }
}

impl SnapshotMptTraitSingleWriter for SliceMptRebuilder {
    fn as_readonly(&mut self) -> &mut dyn SnapshotMptTraitReadOnly { self }

    fn delete_node(&mut self, _path: &dyn CompressedPathTrait) -> Result<()> {
        // It's impossible to delete a node for FullSync / OneStepSync.
        unsafe { unreachable_unchecked() }
    }

    fn write_node(
        &mut self, path: &dyn CompressedPathTrait, trie_node: &SnapshotMptNode,
    ) -> Result<()> {
        if self.boundary_nodes.get(path).is_some() {
            let boundary_node = self.boundary_nodes.get(path).unwrap();
            for (
                child_index,
                &SubtreeMerkleWithSize {
                    ref merkle,
                    ref subtree_size,
                    ..
                },
            ) in trie_node.get_children_table_ref().iter()
            {
                match boundary_node.get_child(child_index) {
                    None => self.is_valid = false,
                    Some(expected_merkle) => {
                        if merkle != expected_merkle {
                            self.is_valid = false;
                        } else {
                            self.boundary_subtree_total_size.insert(
                                BoundarySubtreeIndex {
                                    node: merkle.clone(),
                                    child_index,
                                },
                                *subtree_size,
                            );
                        }
                    }
                }
            }
        } else {
            self.new_nodes.push((
                CompressedPathRaw::from(path.as_ref()),
                trie_node.rlp_bytes().into_boxed_slice(),
            ));
        }

        Ok(())
    }
}

impl GetReadMpt for SliceMptRebuilder {
    fn get_merkle_root(&self) -> &MerkleHash { &self.merkle_root }

    fn get_read_mpt(&mut self) -> &mut dyn SnapshotMptTraitReadOnly { self }
}

impl GetRwMpt for SliceMptRebuilder {
    fn get_write_mpt(&mut self) -> &mut dyn SnapshotMptTraitSingleWriter {
        self
    }

    fn get_write_and_read_mpt(
        &mut self,
    ) -> (
        &mut dyn SnapshotMptTraitSingleWriter,
        Option<&mut dyn SnapshotMptTraitReadOnly>,
    ) {
        (self, None)
    }

    fn is_save_as_write(&self) -> bool { false }

    fn is_in_place_update(&self) -> bool { true }
}

use super::super::super::{
    super::storage_db::snapshot_mpt::*,
    errors::*,
    merkle_patricia_trie::{mpt_cursor::*, *},
};
use crate::storage::impls::merkle_patricia_trie::walk::GetChildTrait;
use cfx_types::H256;
use primitives::MerkleHash;
use rlp::*;
use std::{collections::HashMap, hint::unreachable_unchecked};
