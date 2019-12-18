// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

// The MptSliceVerifier can be used in restoration of Snapshot MPT and
// Delta MPT. For OneStepSync of Snapshot MPT, the verified slice can be applied
// to MptMerger to create the updated snapshot MPT.
pub struct MptSliceVerifier {
    key_value_inserter: MptCursorRw<
        SliceMptRebuilder,
        SliceVerifyReadWritePathNode<SliceMptRebuilder>,
    >,
}

pub struct SliceMptRebuilder {
    merkle_root: MerkleHash,
    // FIXME: add boundary node values,
    // FIXME: add left and right bounds to filter which boundary node values to
    // FIXME: include in chunks and to verify.
    pub boundary_nodes: HashMap<CompressedPathRaw, VanillaTrieNode<MerkleHash>>,
    pub inner_nodes_to_write: Vec<(CompressedPathRaw, SnapshotMptNode)>,
    pub boundary_subtree_total_size: HashMap<BoundarySubtreeIndex, u64>,

    pub is_valid: bool,
}

#[derive(PartialEq, Eq, Hash)]
pub struct BoundarySubtreeIndex {
    pub parent_node: MerkleHash,
    pub child_index: u8,
}

impl MptSliceVerifier {
    /// Validity of the inputs should be already checked.
    pub fn new(
        maybe_left_proof: Option<&TrieProof>,
        maybe_right_proof: Option<&TrieProof>, merkle_root: MerkleHash,
    ) -> Self
    {
        let mut boundary_nodes = HashMap::default();

        match maybe_left_proof {
            None => {}
            Some(left_proof) => {
                let left_node_snapshot_mpt_key =
                    left_proof.compute_snapshot_mpt_key_for_all_nodes();
                for (snapshot_mpt_key, trie_proof_node) in
                    left_node_snapshot_mpt_key
                        .into_iter()
                        .zip(left_proof.get_proof_nodes().iter())
                {
                    boundary_nodes
                        .insert(snapshot_mpt_key, (&**trie_proof_node).clone());
                }
            }
        }
        match maybe_right_proof {
            None => {}
            Some(right_proof) => {
                let right_node_snapshot_mpt_key =
                    right_proof.compute_snapshot_mpt_key_for_all_nodes();
                for (snapshot_mpt_key, trie_proof_node) in
                    right_node_snapshot_mpt_key
                        .into_iter()
                        .zip(right_proof.get_proof_nodes().iter())
                {
                    boundary_nodes
                        .insert(snapshot_mpt_key, (&**trie_proof_node).clone());
                }
            }
        }
        Self {
            key_value_inserter: MptCursorRw::new(SliceMptRebuilder {
                merkle_root,
                boundary_nodes,
                inner_nodes_to_write: Default::default(),
                boundary_subtree_total_size: Default::default(),
                is_valid: true,
            }),
        }
    }

    pub fn restore<Key: Borrow<[u8]>>(
        mut self, keys: &Vec<Key>, values: &Vec<Box<[u8]>>,
    ) -> Result<SliceMptRebuilder> {
        self.key_value_inserter.load_root()?;
        for (key, value) in keys.iter().zip(values.into_iter()) {
            self.key_value_inserter
                .insert(key.borrow(), value.clone())?;
        }
        self.key_value_inserter.finish()?;

        Ok(self.key_value_inserter.take_mpt().unwrap())
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
        // It's impossible to delete a node for FullSync.
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
                                    parent_node: boundary_node
                                        .get_merkle()
                                        .clone(),
                                    child_index,
                                },
                                *subtree_size,
                            );
                        }
                    }
                }
            }
        } else {
            self.inner_nodes_to_write.push((
                CompressedPathRaw::from(path.as_ref()),
                trie_node.clone(),
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
use crate::storage::impls::merkle_patricia_trie::{
    mpt_cursor::slice_restore_read_write_path_node::SliceVerifyReadWritePathNode,
    walk::GetChildTrait,
};
use cfx_types::H256;
use primitives::MerkleHash;
use std::{borrow::Borrow, collections::HashMap, hint::unreachable_unchecked};
