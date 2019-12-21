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
    left_key_bound: Vec<u8>,
    maybe_right_key_bound_excl: Option<Vec<u8>>,
}

pub struct SliceMptRebuilder {
    merkle_root: MerkleHash,
    pub boundary_nodes: HashMap<CompressedPathRaw, VanillaTrieNode<MerkleHash>>,
    pub boundary_nodes_to_load: HashMap<CompressedPathRaw, SnapshotMptNode>,
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
        maybe_left_proof: Option<&TrieProof>, left_key_bound: &[u8],
        maybe_right_proof: Option<&TrieProof>,
        maybe_right_key_bound_excl: Option<&[u8]>, merkle_root: MerkleHash,
    ) -> Self
    {
        let mut boundary_nodes = HashMap::default();

        if let Some(left_proof) = maybe_left_proof {
            Self::add_boundary_nodes(&mut boundary_nodes, left_proof);
        }
        if let Some(right_proof) = maybe_right_proof {
            Self::add_boundary_nodes(&mut boundary_nodes, right_proof);
        }

        let boundary_nodes_to_load = Self::calculate_boundary_nodes_to_load(
            maybe_left_proof,
            maybe_right_proof,
            &boundary_nodes,
        );

        Self {
            key_value_inserter: MptCursorRw::new(SliceMptRebuilder {
                merkle_root,
                boundary_nodes,
                boundary_nodes_to_load,
                inner_nodes_to_write: Default::default(),
                boundary_subtree_total_size: Default::default(),
                is_valid: true,
            }),
            left_key_bound: left_key_bound.into(),
            maybe_right_key_bound_excl: maybe_right_key_bound_excl
                .map(|r| r.into()),
        }
    }

    pub fn restore<Key: Borrow<[u8]>>(
        mut self, keys: &Vec<Key>, values: &Vec<Box<[u8]>>,
    ) -> Result<SliceMptRebuilder> {
        self.key_value_inserter.load_root()?;
        // We must open the path of the left bound, in order to check the merkle
        // root, when the left bound key is missing from the chunk to
        // restore.
        self.key_value_inserter
            .open_path_for_key::<access_mode::Read>(&*self.left_key_bound)?;
        for (key, value) in keys.iter().zip(values.into_iter()) {
            self.key_value_inserter
                .insert(key.borrow(), value.clone())?;
            if !self
                .key_value_inserter
                .current_node_mut()
                .as_ref()
                .mpt
                .as_ref_assumed_owner()
                .is_valid
            {
                break;
            }
        }
        // We must open the path of the right bound, in order to re-calculate
        // merkle root, since some subtree may have been omitted thus
        // the merkle root doesn't match anymore.
        match &self.maybe_right_key_bound_excl {
            None => {}
            Some(right_key_bound_excl) => {
                self.key_value_inserter
                    .open_path_for_key::<access_mode::Read>(
                        &*right_key_bound_excl,
                    )?;
            }
        }
        let got_merkle = self.key_value_inserter.finish()?;

        let mut builder = self.key_value_inserter.take_mpt().unwrap();
        if got_merkle != builder.merkle_root {
            builder.is_valid = false;
        }
        Ok(builder)
    }

    fn calculate_boundary_nodes_to_load(
        maybe_left_proof: Option<&TrieProof>,
        maybe_right_proof: Option<&TrieProof>,
        boundary_nodes: &HashMap<
            CompressedPathRaw,
            VanillaTrieNode<MerkleHash>,
        >,
    ) -> HashMap<CompressedPathRaw, SnapshotMptNode>
    {
        let mut index_open_left_bounds =
            HashMap::<CompressedPathRaw, u8, RandomState>::default();
        let mut index_open_right_bounds_excl =
            HashMap::<CompressedPathRaw, u8, RandomState>::default();
        let mut remove_value =
            HashMap::<CompressedPathRaw, bool, RandomState>::default();

        if let Some(left_proof) = maybe_left_proof {
            let snapshot_mpt_keys =
                left_proof.compute_snapshot_mpt_key_for_all_nodes();

            index_open_left_bounds
                .insert(snapshot_mpt_keys.last().unwrap().clone(), 0);
            index_open_right_bounds_excl.insert(
                snapshot_mpt_keys.last().unwrap().clone(),
                CHILDREN_COUNT as u8,
            );
            remove_value
                .insert(snapshot_mpt_keys.last().unwrap().clone(), true);

            for i in 0..snapshot_mpt_keys.len() - 1 {
                index_open_left_bounds.insert(
                    snapshot_mpt_keys[i].clone(),
                    left_proof.child_index[i + 1] + 1,
                );
                index_open_right_bounds_excl
                    .insert(snapshot_mpt_keys[i].clone(), CHILDREN_COUNT as u8);
                remove_value.insert(snapshot_mpt_keys[i].clone(), false);
            }
        }

        if let Some(right_proof) = maybe_right_proof {
            let snapshot_mpt_keys =
                right_proof.compute_snapshot_mpt_key_for_all_nodes();

            for i in 0..snapshot_mpt_keys.len() - 1 {
                index_open_left_bounds
                    .entry(snapshot_mpt_keys[i].clone())
                    .or_insert(0);
                index_open_right_bounds_excl.insert(
                    snapshot_mpt_keys[i].clone(),
                    right_proof.child_index[i + 1],
                );
                remove_value
                    .entry(snapshot_mpt_keys[i].clone())
                    .or_insert(true);
            }
            index_open_right_bounds_excl
                .insert(snapshot_mpt_keys.last().unwrap().clone(), 0);
            index_open_left_bounds
                .insert(snapshot_mpt_keys.last().unwrap().clone(), 0);
            remove_value
                .insert(snapshot_mpt_keys.last().unwrap().clone(), false);
        }

        let mut boundary_nodes_to_load = HashMap::default();
        for (snapshot_mpt_key, node) in boundary_nodes {
            let index_open_left_bound =
                *index_open_left_bounds.get(snapshot_mpt_key).unwrap();
            let index_open_right_bound_excl =
                *index_open_right_bounds_excl.get(snapshot_mpt_key).unwrap();

            let mut children_table = VanillaChildrenTable::default();
            for (child_index, merkle) in node.get_children_table_ref().iter() {
                if child_index < index_open_left_bound
                    || child_index >= index_open_right_bound_excl
                {
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
            }
            boundary_nodes_to_load.insert(
                snapshot_mpt_key.clone(),
                SnapshotMptNode(VanillaTrieNode::new(
                    node.get_merkle().clone(),
                    children_table,
                    if *remove_value.get(snapshot_mpt_key).unwrap() {
                        None
                    } else {
                        node.value_as_slice()
                            .into_option()
                            .map(|value| value.into())
                    },
                    node.compressed_path_ref().into(),
                )),
            );
        }

        boundary_nodes_to_load
    }

    fn add_boundary_nodes(
        boundary_nodes: &mut HashMap<
            CompressedPathRaw,
            VanillaTrieNode<MerkleHash>,
        >,
        proof: &TrieProof,
    )
    {
        let snapshot_mpt_keys = proof.compute_snapshot_mpt_key_for_all_nodes();
        let trie_proof_nodes = proof.get_proof_nodes();
        for i in 0..snapshot_mpt_keys.len() {
            let trie_node = &*trie_proof_nodes[i];
            boundary_nodes
                .insert(snapshot_mpt_keys[i].clone(), trie_node.clone());
        }
        for (snapshot_mpt_key, trie_proof_node) in snapshot_mpt_keys
            .into_iter()
            .zip(proof.get_proof_nodes().iter())
        {
            boundary_nodes
                .insert(snapshot_mpt_key, (&**trie_proof_node).clone());
        }
    }
}

impl SnapshotMptTraitReadOnly for SliceMptRebuilder {
    fn get_merkle_root(&self) -> &H256 { &self.merkle_root }

    fn load_node(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Option<SnapshotMptNode>> {
        Ok(self.boundary_nodes_to_load.get(path).cloned())
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
        // It may only happen for the terminal boundary node, when the key-value
        // is missing in the chunk to recover,.
        self.is_valid = false;
        Ok(())
    }

    fn write_node(
        &mut self, path: &dyn CompressedPathTrait, trie_node: &SnapshotMptNode,
    ) -> Result<()> {
        if self.boundary_nodes.get(path).is_some() {
            let boundary_node = self.boundary_nodes.get(path).unwrap();
            if boundary_node.get_children_count()
                != trie_node.get_children_count()
            {
                self.is_valid = false;
            }
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

use super::{
    super::super::{
        super::storage_db::snapshot_mpt::*,
        errors::*,
        merkle_patricia_trie::{mpt_cursor::*, *},
    },
    slice_restore_read_write_path_node::SliceVerifyReadWritePathNode,
};
use crate::storage::impls::merkle_patricia_trie::walk::GetChildTrait;
use cfx_types::H256;
use primitives::MerkleHash;
use std::{
    borrow::Borrow,
    collections::{hash_map::RandomState, HashMap},
    hint::unreachable_unchecked,
};
