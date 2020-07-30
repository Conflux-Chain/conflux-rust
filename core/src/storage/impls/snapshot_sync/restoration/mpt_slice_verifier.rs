// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// The MptSliceVerifier can be used in restoration of Snapshot MPT and
/// Delta MPT. For OneStepSync of Snapshot MPT, the verified slice can be
/// applied to MptMerger to create the updated snapshot MPT.
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
            Self::add_boundary_nodes(
                &mut boundary_nodes,
                left_proof,
                left_key_bound,
            );
        }
        if let Some(right_proof) = maybe_right_proof {
            Self::add_boundary_nodes(
                &mut boundary_nodes,
                right_proof,
                // The right key bound must exists when the proof exists.
                maybe_right_key_bound_excl.unwrap(),
            );
        }

        let boundary_nodes_to_load = Self::calculate_boundary_nodes_to_load(
            maybe_left_proof,
            left_key_bound,
            maybe_right_proof,
            maybe_right_key_bound_excl,
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
        mut self, keys: &Vec<Key>, values: &Vec<Vec<u8>>,
    ) -> Result<SliceMptRebuilder> {
        self.key_value_inserter.load_root()?;
        // We must open the path of the left bound, in order to check the merkle
        // root, when the left bound key is missing from the chunk to
        // restore.
        self.key_value_inserter
            .open_path_for_key::<access_mode::Read>(&*self.left_key_bound)?;
        for (key, value) in keys.iter().zip(values.into_iter()) {
            self.key_value_inserter
                .insert(key.borrow(), value.clone().into_boxed_slice())?;
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
        maybe_left_proof: Option<&TrieProof>, left_key_bound: &[u8],
        maybe_right_proof: Option<&TrieProof>,
        maybe_right_key_bound_excl: Option<&[u8]>,
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
            let snapshot_mpt_path =
                left_proof.compute_snapshot_mpt_path_for_proof(left_key_bound);

            let left_bound_snapshot_mpt_key =
                snapshot_mpt_path.last().unwrap().0.clone();
            index_open_left_bounds
                .insert(left_bound_snapshot_mpt_key.clone(), 0);
            index_open_right_bounds_excl.insert(
                left_bound_snapshot_mpt_key.clone(),
                CHILDREN_COUNT as u8,
            );
            remove_value.insert(left_bound_snapshot_mpt_key, true);

            for i in 0..snapshot_mpt_path.len() - 1 {
                let mpt_key = snapshot_mpt_path[i].0.clone();
                let child_index = snapshot_mpt_path[i + 1].1;
                index_open_left_bounds.insert(mpt_key.clone(), child_index + 1);
                index_open_right_bounds_excl
                    .insert(mpt_key.clone(), CHILDREN_COUNT as u8);
                remove_value.insert(mpt_key, false);
            }
        }

        if let Some(right_proof) = maybe_right_proof {
            let snapshot_mpt_path = right_proof
                .compute_snapshot_mpt_path_for_proof(
                    // The key_bound must exists when proof exists.
                    maybe_right_key_bound_excl.unwrap(),
                );

            for i in 0..snapshot_mpt_path.len() - 1 {
                let mpt_key = snapshot_mpt_path[i].0.clone();
                let child_index = snapshot_mpt_path[i + 1].1;
                index_open_left_bounds.entry(mpt_key.clone()).or_insert(0);
                index_open_right_bounds_excl
                    .insert(mpt_key.clone(), child_index);
                remove_value.entry(mpt_key).or_insert(true);
            }

            let last_mpt_key = snapshot_mpt_path.last().unwrap().0.clone();
            index_open_right_bounds_excl.insert(last_mpt_key.clone(), 0);
            index_open_left_bounds.insert(last_mpt_key.clone(), 0);
            remove_value.insert(last_mpt_key, false);
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
        proof: &TrieProof, key: &[u8],
    )
    {
        let keys_and_nodes = proof.compute_snapshot_mpt_path_for_proof(key);
        for (snapshot_mpt_key, _child_index, trie_node) in keys_and_nodes {
            boundary_nodes.insert(snapshot_mpt_key, trie_node.clone());
        }
    }
}

impl SnapshotMptTraitRead for SliceMptRebuilder {
    fn get_merkle_root(&self) -> MerkleHash { self.merkle_root.clone() }

    fn load_node(
        &mut self, path: &dyn CompressedPathTrait,
    ) -> Result<Option<SnapshotMptNode>> {
        Ok(self.boundary_nodes_to_load.get(path).cloned())
    }
}

impl SnapshotMptTraitReadAndIterate for SliceMptRebuilder {
    fn iterate_subtree_trie_nodes_without_root(
        &mut self, _path: &dyn CompressedPathTrait,
    ) -> Result<Box<dyn SnapshotMptIteraterTrait>> {
        // The validator runs the MptCursorRW in in-place mode, where subtree
        // iteration is unnecessary.
        unsafe { unreachable_unchecked() }
    }
}

impl SnapshotMptTraitRw for SliceMptRebuilder {
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
    fn get_merkle_root(&self) -> MerkleHash { self.merkle_root.clone() }

    fn get_read_mpt(&mut self) -> &mut dyn SnapshotMptTraitRead { self }
}

impl GetRwMpt for SliceMptRebuilder {
    fn get_write_mpt(&mut self) -> &mut dyn SnapshotMptTraitRw { self }

    fn get_write_and_read_mpt(
        &mut self,
    ) -> (
        &mut dyn SnapshotMptTraitRw,
        Option<&mut dyn SnapshotMptTraitReadAndIterate>,
    ) {
        (self, None)
    }

    fn is_save_as_write(&self) -> bool { false }

    fn is_in_place_update(&self) -> bool { true }
}

use super::slice_restore_read_write_path_node::SliceVerifyReadWritePathNode;
use crate::storage::{
    impls::{
        errors::*,
        merkle_patricia_trie::{mpt_cursor::*, walk::GetChildTrait, *},
    },
    storage_db::snapshot_mpt::*,
    utils::access_mode,
};
use primitives::MerkleHash;
use std::{
    borrow::Borrow,
    collections::{hash_map::RandomState, HashMap},
    hint::unreachable_unchecked,
};
