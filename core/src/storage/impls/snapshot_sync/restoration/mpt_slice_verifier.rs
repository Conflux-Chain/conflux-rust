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
    must_match_boundary_node_values: HashMap<Vec<u8>, Box<[u8]>>,
}

pub struct SliceMptRebuilder {
    merkle_root: MerkleHash,
    pub boundary_nodes: HashMap<CompressedPathRaw, VanillaTrieNode<MerkleHash>>,
    boundary_node_full_path: HashMap<CompressedPathRaw, CompressedPathRaw>,
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
        let mut must_match_boundary_node_values = HashMap::default();

        match maybe_left_proof {
            None => {}
            Some(left_proof) => {
                Self::add_boundary_nodes(
                    &mut boundary_nodes,
                    &mut must_match_boundary_node_values,
                    left_key_bound,
                    maybe_right_key_bound_excl,
                    left_proof,
                );
            }
        }
        match maybe_right_proof {
            None => {}
            Some(right_proof) => {
                Self::add_boundary_nodes(
                    &mut boundary_nodes,
                    &mut must_match_boundary_node_values,
                    left_key_bound,
                    maybe_right_key_bound_excl,
                    right_proof,
                );
            }
        }

        let mut boundary_node_full_path = Default::default();
        let boundary_nodes_to_load = Self::calculate_boundary_nodes_to_load(
            maybe_left_proof,
            maybe_right_proof,
            &boundary_nodes,
            &mut boundary_node_full_path,
        );

        println!(
            "left_key_bound {:?}, maybe_right_key_bound {:?}, \
             must_match_boundary_node_values: {:?}",
            left_key_bound,
            maybe_right_key_bound_excl,
            must_match_boundary_node_values
        );

        Self {
            key_value_inserter: MptCursorRw::new(SliceMptRebuilder {
                merkle_root,
                boundary_nodes,
                boundary_nodes_to_load,
                boundary_node_full_path,
                inner_nodes_to_write: Default::default(),
                boundary_subtree_total_size: Default::default(),
                is_valid: true,
            }),
            must_match_boundary_node_values,
        }
    }

    pub fn restore<Key: Borrow<[u8]>>(
        mut self, keys: &Vec<Key>, values: &Vec<Box<[u8]>>,
    ) -> Result<SliceMptRebuilder> {
        let mut must_match_mismatch = false;

        self.key_value_inserter.load_root()?;
        for (key, value) in keys.iter().zip(values.into_iter()) {
            self.key_value_inserter
                .insert(key.borrow(), value.clone())?;
            if let Some(expected_value) =
                self.must_match_boundary_node_values.remove(key.borrow())
            {
                if value.ne(&expected_value) {
                    must_match_mismatch = true;
                    break;
                }
            }
        }
        let got_merkle = self.key_value_inserter.finish()?;

        let mut builder = self.key_value_inserter.take_mpt().unwrap();
        if got_merkle != builder.merkle_root
            || must_match_mismatch
            || self.must_match_boundary_node_values.len() > 0
        {
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
        boundary_node_full_path: &mut HashMap<
            CompressedPathRaw,
            CompressedPathRaw,
        >,
    ) -> HashMap<CompressedPathRaw, SnapshotMptNode>
    {
        // FIXME: the calculation of which child to delete from boundary nods
        // FIXME: for OneStepSync shouldn't be based on bounds, but rather based
        // FIXME: on which subtrees with in the range we already have
        // FIXME: locally in the previous snapshot.
        let mut index_open_left_bounds =
            HashMap::<CompressedPathRaw, u8, RandomState>::default();
        let mut index_open_right_bounds_incl =
            HashMap::<CompressedPathRaw, u8, RandomState>::default();
        let mut right_bound_child_must_recover =
            HashMap::<CompressedPathRaw, bool, RandomState>::default();
        let mut remove_value =
            HashMap::<CompressedPathRaw, bool, RandomState>::default();

        if let Some(left_proof) = maybe_left_proof {
            let (snapshot_mpt_keys, full_paths) = left_proof
                .compute_snapshot_mpt_key_and_full_paths_for_all_nodes();

            for (key, full_path) in
                snapshot_mpt_keys.iter().zip(full_paths.iter())
            {
                boundary_node_full_path.insert(key.clone(), full_path.clone());
            }

            index_open_left_bounds
                .insert(snapshot_mpt_keys.last().unwrap().clone(), 0);
            index_open_right_bounds_incl.insert(
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
                index_open_right_bounds_incl
                    .insert(snapshot_mpt_keys[i].clone(), CHILDREN_COUNT as u8);
                remove_value.insert(snapshot_mpt_keys[i].clone(), false);
            }
        }

        if let Some(right_proof) = maybe_right_proof {
            let (snapshot_mpt_keys, full_paths) = right_proof
                .compute_snapshot_mpt_key_and_full_paths_for_all_nodes();

            for (key, full_path) in
                snapshot_mpt_keys.iter().zip(full_paths.iter())
            {
                boundary_node_full_path.insert(key.clone(), full_path.clone());
            }

            // See FIXME above. More than one right boundary nodes may be
            // useless.
            let mut right_unused_boundary_node_index =
                snapshot_mpt_keys.len() - 1;
            while right_unused_boundary_node_index >= 1 {
                let parent_node = boundary_nodes
                    .get(
                        &snapshot_mpt_keys
                            [right_unused_boundary_node_index - 1],
                    )
                    .unwrap();
                if parent_node.has_value() {
                    break;
                }
                let parent_first_child = parent_node
                    .get_children_table_ref()
                    .iter()
                    .next()
                    .unwrap()
                    .0;
                let self_child_index =
                    right_proof.child_index[right_unused_boundary_node_index];
                if self_child_index != parent_first_child {
                    break;
                }

                right_unused_boundary_node_index -= 1;
            }

            for i in 0..snapshot_mpt_keys.len() - 1 {
                remove_value
                    .entry(snapshot_mpt_keys[i].clone())
                    .or_insert(true);
            }
            remove_value
                .insert(snapshot_mpt_keys.last().unwrap().clone(), false);

            for i in 0..snapshot_mpt_keys.len() {
                index_open_left_bounds
                    .entry(snapshot_mpt_keys[i].clone())
                    .or_insert(0);
            }

            for i in 0..right_unused_boundary_node_index - 1 {
                right_bound_child_must_recover
                    .insert(snapshot_mpt_keys[i].clone(), true);
            }
            for i in 0..right_unused_boundary_node_index {
                index_open_right_bounds_incl.insert(
                    snapshot_mpt_keys[i].clone(),
                    right_proof.child_index[i + 1],
                );
            }
            for i in
                right_unused_boundary_node_index - 1..snapshot_mpt_keys.len()
            {
                right_bound_child_must_recover
                    .insert(snapshot_mpt_keys[i].clone(), false);
            }
            for i in right_unused_boundary_node_index..snapshot_mpt_keys.len() {
                index_open_right_bounds_incl
                    .insert(snapshot_mpt_keys[i].clone(), 0);
            }
        }

        let mut boundary_nodes_to_load = HashMap::default();
        for (snapshot_mpt_key, node) in boundary_nodes {
            let index_open_left_bound =
                *index_open_left_bounds.get(snapshot_mpt_key).unwrap();
            let index_open_right_bound_incl =
                *index_open_right_bounds_incl.get(snapshot_mpt_key).unwrap();

            let mut children_table = VanillaChildrenTable::default();
            for (child_index, merkle) in node.get_children_table_ref().iter() {
                if child_index < index_open_left_bound
                    || child_index >= index_open_right_bound_incl
                {
                    let merkle = if child_index == index_open_right_bound_incl
                        && *right_bound_child_must_recover
                            .get(snapshot_mpt_key)
                            .unwrap()
                    {
                        Default::default()
                    } else {
                        *merkle
                    };
                    unsafe {
                        *children_table.get_child_mut_unchecked(child_index) =
                            SubtreeMerkleWithSize {
                                merkle,
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

        println!(
            "index_open_left_bounds {:?},\n\
             index_open_right_bounds {:?},\n\
             remove_value {:?},\nboundary_nodes_to_load {:?}",
            index_open_left_bounds.iter(),
            index_open_right_bounds_incl.iter(),
            remove_value.iter(),
            boundary_nodes_to_load,
        );
        boundary_nodes_to_load
    }

    fn add_boundary_nodes(
        boundary_nodes: &mut HashMap<
            CompressedPathRaw,
            VanillaTrieNode<MerkleHash>,
        >,
        must_match_boundary_node_values: &mut HashMap<Vec<u8>, Box<[u8]>>,
        left_key_bound: &[u8], maybe_right_key_bound_excl: Option<&[u8]>,
        proof: &TrieProof,
    )
    {
        let (snapshot_mpt_keys, full_paths) =
            proof.compute_snapshot_mpt_key_and_full_paths_for_all_nodes();
        let trie_proof_nodes = proof.get_proof_nodes();
        for i in 0..snapshot_mpt_keys.len() {
            let trie_node = &*trie_proof_nodes[i];
            boundary_nodes
                .insert(snapshot_mpt_keys[i].clone(), trie_node.clone());
            println!(
                "full path: {:?}, trie_node maybe_value: {:?}",
                full_paths[i],
                trie_node.value_as_slice(),
            );
            if full_paths[i].end_mask() == 0 && trie_node.has_value() {
                let key = full_paths[i].path_slice();
                if key >= left_key_bound
                    && (maybe_right_key_bound_excl.is_none()
                        || maybe_right_key_bound_excl.unwrap() > key)
                {
                    must_match_boundary_node_values.insert(
                        key.into(),
                        trie_node.value_as_slice().unwrap().into(),
                    );
                }
            }
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
        if path.path_slice() == &*vec![50, 208] && path.end_mask() == 240 {
            println!(
                "load node {:?} {:?}",
                path.as_ref(),
                self.boundary_nodes_to_load.get(path).cloned()
            );
        }

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
        // It's impossible to delete a node for FullSync.
        unsafe { unreachable_unchecked() }
    }

    fn write_node(
        &mut self, path: &dyn CompressedPathTrait, trie_node: &SnapshotMptNode,
    ) -> Result<()> {
        if self.boundary_nodes.get(path).is_some() {
            let boundary_node = self.boundary_nodes.get(path).unwrap();
            // This check isn't necessary because we match merkle root.
            // FIXME: remove debug only code.
            if boundary_node.get_merkle() != trie_node.get_merkle() {
                println!(
                    "node merkle doesn't match. path {:?} Expected {:?}, Got {:?}",
                    path.as_ref(), boundary_node, trie_node
                );
                self.is_valid = false;
            } else if boundary_node.get_children_count()
                != trie_node.get_children_count()
            {
                println!(
                    "children_count doesn't match. path {:?} Expected {:?}, Got {:?}",
                    path.as_ref(), boundary_node, trie_node
                );
                self.is_valid = false;
                println!();
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
                    None => {
                        println!(
                            "node at path {:?} doesn't contain child_index {}, {:?}",
                            path.as_ref(), child_index, boundary_node,
                        );
                        self.is_valid = false
                    }
                    Some(expected_merkle) => {
                        if merkle != expected_merkle {
                            println!(
                                "node at path {:?} child {} merkle root doesn't match. Expected {:?}, got {:?}",
                                path.as_ref(), child_index, expected_merkle, merkle,
                            );
                            let child_mpt_key = CompressedPathRaw::extend_path(
                                self.boundary_node_full_path.get(path).unwrap(),
                                child_index,
                            );
                            match self.boundary_nodes.get(&child_mpt_key) {
                                None => {
                                    println!(
                                        "unmatched child {:?} isn't a boundary node",
                                        child_mpt_key
                                    );
                                }
                                Some(_expected_node) => {
                                    println!(
                                        "unmatched child {:?} is a boundary node",
                                        child_mpt_key
                                    );
                                }
                            }
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
use std::{
    borrow::Borrow,
    collections::{hash_map::RandomState, HashMap},
    hint::unreachable_unchecked,
};
