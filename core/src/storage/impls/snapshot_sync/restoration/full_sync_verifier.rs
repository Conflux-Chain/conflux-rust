// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::storage::impls::merkle_patricia_trie::VanillaChildrenTable;

pub struct FullSyncVerifier<SnapshotDbManager: SnapshotDbManagerTrait> {
    number_chunks: usize,
    merkle_root: MerkleHash,
    chunk_boundaries: Vec<Vec<u8>>,
    chunk_boundary_proofs: Vec<TrieProof>,
    chunk_verified: Vec<bool>,
    number_incomplete_chunk: usize,

    pending_boundary_nodes: HashMap<CompressedPathRaw, SnapshotMptNode>,
    boundary_subtree_total_size: HashMap<BoundarySubtreeIndex, u64>,
    chunk_index_by_upper_key: HashMap<Vec<u8>, usize>,

    temp_snapshot_db: SnapshotDbManager::SnapshotDb,
}

impl<SnapshotDbManager: SnapshotDbManagerTrait>
    FullSyncVerifier<SnapshotDbManager>
{
    pub fn new(
        number_chunks: usize, chunk_boundaries: Vec<Vec<u8>>,
        chunk_boundary_proofs: Vec<TrieProof>, merkle_root: MerkleHash,
        snapshot_db_manager: &SnapshotDbManager, epoch_id: &EpochId,
    ) -> Result<Self>
    {
        if number_chunks != chunk_boundaries.len() + 1 {
            bail!(ErrorKind::InvalidSnapshotSyncProof)
        }
        if number_chunks != chunk_boundary_proofs.len() + 1 {
            bail!(ErrorKind::InvalidSnapshotSyncProof)
        }
        let mut chunk_index_by_upper_key = HashMap::new();
        for (chunk_index, (chunk_boundary, proof)) in chunk_boundaries
            .iter()
            .zip(chunk_boundary_proofs.iter())
            .enumerate()
        {
            if merkle_root.ne(proof.get_merkle_root()) {
                bail!(ErrorKind::InvalidSnapshotSyncProof)
            }
            // We don't want the proof to carry extra nodes.
            if proof.number_leaf_nodes() != 1 {
                bail!(ErrorKind::InvalidSnapshotSyncProof)
            }
            if proof.if_proves_key(&*chunk_boundary)
                != (true, proof.get_proof_nodes().last())
            {
                bail!(ErrorKind::InvalidSnapshotSyncProof)
            }
            chunk_index_by_upper_key
                .insert(chunk_boundary.clone(), chunk_index);
        }

        Ok(Self {
            number_chunks,
            merkle_root,
            chunk_boundaries,
            chunk_boundary_proofs,
            chunk_verified: vec![false; number_chunks],
            number_incomplete_chunk: number_chunks,
            pending_boundary_nodes: Default::default(),
            boundary_subtree_total_size: Default::default(),
            chunk_index_by_upper_key,
            temp_snapshot_db: snapshot_db_manager
                .new_temp_snapshot_for_full_sync(epoch_id, &merkle_root)?,
        })
    }

    pub fn is_completed(&self) -> bool { self.number_incomplete_chunk == 0 }

    // FIXME: multi-threading, where &mut can be dropped.
    pub fn restore_chunk<Key: Borrow<[u8]>>(
        &mut self, chunk_upper_key: &Option<Vec<u8>>, keys: &Vec<Key>,
        values: Vec<Vec<u8>>,
    ) -> Result<bool>
    {
        let chunk_index = match chunk_upper_key {
            None => self.number_chunks - 1,
            Some(upper_key) => {
                match self.chunk_index_by_upper_key.get(upper_key) {
                    Some(index) => *index,
                    // Chunk key does not match boundaries in manifest
                    None => return Ok(false),
                }
            }
        };
        // Check key monotone.
        if !keys.is_empty() {
            let mut previous = keys.first().unwrap();
            for key in &keys[1..] {
                if key.borrow().le(previous.borrow()) {
                    return Ok(false);
                }
                previous = key;
            }
        }

        let key_range_left;
        let maybe_key_range_right_excl;
        let maybe_left_proof;
        let maybe_right_proof;
        if chunk_index == 0 {
            key_range_left = vec![];
            maybe_left_proof = None;
        } else {
            key_range_left = self.chunk_boundaries[chunk_index - 1].clone();
            maybe_left_proof = self.chunk_boundary_proofs.get(chunk_index - 1);

            // Check key boundary.
            if let Some(first_key) = keys.first() {
                if first_key.borrow().lt(&*key_range_left) {
                    return Ok(false);
                }
            }
        };
        if chunk_index == self.number_chunks - 1 {
            maybe_key_range_right_excl = None;
            maybe_right_proof = None;
        } else {
            let key_range_right_excl =
                self.chunk_boundaries[chunk_index].clone();
            maybe_right_proof = self.chunk_boundary_proofs.get(chunk_index);

            // Check key boundary.
            if let Some(last_key) = keys.last() {
                if last_key.borrow().ge(&*key_range_right_excl) {
                    return Ok(false);
                }
            }

            maybe_key_range_right_excl = Some(key_range_right_excl);
        }

        // FIXME: multi-threading.
        // Restore.
        let chunk_verifier = MptSliceVerifier::new(
            maybe_left_proof,
            &*key_range_left,
            maybe_right_proof,
            maybe_key_range_right_excl.as_ref().map(|v| &**v),
            self.merkle_root.clone(),
        );

        let chunk_rebuilder = chunk_verifier.restore(keys, &values)?;
        if chunk_rebuilder.is_valid {
            self.chunk_verified[chunk_index] = true;
            self.number_incomplete_chunk -= 1;

            self.temp_snapshot_db.start_transaction()?;
            // Commit key-values.
            for (key, value) in keys.into_iter().zip(values.into_iter()) {
                self.temp_snapshot_db.put(key.borrow(), &*value)?;
            }

            // Commit inner nodes.
            let mut snapshot_mpt =
                self.temp_snapshot_db.open_snapshot_mpt_owned()?;
            for (path, node) in chunk_rebuilder.inner_nodes_to_write {
                snapshot_mpt.write_node(&path, &node)?;
            }
            drop(snapshot_mpt);
            self.temp_snapshot_db.commit_transaction()?;

            // Combine changes around boundary nodes.
            for (path, node) in chunk_rebuilder.boundary_nodes {
                let mut children_table = VanillaChildrenTable::default();
                unsafe {
                    for (child_index, merkle_ref) in
                        node.get_children_table_ref().iter()
                    {
                        *children_table.get_child_mut_unchecked(child_index) =
                            SubtreeMerkleWithSize {
                                merkle: *merkle_ref,
                                subtree_size: 0,
                                delta_subtree_size: 0,
                            }
                    }
                    *children_table.get_children_count_mut() =
                        node.get_children_count();
                }
                self.pending_boundary_nodes.insert(
                    path,
                    SnapshotMptNode(VanillaTrieNode::new(
                        node.get_merkle().clone(),
                        children_table,
                        node.value_as_slice()
                            .into_option()
                            .map(|ref_v| ref_v.into()),
                        node.compressed_path_ref().into(),
                    )),
                );
            }
            for (subtree_index, subtree_size) in
                chunk_rebuilder.boundary_subtree_total_size
            {
                *self
                    .boundary_subtree_total_size
                    .entry(subtree_index)
                    .or_default() += subtree_size;
            }
        }

        if self.is_completed() {
            self.finalize()?
        }

        Ok(chunk_rebuilder.is_valid)
    }

    // FIXME: multi-threading
    /// Combine and write boundary subtree nodes after all chunks have been
    /// completed.
    pub fn finalize(&mut self) -> Result<()> {
        self.temp_snapshot_db.start_transaction()?;
        let mut snapshot_mpt =
            self.temp_snapshot_db.open_snapshot_mpt_owned()?;

        for (path, mut node) in self.pending_boundary_nodes.drain() {
            let mut subtree_index = BoundarySubtreeIndex {
                parent_node: node.get_merkle().clone(),
                child_index: 0,
            };
            for child_index in 0..CHILDREN_COUNT as u8 {
                subtree_index.child_index = child_index;
                if let Some(subtree_size) =
                    self.boundary_subtree_total_size.get(&subtree_index)
                {
                    // Actually safe.
                    unsafe {
                        node.get_child_mut_unchecked(child_index)
                            .subtree_size = *subtree_size;
                    }
                }
            }

            snapshot_mpt.write_node(&path, &node)?;
        }

        drop(snapshot_mpt);
        self.temp_snapshot_db.commit_transaction()?;
        Ok(())
    }
}

use crate::storage::{
    impls::{
        errors::*,
        merkle_patricia_trie::{
            trie_node::TrieNodeTrait, CompressedPathRaw, VanillaTrieNode,
            CHILDREN_COUNT,
        },
        snapshot_sync::restoration::mpt_slice_verifier::{
            BoundarySubtreeIndex, MptSliceVerifier,
        },
    },
    storage_db::{
        key_value_db::KeyValueDbTraitSingleWriter, OpenSnapshotMptTrait,
        SnapshotDbManagerTrait, SnapshotDbTrait, SnapshotMptNode,
        SnapshotMptTraitRw, SubtreeMerkleWithSize,
    },
    TrieProof,
};
use primitives::{EpochId, MerkleHash};
use std::{borrow::Borrow, collections::HashMap};
