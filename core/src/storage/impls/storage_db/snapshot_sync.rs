// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::storage::impls::errors::*;
use primitives::MerkleHash;
use std::sync::mpsc::Sender;

pub struct ChunkKey {}

pub struct RangedManifest {}

impl RangedManifest {
    /// Validate the manifest with specified snapshot merkle root and the
    /// requested start chunk key. Basically, the retrieved chunks should
    /// not be empty, and the proofs of all chunk keys are valid.
    pub fn validate(
        &self, _snapshot_root: &MerkleHash, _start_chunk: &ChunkKey,
    ) -> Result<()> {
        unimplemented!()
    }

    pub fn next_chunk(&self) -> Option<ChunkKey> { unimplemented!() }

    pub fn chunks(&self) -> Vec<ChunkKey> { unimplemented!() }

    // todo validate the integrity of all manifest, e.g. no chunk missed
}

pub struct Chunk {}

impl Chunk {
    /// Validate the chunk with specified key and snapshot merkle root.
    pub fn validate(
        &self, _key: &ChunkKey, _snapshot_root: &MerkleHash,
    ) -> Result<()> {
        unimplemented!()
    }
}

pub struct Restorer {}

impl Restorer {
    /// Append a chunk for restoration.
    pub fn append(&self, _chunk_key: &ChunkKey, _chunk: Chunk) {
        unimplemented!()
    }

    /// Start to restore chunks asynchronously and notify the restoration
    /// progress with specified sender.
    /// The progress is (num_pending_chunks, num_restored_chunks),
    /// and snapshot restoration completed when num_pending_chunks is 0.
    pub fn start_to_restore(&self, _progress_sender: Sender<(usize, usize)>) {
        unimplemented!()
    }

    /// Check if the restored snapshot match with the specified snapshot root.
    pub fn is_valid(&self, _snapshot_root: &MerkleHash) -> bool {
        unimplemented!()
    }
}
