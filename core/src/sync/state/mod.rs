// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod snapshot_chunk_request;
mod snapshot_chunk_response;
mod snapshot_chunk_sync;
mod snapshot_manifest_request;
mod snapshot_manifest_response;

pub use self::{
    snapshot_chunk_request::SnapshotChunkRequest,
    snapshot_chunk_response::SnapshotChunkResponse,
    snapshot_chunk_sync::{SnapshotChunkSync, Status},
    snapshot_manifest_request::SnapshotManifestRequest,
    snapshot_manifest_response::SnapshotManifestResponse,
};

use super::error::*;
use cfx_types::H256;
use primitives::{MerkleHash, StateRoot};
use rlp::*;
use rlp_derive::*;

#[derive(Clone, Debug, Eq, PartialEq, Hash, RlpEncodable)]
pub struct ChunkKey {}

// rlp_derive::RlpDecodable is broken here so we manually implement Decodable.
impl Decodable for ChunkKey {
    fn decode(_rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        unimplemented!()
    }
}

#[derive(Default, RlpEncodable)]
pub struct Chunk {}

impl Decodable for Chunk {
    fn decode(_rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        unimplemented!()
    }
}

impl Chunk {
    /// Validate the chunk with specified key and snapshot merkle root.
    pub fn validate(
        &self, _key: &ChunkKey, _snapshot_root: &MerkleHash,
    ) -> Result<()> {
        unimplemented!()
    }

    pub fn load(_chunk_key: &ChunkKey) -> Result<Option<Chunk>> {
        unimplemented!()
    }
}

#[derive(Default, RlpEncodable)]
pub struct RangedManifest {}

impl Decodable for RangedManifest {
    fn decode(_rlp: &Rlp) -> std::result::Result<Self, DecoderError> {
        unimplemented!()
    }
}

impl RangedManifest {
    /// Validate the manifest with specified snapshot merkle root and the
    /// requested start chunk key. Basically, the retrieved chunks should
    /// not be empty, and the proofs of all chunk keys are valid.
    pub fn validate(
        &self, _snapshot_root: &MerkleHash, _start_chunk: &Option<ChunkKey>,
    ) -> Result<()> {
        unimplemented!()
    }

    pub fn next_chunk(&self) -> Option<ChunkKey> { unimplemented!() }

    pub fn chunks(&self) -> Vec<ChunkKey> { unimplemented!() }

    // todo validate the integrity of all manifest, e.g. no chunk missed

    pub fn load(
        _checkpoint: &H256, _start_chunk: &Option<ChunkKey>,
    ) -> Result<Option<RangedManifest>> {
        unimplemented!()
    }
}

#[derive(Default)]
pub struct Restorer {}

#[allow(unused)]
impl Restorer {
    /// Append a chunk for restoration.
    pub fn append(&self, _chunk_key: &ChunkKey, _chunk: Chunk) {
        unimplemented!()
    }

    /// Start to restore chunks asynchronously.
    pub fn start_to_restore(&self) { unimplemented!() }

    /// Check if the restored snapshot match with the specified snapshot root.
    pub fn is_valid(&self, _snapshot_root: &MerkleHash) -> bool {
        unimplemented!()
    }

    pub fn progress(&self) -> RestoreProgress { unimplemented!() }

    pub fn restored_state_root(&self) -> StateRoot { unimplemented!() }
}

#[derive(Default, Debug)]
pub struct RestoreProgress {}

impl RestoreProgress {
    pub fn is_completed(&self) -> bool { unimplemented!() }
}
