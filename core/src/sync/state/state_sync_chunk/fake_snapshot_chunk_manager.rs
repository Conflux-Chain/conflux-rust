#![allow(dead_code)]

use crate::sync::{
    message::Context,
    state::storage::{Chunk, ChunkKey, SnapshotSyncCandidate},
};
use cfx_storage::{
    Error as StorageError, ErrorKind as StorageErrorKind,
    Result as StorageResult, SnapshotInfo, TrieProof,
};
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use network::node_table::NodeId;
use std::{
    collections::HashSet,
    fmt::{Debug, Formatter},
    time::{Duration, Instant},
};

pub struct SnapshotChunkManager {
    pub snapshot_candidate: SnapshotSyncCandidate,
}

impl SnapshotChunkManager {
    pub fn new_and_start(
        _: &Context, _: SnapshotSyncCandidate, _: SnapshotInfo,
        _: Vec<Vec<u8>>, _: Vec<TrieProof>, _: HashSet<NodeId>,
        _: SnapshotChunkConfig,
    ) -> StorageResult<Self>
    {
        Err(StorageError::from_kind(StorageErrorKind::NotDeltaMpt))
    }

    /// Add a received chunk, and request new ones if needed.
    /// Return `Ok(true)` if all chunks have been received and the snapshot is
    /// reconstructed. Return `Ok(false)` if there are chunks missing.
    pub fn add_chunk(
        &mut self, _: &Context, _: ChunkKey, _: Chunk,
    ) -> StorageResult<bool> {
        unreachable!()
    }

    fn request_chunk_from_peer(
        &mut self, _: &Context, _: &NodeId,
    ) -> Option<ChunkKey> {
        unreachable!()
    }

    /// Request multiple chunks from random peers.
    fn request_chunks(&mut self, _: &Context) { unreachable!() }

    /// Remove timeout chunks and request new chunks.
    pub fn check_timeout(&mut self, _: &Context) { unreachable!() }

    pub fn is_inactive(&self) -> bool { unreachable!() }

    pub fn set_active_peers(&mut self, _: HashSet<NodeId>) { unreachable!() }

    pub fn on_peer_disconnected(&mut self, _: &NodeId) { unreachable!() }

    fn note_failure(&mut self, _: &NodeId) { unreachable!() }
}

impl Debug for SnapshotChunkManager {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result { write!(f, "") }
}

#[derive(DeriveMallocSizeOf)]
struct DownloadingChunkStatus {
    peer: NodeId,
    start_time: Instant,
}

#[derive(DeriveMallocSizeOf)]
pub struct SnapshotChunkConfig {
    pub max_downloading_chunks: usize,
    pub chunk_request_timeout: Duration,
}
