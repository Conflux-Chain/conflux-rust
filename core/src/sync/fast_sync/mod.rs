mod snapshot_chunk_request;
mod snapshot_chunk_response;
mod snapshot_chunk_sync;
mod snapshot_manifest_request;
mod snapshot_manifest_response;

use crate::sync::request_manager::RequestManager;
use cfx_types::H256;
use network::NetworkContext;

/// Trait of fast sync state with given checkpoint. Generally, there're 2 ways
/// to fast sync state:
/// 1. Recursively sync the state MPT from root node to leaf node without
/// accurate progress.
/// 2. Divide the state MPT into different chunks, and sync up all chunks
/// with accurate progress.
pub trait FastSync {
    /// Start to fast sync state for the specified checkpoint.
    /// - If fast sync is inactive, then start to sync.
    /// - Otherwise if checkpoint not changed, then no-op happen.
    /// - Otherwise, cleanup the previous sync and start new sync.
    fn start(
        &mut self, _checkpoint: H256, _io: &NetworkContext,
        _request_manager: &RequestManager,
    );
}

pub use self::{
    snapshot_chunk_request::SnapshotChunkRequest,
    snapshot_chunk_response::SnapshotChunkResponse,
    snapshot_chunk_sync::SnapshotChunkSync,
    snapshot_manifest_request::SnapshotManifestRequest,
    snapshot_manifest_response::SnapshotManifestResponse,
};
