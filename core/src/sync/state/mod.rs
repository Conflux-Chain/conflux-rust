// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod snapshot_chunk_request;
mod snapshot_chunk_response;
mod snapshot_chunk_sync;
mod snapshot_manifest_request;
mod snapshot_manifest_response;

use crate::sync::SynchronizationProtocolHandler;
use cfx_types::H256;
use network::NetworkContext;

/// Trait of sync state with given checkpoint. Generally, there're 2 ways
/// to sync state:
/// 1. Recursively sync the state MPT from root node to leaf node without
/// accurate progress.
/// 2. Divide the state MPT into different chunks, and sync up all chunks
/// with accurate progress.
pub trait StateSync {
    /// Start to sync state for the specified checkpoint.
    /// - If sync is inactive, then start to sync state.
    /// - Otherwise if checkpoint not changed, then no-op happen.
    /// - Otherwise, cleanup the previous sync and start new sync.
    fn start(
        &self, _checkpoint: H256, _trusted_blame_block: H256,
        _io: &NetworkContext, _sync_handler: &SynchronizationProtocolHandler,
    );
}

pub use self::{
    snapshot_chunk_request::SnapshotChunkRequest,
    snapshot_chunk_response::SnapshotChunkResponse,
    snapshot_chunk_sync::{SnapshotChunkSync, Status},
    snapshot_manifest_request::SnapshotManifestRequest,
    snapshot_manifest_response::SnapshotManifestResponse,
};
